// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_api.h"
#include "ebpf_extension.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"
#include "net_ebpf_ext_program_info.h"
#include "sample_ext_program_info.h"
#include "usersim/ex.h"
#include "usersim/ke.h"

#include <map>
#include <mutex>
#include <vector>

// Prototype added as the libbpf headers cause conflicts with the execution context headers.
int
bpf_link__destroy(bpf_link* link);

typedef struct _close_bpf_link
{
    void
    operator()(_In_opt_ _Post_invalid_ bpf_link* link)
    {
        bpf_link__destroy(link);
    }
} close_bpf_link_t;

typedef std::unique_ptr<bpf_link, close_bpf_link_t> bpf_link_ptr;

typedef class _hook_helper
{
  public:
    _hook_helper(ebpf_attach_type_t attach_type) : _attach_type(attach_type) {}

    _Must_inspect_result_ ebpf_result_t
    attach_link(
        fd_t program_fd,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size,
        _Out_ bpf_link_ptr* unique_link)
    {
        bpf_link* link = nullptr;
        ebpf_result_t result;

        result = ebpf_program_attach_by_fd(program_fd, &_attach_type, attach_parameters, attach_parameters_size, &link);
        if (result == EBPF_SUCCESS) {
            unique_link->reset(link);
        }

        return result;
    }

    _Must_inspect_result_ ebpf_result_t
    attach_link(
        fd_t program_fd,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size,
        _Outptr_ bpf_link** link)
    {
        return ebpf_program_attach_by_fd(program_fd, &_attach_type, attach_parameters, attach_parameters_size, link);
    }

    void
    detach_link(_Inout_ bpf_link* link)
    {
        if (ebpf_link_detach(link) != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_link_detach failed");
        }
    }

    void
    close_link(_Frees_ptr_ bpf_link* link)
    {
#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory '*link'.
        ebpf_link_close(link);
#pragma warning(pop)
    }

    void
    detach_and_close_link(_Inout_ bpf_link_ptr* unique_link)
    {
        bpf_link* link = unique_link->release();
        detach_link(link);
        close_link(link);
    }

  private:
    ebpf_attach_type_t _attach_type;
} hook_helper_t;

/**
 * @brief General-purpose NMR hook provider supporting N clients keyed by attach_id.
 *        Manages the NMR provider lifecycle and client attach/detach.
 *        Programs attach with a uint8_t attach_id (from attach parameters); if no
 *        attach_id is provided, defaults to 0. The attach_id can be any value as
 *        long as it is unique among currently attached clients.
 */
typedef class _hook_provider : public _hook_helper
{
  public:
    _hook_provider(
        ebpf_program_type_t program_type,
        ebpf_attach_type_t attach_type,
        bpf_link_type link_type = BPF_LINK_TYPE_UNSPEC,
        uint32_t max_clients = UINT32_MAX)
        : _hook_helper{attach_type}, nmr_provider_handle(nullptr), _max_clients(max_clients)
    {
        attach_provider_data.header = EBPF_ATTACH_PROVIDER_DATA_HEADER;
        attach_provider_data.supported_program_type = program_type;
        attach_provider_data.bpf_attach_type = ebpf_get_bpf_attach_type(&attach_type);
        this->attach_type = attach_type;
        attach_provider_data.link_type = link_type;
        module_id.Guid = attach_type;
    }

    ~_hook_provider()
    {
        if (nmr_provider_handle != NULL) {
            NTSTATUS status = NmrDeregisterProvider(nmr_provider_handle);
            if (status == STATUS_PENDING) {
                NmrWaitForProviderDeregisterComplete(nmr_provider_handle);
            } else {
                ebpf_assert(status == STATUS_SUCCESS);
            }
        }
    }

    ebpf_result_t
    initialize()
    {
        NTSTATUS status = NmrRegisterProvider(&provider_characteristics, this, &nmr_provider_handle);
        return (status == STATUS_SUCCESS) ? EBPF_SUCCESS : EBPF_FAILED;
    }

    _Must_inspect_result_ ebpf_result_t
    attach(fd_t program_fd, uint8_t attach_id)
    {
        bpf_link* link = nullptr;
        ebpf_result_t result =
            ebpf_program_attach_by_fd(program_fd, &attach_type, &attach_id, sizeof(attach_id), &link);
        if (result == EBPF_SUCCESS) {
            // The NMR attach callback runs synchronously and inserts the client,
            // so clients[attach_id] is guaranteed to exist here.
            std::lock_guard<std::mutex> lock(_mutex);
            clients[attach_id].link_object = link;
        }
        return result;
    }

    _Must_inspect_result_ ebpf_result_t
    attach(_In_ const bpf_program* program, uint8_t attach_id)
    {
        bpf_link* link = nullptr;
        ebpf_result_t result = ebpf_program_attach(program, &attach_type, &attach_id, sizeof(attach_id), &link);
        if (result == EBPF_SUCCESS) {
            std::lock_guard<std::mutex> lock(_mutex);
            clients[attach_id].link_object = link;
        }
        return result;
    }

    _Must_inspect_result_ ebpf_result_t
    attach(
        _In_ const bpf_program* program,
        _In_reads_bytes_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size)
    {
        // Extract attach_id from raw params (same logic as NMR callback).
        uint8_t attach_id = 0;
        if (attach_parameters != nullptr && attach_parameters_size >= sizeof(uint8_t)) {
            attach_id = *reinterpret_cast<const uint8_t*>(attach_parameters);
        }
        bpf_link* link = nullptr;
        ebpf_result_t result =
            ebpf_program_attach(program, &attach_type, attach_parameters, attach_parameters_size, &link);
        if (result == EBPF_SUCCESS) {
            std::lock_guard<std::mutex> lock(_mutex);
            clients[attach_id].link_object = link;
        }
        return result;
    }

    void
    detach(uint8_t attach_id)
    {
        bpf_link* link = nullptr;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            auto it = clients.find(attach_id);
            if (it != clients.end() && it->second.link_object != nullptr) {
                link = it->second.link_object;
                it->second.link_object = nullptr;
            }
        }
        if (link != nullptr) {
            ebpf_link_detach(link);
            ebpf_link_close(link);
        }
    }

    _Must_inspect_result_ ebpf_result_t
    detach(fd_t program_fd, _In_reads_bytes_(attach_parameter_size) void* attach_parameter, size_t attach_parameter_size)
    {
        return ebpf_program_detach(program_fd, &attach_type, attach_parameter, attach_parameter_size);
    }

    _Must_inspect_result_ ebpf_result_t
    fire(_Inout_ void* context, _Out_ uint32_t* result, uint8_t attach_id)
    {
        ebpf_result_t (*invoke_program)(_In_ const void* link, _Inout_ void* context, _Out_ uint32_t* result) = nullptr;
        const void* binding_context = nullptr;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            auto it = clients.find(attach_id);
            if (it == clients.end() || it->second.binding_context == nullptr) {
                return EBPF_EXTENSION_FAILED_TO_LOAD;
            }
            auto* client = &it->second;
            invoke_program = reinterpret_cast<decltype(invoke_program)>(client->dispatch_table->function[0]);
            binding_context = client->binding_context;
        }
        return invoke_program(binding_context, context, result);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_begin(size_t state_size, _Out_writes_(state_size) void* state, uint8_t attach_id)
    {
        ebpf_program_batch_begin_invoke_function_t batch_begin_function = nullptr;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            auto it = clients.find(attach_id);
            if (it == clients.end() || it->second.binding_context == nullptr) {
                return EBPF_EXTENSION_FAILED_TO_LOAD;
            }
            batch_begin_function =
                reinterpret_cast<decltype(batch_begin_function)>(it->second.dispatch_table->function[1]);
        }
        return batch_begin_function(state_size, state);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_invoke(_Inout_ void* program_context, _Out_ uint32_t* result, _In_ const void* state, uint8_t attach_id)
    {
        ebpf_program_batch_invoke_function_t batch_invoke_function = nullptr;
        const void* binding_context = nullptr;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            auto it = clients.find(attach_id);
            if (it == clients.end() || it->second.binding_context == nullptr) {
                return EBPF_EXTENSION_FAILED_TO_LOAD;
            }
            auto* client = &it->second;
            batch_invoke_function =
                reinterpret_cast<decltype(batch_invoke_function)>(client->dispatch_table->function[2]);
            binding_context = client->binding_context;
        }
        return batch_invoke_function(binding_context, program_context, result, state);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_end(_In_ void* state, uint8_t attach_id)
    {
        ebpf_program_batch_end_invoke_function_t batch_end_function = nullptr;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            auto it = clients.find(attach_id);
            if (it == clients.end() || it->second.binding_context == nullptr) {
                return EBPF_EXTENSION_FAILED_TO_LOAD;
            }
            batch_end_function =
                reinterpret_cast<decltype(batch_end_function)>(it->second.dispatch_table->function[3]);
        }
        return batch_end_function(state);
    }

    _Ret_maybenull_ const ebpf_extension_data_t*
    get_client_data(uint8_t attach_id) const
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = clients.find(attach_id);
        if (it == clients.end()) {
            return nullptr;
        }
        return it->second.data;
    }

  protected:
    ebpf_attach_type_t attach_type;

    struct client_entry_t
    {
        _hook_provider* owner = nullptr;
        uint8_t id = 0;
        PNPI_REGISTRATION_INSTANCE registration_instance = nullptr;
        const void* binding_context = nullptr;
        const ebpf_extension_data_t* data = nullptr;
        const ebpf_extension_dispatch_table_t* dispatch_table = nullptr;
        HANDLE nmr_binding_handle = nullptr;
        bpf_link* link_object = nullptr;
    };

    std::map<uint8_t, client_entry_t> clients;

  private:

    static NTSTATUS
    provider_attach_client_callback(
        HANDLE nmr_binding_handle,
        _Inout_ void* provider_context,
        _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
        _In_ const void* client_binding_context,
        _In_ const void* client_dispatch,
        _Out_ void** provider_binding_context,
        _Outptr_result_maybenull_ const void** provider_dispatch)
    {
        auto hook = reinterpret_cast<_hook_provider*>(provider_context);
        std::lock_guard<std::mutex> lock(hook->_mutex);

        // Read attach_id from attach parameters. Default to 0 if absent.
        uint8_t attach_id = 0;
        auto client_data =
            reinterpret_cast<const ebpf_extension_data_t*>(client_registration_instance->NpiSpecificCharacteristics);
        if (client_data != nullptr && client_data->data != nullptr &&
            client_data->data_size >= sizeof(uint8_t)) {
            attach_id = *reinterpret_cast<const uint8_t*>(client_data->data);
        }

        // Reject if max_clients already reached or attach_id already in use.
        if (hook->clients.size() >= hook->_max_clients) {
            return STATUS_NOINTERFACE;
        }
        if (hook->clients.count(attach_id) != 0) {
            return STATUS_NOINTERFACE;
        }

        auto& slot = hook->clients[attach_id];
        slot.owner = hook;
        slot.id = attach_id;
        slot.registration_instance = client_registration_instance;
        slot.binding_context = client_binding_context;
        slot.nmr_binding_handle = nmr_binding_handle;
        slot.dispatch_table = (const ebpf_extension_dispatch_table_t*)client_dispatch;
        slot.data = client_data;

        *provider_binding_context = &slot;
        *provider_dispatch = NULL;
        return STATUS_SUCCESS;
    }

    static NTSTATUS
    provider_detach_client_callback(_Inout_ void* provider_binding_context)
    {
        auto entry = reinterpret_cast<client_entry_t*>(provider_binding_context);
        auto* hook = entry->owner;
        std::lock_guard<std::mutex> lock(hook->_mutex);
        hook->clients.erase(entry->id);
        return EBPF_SUCCESS;
    }

    ebpf_attach_provider_data_t attach_provider_data;
    NPI_MODULEID module_id = {sizeof(NPI_MODULEID), MIT_GUID};
    const NPI_PROVIDER_CHARACTERISTICS provider_characteristics = {
        0,
        sizeof(provider_characteristics),
        (NPI_PROVIDER_ATTACH_CLIENT_FN*)provider_attach_client_callback,
        (NPI_PROVIDER_DETACH_CLIENT_FN*)provider_detach_client_callback,
        NULL,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &EBPF_HOOK_EXTENSION_IID,
            &module_id,
            0,
            &attach_provider_data,
        },
    };
    HANDLE nmr_provider_handle;
    uint32_t _max_clients;
    mutable std::mutex _mutex;
} hook_provider_t;

// For backward compatibility.
typedef _hook_provider multi_instance_hook_t;

/**
 * @brief Single-instance hook provider. Constrains _hook_provider to max 1 client.
 *        Provides convenience overloads that omit attach_id (always uses 0).
 */
typedef class _single_instance_hook : public _hook_provider
{
  public:
    _single_instance_hook(
        ebpf_program_type_t program_type,
        ebpf_attach_type_t attach_type,
        bpf_link_type link_type = BPF_LINK_TYPE_UNSPEC)
        : _hook_provider{program_type, attach_type, link_type, 1}
    {
    }

    using _hook_provider::attach;
    using _hook_provider::detach;
    using _hook_provider::fire;
    using _hook_provider::batch_begin;
    using _hook_provider::batch_invoke;
    using _hook_provider::batch_end;
    using _hook_provider::get_client_data;

    _Must_inspect_result_ ebpf_result_t
    attach(fd_t program_fd)
    {
        return _hook_provider::attach(program_fd, 0);
    }

    _Must_inspect_result_ ebpf_result_t
    attach(_In_ const bpf_program* program)
    {
        return _hook_provider::attach(program, (uint8_t)0);
    }

    void
    detach()
    {
        _hook_provider::detach((uint8_t)0);
    }

    _Must_inspect_result_ ebpf_result_t
    fire(_Inout_ void* context, _Out_ uint32_t* result)
    {
        return _hook_provider::fire(context, result, 0);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_begin(size_t state_size, _Out_writes_(state_size) void* state)
    {
        return _hook_provider::batch_begin(state_size, state, 0);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_invoke(_Inout_ void* program_context, _Out_ uint32_t* result, _In_ const void* state)
    {
        return _hook_provider::batch_invoke(program_context, result, state, 0);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_end(_In_ void* state)
    {
        return _hook_provider::batch_end(state, 0);
    }

    _Ret_maybenull_ const ebpf_extension_data_t*
    get_client_data() const
    {
        return _hook_provider::get_client_data(0);
    }
} single_instance_hook_t;