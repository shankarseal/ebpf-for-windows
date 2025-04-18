// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief Header file for structures/prototypes of the driver.
 */

#include "ebpf_nethooks.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_program_types.h"
#include "ebpf_shared_framework.h"
#include "ebpf_windows.h"
#include "net_ebpf_ext_hook_provider.h"
#include "net_ebpf_ext_prog_info_provider.h"
#include "net_ebpf_ext_program_info.h"
#include "net_ebpf_ext_structs.h"
#include "net_ebpf_ext_tracelog.h"
#include "netebpfext_platform.h"

#include <guiddef.h>
#include <netioapi.h>
#include <netiodef.h>

#define NET_EBPF_EXTENSION_POOL_TAG 'Nfbe'
#define NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

// Note: The maximum number of clients that can attach per-hook in multi-attach case has been currently capped to
// a constant value to keep the implementation simple. Keeping the max limit constant allows allocating the memory
// required for creating a copy of list of clients on the stack itself. In the future, if there is a need to increase
// this maximum count, the value can be simply increased as long as the required memory can still be allocated on stack.
// If the required memory becomes too large, we may need to switch to a different design to handle this. One option is
// to use epoch based memory management for the list of clients. This eliminates the need to create a copy of programs
// per-invocation. Another option can be to always invoke the programs while holding the socket context lock, but that
// comes with a side effect of every program invocation now happening at DISPATCH_LEVEL.
#define NET_EBPF_EXT_MAX_CLIENTS_PER_HOOK_MULTI_ATTACH 16
#define NET_EBPF_EXT_MAX_CLIENTS_PER_HOOK_SINGLE_ATTACH 1

CONST IN6_ADDR DECLSPEC_SELECTANY in6addr_v4mappedprefix = IN6ADDR_V4MAPPEDPREFIX_INIT;

#define _ACQUIRE_PUSH_LOCK(lock, mode) \
    {                                  \
        KeEnterCriticalRegion();       \
        ExAcquirePushLock##mode(lock); \
    }

#define _RELEASE_PUSH_LOCK(lock, mode) \
    {                                  \
        ExReleasePushLock##mode(lock); \
        KeLeaveCriticalRegion();       \
    }

#define ACQUIRE_PUSH_LOCK_EXCLUSIVE(lock) _ACQUIRE_PUSH_LOCK(lock, Exclusive)
#define ACQUIRE_PUSH_LOCK_SHARED(lock) _ACQUIRE_PUSH_LOCK(lock, Shared)

#define RELEASE_PUSH_LOCK_EXCLUSIVE(lock) _RELEASE_PUSH_LOCK(lock, Exclusive)
#define RELEASE_PUSH_LOCK_SHARED(lock) _RELEASE_PUSH_LOCK(lock, Shared)

#define htonl(x) _byteswap_ulong(x)
#define htons(x) _byteswap_ushort(x)
#define ntohl(x) _byteswap_ulong(x)
#define ntohs(x) _byteswap_ushort(x)
struct _net_ebpf_extension_hook_client;

typedef struct _wfp_ale_layer_fields
{
    uint16_t local_ip_address_field;
    uint16_t local_port_field;
    uint16_t remote_ip_address_field;
    uint16_t remote_port_field;
    uint16_t protocol_field;
    uint32_t direction_field;
    uint16_t compartment_id_field;
    uint16_t interface_luid_field;
    uint16_t user_id_field;
    uint16_t flags_field;
} wfp_ale_layer_fields_t;

typedef struct _net_ebpf_extension_wfp_filter_parameters
{
    const GUID* layer_guid;            ///< GUID of WFP layer to which this filter is associated.
    const GUID* sublayer_guid;         ///< GUID of the WFP sublayer to which this filter is associated.
    const GUID* callout_guid;          ///< GUID of WFP callout to which this filter is associated.
    const wchar_t* name;               ///< Display name of filter.
    const wchar_t* description;        ///< Description of filter.
    const FWP_ACTION_TYPE action_type; ///< Action type for the filter.
} net_ebpf_extension_wfp_filter_parameters_t;

typedef struct _net_ebpf_ext_sublayer_info
{
    const GUID* sublayer_guid;
    const wchar_t* name;
    const wchar_t* description;
    const uint32_t flags;
    const uint16_t weight;
} net_ebpf_ext_sublayer_info_t;

typedef struct _net_ebpf_extension_wfp_filter_parameters_array
{
    ebpf_attach_type_t* attach_type;
    uint32_t count;
    net_ebpf_extension_wfp_filter_parameters_t* filter_parameters;
} net_ebpf_extension_wfp_filter_parameters_array_t;

/**
 * "Base class" for all WFP filter contexts used by net ebpf extension hooks.
 */

typedef enum _net_ebpf_ext_wfp_filter_state
{
    NET_EBPF_EXT_WFP_FILTER_ADDED = 1,
    NET_EBPF_EXT_WFP_FILTER_DELETING = 2,
    NET_EBPF_EXT_WFP_FILTER_DELETED = 3,
    NET_EBPF_EXT_WFP_FILTER_DELETE_FAILED = 4,

} net_ebpf_ext_wfp_filter_state_t;

typedef struct _net_ebpf_ext_wfp_filter_id
{
    wchar_t* name;
    uint64_t id;
    net_ebpf_ext_wfp_filter_state_t state;
    NTSTATUS error_code;
} net_ebpf_ext_wfp_filter_id_t;

typedef struct _net_ebpf_extension_wfp_filter_context
{
    LIST_ENTRY link;                   ///< Entry in the list of filter contexts.
    volatile long reference_count;     ///< Reference count.
    EX_SPIN_LOCK lock;                 ///< Lock to protect the client context array.
    uint32_t client_context_count_max; ///< Maximum number of hook NPI clients.
    _Guarded_by_(
        lock) struct _net_ebpf_extension_hook_client** client_contexts; ///< Array of pointers to hook NPI clients.
    _Guarded_by_(lock) uint32_t client_context_count;                   ///< Current number of hook NPI clients.
    const struct _net_ebpf_extension_hook_provider* provider_context;   ///< Pointer to provider binding context.

    net_ebpf_ext_wfp_filter_id_t* filter_ids; ///< Array of WFP filter Ids.
    uint32_t filter_ids_count;                ///< Number of WFP filter Ids.

    bool context_deleting : 1; ///< True if all the clients have been detached and the context is being deleted.
    bool wildcard : 1;         ///< True if the filter context is for wildcard filters.
    bool initialized : 1;      ///< True if the filter context has been successfully initialized.
    HANDLE wfp_engine_handle;  ///< WFP engine handle.
} net_ebpf_extension_wfp_filter_context_t;

/**
 * @brief Structure that holds objects related to WFP that require cleanup.
 */
typedef struct _net_ebpf_extension_wfp_cleanup_state
{
    EX_SPIN_LOCK lock;
    _Guarded_by_(lock) LIST_ENTRY provider_context_cleanup_list; ///< List of provider contexts to cleanup.
    _Guarded_by_(lock)
        LIST_ENTRY filter_cleanup_list; ///< List of filter contexts that are awaiting a WFP filter deletion callback.
    bool signal_empty_filter_list : 1;  ///< True if the WFP filter cleanup event should be signaled.
    KEVENT wfp_filter_cleanup_event;    ///< Event to signal when no remaining WFP filters require a deletion callback.
} net_ebpf_extension_wfp_cleanup_state_t;

// Macro definition of warning suppression for 26100. This is only used in the cleanup context, for which
// we are the only reference of the memory
#define PRAGMA_WARNING_PUSH _Pragma("warning(push)")
// Warning 26100: Variable should be protected by a lock.
#define PRAGMA_WARNING_SUPPRESS_26100 _Pragma("warning(suppress: 26100)")
#define PRAGMA_WARNING_POP _Pragma("warning(pop)")

#define CLEAN_UP_FILTER_CONTEXT(filter_context)                             \
    ASSERT((filter_context) != NULL);                                       \
    net_ebpf_ext_remove_filter_context_from_cleanup_list((filter_context)); \
    if ((filter_context)->filter_ids != NULL) {                             \
        ExFreePool((filter_context)->filter_ids);                           \
    }                                                                       \
    PRAGMA_WARNING_PUSH                                                     \
    PRAGMA_WARNING_SUPPRESS_26100                                           \
    if ((filter_context)->client_contexts != NULL) {                        \
        ExFreePool((filter_context)->client_contexts);                      \
    }                                                                       \
    PRAGMA_WARNING_POP                                                      \
    if ((filter_context)->wfp_engine_handle != NULL) {                      \
        FwpmEngineClose((filter_context)->wfp_engine_handle);               \
    }                                                                       \
    ExFreePool((filter_context));

#define REFERENCE_FILTER_CONTEXT(filter_context)                  \
    if ((filter_context) != NULL) {                               \
        InterlockedIncrement(&(filter_context)->reference_count); \
    }

#define DEREFERENCE_FILTER_CONTEXT(filter_context)                                        \
    if ((filter_context) != NULL) {                                                       \
        if (InterlockedDecrement(&(filter_context)->reference_count) == 0) {              \
            net_ebpf_extension_hook_provider_leave_rundown(                               \
                (net_ebpf_extension_hook_provider_t*)(filter_context)->provider_context); \
            CLEAN_UP_FILTER_CONTEXT((filter_context));                                    \
        }                                                                                 \
    }

/**
 * @brief This function allocates and initializes a net ebpf extension WFP filter context. This should be invoked when
 * the hook client is being attached.
 *
 * @param[in] filter_context_size Size in bytes of the filter context.
 * @param[in] client_context Pointer to hook client being attached.
 * @param[in] provider_context Pointer to hook provider context.
 * @param[out] filter_context Pointer to created filter_context.
 *
 * @retval EBPF_SUCCESS The filter context was created successfully.
 * @retval EBPF_NO_MEMORY Out of memory.
 */
_Must_inspect_result_ ebpf_result_t
net_ebpf_extension_wfp_filter_context_create(
    size_t filter_context_size,
    _In_ const struct _net_ebpf_extension_hook_client* client_context,
    _In_ const struct _net_ebpf_extension_hook_provider* provider_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context);

/**
 * @brief This function cleans up the input ebpf extension WFP filter context. This should be invoked when the hook
 * client is being detached.
 *
 * @param[out] filter_context Pointer to filter_context to clean up.
 *
 */
void
net_ebpf_extension_wfp_filter_context_cleanup(_Frees_ptr_ net_ebpf_extension_wfp_filter_context_t* filter_context);

/**
 * @brief Structure for WFP flow Id parameters.
 */
typedef struct _net_ebpf_extension_flow_context_parameters
{
    uint64_t flow_id;    ///< WFP flow Id.
    uint16_t layer_id;   ///< WFP layer Id that this flow is associated to.
    uint32_t callout_id; ///< WFP callout Id that this flow is associated to.
} net_ebpf_extension_flow_context_parameters_t;

typedef enum _net_ebpf_extension_hook_id
{
    EBPF_HOOK_OUTBOUND_L2 = 0,
    EBPF_HOOK_INBOUND_L2,
    EBPF_HOOK_ALE_RESOURCE_ALLOC_V4,
    EBPF_HOOK_ALE_RESOURCE_ALLOC_V6,
    EBPF_HOOK_ALE_RESOURCE_RELEASE_V4,
    EBPF_HOOK_ALE_RESOURCE_RELEASE_V6, // 5
    EBPF_HOOK_ALE_AUTH_CONNECT_V4,
    EBPF_HOOK_ALE_AUTH_CONNECT_V6,
    EBPF_HOOK_ALE_CONNECT_REDIRECT_V4,
    EBPF_HOOK_ALE_CONNECT_REDIRECT_V6,
    EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4, // 10
    EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6,
    EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4,
    EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6
} net_ebpf_extension_hook_id_t;

/**
 * @brief Helper function to return the eBPF network extension hook Id for the input WFP layer Id.
 *
 * @param[in] wfp_layer_id WFP layer Id.
 *
 * @returns eBPF network extension hook Id for the input WFP layer Id.
 */
net_ebpf_extension_hook_id_t
net_ebpf_extension_get_hook_id_from_wfp_layer_id(uint16_t wfp_layer_id);

/**
 * @brief Helper function to return the assigned Id for the WFP callout corresponding to the eBPF hook.
 *
 * @param[in] hook_id eBPF network extension hook id.
 *
 * @returns assigned Id for the WFP callout corresponding to the eBPF hook.
 */
uint32_t
net_ebpf_extension_get_callout_id_for_hook(net_ebpf_extension_hook_id_t hook_id);

/**
 * @brief Add WFP filters with specified conditions at specified layers.
 *
 * @param[in] wfp_filter_handle The WFP filter handle used to add the filters.
 * @param[in] filter_count Count of filters to be added.
 * @param[in] parameters Filter parameters.
 * @param[in] condition_count Count of filter conditions.
 * @param[in] conditions Common filter conditions to be applied to each filter.
 * @param[in, out] filter_context Caller supplied context to be associated with the WFP filter.
 * @param[out] filter_ids Output buffer where the added filter IDs are stored.
 *
 * @retval EBPF_SUCCESS The operation completed successfully.
 * @retval EBPF_INVALID_ARGUMENT One or more arguments are invalid.
 */
_Must_inspect_result_ ebpf_result_t
net_ebpf_extension_add_wfp_filters(
    _In_ HANDLE wfp_engine_handle,
    uint32_t filter_count,
    _In_count_(filter_count) const net_ebpf_extension_wfp_filter_parameters_t* parameters,
    uint32_t condition_count,
    _In_opt_count_(condition_count) const FWPM_FILTER_CONDITION* conditions,
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _Outptr_result_buffer_maybenull_(filter_count) net_ebpf_ext_wfp_filter_id_t** filter_ids);

/**
 * @brief Deletes WFP filters with specified filter IDs.
 *
 * @param[in] wfp_filter_handle The WFP filter handle used to delete the filters.
 * @param[in]  filter_count Count of filters to be added.
 * @param[in]  filter_ids ID of the filter being deleted.
 */
void
net_ebpf_extension_delete_wfp_filters(
    _In_ HANDLE wfp_engine_handle,
    uint32_t filter_count,
    _Frees_ptr_ _In_count_(filter_count) net_ebpf_ext_wfp_filter_id_t* filter_ids);

// eBPF WFP Provider GUID.
// ddb851f5-841a-4b77-8a46-bb7063e9f162
DEFINE_GUID(EBPF_WFP_PROVIDER, 0xddb851f5, 0x841a, 0x4b77, 0x8a, 0x46, 0xbb, 0x70, 0x63, 0xe9, 0xf1, 0x62);

// Default eBPF WFP Sublayer GUID.
// 7c7b3fb9-3331-436a-98e1-b901df457fff
DEFINE_GUID(EBPF_DEFAULT_SUBLAYER, 0x7c7b3fb9, 0x3331, 0x436a, 0x98, 0xe1, 0xb9, 0x01, 0xdf, 0x45, 0x7f, 0xff);

// Globals.
extern NDIS_HANDLE _net_ebpf_ext_nbl_pool_handle;
extern NDIS_HANDLE _net_ebpf_ext_ndis_handle;
extern HANDLE _net_ebpf_ext_l2_injection_handle;
extern DEVICE_OBJECT* _net_ebpf_ext_driver_device_object;

//
// Shared function prototypes.
//

/**
 * @brief Initialize global NDIS handles.
 *
 * @param[in] driver_object The driver object to associate the NDIS generic object handle with.
 * @retval STATUS_SUCCESS NDIS handles initialized successfully.
 * @retval STATUS_INSUFFICIENT_RESOURCES Failed to initialize NDIS handles due to insufficient resources.
 */
NTSTATUS
net_ebpf_ext_initialize_ndis_handles(_In_ const DRIVER_OBJECT* driver_object);

/**
 * @brief Uninitialize global NDIS handles.
 */
void
net_ebpf_ext_uninitialize_ndis_handles();

/**
 * @brief Register for the WFP callouts used to power hooks.
 *
 * @param[in] device_object Device object used by this driver.
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval FWP_E_* A Windows Filtering Platform (WFP) specific error.
 */
NTSTATUS
net_ebpf_extension_initialize_wfp_components(_Inout_ void* device_object);

/**
 * @brief Unregister the WFP callouts.
 *
 */
void
net_ebpf_extension_uninitialize_wfp_components(void);

/**
 * @brief Register network extension NPI providers with eBPF core.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
net_ebpf_ext_register_providers();

/**
 * @brief Unregister network extension NPI providers from eBPF core.
 *
 */
void
net_ebpf_ext_unregister_providers();

NTSTATUS
net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ FWPS_FILTER* filter);

/**
 * @brief Remove the client context from the filter context.
 *
 * @param filter_context Filter context to remove the client from.
 * @param hook_client Hook client to remove.
 */
void
net_ebpf_ext_remove_client_context(
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _In_ const struct _net_ebpf_extension_hook_client* hook_client);

/**
 * @brief Add a client context to the filter context.
 *
 * @param filter_context Filter context to add the client to.
 * @param hook_client Hook client to add.
 *
 * @retval EBPF_SUCCESS The client context was added successfully.
 * @retval EBPF_NO_MEMORY No more client contexts can be added.
 */
ebpf_result_t
net_ebpf_ext_add_client_context(
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _In_ const struct _net_ebpf_extension_hook_client* hook_client);

/**
 * @brief Add a provider context to the cleanup list.
 *
 * @param provider_context Provider context to add.
 */
void
net_ebpf_ext_add_provider_context_to_cleanup_list(_Inout_ net_ebpf_extension_hook_provider_t* provider_context);

/**
 * @brief Add a filter context to the cleanup list.
 *
 * @param filter_context Filter context to add.
 */
void
net_ebpf_ext_add_filter_context_to_cleanup_list(_Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context);

/**
 * @brief Remove a filter context from the cleanup list.
 *
 * @param filter_context Filter context to remove.
 */
void
net_ebpf_ext_remove_filter_context_from_cleanup_list(_Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context);