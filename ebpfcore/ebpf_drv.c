// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * WDF based driver that does the following:
 * 1. Initializes the eBPF execution context.
 * 2. Opens an IOCTL surface that forwards commands to ebpf_core.
 */

#include "ebpf_core.h"
#include "ebpf_tracelog.h"
#include "ebpf_version.h"
#include "git_commit_id.h"

#pragma warning(push)
#pragma warning(disable : 4062) // enumerator 'identifier' in switch of enum 'enumeration' is not handled
#include <wdf.h>
#pragma warning(pop)

// Driver global variables
static DEVICE_OBJECT* _ebpf_driver_device_object;
static BOOLEAN _ebpf_driver_unloading_flag = FALSE;

// SID for ebpfsvc (generated using command "sc.exe showsid ebpfsvc"):
// S-1-5-80-3453964624-2861012444-1105579853-3193141192-1897355174
//
// SDDL_DEVOBJ_SYS_ALL_ADM_ALL + SID for ebpfsvc.
#define EBPF_EXECUTION_CONTEXT_DEVICE_SDDL \
    L"D:P(A;;GA;;;S-1-5-80-3453964624-2861012444-1105579853-3193141192-1897355174)(A;;GA;;;BA)(A;;GA;;;SY)"

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
// Device type
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPF_CTL_METHOD_BUFFERED CTL_CODE(EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

const char ebpf_core_version[] = EBPF_VERSION " " GIT_COMMIT_ID;

PSECURITY_DESCRIPTOR ebpf_execution_context_privileged_security_descriptor = NULL;

//
// Pre-Declarations
//
static EVT_WDF_FILE_CLOSE _ebpf_driver_file_close;
static EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL _ebpf_driver_io_device_control;
static EVT_WDFDEVICE_WDM_IRP_PREPROCESS _ebpf_driver_query_volume_information;
static EVT_WDF_REQUEST_CANCEL _ebpf_driver_io_device_control_cancel;
DRIVER_INITIALIZE DriverEntry;

static VOID
_ebpf_driver_io_device_control(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    size_t output_buffer_length,
    size_t input_buffer_length,
    unsigned long io_control_code);

static _Function_class_(EVT_WDF_DRIVER_UNLOAD) _IRQL_requires_same_
    _IRQL_requires_max_(PASSIVE_LEVEL) void _ebpf_driver_unload(_In_ WDFDRIVER driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);

    _ebpf_driver_unloading_flag = TRUE;

    if (ebpf_execution_context_privileged_security_descriptor) {
        ebpf_free(ebpf_execution_context_privileged_security_descriptor);
        ebpf_execution_context_privileged_security_descriptor = NULL;
    }

    ebpf_core_terminate();
}

static _Check_return_ NTSTATUS
_ebpf_driver_build_privileged_security_descriptor()
{
    PACL dacl = NULL;
    PSID sid = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    SECURITY_DESCRIPTOR security_descriptor;
    PSECURITY_DESCRIPTOR self_relative_security_descriptor = NULL;
    const ULONG sid_subauthorities[] = {3453964624, 2861012444, 1105579853, 3193141192, 1897355174};
    const SID_IDENTIFIER_AUTHORITY service_authority = {0x00, 0x00, 0x00, 0x00, 0x00, 0x50}; // S-1-5-80
    const ULONG subauthority_count = EBPF_COUNT_OF(sid_subauthorities);
    ULONG security_descriptor_size = 0;

    sid = (PSID)ebpf_allocate_with_tag(
        RtlLengthRequiredSid(subauthority_count), 'fpBE'); // Use a tag to help with debugging memory leaks.
    if (sid == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ebpf_allocate_with_tag, status);
        goto Exit;
    }

    // Initialize the SID for the ebpfsvc service.
    status = RtlInitializeSid(sid, (SID_IDENTIFIER_AUTHORITY*)&service_authority, (UCHAR)subauthority_count);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlInitializeSid, status);
        goto Exit;
    }

    for (ULONG i = 0; i < subauthority_count; i++) {
        *RtlSubAuthoritySid(sid, i) = sid_subauthorities[i];
    }

    status = RtlCreateSecurityDescriptor(&security_descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlCreateSecurityDescriptor, status);
        goto Exit;
    }

    // Allocate and initialize a DACL with one ACE.
    ULONG aclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(sid) - sizeof(ULONG);
    dacl = (PACL)ebpf_allocate_with_tag(aclSize, 'fpBE'); // Use a tag to help with debugging memory leaks.
    if (dacl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ebpf_allocate_with_tag, status);
        goto Exit;
    }

    // Create the DACL with one ACE that allows GENERIC_ALL access to the ebpfsvc service SID.
    status = RtlCreateAcl(dacl, aclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlCreateAcl, status);
        goto Exit;
    }

    // Add an ACE to the DACL that grants GENERIC_ALL access to the ebpfsvc service SID.
    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, sid);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlAddAccessAllowedAce, status);
        goto Exit;
    }

    // Set the DACL in the security descriptor.
    status = RtlSetDaclSecurityDescriptor(&security_descriptor, TRUE, dacl, FALSE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlSetDaclSecurityDescriptor, status);
        goto Exit;
    }

    // Convert security descriptor to self-relative format.
    // First, we need to determine the size of the self-relative security descriptor.
    status = RtlAbsoluteToSelfRelativeSD(&security_descriptor, NULL, &security_descriptor_size);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlAbsoluteToSelfRelativeSD, status);
        goto Exit;
    }

    // Allocate memory for the self-relative security descriptor.
    self_relative_security_descriptor = ebpf_allocate_with_tag(security_descriptor_size, 'fpBE');
    if (self_relative_security_descriptor == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ebpf_allocate_with_tag, status);
        goto Exit;
    }

    // Convert the absolute security descriptor to self-relative format.
    status =
        RtlAbsoluteToSelfRelativeSD(&security_descriptor, self_relative_security_descriptor, &security_descriptor_size);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlAbsoluteToSelfRelativeSD, status);
        goto Exit;
    }

    // Set the global security descriptor to the self-relative format.
    ebpf_execution_context_privileged_security_descriptor = self_relative_security_descriptor;
    self_relative_security_descriptor = NULL;

Exit:
    if (sid) {
        ebpf_free(sid);
    }

    if (dacl) {
        ebpf_free(dacl);
    }

    if (self_relative_security_descriptor) {
        ebpf_free(self_relative_security_descriptor);
    }

    return status;
}

static _Check_return_ NTSTATUS
_ebpf_driver_initialize_device(WDFDRIVER driver_handle, _Out_ WDFDEVICE* device)
{
    NTSTATUS status;
    PWDFDEVICE_INIT device_initialize = NULL;
    WDF_OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING ebpf_device_name;
    WDF_FILEOBJECT_CONFIG file_object_config;
    UNICODE_STRING ebpf_symbolic_device_name;

    // Log the version of the driver at startup.
    // This is useful for debugging purposes and to ensure that the version string is present in the binary.
    EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_CORE, ebpf_core_version);

    // Allow access to kernel/system, administrators, and ebpfsvc only.
    DECLARE_CONST_UNICODE_STRING(security_descriptor, EBPF_EXECUTION_CONTEXT_DEVICE_SDDL);
    device_initialize = WdfControlDeviceInitAllocate(driver_handle, &security_descriptor);
    if (!device_initialize) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfControlDeviceInitAllocate, status);
        goto Exit;
    }

    WdfDeviceInitSetDeviceType(device_initialize, FILE_DEVICE_NULL);
    WdfDeviceInitSetCharacteristics(device_initialize, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetCharacteristics(device_initialize, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);
    RtlInitUnicodeString(&ebpf_device_name, EBPF_DEVICE_NAME);
    status = WdfDeviceInitAssignName(device_initialize, &ebpf_device_name);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDeviceInitAssignName, status);
        goto Exit;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.SynchronizationScope = WdfSynchronizationScopeNone;
    WDF_FILEOBJECT_CONFIG_INIT(&file_object_config, NULL, _ebpf_driver_file_close, WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(device_initialize, &file_object_config, &attributes);

    // WDF framework doesn't handle IRP_MJ_QUERY_VOLUME_INFORMATION so register a handler for this IRP.
    status = WdfDeviceInitAssignWdmIrpPreprocessCallback(
        device_initialize, _ebpf_driver_query_volume_information, IRP_MJ_QUERY_VOLUME_INFORMATION, NULL, 0);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDeviceInitAssignWdmIrpPreprocessCallback, status);
        goto Exit;
    }

    status = WdfDeviceCreate(&device_initialize, WDF_NO_OBJECT_ATTRIBUTES, device);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDeviceCreate, status);
        goto Exit;
    }

    // Create symbolic link for control object for user mode.
    RtlInitUnicodeString(&ebpf_symbolic_device_name, EBPF_SYMBOLIC_DEVICE_NAME);
    status = WdfDeviceCreateSymbolicLink(*device, &ebpf_symbolic_device_name);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDeviceCreateSymbolicLink, status);
        goto Exit;
    }

Exit:
    if (device_initialize) {
        WdfDeviceInitFree(device_initialize);
    }
    return status;
}

// Create a basic WDF driver, set up the device object for a callout driver and set up the ioctl surface.
static _Check_return_ NTSTATUS
_ebpf_driver_initialize_objects(
    _Inout_ DRIVER_OBJECT* driver_object,
    _In_ const UNICODE_STRING* registry_path,
    _Out_ WDFDRIVER* driver_handle,
    _Out_ WDFDEVICE* device)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG driver_configuration;
    WDF_IO_QUEUE_CONFIG io_queue_configuration;
    BOOLEAN device_create_flag = FALSE;
    BOOLEAN ebpf_core_initialized = FALSE;

    // IMPORTANT NOTE: The choice of implementing part of the driver initialization in another function
    // (_ebpf_driver_initialize_device()) is deliberate.  We perform a lot of standard WDF driver initialization here
    // (and ebpf support code as well) and consequently need quite a few local variables (most of 'struct' type). Some
    // of these are quite large and end up chewing up a lot of stack space. This causes Code Analysis tools to flag
    // compile-time stack overflow errors when these variables (together) exceed the default stack size of 1024 bytes.
    //
    // This split between multiple functions ensures we don't hit this condition. Please keep this mind when
    // refactoring/enhancing this function.
    //
    // One way to ensure this would be to run Code Analysis tools locally to catch such issues very early rather than
    // wait for them to be flagged at the CI/CD gate during PR validation.
    //
    // OTOH, the CI/CD pipeline performs this check on a 'Draft PR' as well, so that's an option too.

    WDF_DRIVER_CONFIG_INIT(&driver_configuration, WDF_NO_EVENT_CALLBACK);
    driver_configuration.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    driver_configuration.EvtDriverUnload = _ebpf_driver_unload;
    status =
        WdfDriverCreate(driver_object, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &driver_configuration, driver_handle);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDriverCreate, status);
        goto Exit;
    }

    status = _ebpf_driver_initialize_device(*driver_handle, device);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_CRITICAL, EBPF_TRACELOG_KEYWORD_ERROR, (char*)"_ebpf_driver_initialize_device", status);
        goto Exit;
    }

    device_create_flag = TRUE;

    // Create default queue.
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&io_queue_configuration, WdfIoQueueDispatchParallel);
    io_queue_configuration.EvtIoDeviceControl = _ebpf_driver_io_device_control;
    status = WdfIoQueueCreate(*device, &io_queue_configuration, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfIoQueueCreate, status);
        goto Exit;
    }

    status = ebpf_result_to_ntstatus(ebpf_core_initiate());
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ebpf_core_initiate, status);
        goto Exit;
    }

    ebpf_core_initialized = TRUE;

    status = _ebpf_driver_build_privileged_security_descriptor();
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(
            EBPF_TRACELOG_KEYWORD_ERROR, _ebpf_driver_build_privileged_security_descriptor, status);
        goto Exit;
    }

    WdfControlFinishInitializing(*device);

Exit:
    if (!NT_SUCCESS(status)) {
        if (ebpf_core_initialized) {
            ebpf_core_terminate();
        }

        if (device_create_flag && device != NULL) {

            // Release the reference on the newly created object, since we couldn't initialize it.
            WdfObjectDelete(*device);
        }
    }
    return status;
}

static void
_ebpf_driver_file_close(WDFFILEOBJECT wdf_file_object)
{
    FILE_OBJECT* file_object = WdfFileObjectWdmGetFileObject(wdf_file_object);
    ebpf_core_close_context(file_object->FsContext2);
}

static void
_ebpf_driver_io_device_control_complete(_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result)
{
    NTSTATUS status;
    WDFREQUEST request = (WDFREQUEST)context;
    status = WdfRequestUnmarkCancelable(request);
    UNREFERENCED_PARAMETER(status);
    WdfRequestCompleteWithInformation(request, ebpf_result_to_ntstatus(result), output_buffer_length);
    WdfObjectDereference(request);
}

static void
_ebpf_driver_io_device_control_cancel(WDFREQUEST request)
{
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/nc-wdfrequest-evt_wdf_request_cancel
    ebpf_core_cancel_protocol_handler(request);
}

static bool
_ebpf_driver_is_caller_privileged()
{
    // Check if the caller has the required privileges.
    SECURITY_SUBJECT_CONTEXT subject_context;
    SeCaptureSubjectContext(&subject_context);
    ACCESS_MASK granted_access = 0;
    GENERIC_MAPPING generic_mapping = {1, 1, 1, 1}; // No generic mapping needed for this check
    NTSTATUS status;
    BOOLEAN result = SeAccessCheck(
        ebpf_execution_context_privileged_security_descriptor,
        &subject_context,
        FALSE,            // Subject context is not locked
        GENERIC_ALL,      // Desired access
        0,                // Previously granted access
        NULL,             // No privileges
        &generic_mapping, // Generic mapping
        KernelMode,       // Access mode
        &granted_access,  // Granted access
        &status);
    SeReleaseSubjectContext(&subject_context);
    return result && NT_SUCCESS(status) &&
           granted_access == GENERIC_ALL; // Check if granted access matches GENERIC_ALL.
}

static VOID
_ebpf_driver_io_device_control(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    size_t output_buffer_length,
    size_t input_buffer_length,
    unsigned long io_control_code)
{
    NTSTATUS status = STATUS_SUCCESS;
    WDFDEVICE device;
    void* input_buffer = NULL;
    void* output_buffer = NULL;
    size_t actual_input_length = 0;
    size_t actual_output_length = 0;
    const struct _ebpf_operation_header* user_request = NULL;
    struct _ebpf_operation_header* user_reply = NULL;
    bool async = false;
    bool privileged = false;
    bool wdf_request_ref_acquired = false;

    device = WdfIoQueueGetDevice(queue);

    switch (io_control_code) {
    case IOCTL_EBPF_CTL_METHOD_BUFFERED:
        // Verify that length of the input buffer supplied to the request object
        // is not zero
        if (input_buffer_length != 0) {
            // Retrieve the input buffer associated with the request object
            status = WdfRequestRetrieveInputBuffer(
                request,             // Request object
                input_buffer_length, // Length of input buffer
                &input_buffer,       // Pointer to buffer
                &actual_input_length // Length of buffer
            );

            if (!NT_SUCCESS(status)) {
                EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfRequestRetrieveInputBuffer, status);
                goto Done;
            }

            if (input_buffer == NULL) {
                status = STATUS_INVALID_PARAMETER;
                EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(
                    EBPF_TRACELOG_KEYWORD_ERROR, "WdfRequestRetrieveInputBuffer", status, "Input buffer is null");
                goto Done;
            }

            if (input_buffer != NULL) {
                size_t minimum_request_size = 0;
                size_t minimum_reply_size = 0;
                void* async_context = NULL;

                user_request = input_buffer;
                if (actual_input_length < sizeof(struct _ebpf_operation_header)) {
                    EBPF_LOG_MESSAGE(
                        EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, "Input buffer is too small");
                    status = STATUS_INVALID_PARAMETER;
                    goto Done;
                }

                status = ebpf_result_to_ntstatus(ebpf_core_get_protocol_handler_properties(
                    user_request->id, &minimum_request_size, &minimum_reply_size, &async, &privileged));
                if (status != STATUS_SUCCESS) {
                    EBPF_LOG_NTSTATUS_API_FAILURE(
                        EBPF_TRACELOG_KEYWORD_ERROR, ebpf_core_get_protocol_handler_properties, status);
                    goto Done;
                }

                if (privileged && !_ebpf_driver_is_caller_privileged()) {
                    EBPF_LOG_MESSAGE(
                        EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, "Caller is not privileged");
                    status = STATUS_ACCESS_DENIED;
                    goto Done;
                }

                // Be aware: Input and output buffer point to the same memory.
                if (minimum_reply_size > 0) {
                    // Retrieve output buffer associated with the request object
                    status = WdfRequestRetrieveOutputBuffer(
                        request, output_buffer_length, &output_buffer, &actual_output_length);
                    if (!NT_SUCCESS(status)) {
                        EBPF_LOG_NTSTATUS_API_FAILURE(
                            EBPF_TRACELOG_KEYWORD_ERROR, WdfRequestRetrieveOutputBuffer, status);
                        goto Done;
                    }
                    if (output_buffer == NULL) {
                        status = STATUS_INVALID_PARAMETER;
                        EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(
                            EBPF_TRACELOG_KEYWORD_ERROR,
                            "WdfRequestRetrieveOutputBuffer",
                            status,
                            "Output buffer is null");
                        goto Done;
                    }

                    if (actual_output_length < minimum_reply_size) {
                        EBPF_LOG_MESSAGE(
                            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, "Output buffer is too small");
                        status = STATUS_BUFFER_TOO_SMALL;
                        goto Done;
                    }
                    user_reply = output_buffer;
                }

                if (async) {
                    WdfObjectReference(request);
                    async_context = request;
                    WdfRequestMarkCancelable(request, _ebpf_driver_io_device_control_cancel);
                    wdf_request_ref_acquired = true;
                }

                status = ebpf_result_to_ntstatus(ebpf_core_invoke_protocol_handler(
                    user_request->id,
                    user_request,
                    (uint16_t)actual_input_length,
                    user_reply,
                    (uint16_t)actual_output_length,
                    async_context,
                    _ebpf_driver_io_device_control_complete));
                if (status != STATUS_SUCCESS) {
                    EBPF_LOG_NTSTATUS_API_FAILURE(
                        EBPF_TRACELOG_KEYWORD_ERROR, "ebpf_core_invoke_protocol_handler", status);
                }
                goto Done;
            }
        } else {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, "Zero length input buffer");
            status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Done:
    if (status != STATUS_PENDING) {
        if (wdf_request_ref_acquired) {
            ebpf_assert(status != STATUS_SUCCESS);
            // Async operation failed. Remove cancellable marker.
            (void)WdfRequestUnmarkCancelable(request);
            WdfObjectDereference(request);
        }
        WdfRequestCompleteWithInformation(request, status, output_buffer_length);
    }
    return;
}

NTSTATUS
DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
    NTSTATUS status;
    WDFDRIVER driver_handle;
    WDFDEVICE device;

    status = ebpf_trace_initiate();
    if (!NT_SUCCESS(status)) {

        // Fail silently as there is no other mechanism to indicate this failure. Note that in this case, the
        // EBPF_LOG_EXIT() call at the end will not log anything either.
        goto Exit;
    }

    EBPF_LOG_ENTRY();

    // Request NX Non-Paged Pool when available
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    status = _ebpf_driver_initialize_objects(driver_object, registry_path, &driver_handle, &device);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_CRITICAL,
            EBPF_TRACELOG_KEYWORD_ERROR,
            (char*)"_ebpf_driver_initialize_objects failed",
            status);
        goto Exit;
    }

    _ebpf_driver_device_object = WdfDeviceWdmGetDeviceObject(device);

Exit:
    EBPF_LOG_EXIT();
    if (!NT_SUCCESS(status)) {
        ebpf_trace_terminate();
    }
    return status;
}

_Ret_notnull_ DEVICE_OBJECT*
ebpf_driver_get_device_object()
{
    return _ebpf_driver_device_object;
}

// The C runtime queries the file type via GetFileType when creating a file
// descriptor. GetFileType queries volume information to get device type via
// FileFsDeviceInformation information class.
NTSTATUS
_ebpf_driver_query_volume_information(_In_ WDFDEVICE device, _Inout_ IRP* irp)
{
    NTSTATUS status;
    IO_STACK_LOCATION* irp_stack_location;
    UNREFERENCED_PARAMETER(device);
    irp_stack_location = IoGetCurrentIrpStackLocation(irp);

    switch (irp_stack_location->Parameters.QueryVolume.FsInformationClass) {
    case FileFsDeviceInformation:
        if (irp_stack_location->Parameters.DeviceIoControl.OutputBufferLength < sizeof(FILE_FS_DEVICE_INFORMATION)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            FILE_FS_DEVICE_INFORMATION* device_info = (FILE_FS_DEVICE_INFORMATION*)irp->AssociatedIrp.SystemBuffer;
            device_info->DeviceType = FILE_DEVICE_NULL;
            device_info->Characteristics = 0;
            status = STATUS_SUCCESS;
        }
        break;
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, 0);
    return status;
}
