#include "DedupFilter.h"

PFLT_FILTER g_FilterHandle = NULL;


// ����������� �������  
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),        // ������ ���������
    FLT_REGISTRATION_VERSION,        // ������
    0,                               // �����
    NULL,                            // Contexts (���� �� ������������)
    Callbacks,                       // ��������
    DriverUnload,                    // FilterUnload
    DriverLoad,                      // InstanceSetup
    NULL,                            // InstanceQueryTeardown
    NULL,                            // InstanceTeardownStart
    NULL,                            // InstanceTeardownComplete
    NULL,                            // GenerateFileName
    NULL,                            // GenerateDestinationFileName
    NULL                             // NormalizeNameComponent
};


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DbgPrint("[MYDRIVER] MiniFilter: Started.\n");

    // ������������� �������� ���� ���������� (���� ����)
    ExInitializeFastMutex(&g_HashCacheMutex);

    // ������������� ������� �����
    status = InitializeHashTable();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MYDRIVER] Failed to initialize hash table.\n");
        return status;
    }

    // ������������� ����������
    status = InitializeWatchedDirectories();
    if (!NT_SUCCESS(status)) {
        CleanupHashTable();
        return status;
    }

    // ����������� �������
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[MYDRIVER] MiniFilter: ERROR FltRegisterFilter - %08x\n", status);
        CleanupHashTable();
        return status;
    }

    // ������ ����������
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[MYDRIVER] MiniFilter: ERROR FltStartFiltering - %08x\n", status);
        FltUnregisterFilter(g_FilterHandle);
        CleanupHashTable();
    }

    return status;
}


NTSTATUS
DriverLoad(_In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);


    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ||
        VolumeDeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }


    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[MYDRIVER] MiniFilter: load.\n");

    return STATUS_SUCCESS;
}

NTSTATUS
DriverUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    DumpHashTable();

    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    // ������� ������� �����
    CleanupHashTable();

    // ������� ����������, ���� �����
    g_WatchedDirectoryCount = 0;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[MYDRIVER] MiniFilter: Unload.\n");
    return STATUS_SUCCESS;
}