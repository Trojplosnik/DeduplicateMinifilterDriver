#ifndef _DEDUP_FILTER_H_
#define _DEDUP_FILTER_H_

#include <fltKernel.h>
#include <ntstrsafe.h>
#include "HashTable.h"


//==============================================================================
// ���������
//==============================================================================

#define MAX_PATH_LENGTH 512
#define MAX_WATCHED_DIRS 50
#define CONFIG_FILE_PATH L"\\??\\C:\\DriverConfig\\config.txt"
#define BUFFER_SIZE 4096

// ���� ��� ��������� ������
#define TAG_CONFIG_FILE         'gfnC'


//==============================================================================
// ���������
//==============================================================================

// ��������� ��� �������� ������������� ����������
typedef struct _WATCHED_DIRECTORY {
    UNICODE_STRING DirectoryPath;
    WCHAR PathBuffer[MAX_PATH_LENGTH];
    BOOLEAN IsActive;
} WATCHED_DIRECTORY, * PWATCHED_DIRECTORY;


//==============================================================================
// ���������� ����������
//==============================================================================

extern PFLT_FILTER g_FilterHandle;
extern FAST_MUTEX g_HashCacheMutex;
extern WATCHED_DIRECTORY g_WatchedDirectories[MAX_WATCHED_DIRS];
extern ULONG g_WatchedDirectoryCount;

//==============================================================================
// ������� ������������ � �������������
//==============================================================================

/**
 * �������������� ������������� ���������� � ��������� ������������
 * @return STATUS_SUCCESS ��� ������, ����� ��� ������
 */
NTSTATUS InitializeWatchedDirectories(VOID);

/**
 * ��������� ���������������� ���� � ������ ������������� ����������
 * @return STATUS_SUCCESS ��� ������, ����� ��� ������
 */
NTSTATUS LoadConfigurationFile(VOID);

/**
 * ����������� DOS ���� � NT ����
 * @param DosPath - �������� DOS ���� (��������, C:\Folder)
 * @param NtPath - �������� NT ����
 * @param NtPathBuffer - ����� ��� NT ����
 * @param BufferSize - ������ ������ � ������
 * @return STATUS_SUCCESS ��� ������, ����� ��� ������
 */
NTSTATUS ConvertDosPathToNtPath(
    _In_ PUNICODE_STRING DosPath,
    _Out_ PUNICODE_STRING NtPath,
    _Out_ PWCHAR NtPathBuffer,
    _In_ ULONG BufferSize
);

/**
 * ���������, ��������� �� ��������� ���� � ����� �� ������������� ����������
 * @param FilePath - ���� � ����� ��� ��������
 * @return TRUE ���� ���� ��������� � ������������� ����������, ����� FALSE
 */
BOOLEAN IsPathInWatchedDirectory(_In_ PUNICODE_STRING FilePath);

//==============================================================================
// CALLBACK ������� MINIFILTER
//==============================================================================

/**
 * Pre-callback ��� �������� ��������� ���������� � ����� (IRP_MJ_SET_INFORMATION)
 * ������������ �������� ��������������, ����������� � �������� ������
 */
FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);


//==============================================================================
// ������� ��������
//==============================================================================

// ������� �������� ��������
NTSTATUS DriverUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// ������� �������� ���������� ������� �� ���
NTSTATUS DriverLoad(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

//==============================================================================
// ��������������� �������
//==============================================================================

/**
 * �������� �������� �������� � ������������� �����������
 * @param FilePath - ���� � �����
 * @param OperationType - ��� �������� (CREATE, DELETE, MOVE, etc.)
 */
VOID LogFileOperation(
    _In_ PUNICODE_STRING FilePath,
    _In_ PCSTR OperationType
);


// ������� �������������� DOS ���� � NT ����
NTSTATUS ConvertDosPathToNtPath(
    _In_ PUNICODE_STRING DosPath,
    _Out_ PUNICODE_STRING NtPath,
    _Out_ PWCHAR NtPathBuffer,
    _In_ ULONG BufferSize
);

extern CONST FLT_OPERATION_REGISTRATION Callbacks[];

#endif // _DEDUP_FILTER_H_