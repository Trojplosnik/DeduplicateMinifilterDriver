#include "DedupFilter.h"

BOOLEAN IsPathInWatchedDirectory(_In_ PUNICODE_STRING filePath)
{
    if (!filePath || !filePath->Buffer || filePath->Length == 0) {
        return FALSE;
    }

    for (ULONG i = 0; i < g_WatchedDirectoryCount; i++) {
        if (!g_WatchedDirectories[i].IsActive) {
            continue;
        }

        UNICODE_STRING* dirPath = &g_WatchedDirectories[i].DirectoryPath;

        // ��������� ������������ ����������
        if (!dirPath->Buffer || dirPath->Length == 0) {
            continue;
        }

        // ���������� ��� ������� (��� ����� ��������)
        if (RtlPrefixUnicodeString(dirPath, filePath, TRUE)) {
            USHORT dirLen = dirPath->Length / sizeof(WCHAR);
            USHORT fileLen = filePath->Length / sizeof(WCHAR);

            // ��������� ������������ ������� ����� �������� � ������
            if (dirLen >= fileLen) {
                // ���� ����� ����� ��� ������ ���� ����������
                if (filePath->Length == dirPath->Length) {
                    return TRUE; // ������ ����������
                }
            }
            else {
                // ���������, ��� ��������� ������ � ����������� ����
                if (filePath->Buffer[dirLen] == L'\\') {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}




// ������� �������������� DOS ���� � NT ����
NTSTATUS ConvertDosPathToNtPath(
    _In_ PUNICODE_STRING DosPath,
    _Out_ PUNICODE_STRING NtPath,
    _Out_ PWCHAR NtPathBuffer,
    _In_ ULONG BufferSize
) {
    NTSTATUS status;
    UNICODE_STRING dosDeviceName;
    UNICODE_STRING ntDeviceName;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE linkHandle = NULL;
    WCHAR dosDeviceBuffer[8]; // "\??\C:"
    WCHAR ntDeviceBuffer[256];
    ULONG returnedLength;
    ULONG dosDeviceLength;
    ULONG pathOffset;
    ULONG totalLength;
    ULONG ntDeviceLength;

    // �������� ������� ����������
    if (!DosPath || !NtPath || !NtPathBuffer || BufferSize < (sizeof(WCHAR)) * 4) {
        return STATUS_INVALID_PARAMETER;
    }

    // �������� ����������� ����� ��� DOS ���� (��������, "C:\")
    if (DosPath->Length < 6 || !DosPath->Buffer) {
        return STATUS_INVALID_PARAMETER;
    }

    // �������� ������� DOS ���� (X:\...)
    if (DosPath->Buffer[1] != L':' || DosPath->Buffer[2] != L'\\') {
        return STATUS_INVALID_PARAMETER;
    }

    // �������� ������������ ����� �����
    WCHAR driveLetter = DosPath->Buffer[0];
    if (!((driveLetter >= L'A' && driveLetter <= L'Z') ||
        (driveLetter >= L'a' && driveLetter <= L'z'))) {
        return STATUS_INVALID_PARAMETER;
    }

    // ������������ ����� DOS ���������� "\??\C:"
    dosDeviceBuffer[0] = L'\\';
    dosDeviceBuffer[1] = L'?';
    dosDeviceBuffer[2] = L'?';
    dosDeviceBuffer[3] = L'\\';
    dosDeviceBuffer[4] = driveLetter;
    dosDeviceBuffer[5] = L':';
    dosDeviceBuffer[6] = L'\0';

    RtlInitUnicodeString(&dosDeviceName, dosDeviceBuffer);

    // �������� ������������� ������
    InitializeObjectAttributes(
        &objectAttributes,
        &dosDeviceName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    status = ZwOpenSymbolicLinkObject(
        &linkHandle,
        SYMBOLIC_LINK_QUERY,
        &objectAttributes
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ��������� �������� ���� ������������� ������
    ntDeviceName.Buffer = ntDeviceBuffer;
    ntDeviceName.Length = 0;
    ntDeviceName.MaximumLength = sizeof(ntDeviceBuffer);

    status = ZwQuerySymbolicLinkObject(
        linkHandle,
        &ntDeviceName,
        &returnedLength
    );

    ZwClose(linkHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ���������� ����� ���� ����� ����� ����� (������� � '\')
    pathOffset = 3 * sizeof(WCHAR); // ���������� "C:\"
    dosDeviceLength = DosPath->Length - pathOffset;
    ntDeviceLength = ntDeviceName.Length;

    // ���������� ����� �����: NT ���� + '\' + ���������� ����� DOS ���� + null terminator
    totalLength = ntDeviceLength + sizeof(WCHAR) + dosDeviceLength + sizeof(WCHAR);
    if (BufferSize < totalLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // �������� ������� NT ����
    RtlCopyMemory(NtPathBuffer, ntDeviceName.Buffer, ntDeviceLength);

    // ��������� �������� ���� ����� ��������� � ���������� ������ ����
    NtPathBuffer[ntDeviceLength / sizeof(WCHAR)] = L'\\';

    // �������� ���������� ����� ���� ����� "C:\"
    if (dosDeviceLength > 0) {
        RtlCopyMemory(
            (PUCHAR)NtPathBuffer + ntDeviceLength + sizeof(WCHAR),
            (PUCHAR)DosPath->Buffer + pathOffset,
            dosDeviceLength
        );
    }

    // ��������� ����������� null-����������
    ULONG totalChars = (ntDeviceLength / sizeof(WCHAR)) + 1 + (dosDeviceLength / sizeof(WCHAR));
    if (totalChars >= (BufferSize / sizeof(WCHAR))) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Fix: Ensure the buffer is accessed within bounds
    NtPathBuffer[BufferSize / sizeof(WCHAR) - 1] = L'\0';

    // �������������� UNICODE_STRING
    NtPath->Buffer = NtPathBuffer;
    NtPath->Length = (USHORT)(totalChars * sizeof(WCHAR));
    NtPath->MaximumLength = (USHORT)BufferSize;

    return STATUS_SUCCESS;
}


VOID LogFileOperation(_In_ PUNICODE_STRING FilePath, _In_ PCSTR OperationType)
{
    if (!FilePath || !OperationType) {
        return;
    }

    // ��������� ������������ UNICODE_STRING
    if (!FilePath->Buffer || FilePath->Length == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[WdmFileDedupe] %s: <Invalid path>\n", OperationType);
        return;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[WdmFileDedupe] %s: %wZ\n", OperationType, FilePath);
}
