#include "DedupFilter.h"


NTSTATUS InitializeWatchedDirectories(VOID) {
    // Инициализируем мьютекс
    ExInitializeFastMutex(&g_HashCacheMutex);

    // Инициализация массива директорий
    RtlZeroMemory(g_WatchedDirectories, sizeof(g_WatchedDirectories));
    g_WatchedDirectoryCount = 0;

    return LoadConfigurationFile();
}



NTSTATUS LoadConfigurationFile(VOID) {
    NTSTATUS status;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING configFilePath;
    PVOID fileBuffer = NULL;
    FILE_STANDARD_INFORMATION fileInfo;
    PCHAR currentLine, nextLine;
    ULONG bytesRead;
    ANSI_STRING ansiPath;
    UNICODE_STRING unicodePath;
    UNICODE_STRING ntPath;
    WCHAR ntPathBuffer[MAX_PATH_LENGTH];

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[MYDRIVER] Loading configuration file: %ws\n", CONFIG_FILE_PATH);

    RtlInitUnicodeString(&configFilePath, CONFIG_FILE_PATH);

    InitializeObjectAttributes(
        &objectAttributes,
        &configFilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    status = ZwCreateFile(
        &fileHandle,
        GENERIC_READ,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[MYDRIVER] Failed to open config file: 0x%08X\n", status);
        return status;
    }

    // Получение размера файла
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[MYDRIVER] Failed to query file information: 0x%08X\n", status);
        ZwClose(fileHandle);
        return status;
    }

    if (fileInfo.EndOfFile.HighPart != 0 || fileInfo.EndOfFile.LowPart > 65536) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[MYDRIVER] Config file too large\n");
        ZwClose(fileHandle);
        return STATUS_FILE_TOO_LARGE;
    }

    // Выделение буфера для чтения файла
    fileBuffer = ExAllocatePool2(POOL_FLAG_PAGED, fileInfo.EndOfFile.LowPart + 1, 'gfnC');
    if (!fileBuffer) {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Чтение файла
    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        fileBuffer,
        fileInfo.EndOfFile.LowPart,
        NULL,
        NULL
    );

    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[MYDRIVER] Failed to read config file: 0x%08X\n", status);
        ExFreePool(fileBuffer);
        return status;
    }

    bytesRead = (ULONG)ioStatusBlock.Information;
    ((PCHAR)fileBuffer)[bytesRead] = '\0';

    // Парсинг строк из файла
    currentLine = (PCHAR)fileBuffer;

    while (currentLine && *currentLine && g_WatchedDirectoryCount < MAX_WATCHED_DIRS) {
        // Поиск конца строки
        nextLine = strchr(currentLine, '\n');
        if (nextLine) {
            *nextLine = '\0';
            nextLine++;
        }

        // Удаление символа возврата каретки если есть
        PCHAR cr = strchr(currentLine, '\r');
        if (cr) {
            *cr = '\0';
        }

        // Пропуск пустых строк и комментариев
        if (strlen(currentLine) > 0 && currentLine[0] != '#') {
            // Инициализация ANSI строки
            RtlInitAnsiString(&ansiPath, currentLine);

            // Преобразование в Unicode
            status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
            if (NT_SUCCESS(status)) {
                // Преобразование DOS пути в NT путь с помощью собственной функции
                status = ConvertDosPathToNtPath(
                    &unicodePath,
                    &ntPath,
                    ntPathBuffer,
                    (ULONG)sizeof(ntPathBuffer)
                );

                if (NT_SUCCESS(status)) {
                    // Проверка длины NT пути
                    if (ntPath.Length < (MAX_PATH_LENGTH - 1) * sizeof(WCHAR)) {
                        // Копирование NT пути в буфер структуры
                        RtlCopyMemory(
                            g_WatchedDirectories[g_WatchedDirectoryCount].PathBuffer,
                            ntPath.Buffer,
                            ntPath.Length
                        );
                        g_WatchedDirectories[g_WatchedDirectoryCount].PathBuffer[ntPath.Length / sizeof(WCHAR)] = L'\0';

                        // Инициализация UNICODE_STRING с NT путем
                        RtlInitUnicodeString(
                            &g_WatchedDirectories[g_WatchedDirectoryCount].DirectoryPath,
                            g_WatchedDirectories[g_WatchedDirectoryCount].PathBuffer
                        );

                        g_WatchedDirectories[g_WatchedDirectoryCount].IsActive = TRUE;
                        g_WatchedDirectoryCount++;

                        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                            "[MYDRIVER] Added watched directory (DOS->NT): %wZ -> %wZ\n",
                            &unicodePath, &g_WatchedDirectories[g_WatchedDirectoryCount - 1].DirectoryPath);
                    }
                    else {
                        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                            "[MYDRIVER] NT path too long, skipping: %wZ\n", &ntPath);
                    }
                }
                else {
                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                        "[MYDRIVER] Failed to convert DOS path to NT path: %wZ (0x%08X)\n",
                        &unicodePath, status);
                }

                RtlFreeUnicodeString(&unicodePath);
            }
            else {
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                    "[MYDRIVER] Failed to convert ANSI to Unicode: %s (0x%08X)\n",
                    currentLine, status);
            }
        }

        currentLine = nextLine;
    }

    ExFreePoolWithTag(fileBuffer, 'gfnC');

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[MYDRIVER] Initialized %lu watched directories\n", g_WatchedDirectoryCount);

    return STATUS_SUCCESS;
}