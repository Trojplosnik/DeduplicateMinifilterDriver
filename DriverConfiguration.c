#include "DedupFilter.h"

// Глобальные переменные для отслеживаемых директорий
WATCHED_DIRECTORY g_WatchedDirectories[MAX_WATCHED_DIRS];
ULONG g_WatchedDirectoryCount = 0;


NTSTATUS InitializeWatchedDirectories(VOID) {

    // Обнуление массива директорий для гарантированной инициализации
    RtlZeroMemory(g_WatchedDirectories, sizeof(g_WatchedDirectories));
    g_WatchedDirectoryCount = 0;


    return LoadConfigurationFile();
}

//Очищает строку от символов перевода строки и возврата каретки
VOID TrimLine(_Inout_ PCHAR line) {
    if (!line) return;

    // Удаление символа перевода строки
    PCHAR newline = strchr(line, '\n');
    if (newline) {
        *newline = '\0';
    }

    // Удаление символа возврата каретки
    PCHAR cr = strchr(line, '\r');
    if (cr) {
        *cr = '\0';
    }

    // Удаление пробелов в начале строки
    while (*line == ' ' || *line == '\t') {
        memmove(line, line + 1, strlen(line));
    }

    // Удаление пробелов в конце строки
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == ' ' || line[len - 1] == '\t')) {
        line[--len] = '\0';
    }
}

//Проверяет валидность пути к директории 
BOOLEAN IsValidLine(_In_ PCHAR line) {
    if (!line || strlen(line) == 0) {
        return FALSE; // Пустая строка
    }

	// Проверка на комментарии
    if (line[0] == '#' || line[0] == ';') {
        return FALSE; // Комментарий
    }

    // Проверка на минимальную длину пути
    if (strlen(line) < MIN_PATH_LENGTH) {
        return FALSE; // Слишком короткий путь
    }

    if (strlen(line) >= MAX_PATH_LENGTH) {
        return FALSE; // Слишком длинный путь
    }

    return TRUE;
}

//Добавляет директорию в список отслеживаемых
NTSTATUS AddWatchedDirectory(_In_ PUNICODE_STRING dosPath) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING ntPath;
    WCHAR ntPathBuffer[MAX_PATH_LENGTH];


    // Преобразование DOS пути в NT путь
    status = ConvertDosPathToNtPath(dosPath, &ntPath, ntPathBuffer, sizeof(ntPathBuffer));
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[WdmFileDedupe] Failed to convert DOS path to NT path: %wZ (0x%08X)\n",
            dosPath, status);
        return status;
    }


    // Проверка на дубликаты
    for (ULONG i = 0; i < g_WatchedDirectoryCount; i++) {
        if (RtlEqualUnicodeString(&ntPath, &g_WatchedDirectories[i].DirectoryPath, TRUE)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[WdmFileDedupe] Directory already being watched: %wZ\n", &ntPath);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    // Копирование NT пути в буфер структуры
    RtlCopyMemory(
        g_WatchedDirectories[g_WatchedDirectoryCount].PathBuffer,
        ntPath.Buffer,
        ntPath.Length
    );

    // Завершение строки нулевым символом
    g_WatchedDirectories[g_WatchedDirectoryCount].PathBuffer[ntPath.Length / sizeof(WCHAR)] = L'\0';

    // Инициализация UNICODE_STRING с NT путем
    RtlInitUnicodeString(
        &g_WatchedDirectories[g_WatchedDirectoryCount].DirectoryPath,
        g_WatchedDirectories[g_WatchedDirectoryCount].PathBuffer
    );

    // Установка флага активности
    g_WatchedDirectories[g_WatchedDirectoryCount].IsActive = TRUE;

    g_WatchedDirectoryCount++;

    return status;
}

//Загружает конфигурационный файл с путями отслеживаемых директорий
NTSTATUS LoadConfigurationFile(VOID) {
    NTSTATUS status = STATUS_SUCCESS;
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
    ULONG processedLines = 0;
    ULONG addedDirectories = 0;


    // Инициализация пути к конфигурационному файлу
    RtlInitUnicodeString(&configFilePath, CONFIG_FILE_PATH);

    // Настройка атрибутов объекта для открытия файла
    InitializeObjectAttributes(
        &objectAttributes,
        &configFilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Открытие конфигурационного файла
    status = ZwCreateFile(
        &fileHandle,
        GENERIC_READ,
        &objectAttributes,
        &ioStatusBlock,
        NULL,                           // Размер не указываем при открытии существующего файла
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,               // Разрешаем параллельное чтение
        FILE_OPEN,                     // Открываем только существующий файл
        FILE_SYNCHRONOUS_IO_NONALERT,  // Синхронный ввод-вывод
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[WdmFileDedupe] Failed to open config file: 0x%08X\n", status);
        return status;
    }

    // Получение информации о размере файла
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[WdmFileDedupe] Failed to query file information: 0x%08X\n", status);
        ZwClose(fileHandle);
        return status;
    }

    // Проверка разумного размера файла (защита от слишком больших файлов)
    if (fileInfo.EndOfFile.HighPart != 0 || fileInfo.EndOfFile.LowPart > 65536) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[WdmFileDedupe] Config file too large (%lu bytes), maximum allowed: 65536\n",
            fileInfo.EndOfFile.LowPart);
        ZwClose(fileHandle);
        return STATUS_FILE_TOO_LARGE;
    }

    // Проверка на пустой файл
    if (fileInfo.EndOfFile.LowPart == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[WdmFileDedupe] Config file is empty\n");
        ZwClose(fileHandle);
        return STATUS_SUCCESS; // Не ошибка, просто нет директорий для отслеживания
    }

    // Выделение буфера для чтения файла (+1 для завершающего нуля)
    fileBuffer = ExAllocatePool2(
        POOL_FLAG_PAGED,
        fileInfo.EndOfFile.LowPart + 1,
        TAG_CONFIG_FILE
    );

    if (!fileBuffer) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[WdmFileDedupe] Failed to allocate memory for config file (%lu bytes)\n",
            fileInfo.EndOfFile.LowPart + 1);
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Чтение содержимого файла
    status = ZwReadFile(
        fileHandle,
        NULL,           // Event handle
        NULL,           // APC routine
        NULL,           // APC context
        &ioStatusBlock,
        fileBuffer,
        fileInfo.EndOfFile.LowPart,
        NULL,           // Byte offset (NULL для текущей позиции)
        NULL            // Key
    );

    // Закрытие файла независимо от результата чтения
    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[WdmFileDedupe] Failed to read config file: 0x%08X\n", status);
        ExFreePoolWithTag(fileBuffer, TAG_CONFIG_FILE);
        return status;
    }

    // Получение количества прочитанных байт
    bytesRead = (ULONG)ioStatusBlock.Information;

    // Добавление завершающего нуля для безопасной работы со строками
    ((PCHAR)fileBuffer)[bytesRead] = '\0';

    // Парсинг строк из файла
    currentLine = (PCHAR)fileBuffer;

    while (currentLine && *currentLine && g_WatchedDirectoryCount < MAX_WATCHED_DIRS) {
        // Поиск конца текущей строки
        nextLine = strchr(currentLine, '\n');
        if (nextLine) {
            *nextLine = '\0';  // Завершаем текущую строку
            nextLine++;        // Переходим к следующей строке
        }

        // Очистка строки от лишних символов
        TrimLine(currentLine);
        processedLines++;

        // Проверка валидности строки
        if (IsValidLine(currentLine)) {
            // Преобразование ANSI строки в Unicode
            RtlInitAnsiString(&ansiPath, currentLine);

            status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
            if (NT_SUCCESS(status)) {
                // Добавление директории в список отслеживаемых
                NTSTATUS addStatus = AddWatchedDirectory(&unicodePath);
                if (NT_SUCCESS(addStatus)) {
                    addedDirectories++;
                }
                else if (addStatus != STATUS_OBJECT_NAME_COLLISION) {
                    // Логируем только реальные ошибки, дубликаты - это нормально
                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                        "[WdmFileDedupe] Failed to add directory from line %lu: %s (0x%08X)\n",
                        processedLines, currentLine, addStatus);
                }

                // Освобождение памяти, выделенной для Unicode строки
                RtlFreeUnicodeString(&unicodePath);
            }
            else {
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                    "[WdmFileDedupe] Failed to convert ANSI to Unicode on line %lu: %s (0x%08X)\n",
                    processedLines, currentLine, status);
            }
        }
        else {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
                "[WdmFileDedupe] Skipping line %lu (empty or comment): %s\n",
                processedLines, currentLine);
        }

        // Переход к следующей строке
        currentLine = nextLine;
    }

    // Освобождение буфера файла
    ExFreePoolWithTag(fileBuffer, TAG_CONFIG_FILE);

    if (g_WatchedDirectoryCount == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[WdmFileDedupe] No valid directories found in configuration file\n");
    }

    return status;
}

