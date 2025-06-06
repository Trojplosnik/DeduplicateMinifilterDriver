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

		// Проверяем корректность директории
		if (!dirPath->Buffer || dirPath->Length == 0) {
			continue;
		}

		// Сравниваем как префикс (без учета регистра)
		if (RtlPrefixUnicodeString(dirPath, filePath, TRUE)) {
			USHORT dirLen = dirPath->Length / sizeof(WCHAR);
			USHORT fileLen = filePath->Length / sizeof(WCHAR);

			// Проверяем корректность индекса перед доступом к буферу
			if (dirLen >= fileLen) {
				// Путь файла равен или короче пути директории
				if (filePath->Length == dirPath->Length) {
					return TRUE; // Точное совпадение
				}
			}
			else {
				// Проверяем, что следующий символ — разделитель пути
				if (filePath->Buffer[dirLen] == L'\\') {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

// Функция преобразования DOS пути в NT путь
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

	// Проверка входных параметров
	if (!DosPath || !NtPath || !NtPathBuffer || BufferSize < (sizeof(WCHAR)) * 4) {
		return STATUS_INVALID_PARAMETER;
	}

	// Проверка минимальной длины для DOS пути (например, "C:\")
	if (DosPath->Length < 6 || !DosPath->Buffer) {
		return STATUS_INVALID_PARAMETER;
	}

	// Проверка формата DOS пути (X:\...)
	if (DosPath->Buffer[1] != L':' || DosPath->Buffer[2] != L'\\') {
		return STATUS_INVALID_PARAMETER;
	}

	// Проверка корректности буквы диска
	WCHAR driveLetter = DosPath->Buffer[0];
	if (!((driveLetter >= L'A' && driveLetter <= L'Z') ||
		(driveLetter >= L'a' && driveLetter <= L'z'))) {
		return STATUS_INVALID_PARAMETER;
	}

	// Формирование имени DOS устройства "\??\C:"
	dosDeviceBuffer[0] = L'\\';
	dosDeviceBuffer[1] = L'?';
	dosDeviceBuffer[2] = L'?';
	dosDeviceBuffer[3] = L'\\';
	dosDeviceBuffer[4] = driveLetter;
	dosDeviceBuffer[5] = L':';
	dosDeviceBuffer[6] = L'\0';

	RtlInitUnicodeString(&dosDeviceName, dosDeviceBuffer);

	// Открытие символической ссылки
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

	// Получение целевого пути символической ссылки
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

	// Вычисление длины пути после буквы диска (начиная с '\')
	pathOffset = 3 * sizeof(WCHAR); // Пропускаем "C:\"
	dosDeviceLength = DosPath->Length - pathOffset;
	ntDeviceLength = ntDeviceName.Length;

	// Вычисление общей длины: NT путь + '\' + оставшаяся часть DOS пути + null terminator
	totalLength = ntDeviceLength + sizeof(WCHAR) + dosDeviceLength + sizeof(WCHAR);
	if (BufferSize < totalLength) {
		return STATUS_BUFFER_TOO_SMALL;
	}

	// Копируем префикс NT пути
	RtlCopyMemory(NtPathBuffer, ntDeviceName.Buffer, ntDeviceLength);

	// Добавляем обратный слэш между префиксом и оставшейся частью пути
	NtPathBuffer[ntDeviceLength / sizeof(WCHAR)] = L'\\';

	// Копируем оставшуюся часть пути после "C:\"
	if (dosDeviceLength > 0) {
		RtlCopyMemory(
			(PUCHAR)NtPathBuffer + ntDeviceLength + sizeof(WCHAR),
			(PUCHAR)DosPath->Buffer + pathOffset,
			dosDeviceLength
		);
	}

	// Добавляем завершающий null-терминатор
	ULONG totalChars = (ntDeviceLength / sizeof(WCHAR)) + 1 + (dosDeviceLength / sizeof(WCHAR));
	if (totalChars >= (BufferSize / sizeof(WCHAR))) {
		return STATUS_BUFFER_TOO_SMALL;
	}

	// Fix: Ensure the buffer is accessed within bounds
	NtPathBuffer[BufferSize / sizeof(WCHAR) - 1] = L'\0';

	// Инициализируем UNICODE_STRING
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

	// Проверяем корректность UNICODE_STRING
	if (!FilePath->Buffer || FilePath->Length == 0) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[WdmFileDedupe] %s: <Invalid path>\n", OperationType);
		return;
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[WdmFileDedupe] %s: %wZ\n", OperationType, FilePath);
}


// Хэширует все файлы в указанной директории и добавляет их в таблицу хэшей
NTSTATUS ScanDirectoryAndAddHashes(
    _In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING DirectoryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE directoryHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    FILE_OBJECT* fileObject = NULL;
    PFILE_BOTH_DIR_INFORMATION dirInfo = NULL;
    ULONG bufferSize = BUFFER_SIZE;
    ULONG context = 0;


    // Проверяем, что путь не пустой
    if (DirectoryPath->Length == 0 || DirectoryPath->Buffer == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[WdmFileDedupe] Error: Empty directory path\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Проверяем, что путь заканчивается на обратный слеш
    UNICODE_STRING normalizedPath = { 0 };
    WCHAR pathBuffer[MAX_PATH_LENGTH];
    RtlInitEmptyUnicodeString(&normalizedPath, pathBuffer, sizeof(pathBuffer));

    // Копируем исходный путь
    RtlCopyUnicodeString(&normalizedPath, DirectoryPath);

    // Добавляем слеш в конце если нужно
    if (normalizedPath.Buffer[(normalizedPath.Length / sizeof(WCHAR)) - 1] != L'\\') {
        status = RtlAppendUnicodeToString(&normalizedPath, L"\\");
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[WdmFileDedupe] Failed to normalize path: 0x%X\n", status);
            return status;
        }
    }

    // Инициализируем атрибуты объекта
    InitializeObjectAttributes(
        &objectAttributes,
        &normalizedPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = FltCreateFile(
        g_FilterHandle,
        Instance,
        &directoryHandle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        0,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[WdmFileDedupe] Failed to open directory (0x%X). Path: %wZ\n",
            status, &normalizedPath);
        return status;
    }

    // Получаем объект файла
    status = ObReferenceObjectByHandle(
        directoryHandle,
        FILE_READ_DATA,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&fileObject,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[WdmFileDedupe] Failed to get file object: 0x%X\n", status);
        ZwClose(directoryHandle);
        return status;
    }

    // Выделяем буфер для информации о файлах
    dirInfo = (PFILE_BOTH_DIR_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED,
        bufferSize,
        TAG_CONFIG_FILE
    );

    if (dirInfo == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[WdmFileDedupe] Failed to allocate memory for directory info\n");
        ObDereferenceObject(fileObject);
        ZwClose(directoryHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Читаем содержимое директории
    while (TRUE) {
        status = FltQueryDirectoryFile(
            Instance,
            fileObject,
            dirInfo,
            bufferSize,
            FileBothDirectoryInformation,
            FALSE,  // Не возвращать одну запись
            NULL,   // Не использовать шаблон
            FALSE,  // Не перезапускать сканирование
            &context
        );

        if (!NT_SUCCESS(status)) {
            if (status == STATUS_NO_MORE_FILES) {
                status = STATUS_SUCCESS;
                break;
            }
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[WdmFileDedupe] Failed to query directory: 0x%X\n", status);
            break;
        }

        // Обрабатываем каждый файл в директории
        PFILE_BOTH_DIR_INFORMATION currentEntry = dirInfo;
        while (TRUE) {
            // Пропускаем текущую и родительскую директории
            if (currentEntry->FileNameLength == 0 ||
                (currentEntry->FileName[0] == L'.' &&
                    (currentEntry->FileNameLength == 2 ||
                        (currentEntry->FileNameLength == 4 && currentEntry->FileName[1] == L'.')))) {
                if (currentEntry->NextEntryOffset == 0) {
                    break;
                }
                currentEntry = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)currentEntry + currentEntry->NextEntryOffset);
                continue;
            }

            // Пропускаем поддиректории
            if (currentEntry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (currentEntry->NextEntryOffset == 0) {
                    break;
                }
                currentEntry = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)currentEntry + currentEntry->NextEntryOffset);
                continue;
            }

            // Создаем полный путь к файлу
            UNICODE_STRING fileName;
            fileName.Buffer = currentEntry->FileName;
            fileName.Length = (USHORT)currentEntry->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            UNICODE_STRING fullPath;
            WCHAR fullPathBuffer[MAX_PATH_LENGTH];
            fullPath.Buffer = fullPathBuffer;
            fullPath.MaximumLength = MAX_PATH_LENGTH * sizeof(WCHAR);

            // Копируем путь директории
            RtlCopyUnicodeString(&fullPath, &normalizedPath);

            // Добавляем имя файла
            RtlAppendUnicodeStringToString(&fullPath, &fileName);

            // Открываем файл для чтения
            HANDLE fileHandle = NULL;
            OBJECT_ATTRIBUTES fileAttributes;
            IO_STATUS_BLOCK fileIoStatus;

            InitializeObjectAttributes(
                &fileAttributes,
                &fullPath,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                NULL,
                NULL
            );

            status = FltCreateFile(
                g_FilterHandle,
                Instance,
                &fileHandle,
                FILE_READ_DATA | SYNCHRONIZE,
                &fileAttributes,
                &fileIoStatus,
                0,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0,
                IO_IGNORE_SHARE_ACCESS_CHECK
            );

            if (NT_SUCCESS(status)) {
                PFILE_OBJECT fileObj = NULL;
                status = ObReferenceObjectByHandle(
                    fileHandle,
                    FILE_READ_DATA,
                    *IoFileObjectType,
                    KernelMode,
                    (PVOID*)&fileObj,
                    NULL
                );

                if (NT_SUCCESS(status)) {
                    UCHAR fileHash[SHA256_HASH_SIZE];
                    status = HashFileContentSHA256(Instance, fileObj, fileHash);

                    if (NT_SUCCESS(status)) {
                        // Добавляем хэш в таблицу
                        status = AddHashToTable(fileHash, &fullPath);
                        if (NT_SUCCESS(status)) {
                            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                                "[WdmFileDedupe] Added hash for file: %wZ\n", &fullPath);
                        }
                        else {
                            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                                "[WdmFileDedupe] Failed to add hash to table: 0x%X\n", status);
                        }
                    }
                    else {
                        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                            "[WdmFileDedupe] Failed to hash file: 0x%X\n", status);
                    }

                    ObDereferenceObject(fileObj);
                }
                else {
                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                        "[WdmFileDedupe] Failed to get file object: 0x%X\n", status);
                }

                ZwClose(fileHandle);
            }
            else {
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                    "[WdmFileDedupe] Failed to open file: %wZ, status: 0x%X\n",
                    &fullPath, status);
            }

            // Переходим к следующей записи или выходим
            if (currentEntry->NextEntryOffset == 0) {
                break;
            }
            currentEntry = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)currentEntry + currentEntry->NextEntryOffset);
        }
    }

    // Освобождаем ресурсы
    if (dirInfo != NULL) {
        ExFreePoolWithTag(dirInfo, TAG_CONFIG_FILE);
    }
    ObDereferenceObject(fileObject);
    ZwClose(directoryHandle);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[WdmFileDedupe] files in this directory have been hashed: %wZ\n", DirectoryPath);

    return status;
}