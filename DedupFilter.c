#include "DedupFilter.h"

FAST_MUTEX g_HashCacheMutex;
WATCHED_DIRECTORY g_WatchedDirectories[MAX_WATCHED_DIRS];
ULONG g_WatchedDirectoryCount = 0;

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {


    // IRP_MJ_SET_INFORMATION - удаления, переименования, перемещения
    {
        IRP_MJ_SET_INFORMATION,
        0,                                    // Flags
        PreSetInformationCallback,            // PreOperation callback
        NULL            
    },

    // Завершающий элемент массива
    {
        IRP_MJ_OPERATION_END
    }
};


//==============================================================================
// CALLBACK ФУНКЦИИ
//==============================================================================


FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(CompletionContext);

    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FILE_INFORMATION_CLASS infoClass;
    UCHAR fileHash[SHA256_HASH_SIZE];
    WCHAR existingFilePathBuffer[MAX_PATH_LENGTH];
    UNICODE_STRING existingFilePath;

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // Обрабатываем только нужные операции
    if (infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx &&
        infoClass != FileLinkInformation &&
        infoClass != FileDispositionInformation &&
        infoClass != FileDispositionInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Получение исходного пути файла
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &nameInfo);

    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    BOOLEAN sourceInWatchedDir = IsPathInWatchedDirectory(&nameInfo->Name);

    //// === ОБРАБОТКА УДАЛЕНИЯ ===
    //if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
    //    if (sourceInWatchedDir && Data->Iopb->Parameters.SetFileInformation.InfoBuffer) {
    //        PFILE_DISPOSITION_INFORMATION dispInfo =
    //            (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    //        if (dispInfo && dispInfo->DeleteFile) {
    //            // Удаляем хэш из таблицы
    //            status = RemoveHashFromTable(&nameInfo->Name);
    //            if (NT_SUCCESS(status)) {
    //                LogFileOperation(&nameInfo->Name, "DELETE FILE");
    //                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
    //                    "[DEDUP] Removed hash for deleted file: %wZ\n", &nameInfo->Name);
    //            }
    //        }
    //    }
    //    FltReleaseFileNameInformation(nameInfo);
    //    return FLT_PREOP_SUCCESS_NO_CALLBACK;
    //}

    // === ОБРАБОТКА ПЕРЕИМЕНОВАНИЯ/ПЕРЕМЕЩЕНИЯ ===
    if ((infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) &&
        Data->Iopb->Parameters.SetFileInformation.InfoBuffer) {

        PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)
            Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (renameInfo->FileNameLength > 0) {
            PFLT_FILE_NAME_INFORMATION newNameInfo = NULL;

            // Получаем путь назначения
            status = FltGetDestinationFileNameInformation(
                Data->Iopb->TargetInstance,
                Data->Iopb->TargetFileObject,
                renameInfo->RootDirectory,
                renameInfo->FileName,
                renameInfo->FileNameLength,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                &newNameInfo);

            if (NT_SUCCESS(status)) {
                status = FltParseFileNameInformation(newNameInfo);
                if (NT_SUCCESS(status)) {
                    BOOLEAN destInWatchedDir = IsPathInWatchedDirectory(&newNameInfo->Name);

                    // === ПЕРЕМЕЩЕНИЕ В ОТСЛЕЖИВАЕМУЮ ДИРЕКТОРИЮ ===
                    if (!sourceInWatchedDir && destInWatchedDir) {

                            status = HashFileContentSHA256(
                                FltObjects->Instance,    // Используем Instance из FltObjects
                                Data->Iopb->TargetFileObject,  // Файл уже открыт системой
                                fileHash
                            ); 
                        if (NT_SUCCESS(status)) {
                            // Проверяем на дубликаты
                            RtlInitEmptyUnicodeString(&existingFilePath, existingFilePathBuffer,
                                sizeof(existingFilePathBuffer));
                            NTSTATUS duplicateStatus = CheckForDuplicate(fileHash, &existingFilePath);

                            if (duplicateStatus != STATUS_NOT_FOUND) {
                                // Блокируем операцию - найден дубликат
                                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                                    "[DEDUP] BLOCKED: Duplicate move into watched dir\n"
                                    "  Target: %wZ\n  Existing: %ws\n",
                                    &newNameInfo->Name, existingFilePathBuffer);

                                LogFileOperation(&newNameInfo->Name, "BLOCKED MOVE DUPLICATE");

                                FltReleaseFileNameInformation(newNameInfo);
                                FltReleaseFileNameInformation(nameInfo);
                                Data->IoStatus.Status = STATUS_DATA_ERROR;
                                Data->IoStatus.Information = 0;
                                return FLT_PREOP_COMPLETE;
                            }
                            else {
                                // Дубликат не найден, добавляем хэш в таблицу
                                status = AddHashToTable(fileHash, &newNameInfo->Name);
                                if (NT_SUCCESS(status)) {
                                    LogFileOperation(&newNameInfo->Name, "MOVE INTO WATCHED DIR");
                                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                                        "[DEDUP] Added hash for moved-in file: %wZ\n", &newNameInfo->Name);
                                }
                                else {
                                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                                        "[DEDUP] Failed to add hash for moved-in file: %wZ (0x%08X)\n",
                                        &newNameInfo->Name, status);
                                }
                            }
                        }
                        else {
                            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                                "[DEDUP] Failed to calculate hash for moved-in file: %wZ (0x%08X)\n",
                                &nameInfo->Name, status);
                        }
                    }
                    // === ПЕРЕМЕЩЕНИЕ ИЗ ОТСЛЕЖИВАЕМОЙ ДИРЕКТОРИИ ===
                    else if (sourceInWatchedDir && !destInWatchedDir) {
                        // Удаляем хэш из таблицы
                        status = RemoveHashFromTable(&nameInfo->Name);
                        if (NT_SUCCESS(status)) {
                            LogFileOperation(&nameInfo->Name, "MOVE FROM WATCHED DIR");
                            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                                "[DEDUP] Removed hash for moved-out file: %wZ\n", &nameInfo->Name);
                        }
                        else {
                            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                                "[DEDUP] Failed to remove hash for moved-out file: %wZ (0x%08X)\n",
                                &nameInfo->Name, status);
                        }
                    }
                    // === ПЕРЕИМЕНОВАНИЕ ВНУТРИ ОТСЛЕЖИВАЕМОЙ ДИРЕКТОРИИ ===
                    else if (sourceInWatchedDir && destInWatchedDir) {
                        // Используем Alternative версию для хэширования
                            status = HashFileContentSHA256(
                                FltObjects->Instance,
                                Data->Iopb->TargetFileObject,
                                fileHash
                            );



                        if (NT_SUCCESS(status)) {
                            // Удаляем старую запись и добавляем новую
                            RemoveHashFromTable(&nameInfo->Name);
                            status = AddHashToTable(fileHash, &newNameInfo->Name);
                            if (NT_SUCCESS(status)) {
                                LogFileOperation(&newNameInfo->Name, "RENAME IN WATCHED DIR");
                                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                                    "[DEDUP] Updated hash after rename: %wZ -> %wZ\n",
                                    &nameInfo->Name, &newNameInfo->Name);
                            }
                            else {
                                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                                    "[DEDUP] Failed to update hash after rename: %wZ (0x%08X)\n",
                                    &nameInfo->Name, status);
                            }
                        }
                        else {
                            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                                "[DEDUP] Failed to calculate hash for renamed file: %wZ (0x%08X)\n",
                                &nameInfo->Name, status);
                        }
                    }

                    FltReleaseFileNameInformation(newNameInfo);
                }
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
