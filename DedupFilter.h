#ifndef _DEDUP_FILTER_H_
#define _DEDUP_FILTER_H_

#include "HashTable.h"
#include <ntstrsafe.h>

// Константы
#define MIN_PATH_LENGTH 4
#define MAX_PATH_LENGTH 512
#define MAX_WATCHED_DIRS 50
#define CONFIG_FILE_PATH L"\\??\\C:\\DriverConfig\\config.txt"
#define MAX_CONFIG_FILE_SIZE 65536
#define BUFFER_SIZE 4096


// Теги для выделения памяти
#define TAG_CONFIG_FILE 'gfnC'

// Структура для хранения отслеживаемых директорий
typedef struct _WATCHED_DIRECTORY {
    UNICODE_STRING DirectoryPath;
    WCHAR PathBuffer[MAX_PATH_LENGTH];
    BOOLEAN IsActive;
} WATCHED_DIRECTORY, * PWATCHED_DIRECTORY;

// Глобальбые переменные
extern PFLT_FILTER g_FilterHandle;
extern WATCHED_DIRECTORY g_WatchedDirectories[MAX_WATCHED_DIRS];
extern ULONG g_WatchedDirectoryCount;
extern BOOLEAN g_InitialScanCompleted;

extern CONST FLT_OPERATION_REGISTRATION Callbacks[];

//Инициализирует отслеживаемые директории и загружает конфигурацию
NTSTATUS InitializeWatchedDirectories(VOID);


//Загружает конфигурационный файл с путями отслеживаемых директорий
NTSTATUS LoadConfigurationFile(VOID);

/**
 * Преобразует DOS путь в NT путь
 * @param DosPath - исходный DOS путь (например, C:\Folder)
 * @param NtPath - выходной NT путь
 * @param NtPathBuffer - буфер для NT пути
 * @param BufferSize - размер буфера в байтах
 */
NTSTATUS ConvertDosPathToNtPath(
    _In_ PUNICODE_STRING DosPath,
    _Out_ PUNICODE_STRING NtPath,
    _Out_ PWCHAR NtPathBuffer,
    _In_ ULONG BufferSize
);

/**
 * Проверяет, находится ли указанный путь в одной из отслеживаемых директорий
 * @param FilePath - путь к файлу для проверки
 * @return TRUE если файл находится в отслеживаемой директории, иначе FALSE
 */
BOOLEAN IsPathInWatchedDirectory(_In_ PUNICODE_STRING FilePath);

/**
 * Pre-callback для операций изменения информации о файле (IRP_MJ_SET_INFORMATION)
 * Обрабатывает операции переименования, перемещения и удаления файлов
 */
FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

// Функция выгрузки драйвера
NTSTATUS DriverUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// Функция загрузки экземпляра фильтра на том
NTSTATUS DriverLoad(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

/**
 * Логирует файловые операции в отслеживаемых директориях
 * @param FilePath - путь к файлу
 * @param OperationType - тип операции (CREATE, DELETE, MOVE, etc.)
 */
VOID LogFileOperation(
    _In_ PUNICODE_STRING FilePath,
    _In_ PCSTR OperationType
);


/**
 * Хэширует все файлы в указанной директории и добавляет их в таблицу хэшей
 * Поддиректории игнорируются
 * @param Instance - экземпляр фильтра
 * @param DirectoryPath - путь к директории для обработки
 * @return NTSTATUS - статус выполнения операции
 */
NTSTATUS ScanDirectoryAndAddHashes(
    _In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING DirectoryPath
);

#endif // _DEDUP_FILTER_H_