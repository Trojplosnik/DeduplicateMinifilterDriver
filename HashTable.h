#ifndef _HASH_TABLE_H_
#define _HASH_TABLE_H_

#include <fltKernel.h>

// КОНСТАНТЫ
#define SHA256_HASH_SIZE 32
#define MAX_HASH_ENTRIES 50000

// Структура таблицы хэшей
typedef struct _HASH_ENTRY {
    UCHAR FileHash[SHA256_HASH_SIZE];
    UNICODE_STRING FilePath;
    LARGE_INTEGER Timestamp;
} HASH_ENTRY, * PHASH_ENTRY;

// Глобальные переменные
extern FAST_MUTEX g_HashTableMutex;
extern HASH_ENTRY g_HashTable[MAX_HASH_ENTRIES];
extern ULONG g_HashTableCount;

// Хэширование содержимого файла с использованием SHA-256
NTSTATUS HashFileContentSHA256(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_(SHA256_HASH_SIZE) UCHAR Hash[SHA256_HASH_SIZE]
);

 // Инициализация таблицы хэшей
NTSTATUS InitializeHashTable(VOID);

//Очистка таблицы хэшей
VOID CleanupHashTable(VOID);

//Сравнение двух хэшей
BOOLEAN CompareHashes(
    _In_reads_(SHA256_HASH_SIZE) const UCHAR Hash1[SHA256_HASH_SIZE],
    _In_reads_(SHA256_HASH_SIZE) const UCHAR Hash2[SHA256_HASH_SIZE]
);

//Поиск хэша в таблице
NTSTATUS CheckForDuplicate(
    _In_reads_(SHA256_HASH_SIZE) const UCHAR Hash[SHA256_HASH_SIZE],
    _Out_opt_ PUNICODE_STRING FoundFilePath
);

//Добавление нового хэша в таблицу
NTSTATUS AddHashToTable(
    _In_reads_(SHA256_HASH_SIZE) const UCHAR Hash[SHA256_HASH_SIZE],
    _In_ PUNICODE_STRING FilePath
);


//Удаление записи из таблицы по пути к файлу
NTSTATUS RemoveHashFromTable(
    _In_ PUNICODE_STRING FilePath
);

//Получение количества записей в таблице
ULONG GetHashTableCount(VOID);

//Вывод содержимого таблицы хэшей (отладка)
VOID DumpHashTable(VOID);

#endif // _HASH_TABLE_H_
