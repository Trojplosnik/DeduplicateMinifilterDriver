#include "HashTable.h"


FAST_MUTEX g_HashTableMutex;
HASH_ENTRY g_HashTable[MAX_HASH_ENTRIES];
ULONG g_HashTableCount = 0;
BOOLEAN g_HashTableInitialized = FALSE;

// Инициализация хэш-таблицы
NTSTATUS InitializeHashTable(VOID)
{
	if (g_HashTableInitialized) {
		return STATUS_SUCCESS;
	}

	// Инициализируем мьютекс
	ExInitializeFastMutex(&g_HashTableMutex);

	// Очищаем таблицу
	RtlZeroMemory(g_HashTable, sizeof(g_HashTable));
	g_HashTableCount = 0;

	g_HashTableInitialized = TRUE;

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[WdmFileDedupe] Hash table initialized\n");

	return STATUS_SUCCESS;
}

// Освобождение ресурсов хэш-таблицы
VOID CleanupHashTable(VOID)
{
	if (!g_HashTableInitialized) {
		return;
	}

	ExAcquireFastMutex(&g_HashTableMutex);

	// Освобождаем все выделенные строки путей
	for (ULONG i = 0; i < g_HashTableCount; i++) {
		if (g_HashTable[i].FilePath.Buffer != NULL) {
			ExFreePoolWithTag(g_HashTable[i].FilePath.Buffer, 'hPth');
			g_HashTable[i].FilePath.Buffer = NULL;
			g_HashTable[i].FilePath.Length = 0;
			g_HashTable[i].FilePath.MaximumLength = 0;
		}
	}

	// Очищаем всю таблицу
	RtlZeroMemory(g_HashTable, sizeof(g_HashTable));
	g_HashTableCount = 0;

	ExReleaseFastMutex(&g_HashTableMutex);

	g_HashTableInitialized = FALSE;

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[WdmFileDedupe] Hash table cleaned up\n");
}

// Сравнение двух хэш-значений
BOOLEAN CompareHashes(
	_In_reads_(SHA256_HASH_SIZE) const UCHAR Hash1[SHA256_HASH_SIZE],
	_In_reads_(SHA256_HASH_SIZE) const UCHAR Hash2[SHA256_HASH_SIZE]
)
{
	if (!Hash1 || !Hash2) {
		return FALSE;
	}

	return (RtlCompareMemory(Hash1, Hash2, SHA256_HASH_SIZE) == SHA256_HASH_SIZE);
}

// Проверка на дубликаты в хэш-таблице
NTSTATUS CheckForDuplicate(
	_In_reads_(SHA256_HASH_SIZE) const UCHAR Hash[SHA256_HASH_SIZE],
	_Out_opt_ PUNICODE_STRING FoundFilePath
)
{
	if (!Hash || !g_HashTableInitialized) {
		return STATUS_NOT_FOUND;
	}

	if (FoundFilePath) {
		FoundFilePath->Length = 0;
		if (FoundFilePath->Buffer && FoundFilePath->MaximumLength >= sizeof(WCHAR)) {
			FoundFilePath->Buffer[0] = L'\0';
		}
	}

	ExAcquireFastMutex(&g_HashTableMutex);

	for (ULONG i = 0; i < g_HashTableCount; i++) {
		if (CompareHashes(g_HashTable[i].FileHash, Hash)) {
			// Возвращаем путь, если нужно
			if (FoundFilePath && FoundFilePath->Buffer && FoundFilePath->MaximumLength > 0) {
				USHORT copyLength = min(g_HashTable[i].FilePath.Length,
					FoundFilePath->MaximumLength - sizeof(WCHAR));
				if (copyLength > 0) {
					RtlCopyMemory(FoundFilePath->Buffer,
						g_HashTable[i].FilePath.Buffer,
						copyLength);
					FoundFilePath->Length = copyLength;
					FoundFilePath->Buffer[copyLength / sizeof(WCHAR)] = L'\0';
				}
			}

			ExReleaseFastMutex(&g_HashTableMutex);
			return STATUS_DUPLICATE_OBJECTID;
		}
	}

	ExReleaseFastMutex(&g_HashTableMutex);
	return STATUS_NOT_FOUND;
}

// Добавление хэша в таблицу
NTSTATUS AddHashToTable(
	_In_reads_(SHA256_HASH_SIZE) const UCHAR Hash[SHA256_HASH_SIZE],
	_In_ PUNICODE_STRING FilePath
)
{

	if (!Hash || !FilePath || !FilePath->Buffer || FilePath->Length == 0) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[WdmFileDedupe] AddHashToTable: Invalid parameters\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (!g_HashTableInitialized) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[WdmFileDedupe] AddHashToTable: g_HashTableInitialized\n");
		return STATUS_UNSUCCESSFUL;
	}

	PWCHAR pathBuffer = NULL;
	ULONG pathBufferSize = FilePath->Length + sizeof(WCHAR);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[WdmFileDedupe] pathBufferSize %d\n", pathBufferSize);

	ExAcquireFastMutex(&g_HashTableMutex);


	// Проверяем, есть ли место для новой записи
	if (g_HashTableCount >= MAX_HASH_ENTRIES) {
		ExReleaseFastMutex(&g_HashTableMutex);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[WdmFileDedupe] AddHashToTable: Hash table is full\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}


	// Выделяем память для пути
	pathBuffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pathBufferSize, 'hPth');

	if (!pathBuffer) {
		ExReleaseFastMutex(&g_HashTableMutex);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[WdmFileDedupe] AddHashToTable: ExAllocatePool2 failed, size: %lu\n", pathBufferSize);
		return STATUS_INSUFFICIENT_RESOURCES;
	}


	// Копируем данные в новую запись
	RtlCopyMemory(pathBuffer, FilePath->Buffer, FilePath->Length);
	pathBuffer[FilePath->Length / sizeof(WCHAR)] = L'\0';

	RtlCopyMemory(g_HashTable[g_HashTableCount].FileHash, Hash, SHA256_HASH_SIZE);
	g_HashTable[g_HashTableCount].FilePath.Buffer = pathBuffer;
	g_HashTable[g_HashTableCount].FilePath.Length = FilePath->Length;
	g_HashTable[g_HashTableCount].FilePath.MaximumLength = (USHORT)pathBufferSize;
	KeQuerySystemTimePrecise(&g_HashTable[g_HashTableCount].Timestamp);


	g_HashTableCount++;


	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[WdmFileDedupe] Added to table: path len %d, entries: %lu\n",
		FilePath->Length, g_HashTableCount);

	ExReleaseFastMutex(&g_HashTableMutex);

	return STATUS_SUCCESS;
}

// Удаление хэша из таблицы
NTSTATUS RemoveHashFromTable(_In_ PUNICODE_STRING FilePath)
{
	if (!FilePath || !FilePath->Buffer || FilePath->Length == 0) {
		return STATUS_INVALID_PARAMETER;
	}

	if (!g_HashTableInitialized) {
		return STATUS_UNSUCCESSFUL;
	}

	ExAcquireFastMutex(&g_HashTableMutex);

	for (ULONG i = 0; i < g_HashTableCount; i++) {
		if (RtlEqualUnicodeString(&g_HashTable[i].FilePath, FilePath, TRUE)) {
			// Освобождаем память пути
			if (g_HashTable[i].FilePath.Buffer) {
				ExFreePoolWithTag(g_HashTable[i].FilePath.Buffer, 'hPth');
			}

			// Сдвигаем все последующие записи
			if (i < g_HashTableCount - 1) {
				RtlMoveMemory(&g_HashTable[i], &g_HashTable[i + 1],
					(g_HashTableCount - i - 1) * sizeof(HASH_ENTRY));
			}

			// Очищаем последний элемент
			g_HashTableCount--;
			RtlZeroMemory(&g_HashTable[g_HashTableCount], sizeof(HASH_ENTRY));

			ExReleaseFastMutex(&g_HashTableMutex);

			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[WdmFileDedupe] Hash removed from table. Count: %lu\n", g_HashTableCount);

			return STATUS_SUCCESS;
		}
	}

	ExReleaseFastMutex(&g_HashTableMutex);
	return STATUS_NOT_FOUND;
}

// Получение количества записей в хэш-таблице
ULONG GetHashTableCount(VOID)
{
	if (!g_HashTableInitialized) {
		return 0;
	}

	ExAcquireFastMutex(&g_HashTableMutex);
	ULONG count = g_HashTableCount;
	ExReleaseFastMutex(&g_HashTableMutex);

	return count;
}

// Вывод содержимого хэш-таблицы в отладочный вывод
VOID DumpHashTable(VOID)
{
	if (!g_HashTableInitialized) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[WdmFileDedupe] Hash table not initialized\n");
		return;
	}

	ExAcquireFastMutex(&g_HashTableMutex);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[WdmFileDedupe] Hash table dump (%lu entries):\n", g_HashTableCount);

	for (ULONG i = 0; i < g_HashTableCount; i++) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[WdmFileDedupe] [%lu] Hash: %02X%02X%02X%02X... Path: %wZ\n",
			i,
			g_HashTable[i].FileHash[0],
			g_HashTable[i].FileHash[1],
			g_HashTable[i].FileHash[2],
			g_HashTable[i].FileHash[3],
			&g_HashTable[i].FilePath);
	}

	ExReleaseFastMutex(&g_HashTableMutex);
}