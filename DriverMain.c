#include "DedupFilter.h"

PFLT_FILTER g_FilterHandle = NULL;

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),        // Размер структуры
	FLT_REGISTRATION_VERSION,        // Версия
	0,                               // Флаги
	NULL,                            // Contexts (пока не используются)
	Callbacks,                       // Операции
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

	DbgPrint("[WdmFileDedupe] MiniFilter: Started.\n");


	// Инициализация таблицы хэшей
	status = InitializeHashTable();
	if (!NT_SUCCESS(status)) {
		DbgPrint("[WdmFileDedupe] Failed to initialize hash table.\n");
		return status;
	}

	// Инициализация отслеживаемых директорий
	status = InitializeWatchedDirectories();
	if (!NT_SUCCESS(status)) {
		CleanupHashTable();
		return status;
	}

	// Регистрация фильтра
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"[WdmFileDedupe] MiniFilter: ERROR FltRegisterFilter - %08x\n", status);
		CleanupHashTable();
		return status;
	}

	// Запуск фильтрации
	status = FltStartFiltering(g_FilterHandle);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"[WdmFileDedupe] MiniFilter: ERROR FltStartFiltering - %08x\n", status);
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
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);


	// Проверка, что фильтр не загружается на файловую систему, которую мы не поддерживаем
	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ||
		VolumeDeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM) {
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	// Сканируем все отслеживаемые директории при подключении к тому
	NTSTATUS status = STATUS_SUCCESS;

	// Проверяем, что это первая загрузка
	static BOOLEAN firstLoad = TRUE;

	if (firstLoad) {
		firstLoad = FALSE;

		// Сканируем все отслеживаемые директории
		for (ULONG i = 0; i < g_WatchedDirectoryCount; i++) {
			if (g_WatchedDirectories[i].IsActive) {
				status = ScanDirectoryAndAddHashes(FltObjects->Instance, &g_WatchedDirectories[i].DirectoryPath);
				if (!NT_SUCCESS(status)) {
					DbgPrint("[WdmFileDedupe] Failed to scan directory %wZ: 0x%X\n",
						&g_WatchedDirectories[i].DirectoryPath, status);
				}
			}
		}

		// Логирование содержания таблицы хэшей перед началом работы
		DumpHashTable();
	}


	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
		"[WdmFileDedupe] MiniFilter: load.\n");

	return STATUS_SUCCESS;
}

NTSTATUS
DriverUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);

	// Логирование содержания таблицы хэшей перед отчисткой
	DumpHashTable();

	if (g_FilterHandle) {
		FltUnregisterFilter(g_FilterHandle);
		g_FilterHandle = NULL;
	}

	// Очистка таблицы хэшей
	CleanupHashTable();


	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[WdmFileDedupe] MiniFilter: Unload.\n");
	return STATUS_SUCCESS;
}