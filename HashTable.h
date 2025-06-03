#ifndef _HASH_H_
#define _HASH_H_


#include <fltKernel.h>

//==============================================================================
// ���������
//==============================================================================

#define SHA256_HASH_SIZE 32
#define MAX_HASH_ENTRIES 1024

//==============================================================================
// ���������
//==============================================================================

// ������ ������� �����
typedef struct _HASH_ENTRY {
    UCHAR FileHash[SHA256_HASH_SIZE];
    UNICODE_STRING FilePath;
    LARGE_INTEGER Timestamp;
} HASH_ENTRY, * PHASH_ENTRY;

//==============================================================================
// ���������� ����������
//==============================================================================

extern FAST_MUTEX g_HashTableMutex;
extern HASH_ENTRY g_HashTable[MAX_HASH_ENTRIES];
extern ULONG g_HashTableCount;
extern BOOLEAN g_HashTableInitialized;

//==============================================================================
// �������: ����������� (Hash.c)
//==============================================================================

NTSTATUS HashFileContentSHA256(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_writes_(SHA256_HASH_SIZE) UCHAR Hash[SHA256_HASH_SIZE]
);


//==============================================================================
// �������: ���-������� (HashTable.c)
//==============================================================================


 // ������������� ������� �����
NTSTATUS InitializeHashTable(VOID);


//������� ������� �����
VOID CleanupHashTable(VOID);

//��������� ���� �����
BOOLEAN CompareHashes(
    _In_reads_(SHA256_HASH_SIZE) const UCHAR Hash1[SHA256_HASH_SIZE],
    _In_reads_(SHA256_HASH_SIZE) const UCHAR Hash2[SHA256_HASH_SIZE]
);

//����� ���� � �������
//@param hash - ������� ��� @param foundFilePath - ���� �������, ���������� ���� �����*/
NTSTATUS CheckForDuplicate(
    _In_reads_(SHA256_HASH_SIZE) const UCHAR Hash[SHA256_HASH_SIZE],
    _Out_opt_ PUNICODE_STRING FoundFilePath
);

//���������� ������ ���� � �������
NTSTATUS AddHashToTable(
    _In_reads_(SHA256_HASH_SIZE) const UCHAR Hash[SHA256_HASH_SIZE],
    _In_ PUNICODE_STRING FilePath
);


//�������� ������ �� ������� �� ���� � �����
NTSTATUS RemoveHashFromTable(
    _In_ PUNICODE_STRING FilePath
);

//�������� ������ �� ������� �� �������� ����
NTSTATUS RemoveHashFromTableByHash(
    _In_reads_(SHA256_HASH_SIZE) const UCHAR Hash[SHA256_HASH_SIZE]
);

//��������� ���������� ������� � �������
ULONG GetHashTableCount(VOID);

//����� ����������� ������� ����� (�������)
VOID DumpHashTable(VOID);

#endif // _HASH_H_
