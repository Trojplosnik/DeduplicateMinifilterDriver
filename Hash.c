﻿#include "HashTable.h"

// Макрос для циклического сдвига вправо на b бит.
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

// Преобразования, определённые стандартом SHA-256, используемые при обработке блоков.
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static volatile LONG g_HashingInProgress = 0;

typedef struct {
	UCHAR data[64];
	ULONG datalen;
	ULONGLONG bitlen;
	UINT32 state[8];
} SHA256_CTX;

// 64 константы из стандарта SHA-256
static const UINT32 k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
	0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// Функция для преобразования блока данных SHA-256.
static VOID SHA256Transform(SHA256_CTX* ctx, const UCHAR data[])
{
	UINT32 a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = ((UINT32)data[j] << 24) | ((UINT32)data[j + 1] << 16) |
		((UINT32)data[j + 2] << 8) | ((UINT32)data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g; g = f; f = e;
		e = d + t1; d = c;
		c = b; b = a; a = t1 + t2;
	}

	ctx->state[0] += a; ctx->state[1] += b;
	ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f;
	ctx->state[6] += g; ctx->state[7] += h;
}

// Инициализация контекста SHA-256.
static VOID SHA256Init(SHA256_CTX* ctx)
{
	ctx->datalen = 0; ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

// Обновление контекста SHA-256 с новыми данными.
static VOID SHA256Update(SHA256_CTX* ctx, const UCHAR* data, SIZE_T len)
{
	for (SIZE_T i = 0; i < len; ++i) {
		ctx->data[ctx->datalen++] = data[i];
		if (ctx->datalen == 64) {
			SHA256Transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

// Завершение вычисления хеша SHA-256 и получение итогового хеша.
static VOID SHA256Final(SHA256_CTX* ctx, UCHAR hash[])
{
	ULONG i = ctx->datalen;

	ctx->data[i++] = 0x80;
	while (i < 56) ctx->data[i++] = 0x00;

	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = (UCHAR)(ctx->bitlen);
	ctx->data[62] = (UCHAR)(ctx->bitlen >> 8);
	ctx->data[61] = (UCHAR)(ctx->bitlen >> 16);
	ctx->data[60] = (UCHAR)(ctx->bitlen >> 24);
	ctx->data[59] = (UCHAR)(ctx->bitlen >> 32);
	ctx->data[58] = (UCHAR)(ctx->bitlen >> 40);
	ctx->data[57] = (UCHAR)(ctx->bitlen >> 48);
	ctx->data[56] = (UCHAR)(ctx->bitlen >> 56);

	SHA256Transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		for (ULONG j = 0; j < 8; ++j) {
			hash[i + j * 4] = (UCHAR)(ctx->state[j] >> (24 - i * 8));
		}
	}
}

// Функция для поиска хеша SHA-256 по содержимому файла.
NTSTATUS HashFileContentSHA256(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_Out_writes_(SHA256_HASH_SIZE) UCHAR Hash[SHA256_HASH_SIZE]
)
{
	NTSTATUS status;
	UCHAR* buffer = NULL;
	ULONG bufferSize = 64 * 1024;
	LARGE_INTEGER offset = { 0 };
	SHA256_CTX ctx;
	ULONG bytesRead;

	if (!Instance || !FileObject || !Hash) {
		return STATUS_INVALID_PARAMETER;
	}

	// Защита от рекурсии
	if (InterlockedCompareExchange(&g_HashingInProgress, 1, 0) != 0) {
		return STATUS_UNSUCCESSFUL;
	}

	__try {
		buffer = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'hBuf');
		if (!buffer) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		SHA256Init(&ctx);

		while (TRUE) {
			status = FltReadFile(
				Instance,
				FileObject,
				&offset,
				bufferSize,
				buffer,
				FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
				&bytesRead,
				NULL,
				NULL
			);

			if (status == STATUS_END_OF_FILE || bytesRead == 0) {
				status = STATUS_SUCCESS;
				break;
			}

			if (!NT_SUCCESS(status)) {
				__leave;
			}

			SHA256Update(&ctx, buffer, bytesRead);
			offset.QuadPart += bytesRead;
		}

		SHA256Final(&ctx, Hash);
		status = STATUS_SUCCESS;
	}
	__finally {
		if (buffer) {
			ExFreePoolWithTag(buffer, 'hBuf');
		}
		InterlockedExchange(&g_HashingInProgress, 0);
	}
	return status;
}