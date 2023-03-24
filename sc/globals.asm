
glOffsetsArray:
	TOKEN_PROCESS_OFFSET dd 0 ; +
	glActiveListProcessOffset dd 0 ; win7 = 0b8h
	glHandleTableListOffset dd 0
	glHandleTableOffset dd 0
	glImageFileNameOffset dd 0
	glZwCreateThreadIndex dd 0 ; ZW_CREATE_THREAD_INDEX
	glThreadPreviousModeOffset dd 0

count_offsets = 7

OffsetsTableWin10:
	TOKEN_PROCESS_OFFSET_WIN10 dd 0f4h ; 
	ACTIVE_LIST_PROCESS_OFFSET_WIN10 dd 0b8h ; 
	HANDLE_TABLE_LIST_OFFSET_WIN10 dd 010h
	HANDLE_TABLE_OFFSET_WIN10 dd 0154h
	IMAGE_FILE_NAME_OFFSET_WIN10 dd 0170h
	ZW_CREATE_THREAD_INDEX_WIN10 dd 0157h
	THREAD_PREVIOUS_MODE_OFFSET_WIN10 dd 015ah	

OffsetsTableWin7:
	TOKEN_PROCESS_OFFSET_WIN7 dd 0f8h ; 
	ACTIVE_LIST_PROCESS_OFFSET_WIN7 dd 0b8h ; 
	HANDLE_TABLE_LIST_OFFSET_WIN7 dd 010h
	HANDLE_TABLE_OFFSET_WIN7 dd 0f4h
	IMAGE_FILE_NAME_OFFSET_WIN7 dd 016ch
	ZW_CREATE_THREAD_INDEX_WIN7 dd 0057h
	THREAD_PREVIOUS_MODE_OFFSET_WIN7 dd 13ah
	
OffsetsTableWin8:
	TOKEN_PROCESS_OFFSET_WIN8 dd 0ech ; 
	ACTIVE_LIST_PROCESS_OFFSET_WIN8 dd 0b8h ; 
	HANDLE_TABLE_LIST_OFFSET_WIN8 dd 010h
	HANDLE_TABLE_OFFSET_WIN8 dd 0150h
	IMAGE_FILE_NAME_OFFSET_WIN8 dd 0170h
	ZW_CREATE_THREAD_INDEX_WIN8 dd 014dh
	THREAD_PREVIOUS_MODE_OFFSET_WIN8 dd 15ah ; need check

OffsetsTableWinXP:
	TOKEN_PROCESS_OFFSET_WINXP dd 0c8h ;  check
	ACTIVE_LIST_PROCESS_OFFSET_WINXP dd 088h ; 
	HANDLE_TABLE_LIST_OFFSET_WINXP dd 01ch
	HANDLE_TABLE_OFFSET_WINXP dd 0c4h
	IMAGE_FILE_NAME_OFFSET_WINXP dd 0174h
	ZW_CREATE_THREAD_INDEX_WINXP dd 0035h
	THREAD_PREVIOUS_MODE_OFFSET_WINXP dd 13ah ; need check

;--------------------------

pDbgPrint dd 0	;+
pPsLookupProcessByProcessId dd 0 ;+
pObDereferenceObject dd 0 ;+
pPsGetCurrentProcess dd 0 ;+
pPsGetProcessId dd 0
p_stricmp dd 0
pObReferenceObjectSafe dd 0
pZwAllocateVirtualMemory dd 0
pMemcpy dd 0
pPsGetCurrentThread dd 0
pKeStallExecutionProcessor dd 0
pZwCreateFile dd 0
pRtlInitUnicodeString dd 0
pZwClose dd 0

BuildNumber dw 0
PsActiveProcessHead dd 0
PsActiveHandleTableHead dd 0
pObOpenObjectByPointer dd 0
pObCloseHandle dd 0
KeServiceDescriptorTable dd 0
