GetHashByStr:

	xor eax, eax
	push esi
	mov esi, [esp + 8]

@@:
	mov cl, [esi]
	test cl, cl
	je @f
	xor al, cl
	rol eax, 7
	inc esi
	jmp @b
	
@@:
	pop esi
	ret 4

FindKernelBaseByAddr proc stdcall uses edi esi ebx addr_:dword

	mov eax, 905A4Dh
	mov ecx, 10000000h
	mov edi, [addr_]
	
	std
	@@:
	repne scasb
	jnz end_FBK_bad
	
	cmp dword ptr [edi+1], eax
	jnz @b
	
	lea eax, [edi+1]
	jmp end_FBK_good
	
end_FBK_bad:
	xor eax, eax
end_FBK_good:
	cld
	ret
	
FindKernelBaseByAddr endp

FindBaseKernelByIDT proc stdcall uses edi esi ebx 

	local pIDT:IDTR
	;local deskr:dword
	local addrInt:dword
	
	xor ebx, ebx
	sidt fword ptr [pIDT]
	
	mov eax, [pIDT].Base
	;mov [deskr], eax
	mov bx, word ptr [eax].IdtDescriptorGate.DestinationOffsetHigh
	shl ebx, 16
	mov cx, word ptr [eax].IdtDescriptorGate.DestinationOffsetLow
	or bx, cx
	
	mov [addrInt], ebx
	
	invoke FindKernelBaseByAddr, ebx
	.if !eax
		jmp end_FBKi_bad
	.endif
	jmp end_FBKi_good

end_FBKi_bad:
	xor eax, eax
	
end_FBKi_good:
	ret
	
FindBaseKernelByIDT endp
	
;
; Осуществляет поиск адреса функции по хешу
; void *FindProcAddressByHash (void *baseLib, DWORD hash)
;
FindProcAddressByHash proc stdcall uses edi esi ebx baseLib:dword, hash:dword

    local   functionsArray:dword
    local   namesArray:dword
    local   nameOrdinalsArray:dword

    mov ebx, [baseLib]
    
    mov eax, [ebx].IMAGE_DOS_HEADER.e_lfanew    ; eax = offset PE header
    
    ; esi = rva export directory
    mov esi, [ebx + eax].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    add esi, ebx                ; esi = va export directory
    
    mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions    ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    add eax, ebx
    mov [functionsArray], eax
    
    mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNames        ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNames
    add eax, ebx
    mov [namesArray], eax
    
    mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
    add eax, ebx
    mov [nameOrdinalsArray], eax
    
    xor edi, edi

@@:
		xor eax, eax
        cmp edi, [esi].IMAGE_EXPORT_DIRECTORY.NumberOfNames      ; edi < IMAGE_EXPORT_DIRECTORY.NumberOfNames
        
        ; после сравнения хешей на предыдущей итерации eax=0
        jge find_ret

        mov eax, [namesArray]
        mov eax, [eax+edi*4]
        add eax, ebx
		push eax
		call GetHashByStr
		cmp eax, [hash]
		je @f

        inc edi
        jmp @b
@@:
    
    mov eax, [nameOrdinalsArray]
    movzx edi, word ptr [eax+edi*2]
    mov eax, [functionsArray]
    mov eax, [eax+edi*4]
    add eax, ebx
    
find_ret:
    
    ret
	
FindProcAddressByHash endp

; -------------------------

FindProcAddressForImportByHash proc stdcall uses esi edi ebx baseLib:dword, libHash:dword, procHash:dword

    local pCurrIID:dword
    local FTindex:dword
    local ThunkEntry:dword
    local ImportByName:dword

    mov [FTindex], 0
    mov ebx, [baseLib]    
    mov eax, [ebx].IMAGE_DOS_HEADER.e_lfanew    ; eax = offset PE header
    
    ; esi = rva export directory
    lea esi, [ebx + eax].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory
    mov esi, [esi + 8]
    ;mov esi, [ebx + eax + 78h];.IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    .if !esi
        jmp find_FAI_bad
    .endif

    add esi, ebx
    ;mov esi, [esi]
    mov dword ptr [pCurrIID], esi    

    .while [esi].IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk != 0
        mov ecx, dword ptr [esi].IMAGE_IMPORT_DESCRIPTOR.Name1
        lea ecx, [ebx + ecx]
        push ecx
        call GetHashByStr
        .if eax != [libHash]
            jmp next_stage
        .endif

        mov edi, [esi].IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
        .while [edi].IMAGE_THUNK_DATA.u1.AddressOfData != 0
            mov ecx, [edi].IMAGE_THUNK_DATA.u1.AddressOfData
            lea ecx, [ebx + ecx]
            mov [ImportByName], ecx
            mov edx, [edi].IMAGE_THUNK_DATA.u1.Ordinal
            and edx, IMAGE_ORDINAL_FLAG32
            .if edx == 0 && \
                byte ptr [ecx].IMAGE_IMPORT_BY_NAME.Name1 != 0

                lea eax, [ecx].IMAGE_IMPORT_BY_NAME.Name1
                push eax
                call GetHashByStr
                .if eax != [libHash]
                    jmp next_stage1
                .endif

                mov edx, [esi].IMAGE_IMPORT_DESCRIPTOR.FirstThunk
                mov ecx, [FTindex]
                lea edx, [edx + ecx * 4]
                lea eax, [ebx + edx]
                jmp find_FAI_good
            .endif 
            next_stage1:
            inc [FTindex]
            lea edi, [edi + 4]
        .endw

        next_stage:
        mov esi, [esi + 20]
    .endw


find_FAI_bad:
    xor eax, eax
find_FAI_good:
    ret

FindProcAddressForImportByHash endp