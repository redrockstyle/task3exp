;
; Шеллкод, выводящий сообщение с помощью DbgPrint.
;
; jwasm -bin -Fo sc.bin sc.asm
;
;

.686P
.model flat,stdcall
option casemap:none

include C:\masm32\include\windows.inc
include .\imageWork.inc
du	macro string
local bslash
bslash = 0
	irpc c,<string>
	if bslash eq 0
		if '&c' eq "/"
	        bslash = 1
		elseif '&c' gt 127
		db ('&c'- 0B0h),4
		else
		dw '&c'
		endif
	else
           bslash = 0
           if '&c' eq "n"
           DW 0Dh,0Ah
           elseif '&c' eq "/"
           dw '/'
           elseif '&c' eq "r"
           dw 0Dh
           elseif '&c' eq "l"
           dw 0Ah
           elseif '&c' eq "s"
           dw 20h
           elseif '&c' eq "c"
           dw 3Bh
           elseif '&c' eq "t"
           dw 9
	   endif
	endif
	endm
	dw 0
endm

OBJECT_ATTRIBUTES struct
	Length_ dword 24
	RootDirectory dword 0
	ObjectName dword 0
	Attributes dword ?
	SecurityDescriptor dword ?
	SecurityQualityOfService dword 0
OBJECT_ATTRIBUTES ends

UNICODE_STRING struct
	Length_ word ?
	MaximumLength word ?
	Buffer dword ?
UNICODE_STRING ends

sc segment

assume fs:nothing

start:
	; pushad
	; pushf
	
	call $+5
	pop ebx
	sub ebx, 5
	
STACK_LOCATION = 16
pBaseSC = 0
pDbgPrint_ = 4
pMsg = 8
KernelBase = 12

	sub esp, STACK_LOCATION
	
	mov dword ptr [esp+pBaseSC], ebx
		
	call hello_str
db "Hello, World, from shellcode", 0Ah, 0
	hello_str:
	pop eax

	mov dword ptr [esp+pMsg], eax	
	
	invoke FindBaseKernelByIDT
	.if !eax
		jmp end_sc1
	.endif
	
	mov dword ptr [esp+KernelBase], eax

NtBuildNumber_hash = 47d81fd8h

	mov eax, dword ptr [esp+KernelBase]
	invoke FindProcAddressByHash, eax, NtBuildNumber_hash
	.if !eax
		jmp end_sc1
	.endif

	mov ax, word ptr [eax]
	mov word ptr [ebx + BuildNumber], ax

DbgPrint_hash = 69fe2487h

	mov eax, dword ptr [esp+KernelBase]
	invoke FindProcAddressByHash, eax, DbgPrint_hash
	.if !eax
		jmp end_sc1
	.endif
	
	mov [ebx+pDbgPrint], eax
	
	mov ecx, dword ptr [esp+pMsg]
	push ecx
	call eax ; call DbgPrint
	add esp, 4 ;

end_sc1:
	add esp, STACK_LOCATION

	push [ebx + end_sc] ; socket
	push [ebx + end_sc + 4] ; CloseSocket addr
	ret

;---------------------------------

include .\imageWork.asm
include .\globals.asm


end_sc:
sc ends

end
