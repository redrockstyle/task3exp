; jwasm -bin -Fo nop_sc.bin nop_sc.asm
;
;

.686P
.model flat,stdcall
option casemap:none


sc segment

assume fs:nothing

	nop



end_sc:
sc ends

end
