
.data
realVal dq 4 ; this stores a real number in 8 bytes

.code

PageOn64_asm PROC
	mov  rax, cr0
	or   rax, 010000h
	mov  cr0, rax
	sti
    RET                             ; return
PageOn64_asm ENDP

PageOff64_asm PROC
	cli 
	mov rax, cr0
	and rax, not 010000h
	mov cr0, rax
    RET                             ; return
PageOff64_asm ENDP

End
