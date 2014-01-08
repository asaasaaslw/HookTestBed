.386p
.model flat,stdcall
option casemap:none

EXTERN g_FunNtCreateProcess:PTR DWORD

.data


.code
OriginalNewNtCreateProcessEx32_asm PROC stdcall ProcessHandle:PTR DWORD,
	ThreadHandle:PTR DWORD,
	Parameter2:PTR DWORD,
	Parameter3:PTR DWORD,
	ProcessSecurityDescriptor:PTR DWORD,
	ThreadSecurityDescriptor,
	Parameter6:PTR DWORD,
	Parameter7:PTR DWORD,
	ProcessParameters:PTR DWORD,
	Parameter9:PTR DWORD,
	pProcessUnKnow:PTR DWORD

		pop ebp  ;nacked

		push 6B8h
		mov eax,g_FunNtCreateProcess
		add eax,5
		jmp eax

OriginalNewNtCreateProcessEx32_asm ENDP

END