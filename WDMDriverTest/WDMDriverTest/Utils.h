#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#include <wdm.h>
#ifdef __cplusplus
}
#endif 

#define WIN_7_32BIT

#define EPROCESS_NAME_OFFSET 0x16c

inline VOID * _cdecl operator new(size_t size, POOL_TYPE pagePool = PagedPool)
{
	return ExAllocatePool(pagePool, size);
}

inline VOID _cdecl operator delete(VOID *pointer)
{
	ExFreePool(pointer);
}

inline VOID PageOn()
{
#ifdef _X86_
	__asm
	{
		mov  eax, cr0
		or     eax, 0x10000
		mov  cr0, eax
		sti ;//将处理器标志寄存器的中断标志置1，允许中断
	}
#endif 
	
}

inline VOID PageOff()
{
#ifdef _X86_
	__asm
	{
		cli ;//将处理器标志寄存器的中断标志位清0，不允许中断
		mov eax, cr0
		and  eax, ~0x10000
		mov cr0, eax
	}
#endif 
}

inline 
BOOLEAN
	FindSubString (
	IN PUNICODE_STRING String,
	IN PUNICODE_STRING SubString
	)
{
	ULONG index;

	//
	//  First, check to see if the strings are equal.
	//

	if (RtlEqualUnicodeString( String, SubString, TRUE )) {

		return TRUE;
	}

	//
	//  String and SubString aren't equal, so now see if SubString
	//  in in String any where.
	//
	for (index = 0;
		index + SubString->Length <= String->Length;
		index++) {
			if (_wcsnicmp(&(String->Buffer[index]),
				SubString->Buffer,
				SubString->Length) == 0) {
					//
					//  SubString is found in String, so return TRUE.
					//
					return TRUE;
			}
	}

	return FALSE;
}