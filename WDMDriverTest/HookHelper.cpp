#include "HookHelper.h"
#include "Utils.h"
#include <minwindef.h>

/************************************************************************
 * ObReferenceObjectByHandle                                                       
************************************************************************/
UCHAR  ObReferenceObjectByHandleOriginalBytes[5] = {0};             //保存原始函数前五个字节

_declspec(naked) NTSTATUS OriginalObReferenceObjectByHandle(
	_In_       HANDLE Handle,
	_In_       ACCESS_MASK DesiredAccess,
	_In_opt_   POBJECT_TYPE ObjectType,
	_In_       KPROCESSOR_MODE AccessMode,
	_Out_      PVOID *Object,
	_Out_opt_  POBJECT_HANDLE_INFORMATION HandleInformation
	)
{
	_asm     
	{         
		mov edi,edi
		push ebp
		mov ebp,esp; //到此为 ObReferenceObjectByHandle 原来的前5个字节(windbg)
		mov eax,ObReferenceObjectByHandle
		add eax,5
		jmp eax                      
	}
}

NTSTATUS NewObReferenceObjectByHandle(
	_In_       HANDLE Handle,
	_In_       ACCESS_MASK DesiredAccess,
	_In_opt_   POBJECT_TYPE ObjectType,
	_In_       KPROCESSOR_MODE AccessMode,
	_Out_      PVOID *Object,
	_Out_opt_  POBJECT_HANDLE_INFORMATION HandleInformation
	)
{
	//KdPrint(("[%s] <----------------------\n", __FUNCTION__));  
	NTSTATUS status;
	status = OriginalObReferenceObjectByHandle(Handle,
			DesiredAccess,
			ObjectType,
			AccessMode,
			Object,
			HandleInformation
		);

	if((status==STATUS_SUCCESS)&&(DesiredAccess==1))
	{         
		if(ObjectType== *PsProcessType)
		{  
			KdPrint(("[%s] , ProcessName: %s\n", __FUNCTION__, (char *)((ULONG)(*Object) + EPROCESS_NAME_OFFSET)));  
			if( _stricmp((char *)((ULONG)(*Object) + EPROCESS_NAME_OFFSET),"notepad.exe")==0) 
			{             
				return STATUS_ACCESS_DENIED;
			}  
		}   
	}  
	return status;
}

/************************************************************************
 * NtCreateProcess                                                       
************************************************************************/


typedef NTSTATUS (*FunNtCreateUserProcessEx)(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	PVOID Parameter2,
	PVOID Parameter3,
	PVOID ProcessSecurityDescriptor,
	PVOID ThreadSecurityDescriptor,
	PVOID Parameter6,
	PVOID Parameter7,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PVOID Parameter9,
	PVOID pProcessUnKnow
	);

FunNtCreateUserProcessEx g_FunNtCreateProcess = NULL;
UCHAR  NtCreateProcessOriginalBytes[5] = {0};             //保存原始函数前五个字节

_declspec(naked) NTSTATUS
OriginalNewNtCreateProcessEx(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	PVOID Parameter2,
	PVOID Parameter3,
	PVOID ProcessSecurityDescriptor,
	PVOID ThreadSecurityDescriptor,
	PVOID Parameter6,
	PVOID Parameter7,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PVOID Parameter9,
	PVOID pProcessUnKnow
	)
{
	_asm     
	{         
		push 6B8h
		mov eax,g_FunNtCreateProcess
		add eax,5
		jmp eax                      
	}
}

NTSTATUS
NewNtCreateProcessEx(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	PVOID Parameter2,
	PVOID Parameter3,
	PVOID ProcessSecurityDescriptor,
	PVOID ThreadSecurityDescriptor,
	PVOID Parameter6,
	PVOID Parameter7,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PVOID Parameter9,
	PVOID pProcessUnKnow
	)
{
	KdPrint(("[%s] <----------------------\n ImageName:[%wZ],  \n", __FUNCTION__, &(ProcessParameters->ImagePathName)));  
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING strNotePad;

	RtlInitUnicodeString(&strNotePad, L"NOTEPAD.EXE");

	if (FindSubString(&(ProcessParameters->ImagePathName),&(strNotePad)))
	{
		KdPrint(("[%s] IS NOTEPAD.EXE!!  \n", __FUNCTION__));  
		return STATUS_ACCESS_DENIED;
	}

	status = OriginalNewNtCreateProcessEx(ProcessHandle,
		ThreadHandle,
		Parameter2,
		Parameter3,
		ProcessSecurityDescriptor,
		ThreadSecurityDescriptor,
		Parameter6,
		Parameter7,
		ProcessParameters,
		Parameter9,
		pProcessUnKnow
		);

	if (NT_SUCCESS(status))
	{
		//KdPrint(("[%s] , ProcessName: %s\n", __FUNCTION__, (char *)((ULONG)(*ProcessHandle) + EPROCESS_NAME_OFFSET)));  
	}

	return status;
}

HookHelper::HookHelper(void)
{
	KdPrint(("[%s] <----------------------\n", __FUNCTION__));
	m_bHookObSuccess = FALSE;
	m_bHookZwCreUserProcSuccess = FALSE;
}


HookHelper::~HookHelper(void)
{
	//UnHookObReferenceObjectByHandle();
	if (m_bHookObSuccess)
	{
		UnHookObReferenceObjectByHandle();
	}

	if (m_bHookZwCreUserProcSuccess)
	{
		UnHookNtCreateProcess();
	}
	
	KdPrint(("[%s] <----------------------\n", __FUNCTION__));  
}

BOOLEAN HookHelper::HookObReferenceObjectByHandle(PVOID *newFun)
{
	KdPrint(("[%s] <----------------------\n", __FUNCTION__));  
	KIRQL Irql;
	ULONG  CR0VALUE;  
	UCHAR JmpAddress[5] = {0xE9,0,0,0,0};       //跳转到HOOK函数的地址

	RtlCopyMemory(ObReferenceObjectByHandleOriginalBytes, ObReferenceObjectByHandle, 5);
	*(ULONG  *)(JmpAddress+1)=(ULONG)NewObReferenceObjectByHandle - ((ULONG)ObReferenceObjectByHandle+5);
	KdPrint(("[ObReferenceObjectByHandle] :0x%x",ObReferenceObjectByHandle));

	
	PageOff();
	Irql=KeRaiseIrqlToDpcLevel();  //函数开头五个字节写JMP
	RtlCopyMemory((UCHAR *)ObReferenceObjectByHandle,JmpAddress,5);  
	KeLowerIrql(Irql);
	PageOn();

	KdPrint(("[%s] ---------------------> \n", __FUNCTION__));  

	m_bHookObSuccess = TRUE;

	return FALSE;
}

BOOLEAN HookHelper::UnHookObReferenceObjectByHandle()
{
	KdPrint(("[%s] <----------------------\n", __FUNCTION__));  
	KIRQL Irql;
	PageOff();
	Irql=KeRaiseIrqlToDpcLevel();  //函数开头五个字节写JMP
	RtlCopyMemory((UCHAR *)ObReferenceObjectByHandle,ObReferenceObjectByHandleOriginalBytes,5);  
	KeLowerIrql(Irql);
	PageOn();

	return TRUE;
}

BOOLEAN HookHelper::HookNtCreateProcess(PVOID *newFun)
{
	KdPrint(("[%s] <----------------------\n", __FUNCTION__));  
	KIRQL Irql;
	ULONG  CR0VALUE;  
	UCHAR JmpAddress[5] = {0xE9,0,0,0,0};       //跳转到HOOK函数的地址
	UNICODE_STRING strNtCreateProcess;
	ULONG uAddress = 0;

	RtlInitUnicodeString(&strNtCreateProcess, L"NtCreateUserProcess");

	//85890845 fffff9b0 890c458b fff9ac85 NtCreateUserProcess + 0x10的特征码
	ULONG uSpecArray[8] = {
		0x85890845, 0xfffff9b0, 0x890c458b, 0xfff9ac85,
		0x185d8bff, 0xf9a09d89, 0x458bffff, 0x8c85891c};
	FindSpeCodeInMemory(&uAddress, uSpecArray, 8 );
	uAddress -= 0x10;

	g_FunNtCreateProcess = (FunNtCreateUserProcessEx) uAddress;
	if (!g_FunNtCreateProcess)
	{
		RtlCopyMemory(NtCreateProcessOriginalBytes, g_FunNtCreateProcess, 5);
		KdPrint(("[%s] g_FunNtCreateProcess == NULL !!!!!\n", __FUNCTION__)); 
		return FALSE;
	}
	RtlCopyMemory(NtCreateProcessOriginalBytes, g_FunNtCreateProcess, 5);
	*(ULONG  *)(JmpAddress+1)=(ULONG)NewNtCreateProcessEx - ((ULONG)g_FunNtCreateProcess + 5);
	KdPrint(("[NtCreateProcess] :0x%x",g_FunNtCreateProcess));


	PageOff();
	Irql=KeRaiseIrqlToDpcLevel();  
	RtlCopyMemory((UCHAR *)g_FunNtCreateProcess,JmpAddress,5);  
	KeLowerIrql(Irql);
	PageOn();

	m_bHookZwCreUserProcSuccess = TRUE;

	KdPrint(("[%s] ---------------------> \n", __FUNCTION__));  
	return TRUE;
}

BOOLEAN HookHelper::UnHookNtCreateProcess()
{
	KdPrint(("[%s] <----------------------\n", __FUNCTION__));  
	KIRQL Irql;
	PageOff();
	Irql=KeRaiseIrqlToDpcLevel();  //函数开头五个字节写JMP
	RtlCopyMemory((UCHAR *)g_FunNtCreateProcess,NtCreateProcessOriginalBytes,5);  
	KeLowerIrql(Irql);
	PageOn();

	return TRUE;
}

NTSTATUS HookHelper::FindSpeCodeInMemory(PULONG pRet, ULONG* code_sp_array, ULONG uCount)
{
	PAGED_CODE()

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG uResult = -1;
	ULONG uSzie;
	ULONG ntosknlBase;
	ULONG ntosknlEndAddr;
	ULONG uMCount;
	PULONG pBuf;

	PSYSTEM_MODULE_INFORMATION_ENTRY module;

	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &uSzie);
	if(NULL==(pBuf = (PULONG)ExAllocatePool(PagedPool, uSzie)))
	{
		KdPrint(("[%s] failed alloc memory failed \n", __FUNCTION__));
		return status;
	}
	KdPrint(("[%s] uSzie = %d \n", __FUNCTION__, uSzie));
	status = ZwQuerySystemInformation(SystemModuleInformation,pBuf, uSzie, 0);
	if(!NT_SUCCESS( status ))
	{
		KdPrint(("[%s] failed query \n", __FUNCTION__));
		return status;
	}
	module = (PSYSTEM_MODULE_INFORMATION_ENTRY)(( PULONG )pBuf + 1);

	ntosknlEndAddr=(ULONG)module->Base+(ULONG)module->Size;
	ntosknlBase=(ULONG)module->Base;

	KdPrint(("[%s] Base:%08x, End:%08x ImageName:%s \n", __FUNCTION__, ntosknlBase, ntosknlEndAddr ,module->ImageName));

	ExFreePool(pBuf);

	for (ULONG i = ntosknlBase;i < ntosknlEndAddr - (4 * uCount); i++)
	{
		BOOL bFind = TRUE;
		for (int j = 0; j < uCount; j++)
		{
			if ((*((ULONG *)(i + j * 4)) == code_sp_array[j]))
			{
				continue;
			}
			else
			{
				bFind = FALSE;
				break;
			}
		}

		if (bFind)
		{
			(*pRet) = i;
			KdPrint(("[%s] Find:%08x\n",__FUNCTION__, *pRet));
			status = STATUS_SUCCESS;
			return status;
		}
	}

	KdPrint(("[%s] UnFind . \n",__FUNCTION__));

	return status;
}