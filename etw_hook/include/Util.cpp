#include "Util.hpp"
#include <ntddk.h>
#include <ntimage.h>
// 通过PID获得进程名
PCHAR GetProcessNameByProcessId(HANDLE ProcessId)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PEPROCESS ProcessObj = NULL;
	PCHAR string = NULL;
	st = PsLookupProcessByProcessId(ProcessId, &ProcessObj);
	if (NT_SUCCESS(st))
	{
		// XXX: PsGetProcessImageFileName 只能获取到15个字符，内部缓冲区限制，无法获取完整的进程名
		string = (PCHAR)PsGetProcessImageFileName(ProcessObj);
		ObfDereferenceObject(ProcessObj);
	}
	return string;
}

// 通过句柄获取进程PID
NTSTATUS GetPidFromHandle(HANDLE Handle, HANDLE* Pid)
{
	PEPROCESS Process;
	NTSTATUS status;

	// 引用与句柄关联的进程对象
	status = ObReferenceObjectByHandle(
		Handle,                  // 句柄
		GENERIC_READ,			 // 访问权限
		*PsProcessType,          // 进程对象类型
		KernelMode,              // 模式
		(PVOID*)&Process,        // 返回的进程对象指针
		NULL                     // 额外信息（通常为NULL）
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to reference object by handle（status:%d）\n");
		return status;
	}

	// 获取进程的 PID
	*Pid = PsGetProcessId(Process);

	// 释放进程对象
	ObDereferenceObject(Process);

	return STATUS_SUCCESS;
}


// 获取父进程的 PID
NTSTATUS GetParentProcessId(HANDLE ProcessId, HANDLE* ParentProcessId) {
	PEPROCESS Process;
	NTSTATUS status;

	// 根据 PID 查找对应的 EPROCESS 结构
	status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (!NT_SUCCESS(status)) {
		//DbgPrint(("[kernel] 查找进程的process结构体失败（PID: %d）。\n", ProcessId));
		return status;
	}

	// 获取父进程的 EPROCESS
	if (Process != NULL) {
		*ParentProcessId = PsGetProcessInheritedFromUniqueProcessId(Process);
	}
	else
	{
		//DbgPrint(("[kernel] 查找父进程的process结构体失败（PID: %d）。\n", ProcessId));
		ObDereferenceObject(Process); // 释放引用
		return STATUS_UNSUCCESSFUL;
	}

	// 释放引用
	ObDereferenceObject(Process);
	return STATUS_SUCCESS;
}

// 判断是否为父子进程
BOOLEAN AreParentChildProcesses(HANDLE ParentPid, HANDLE ChildPid) {
	HANDLE ChildParentPid;
	NTSTATUS status;

	// 获取子进程的父进程 ID
	status = GetParentProcessId(ChildPid, &ChildParentPid);
	if (!NT_SUCCESS(status)) {
		//DbgPrint(("[kernel] 获取父进程失败，子进程 PID: %d, Status: 0x%X\n", ChildPid, status));
		return FALSE;
	}

	// 判断是否为父子关系
	return (ChildParentPid == ParentPid);
}

const char* ProtectionString(DWORD Protection) {
	switch (Protection) {
	case PAGE_NOACCESS:
		return "---";
	case PAGE_READONLY:
		return "R--";
	case PAGE_READWRITE:
		return "RW-";
	case PAGE_WRITECOPY:
		return "RC-";
	case PAGE_EXECUTE:
		return "--X";
	case PAGE_EXECUTE_READ:
		return "R-X";
	case PAGE_EXECUTE_READWRITE:
		return "RWX";
	case PAGE_EXECUTE_WRITECOPY:
		return "RCX";
	}
	return "???";
}

PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, const CHAR* ExportedFunctionName)
{
	KAPC_STATE State;
	PVOID FunctionAddress = 0;
	if (TargetProcess != NULL)
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

	do
	{
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(DosHeader->e_lfanew + (ULONG64)ModuleBase);
		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (ImageDataDirectory.Size == 0 || ImageDataDirectory.VirtualAddress == 0)
			break;

		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModuleBase + ImageDataDirectory.VirtualAddress);
		ULONG* Address = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfFunctions);
		ULONG* Name = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNames);
		USHORT* Ordinal = (USHORT*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNameOrdinals);

		STRING TargetExportedFunctionName;
		RtlInitString(&TargetExportedFunctionName, ExportedFunctionName);

		for (size_t i = 0; i < ExportDirectory->NumberOfFunctions; i++)
		{
			STRING CurrentExportedFunctionName;
			RtlInitString(&CurrentExportedFunctionName, (PCHAR)ModuleBase + Name[i]);

			if (RtlCompareString(&TargetExportedFunctionName, &CurrentExportedFunctionName, TRUE) == 0)
			{
				FunctionAddress = (PVOID)((ULONG64)ModuleBase + Address[Ordinal[i]]);
				break;
			}
		}

	} while (0);

	if (TargetProcess != NULL)
		KeUnstackDetachProcess(&State);

	return FunctionAddress;
}


int contains_bytes_bitwise(UINT64 address, const UINT8* bytes, size_t num_bytes) {

	for (int i = 0; i < 8; ++i) {
		UINT8 current_byte = (address >> (i * 8)) & 0xFF;

		for (size_t j = 0; j < num_bytes; ++j) {
			if (current_byte == bytes[j]) {
				return 1;
			}
		}
	}
	return 0;
}


//BOOLEAN IsDllLoaded(PEPROCESS Process, const WCHAR* DllName) {
//	PLDR_DATA_TABLE_ENTRY64 pEntry = (PLDR_DATA_TABLE_ENTRY64)PsGetProcessPeb(Process)->Ldr->InLoadOrderModuleList.Flink;
//	UNICODE_STRING uDllName;
//	RtlInitUnicodeString(&uDllName, DllName);
//	do {
//		if (RtlEqualUnicodeString(&pEntry->BaseDllName, &uDllName, TRUE)) {
//			return TRUE;
//		}
//		pEntry = (PLDR_DATA_TABLE_ENTRY64)pEntry->InLoadOrderLinks.Flink;
//	} while (pEntry != (PLDR_DATA_TABLE_ENTRY64)PsGetProcessPeb(Process)->Ldr->InLoadOrderModuleList.Blink);
//	return FALSE;
//}


// 绕过驱动签名检查
BOOLEAN BypassCheckSign(PDRIVER_OBJECT pDriverObject)
{
#ifdef _WIN64
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY listEntry;
		ULONG64 __Undefined1;
		ULONG64 __Undefined2;
		ULONG64 __Undefined3;
		ULONG64 NonPagedDebugInfo;
		ULONG64 DllBase;
		ULONG64 EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING path;
		UNICODE_STRING name;
		ULONG   Flags;
		USHORT  LoadCount;
		USHORT  __Undefined5;
		ULONG64 __Undefined6;
		ULONG   CheckSum;
		ULONG   __padding1;
		ULONG   TimeDateStamp;
		ULONG   __padding2;
	} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#else
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY listEntry;
		ULONG unknown1;
		ULONG unknown2;
		ULONG unknown3;
		ULONG unknown4;
		ULONG unknown5;
		ULONG unknown6;
		ULONG unknown7;
		UNICODE_STRING path;
		UNICODE_STRING name;
		ULONG   Flags;
	} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#endif

	PKLDR_DATA_TABLE_ENTRY pLdrData = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	pLdrData->Flags = pLdrData->Flags | 0x20;

	return TRUE;
}