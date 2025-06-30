#include "Util.hpp"
#include <ntddk.h>
#include <ntimage.h>
// ͨ��PID��ý�����
PCHAR GetProcessNameByProcessId(HANDLE ProcessId)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PEPROCESS ProcessObj = NULL;
	PCHAR string = NULL;
	st = PsLookupProcessByProcessId(ProcessId, &ProcessObj);
	if (NT_SUCCESS(st))
	{
		// XXX: PsGetProcessImageFileName ֻ�ܻ�ȡ��15���ַ����ڲ����������ƣ��޷���ȡ�����Ľ�����
		string = (PCHAR)PsGetProcessImageFileName(ProcessObj);
		ObfDereferenceObject(ProcessObj);
	}
	return string;
}

// ͨ�������ȡ����PID
NTSTATUS GetPidFromHandle(HANDLE Handle, HANDLE* Pid)
{
	PEPROCESS Process;
	NTSTATUS status;

	// �������������Ľ��̶���
	status = ObReferenceObjectByHandle(
		Handle,                  // ���
		GENERIC_READ,			 // ����Ȩ��
		*PsProcessType,          // ���̶�������
		KernelMode,              // ģʽ
		(PVOID*)&Process,        // ���صĽ��̶���ָ��
		NULL                     // ������Ϣ��ͨ��ΪNULL��
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to reference object by handle��status:%d��\n");
		return status;
	}

	// ��ȡ���̵� PID
	*Pid = PsGetProcessId(Process);

	// �ͷŽ��̶���
	ObDereferenceObject(Process);

	return STATUS_SUCCESS;
}


// ��ȡ�����̵� PID
NTSTATUS GetParentProcessId(HANDLE ProcessId, HANDLE* ParentProcessId) {
	PEPROCESS Process;
	NTSTATUS status;

	// ���� PID ���Ҷ�Ӧ�� EPROCESS �ṹ
	status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (!NT_SUCCESS(status)) {
		//DbgPrint(("[kernel] ���ҽ��̵�process�ṹ��ʧ�ܣ�PID: %d����\n", ProcessId));
		return status;
	}

	// ��ȡ�����̵� EPROCESS
	if (Process != NULL) {
		*ParentProcessId = PsGetProcessInheritedFromUniqueProcessId(Process);
	}
	else
	{
		//DbgPrint(("[kernel] ���Ҹ����̵�process�ṹ��ʧ�ܣ�PID: %d����\n", ProcessId));
		ObDereferenceObject(Process); // �ͷ�����
		return STATUS_UNSUCCESSFUL;
	}

	// �ͷ�����
	ObDereferenceObject(Process);
	return STATUS_SUCCESS;
}

// �ж��Ƿ�Ϊ���ӽ���
BOOLEAN AreParentChildProcesses(HANDLE ParentPid, HANDLE ChildPid) {
	HANDLE ChildParentPid;
	NTSTATUS status;

	// ��ȡ�ӽ��̵ĸ����� ID
	status = GetParentProcessId(ChildPid, &ChildParentPid);
	if (!NT_SUCCESS(status)) {
		//DbgPrint(("[kernel] ��ȡ������ʧ�ܣ��ӽ��� PID: %d, Status: 0x%X\n", ChildPid, status));
		return FALSE;
	}

	// �ж��Ƿ�Ϊ���ӹ�ϵ
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


// �ƹ�����ǩ�����
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