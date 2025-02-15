#pragma once
#pragma once
extern "C" {
#include <ntifs.h>
#include <minwindef.h>
}

extern "C"
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);

extern "C"
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);

PCHAR GetProcessNameByProcessId(HANDLE ProcessId);

NTSTATUS GetPidFromHandle(HANDLE Handle, HANDLE* Pid);

BOOLEAN AreParentChildProcesses(HANDLE ParentPid, HANDLE ChildPid);

const char* ProtectionString(DWORD Protection);

template<typename... Ts>
__forceinline void Ensure(NTSTATUS status, [[maybe_unused]] const char* format, [[maybe_unused]] Ts... args) {
	if (!NT_SUCCESS(status)) {
		KdPrint(("shrimp failure :c (status: 0x%X): ", status));
		KdPrint((format, args...));
		DbgRaiseAssertionFailure();
	}
}

__forceinline void EnsureDebug([[maybe_unused]] NTSTATUS status, [[maybe_unused]] const char* message) {
#if DBG
	Ensure(status, message);
#endif
}

PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, CONST CHAR* ExportedFunctionName);

int contains_bytes_bitwise(UINT64 address, const UINT8* bytes, size_t num_bytes);

NTSTATUS Sleep(ULONGLONG microseconds);
