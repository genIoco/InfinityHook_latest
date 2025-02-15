#pragma once
extern "C" {
#include <ntifs.h>

}
#include "Util.hpp"
typedef struct _SSDT
{
	LONG* ServiceTable;
	PVOID CounterTable;
	ULONG64 SyscallsNumber;
	PVOID ArgumentTable;
}_SSDT, * _PSSDT;

namespace Syscall {
	SHORT GetSyscallNumber(PVOID FunctionAddress);
	BOOLEAN GetNtSyscallNumber(SHORT* syscallNumberOut, const char* syscall);
	PVOID GetNtSyscallFunc(_PSSDT ssdt, SHORT index);

	// https://github.com/JakubGlisz/GetSSDT
	_PSSDT GetSSDT();

}