#include "Syscall.hpp"

#include <intrin.h>

SHORT Syscall::GetSyscallNumber(PVOID FunctionAddress)
{
	return *(SHORT*)((ULONG64)FunctionAddress + 4);
}

BOOLEAN Syscall::GetNtSyscallNumber(SHORT* syscallNumberOut, const char* syscall)
{
	UNICODE_STRING knownDlls{};
	RtlInitUnicodeString(&knownDlls, LR"(\KnownDlls\ntdll.dll)");

	OBJECT_ATTRIBUTES objAttributes{};
	InitializeObjectAttributes(&objAttributes, &knownDlls, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	HANDLE section{};
	if (!NT_SUCCESS(ZwOpenSection(&section, SECTION_MAP_READ, &objAttributes)))
		return false;

	PVOID ntdllBase{};
	size_t ntdllSize{};
	LARGE_INTEGER sectionOffset{};
	if (!NT_SUCCESS(ZwMapViewOfSection(section, ZwCurrentProcess(), &ntdllBase, 0, 0, &sectionOffset, &ntdllSize, ViewShare, 0, PAGE_READONLY)))
	{
		ZwClose(section);
		return false;
	}

	auto status = true;
	const auto functionAddress = GetExportedFunctionAddress(0, ntdllBase, syscall);
	if (!functionAddress)
	{
		status = false;
	}
	else {
		*syscallNumberOut = GetSyscallNumber(functionAddress);
	}

	ZwClose(section);
	ZwUnmapViewOfSection(ZwCurrentProcess(), ntdllBase);

	return status;
}

PVOID Syscall::GetNtSyscallFunc(_PSSDT ssdt, SHORT index)
{
	return (PVOID)((ULONG64)ssdt->ServiceTable + (ssdt->ServiceTable[index] >> 4));
}

extern "C" NTKERNELAPI SHORT NtBuildNumber;

// https://github.com/JakubGlisz/GetSSDT
// https://www.unknowncheats.me/forum/3383983-post3.html
_PSSDT Syscall::GetSSDT()
{
	ULONGLONG KiSystemCall64 = __readmsr(0xC0000082 /* lstar */);
	INT32 Limit = 4096;
	//DbgBreakPoint();

	for (int i = 0; i < Limit; i++) {
		// 使用MmIsAddressValid来检查地址是否有效
		if (MmIsAddressValid((PUINT8)(KiSystemCall64 + i)) && MmIsAddressValid((PUINT8)(KiSystemCall64 + i + 9)))
			if (*(PUINT8)(KiSystemCall64 + i) == 0x4C
				&& *(PUINT8)(KiSystemCall64 + i + 1) == 0x8D
				&& *(PUINT8)(KiSystemCall64 + i + 2) == 0x15
				&& *(PUINT8)(KiSystemCall64 + i + 7) == 0x4C
				&& *(PUINT8)(KiSystemCall64 + i + 8) == 0x8D
				&& *(PUINT8)(KiSystemCall64 + i + 9) == 0x1D)
			{
				ULONGLONG KiSystemServiceRepeat = KiSystemCall64 + i;

				// convert relative address to absolute address
				return (_PSSDT)((ULONGLONG) * (PINT32)(KiSystemServiceRepeat + 3) + KiSystemServiceRepeat + 7);
			}
	}
	ULONGLONG KiSystemCall64Shadow = __readmsr(0xC0000082 /* lstar */);

	if (NtBuildNumber > 17134)
	{
		for (int i = 0; i < Limit; i++) {
			// 使用MmIsAddressValid来检查地址是否有效
			if (MmIsAddressValid((PUINT8)(KiSystemCall64Shadow + i)) && MmIsAddressValid((PUINT8)(KiSystemCall64Shadow + i + 6)))
				if (*(PUINT8)(KiSystemCall64Shadow + i) == 0xE9
					&& *(PUINT8)(KiSystemCall64Shadow + i + 5) == 0xC3
					&& !*(PUINT8)(KiSystemCall64Shadow + i + 6))
				{
					//https://github.com/Xacone/KeServiceDescriptorTableLeak
					ULONGLONG lastJmpAddr = NULL;
					do {
						__try {

							KiSystemCall64Shadow += 2;
							UINT8 jmp_byte[] = { 0xE9 };

							if (contains_bytes_bitwise(*(PULONG)KiSystemCall64Shadow, jmp_byte, 1)) {
								lastJmpAddr = KiSystemCall64Shadow;
							}
						}
						__except (EXCEPTION_EXECUTE_HANDLER) {
							DbgPrint("[-] Exception\n");
							return NULL;
						}

					} while (*(PULONG)KiSystemCall64Shadow != 0);

					LONG KiSystemServiceUserOffset = -(*(PLONG)(lastJmpAddr + 2));
					ULONGLONG KiSystemServiceUser = (ULONGLONG)((lastJmpAddr + 2 + 4) - (LONG)KiSystemServiceUserOffset);


					for (int j = 0; j < Limit; j++) {
						// 使用MmIsAddressValid来检查地址是否有效
						if (MmIsAddressValid((PUINT8)(KiSystemServiceUser + j)) && MmIsAddressValid((PUINT8)(KiSystemServiceUser + j + 9)))
							if (*(PUINT8)(KiSystemServiceUser + j) == 0x4C
								&& *(PUINT8)(KiSystemServiceUser + j + 1) == 0x8D
								&& *(PUINT8)(KiSystemServiceUser + j + 2) == 0x15
								&& *(PUINT8)(KiSystemServiceUser + j + 7) == 0x4C
								&& *(PUINT8)(KiSystemServiceUser + j + 8) == 0x8D
								&& *(PUINT8)(KiSystemServiceUser + j + 9) == 0x1D)
							{
								ULONGLONG KiSystemServiceRepeat = KiSystemServiceUser + j;

								// convert relative address to absolute address
								return (_PSSDT)((ULONGLONG) * (PINT32)(KiSystemServiceRepeat + 3) + KiSystemServiceRepeat + 7);
							}
					}
				}
		}
	}

	return 0;
}
