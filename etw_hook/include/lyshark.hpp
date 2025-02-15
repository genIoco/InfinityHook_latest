#pragma once
// 署名权
// right to sign one's name on a piece of work
// PowerBy: LyShark
// Email: me@lyshark.com

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

// -----------------------------------------------------------------------------------
// 声明未导出函数
// -----------------------------------------------------------------------------------

EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
EXTERN_C NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);
EXTERN_C NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* LPFN_NTCREATETHREADEX)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID StartAddress,
	IN PVOID Parameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID ByteBuffer
	);

// -----------------------------------------------------------------------------------
// 结构体声明
// -----------------------------------------------------------------------------------

// SSDT表结构
typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID       ServiceTableBase;
	PVOID       ServiceCounterTableBase;
	ULONGLONG   NumberOfServices;
	PVOID       ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// PEB32/PEB64
typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY
{
	ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX
	SIZE_T Size;
	ULONG_PTR Value;
	ULONG Unknown;
} NT_PROC_THREAD_ATTRIBUTE_ENTRY, * NT_PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
{
	ULONG Length;
	NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, * PNT_PROC_THREAD_ATTRIBUTE_LIST;


// 注入ShellCode结构
typedef struct _INJECT_BUFFER
{
	UCHAR Code[0x200];
	union
	{
		UNICODE_STRING Path64;
		UNICODE_STRING32 Path32;
	};
	wchar_t Buffer[488];
	PVOID ModuleHandle;
	ULONG Complete;
	NTSTATUS Status;
} INJECT_BUFFER, * PINJECT_BUFFER;

// -----------------------------------------------------------------------------------
// 一些开发中的通用函数封装，可任意拷贝使用
// -----------------------------------------------------------------------------------

// 传入函数名获取SSDT导出表RVA
// 参数1：传入函数名称
ULONG GetSSDTRVA(UCHAR* function_name)
{
	NTSTATUS Status;
	HANDLE FileHandle;
	IO_STATUS_BLOCK ioStatus;
	FILE_STANDARD_INFORMATION FileInformation;

	// 设置NTDLL路径
	UNICODE_STRING uniFileName;
	RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntoskrnl.exe");

	// 初始化打开文件的属性
	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &uniFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	// 打开文件
	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes, &ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(Status))
	{
		return 0;
	}

	// 获取文件信息
	Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(FileHandle);
		return 0;
	}

	// 判断文件大小是否过大
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		ZwClose(FileHandle);
		return 0;
	}
	// 取文件大小
	ULONG uFileSize = FileInformation.EndOfFile.LowPart;

	// 分配内存
	PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, uFileSize + 0x100, (ULONG)"PGu");
	if (pBuffer == NULL)
	{
		ZwClose(FileHandle);
		return 0;
	}

	// 从头开始读取文件
	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = 0;
	byteOffset.HighPart = 0;
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(FileHandle);
		return 0;
	}

	// 取出导出表
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	ULONGLONG FileOffset;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;

	// DLL内存数据转成DOS头结构
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;

	// 取出PE头结构
	pNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)pBuffer + pDosHeader->e_lfanew);

	// 判断PE头导出表表是否为空
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		return 0;
	}

	// 取出导出表偏移
	FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	// 取出节头结构
	pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;

	// 遍历节结构进行地址运算
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}

	// 导出表地址
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pBuffer + FileOffset);

	// 取出导出表函数地址
	PULONG AddressOfFunctions;
	FileOffset = pExportDirectory->AddressOfFunctions;

	// 遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfFunctions = (PULONG)((ULONGLONG)pBuffer + FileOffset);

	// 取出导出表函数名字
	PUSHORT AddressOfNameOrdinals;
	FileOffset = pExportDirectory->AddressOfNameOrdinals;

	// 遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfNameOrdinals = (PUSHORT)((ULONGLONG)pBuffer + FileOffset);

	//取出导出表函数序号
	PULONG AddressOfNames;
	FileOffset = pExportDirectory->AddressOfNames;

	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;

	// 循环所有节
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		// 寻找符合条件的节
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			// 得到文件偏移
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfNames = (PULONG)((ULONGLONG)pBuffer + FileOffset);

	//DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", (ULONGLONG)AddressOfFunctions- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNameOrdinals- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNames- (ULONGLONG)pBuffer);
	//DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", pExportDirectory->AddressOfFunctions, pExportDirectory->AddressOfNameOrdinals, pExportDirectory->AddressOfNames);

	// 开始分析导出表
	ULONG uOffset;
	LPSTR FunName;
	ULONG uAddressOfNames;
	ULONG TargetOff = 0;

	// 循环导出表
	for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++)
	{
		uAddressOfNames = *AddressOfNames;
		pSectionHeader = pOldSectionHeader;
		for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
		{
			// 函数地址在某个范围内
			if (pSectionHeader->VirtualAddress <= uAddressOfNames && uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			{
				uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
			}
		}

		// 得到函数名
		FunName = (LPSTR)((ULONGLONG)pBuffer + uOffset);

		// 判断是否符合要求
		if (!_stricmp((const char*)function_name, FunName))
		{
			// 返回函数地址
			TargetOff = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];
			DbgPrint("索引 [ %p ] 函数名 [ %s ] 相对RVA [ %p ] \n", *AddressOfNameOrdinals, FunName, TargetOff);
		}

	}

	ExFreePoolWithTag(pBuffer, (ULONG)"PGu");
	ZwClose(FileHandle);
	return TargetOff;
}

// 传入函数名 获取该函数所在模块下标
ULONG GetIndexByName(UCHAR* function_name)
{
	NTSTATUS Status;
	HANDLE FileHandle;
	IO_STATUS_BLOCK ioStatus;
	FILE_STANDARD_INFORMATION FileInformation;

	// 设置NTDLL路径
	UNICODE_STRING uniFileName;
	RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntdll.dll");

	// 初始化打开文件的属性
	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &uniFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	// 打开文件
	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes, &ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(Status))
	{
		return 0;
	}

	// 获取文件信息
	Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(FileHandle);
		return 0;
	}

	// 判断文件大小是否过大
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		ZwClose(FileHandle);
		return 0;
	}

	// 取文件大小
	ULONG uFileSize = FileInformation.EndOfFile.LowPart;

	// 分配内存
	PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, uFileSize + 0x100, (ULONG)"Ntdl");
	if (pBuffer == NULL)
	{
		ZwClose(FileHandle);
		return 0;
	}

	// 从头开始读取文件
	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = 0;
	byteOffset.HighPart = 0;
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(FileHandle);
		return 0;
	}

	// 取出导出表
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	ULONGLONG FileOffset;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;

	// DLL内存数据转成DOS头结构
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;

	// 取出PE头结构
	pNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)pBuffer + pDosHeader->e_lfanew);

	// 判断PE头导出表表是否为空
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		return 0;
	}

	// 取出导出表偏移
	FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	// 取出节头结构
	pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;

	// 遍历节结构进行地址运算
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}

	// 导出表地址
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pBuffer + FileOffset);

	// 取出导出表函数地址
	PULONG AddressOfFunctions;
	FileOffset = pExportDirectory->AddressOfFunctions;

	// 遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}

	// 此处需要注意foa和rva转换过程
	AddressOfFunctions = (PULONG)((ULONGLONG)pBuffer + FileOffset);

	// 取出导出表函数名字
	PUSHORT AddressOfNameOrdinals;
	FileOffset = pExportDirectory->AddressOfNameOrdinals;

	// 遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}

	// 此处需要注意foa和rva转换过程
	AddressOfNameOrdinals = (PUSHORT)((ULONGLONG)pBuffer + FileOffset);

	// 取出导出表函数序号
	PULONG AddressOfNames;
	FileOffset = pExportDirectory->AddressOfNames;

	// 遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}

	// 此处需要注意foa和rva转换过程
	AddressOfNames = (PULONG)((ULONGLONG)pBuffer + FileOffset);

	// 分析导出表
	ULONG uNameOffset;
	ULONG uOffset;
	LPSTR FunName;
	PVOID pFuncAddr;
	ULONG uServerIndex;
	ULONG uAddressOfNames;

	for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++)
	{
		uAddressOfNames = *AddressOfNames;
		pSectionHeader = pOldSectionHeader;
		for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
		{
			if (pSectionHeader->VirtualAddress <= uAddressOfNames && uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			{
				uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
			}
		}

		FunName = (LPSTR)((ULONGLONG)pBuffer + uOffset);

		// 判断开头是否是Zw
		if (FunName[0] == 'Z' && FunName[1] == 'w')
		{
			pSectionHeader = pOldSectionHeader;

			// 如果是则根据AddressOfNameOrdinals得到文件偏移
			uOffset = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];

			for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
			{
				if (pSectionHeader->VirtualAddress <= uOffset && uOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
				{
					uNameOffset = uOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
				}
			}

			pFuncAddr = (PVOID)((ULONGLONG)pBuffer + uNameOffset);
			uServerIndex = *(PULONG)((ULONGLONG)pFuncAddr + 4);
			FunName[0] = 'N';
			FunName[1] = 't';

			// 获得指定的编号
			if (!_stricmp(FunName, (const char*)function_name))
			{
				ExFreePoolWithTag(pBuffer, (ULONG)"Ntdl");
				ZwClose(FileHandle);
				return uServerIndex;
			}
		}
	}

	ExFreePoolWithTag(pBuffer, (ULONG)"Ntdl");
	ZwClose(FileHandle);
	return 0;
}

// 获取模块导出函数
PVOID GetModuleExportAddress(IN PVOID ModuleBase, IN PCCHAR FunctionName, IN PEPROCESS EProcess)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	PIMAGE_NT_HEADERS32 ImageNtHeaders32 = NULL;
	PIMAGE_NT_HEADERS64 ImageNtHeaders64 = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = NULL;
	ULONG ExportDirectorySize = 0;
	ULONG_PTR FunctionAddress = 0;

	if (ModuleBase == NULL)
	{
		return NULL;
	}

	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	ImageNtHeaders32 = (PIMAGE_NT_HEADERS32)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);
	ImageNtHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);

	// 判断PE结构位数
	if (ImageNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
		ExportDirectorySize = ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	else
	{
		ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
		ExportDirectorySize = ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	// 解析内存导出表
	PUSHORT pAddressOfOrds = (PUSHORT)(ImageExportDirectory->AddressOfNameOrdinals + (ULONG_PTR)ModuleBase);
	PULONG  pAddressOfNames = (PULONG)(ImageExportDirectory->AddressOfNames + (ULONG_PTR)ModuleBase);
	PULONG  pAddressOfFuncs = (PULONG)(ImageExportDirectory->AddressOfFunctions + (ULONG_PTR)ModuleBase);

	for (ULONG i = 0; i < ImageExportDirectory->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR  pName = NULL;

		// 如果函数名小于等于0xFFFF 则说明是序号导出
		if ((ULONG_PTR)FunctionName <= 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}

		// 否则则说明是名字导出
		else if ((ULONG_PTR)FunctionName > 0xFFFF && i < ImageExportDirectory->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)ModuleBase);
			OrdIndex = pAddressOfOrds[i];
		}

		// 未知导出函数
		else
		{
			return NULL;
		}

		// 对比模块名是否是我们所需要的
		if (((ULONG_PTR)FunctionName <= 0xFFFF && (USHORT)((ULONG_PTR)FunctionName) == OrdIndex + ImageExportDirectory->Base) || ((ULONG_PTR)FunctionName > 0xFFFF && strcmp(pName, FunctionName) == 0))
		{
			// 是则保存下来
			FunctionAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)ModuleBase;
			break;
		}
	}
	return (PVOID)FunctionAddress;
}

// 获取指定用户模块基址
PVOID GetUserModuleAddress(IN PEPROCESS EProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN IsWow64)
{
	if (EProcess == NULL)
	{
		return NULL;
	}

	__try
	{
		// 定时250ms毫秒
		LARGE_INTEGER Time = { 0 };
		Time.QuadPart = -250ll * 10 * 1000;

		// 32位执行
		if (IsWow64)
		{
			// 得到进程PEB进程环境块
			PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(EProcess);
			if (Peb32 == NULL)
			{
				return NULL;
			}

			// 等待 250ms * 10
			for (INT i = 0; !Peb32->Ldr && i < 10; i++)
			{
				// 等待一会在执行
				KeDelayExecutionThread(KernelMode, TRUE, &Time);
			}

			// 没有找到返回空
			if (!Peb32->Ldr)
			{
				return NULL;
			}

			// 搜索 InLoadOrderModuleList
			for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList.Flink; ListEntry != &((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList; ListEntry = (PLIST_ENTRY32)ListEntry->Flink)
			{
				UNICODE_STRING UnicodeString;
				PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry32 = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
				RtlUnicodeStringInit(&UnicodeString, (PWCH)LdrDataTableEntry32->BaseDllName.Buffer);

				// 判断模块名是否符合要求
				if (RtlCompareUnicodeString(&UnicodeString, ModuleName, TRUE) == 0)
				{
					// 符合则返回模块基址
					return (PVOID)LdrDataTableEntry32->DllBase;
				}
			}
		}

		// 64位执行
		else
		{
			// 得到进程PEB进程环境块
			PPEB Peb = PsGetProcessPeb(EProcess);
			if (!Peb)
			{
				return NULL;
			}

			// 等待
			for (INT i = 0; !Peb->Ldr && i < 10; i++)
			{
				// 将当前线程置于指定间隔的可警报或不可操作的等待状态
				KeDelayExecutionThread(KernelMode, TRUE, &Time);
			}
			if (!Peb->Ldr)
			{
				return NULL;
			}

			// 遍历链表
			for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink; ListEntry != &Peb->Ldr->InLoadOrderModuleList; ListEntry = ListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY64 LdrDataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);

				// 判断模块名是否符合要求
				if (RtlCompareUnicodeString(&LdrDataTableEntry->BaseDllName, ModuleName, TRUE) == 0)
				{
					// 返回模块基址
					return LdrDataTableEntry->DllBase;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	return NULL;
}

//得到ntos的基址
ULONGLONG GetOsBaseAddress(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING osName = { 0 };
	WCHAR wzData[0x100] = L"ntoskrnl.exe";

	RtlInitUnicodeString(&osName, wzData);

	LDR_DATA_TABLE_ENTRY64* pDataTableEntry, * pTempDataTableEntry;

	// 双循环链表定义
	PLIST_ENTRY pList;

	// 指向驱动对象的DriverSection
	pDataTableEntry = (LDR_DATA_TABLE_ENTRY64*)pDriverObject->DriverSection;

	// 判断是否为空
	if (!pDataTableEntry)
	{
		return 0;
	}

	// 得到链表地址
	pList = pDataTableEntry->InLoadOrderLinks.Flink;

	// 判断是否等于头部
	while (pList != &pDataTableEntry->InLoadOrderLinks)
	{
		pTempDataTableEntry = (LDR_DATA_TABLE_ENTRY64*)pList;

		// 如果是ntoskrnl.exe则返回该模块基址
		if (RtlEqualUnicodeString(&pTempDataTableEntry->BaseDllName, &osName, TRUE))
		{
			return (ULONGLONG)pTempDataTableEntry->DllBase;
		}
		pList = pList->Flink;
	}
	return 0;
}

// 得到SSDT表的基地址
ULONGLONG GetKeServiceDescriptorTable64(PDRIVER_OBJECT DriverObject)
{

	/*
	nt!KiSystemServiceUser+0xdc:
	fffff806`42c79987 8bf8            mov     edi,eax
	fffff806`42c79989 c1ef07          shr     edi,7
	fffff806`42c7998c 83e720          and     edi,20h
	fffff806`42c7998f 25ff0f0000      and     eax,0FFFh

	nt!KiSystemServiceRepeat:
	fffff806`42c79994 4c8d15e59e3b00  lea     r10,[nt!KeServiceDescriptorTable (fffff806`43033880)]
	fffff806`42c7999b 4c8d1dde203a00  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff806`4301ba80)]
	fffff806`42c799a2 f7437880000000  test    dword ptr [rbx+78h],80h
	fffff806`42c799a9 7413            je      nt!KiSystemServiceRepeat+0x2a (fffff806`42c799be)
	*/
	//char KiSystemServiceStart_pattern[14] = "\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00";

	unsigned char KiSystemServiceStart_pattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };

	/*
	ULONG rva = GetRvaFromModule(L"\\SystemRoot\\system32\\ntoskrnl.exe", "_stricmp");
	DbgPrint("NtReadFile VA = %p \n", rva);
	ULONG _stricmp_offset = 0x19d710;
	*/

	ULONGLONG CodeScanStart = GetSSDTRVA((UCHAR*)"_stricmp") + GetOsBaseAddress(DriverObject);

	ULONGLONG i, tbl_address, b;
	for (i = 0; i < 0x50000; i++)
	{
		// 比较特征
		if (!memcmp((char*)(ULONGLONG)CodeScanStart + i, (char*)KiSystemServiceStart_pattern, 13))
		{
			for (b = 0; b < 50; b++)
			{
				tbl_address = ((ULONGLONG)CodeScanStart + i + b);

				// 4c 8d 15 e5 9e 3b 00  lea r10,[nt!KeServiceDescriptorTable (fffff802`64da4880)]
				// if (*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x158d4c)
				if (*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x8d4c)
				{
					return ((LONGLONG)tbl_address + 7) + *(LONG*)(tbl_address + 3);
				}
			}
		}
	}
	return 0;
}

// 根据SSDT序号得到函数基址
ULONGLONG GetSSDTFuncCurAddr(ULONG index)
{
	/*
	mov rax, rcx                   ; rcx=Native API 的 index
	lea r10,[rdx]                  ; rdx=ssdt 基址
	mov edi,eax                    ; index
	shr edi,7
	and edi,20h
	mov r10, qword ptr [r10+rdi]   ; ServiceTableBase
	movsxd r11,dword ptr [r10+rax] ; 没有右移的假ssdt的地址
	mov rax,r11
	sar r11,4
	add r10,r11
	mov rax,r10
	ret
	*/
	LONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ServiceTableBase[index];

	// 先右移4位之后加上基地址 就可以得到ssdt的地址
	dwtmp = dwtmp >> 4;

	return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
}

// 根据进程ID返回进程EPROCESS
PEPROCESS LookupProcess(HANDLE Pid)
{
	PEPROCESS eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess)))
	{
		return eprocess;
	}
	else
	{
		return NULL;
	}
}

// 根据用户传入进程名得到该进程PID
HANDLE GetProcessID(PCHAR ProcessName)
{
	ULONG i = 0;
	PEPROCESS eproc = NULL;
	for (i = 4; i < 100000000; i = i + 4)
	{
		eproc = LookupProcess((HANDLE)i);
		if (eproc != NULL)
		{
			ObDereferenceObject(eproc);

			// 根据进程名得到进程EPEPROCESS
			if (strstr((const char*)PsGetProcessImageFileName(eproc), ProcessName) != NULL)
			{
				return PsGetProcessId(eproc);
			}
		}
	}
	return NULL;
}

// -----------------------------------------------------------------------------------
// 注入代码生成函数
// -----------------------------------------------------------------------------------

// 创建64位注入代码
PINJECT_BUFFER GetNative64Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllFullPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER InjectBuffer = NULL;
	SIZE_T Size = PAGE_SIZE;

	UCHAR Code[] = {
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
		0x48, 0x31, 0xC9,                       // xor rcx, rcx
		0x48, 0x31, 0xD2,                       // xor rdx, rdx
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +28
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
		0xFF, 0xD0,                             // call rax
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +44
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE 
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +60
		0x89, 0x02,                             // mov [rdx], eax
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
		0xC3                                    // ret
	};

	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&InjectBuffer, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{
		PUNICODE_STRING UserPath = &InjectBuffer->Path64;
		UserPath->Length = 0;
		UserPath->MaximumLength = sizeof(InjectBuffer->Buffer);
		UserPath->Buffer = InjectBuffer->Buffer;

		RtlUnicodeStringCopy(UserPath, DllFullPath);

		// Copy code
		memcpy(InjectBuffer, Code, sizeof(Code));

		// Fill stubs
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 12) = (ULONGLONG)UserPath;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 22) = (ULONGLONG)&InjectBuffer->ModuleHandle;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 32) = (ULONGLONG)LdrLoadDll;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 44) = (ULONGLONG)&InjectBuffer->Complete;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 60) = (ULONGLONG)&InjectBuffer->Status;

		return InjectBuffer;
	}

	UNREFERENCED_PARAMETER(DllFullPath);
	return NULL;
}

// 创建32位注入代码
PINJECT_BUFFER GetNative32Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllFullPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER InjectBuffer = NULL;
	SIZE_T Size = PAGE_SIZE;

	// Code
	UCHAR Code[] = {
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
		0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +6
		0x6A, 0,                                // push Flags  
		0x6A, 0,                                // push PathToFile
		0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +15
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [edx], CALL_COMPLETE     
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +31
		0x89, 0x02,                             // mov [edx], eax
		0xC2, 0x04, 0x00                        // ret 4
	};

	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&InjectBuffer, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{
		// Copy path
		PUNICODE_STRING32 pUserPath = &InjectBuffer->Path32;
		pUserPath->Length = DllFullPath->Length;
		pUserPath->MaximumLength = DllFullPath->MaximumLength;
		pUserPath->Buffer = (ULONG)(ULONG_PTR)InjectBuffer->Buffer;

		// Copy path
		memcpy((PVOID)pUserPath->Buffer, DllFullPath->Buffer, DllFullPath->Length);

		// Copy code
		memcpy(InjectBuffer, Code, sizeof(Code));

		// Fill stubs
		*(ULONG*)((PUCHAR)InjectBuffer + 1) = (ULONG)(ULONG_PTR)&InjectBuffer->ModuleHandle;
		*(ULONG*)((PUCHAR)InjectBuffer + 6) = (ULONG)(ULONG_PTR)pUserPath;
		*(ULONG*)((PUCHAR)InjectBuffer + 15) = (ULONG)((ULONG_PTR)LdrLoadDll - ((ULONG_PTR)InjectBuffer + 15) - 5 + 1);
		*(ULONG*)((PUCHAR)InjectBuffer + 20) = (ULONG)(ULONG_PTR)&InjectBuffer->Complete;
		*(ULONG*)((PUCHAR)InjectBuffer + 31) = (ULONG)(ULONG_PTR)&InjectBuffer->Status;

		return InjectBuffer;
	}

	UNREFERENCED_PARAMETER(DllFullPath);
	return NULL;
}

// -----------------------------------------------------------------------------------
// 启动子线程函数(注入函数)
// -----------------------------------------------------------------------------------

// 启动线程
NTSTATUS NTAPI SeCreateThreadEx(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID StartAddress, IN PVOID Parameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList)
{
	NTSTATUS Status = STATUS_SUCCESS;

	// 根据字符串NtCreateThreadEx得到下标,并通过下标查询SSDT函数地址
	LPFN_NTCREATETHREADEX NtCreateThreadEx = (LPFN_NTCREATETHREADEX)(GetSSDTFuncCurAddr(GetIndexByName((UCHAR*)"NtCreateThreadEx")));
	DbgPrint("线程函数地址: %p --> 开始执行地址: %p \n", NtCreateThreadEx, StartAddress);

	if (NtCreateThreadEx)
	{
		// 如果之前的模式是用户模式，地址传递到ZwCreateThreadEx必须在用户模式空间
		// 切换到内核模式允许使用内核模式地址
		/*
		dt !_KTHREAD
		+0x1c8 Win32Thread      : Ptr64 Void
		+ 0x140 WaitBlockFill11 : [176] UChar
		+ 0x1f0 Ucb : Ptr64 _UMS_CONTROL_BLOCK
		+ 0x232 PreviousMode : Char
		*/

		// Windows10 PreviousMode = 0x232
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + 0x232;

		// 64位 pPrevMode = 01
		UCHAR prevMode = *pPrevMode;

		// 内核模式
		*pPrevMode = KernelMode;

		// 创建线程
		Status = NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartAddress, Parameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, AttributeList);

		// 恢复之前的线程模式
		*pPrevMode = prevMode;
	}
	else
	{
		Status = STATUS_NOT_FOUND;
	}
	return Status;
}

// 执行线程
NTSTATUS ExecuteInNewThread(IN PVOID BaseAddress, IN PVOID Parameter, IN ULONG Flags, IN BOOLEAN Wait, OUT PNTSTATUS ExitStatus)
{
	HANDLE ThreadHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

	// 初始化对象属性
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	// 创建线程
	NTSTATUS Status = SeCreateThreadEx(&ThreadHandle, THREAD_QUERY_LIMITED_INFORMATION, &ObjectAttributes, ZwCurrentProcess(), BaseAddress, Parameter, Flags, 0, 0x1000, 0x100000, NULL);
	// 等待线程完成
	if (NT_SUCCESS(Status) && Wait != FALSE)
	{
		// 延迟 60s
		LARGE_INTEGER Timeout = { 0 };
		Timeout.QuadPart = -(60ll * 10 * 1000 * 1000);

		Status = ZwWaitForSingleObject(ThreadHandle, TRUE, &Timeout);
		if (NT_SUCCESS(Status))
		{
			// 查询线程退出码
			THREAD_BASIC_INFORMATION ThreadBasicInfo = { 0 };
			ULONG ReturnLength = 0;

			Status = ZwQueryInformationThread(ThreadHandle, ThreadBasicInformation, &ThreadBasicInfo, sizeof(ThreadBasicInfo), &ReturnLength);

			if (NT_SUCCESS(Status) && ExitStatus)
			{
				// 这里是查询当前的dll是否注入成功
				*ExitStatus = ThreadBasicInfo.ExitStatus;
			}
			else if (!NT_SUCCESS(Status))
			{
				DbgPrint("%s: ZwQueryInformationThread failed with status 0x%X\n", __FUNCTION__, Status);
			}
		}
		else
		{
			DbgPrint("%s: ZwWaitForSingleObject failed with status 0x%X\n", __FUNCTION__, Status);
		}
	}
	else
	{
		DbgPrint("%s: ZwCreateThreadEx failed with status 0x%X\n", __FUNCTION__, Status);
	}

	if (ThreadHandle)
	{
		ZwClose(ThreadHandle);
	}
	return Status;
}

// 切换到目标进程创建内核线程进行注入 (cr3切换)
NTSTATUS AttachAndInjectProcess(IN HANDLE ProcessID, PWCHAR DllPath32 = nullptr, PWCHAR DllPath64 = nullptr)
{
	PEPROCESS EProcess = NULL;
	KAPC_STATE ApcState;
	NTSTATUS Status = STATUS_SUCCESS;

	if (ProcessID == NULL)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}

	// 获取EProcess
	Status = PsLookupProcessByProcessId(ProcessID, &EProcess);
	if (Status != STATUS_SUCCESS)
	{
		return Status;
	}

	// 判断目标进程x86 or x64
	BOOLEAN IsWow64 = (PsGetProcessWow64Process(EProcess) != NULL) ? TRUE : FALSE;

	// 将当前线程连接到目标进程的地址空间
	KeStackAttachProcess((PRKPROCESS)EProcess, &ApcState);
	__try
	{
		PVOID NtdllAddress = NULL;
		PVOID LdrLoadDll = NULL;
		UNICODE_STRING NtdllUnicodeString = { 0 };
		UNICODE_STRING DllFullPath = { 0 };

		// 获取ntdll模块基地址
		RtlInitUnicodeString(&NtdllUnicodeString, L"Ntdll.dll");
		NtdllAddress = GetUserModuleAddress(EProcess, &NtdllUnicodeString, IsWow64);
		if (!NtdllAddress)
		{
			Status = STATUS_NOT_FOUND;
		}

		// 获取LdrLoadDll
		if (NT_SUCCESS(Status))
		{
			LdrLoadDll = GetModuleExportAddress(NtdllAddress, "LdrLoadDll", EProcess);
			if (!LdrLoadDll)
			{
				Status = STATUS_NOT_FOUND;
			}
		}

		PINJECT_BUFFER InjectBuffer = NULL;
		if (IsWow64)
		{
			// 注入32位DLL
			RtlInitUnicodeString(&DllFullPath, DllPath32);
			InjectBuffer = GetNative32Code(LdrLoadDll, &DllFullPath);
			DbgPrint("[*] 注入32位DLL \n");
		}
		else
		{
			// 注入64位DLL
			RtlInitUnicodeString(&DllFullPath, DllPath64);
			InjectBuffer = GetNative64Code(LdrLoadDll, &DllFullPath);
			DbgPrint("[*] 注入64位DLL \n");
		}

		//创建线程,执行构造的 shellcode
		ExecuteInNewThread(InjectBuffer, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, TRUE, &Status);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("ExecuteInNewThread Failed\n");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = STATUS_UNSUCCESSFUL;
	}
	// 释放EProcess
	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(EProcess);
	return Status;
}