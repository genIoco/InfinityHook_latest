
#include <refs.hpp>
#include <etwhook_init.hpp>
#include <etwhook_manager.hpp>

#include <kstl/ksystem_info.hpp>

#include <syscall.hpp>
#include <Util.hpp>
#include <ntifs.h>

#include "Functions.hpp"
#include "Driver.hpp"
#include "Communication.hpp"

#include "lyshark.hpp"


#define InjectDllPath86 L"C:\\Users\\admin\\Desktop\\VS\\ProcessInjectionDection\\bin\\Release\\x86\\Dll.dll"
#define InjectDllPath64 L"C:\\Users\\admin\\Desktop\\VS\\ProcessInjectionDection\\bin\\Release\\x64\\Dll.dll"

#define EXECUTE_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

NTSTATUS detour_NtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength) {

	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		wchar_t* name = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t), 'lala');

		if (name)
		{
			RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

			if (wcsstr(name, L"oxygen.txt"))
			{
				ExFreePool(name);
				return STATUS_ACCESS_DENIED;
			}

			ExFreePool(name);
		}
	}


	return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, \
		IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, \
		CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


NTSTATUS detour_NtClose(HANDLE h) {

	//FLOG_INFO("ZwClose was Caguth\r\n");

	return NtClose(h);

}

NTSTATUS detour_NtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
) {
	NTSTATUS status = STATUS_SUCCESS;
	// 是否为自身内存分配
	if (ProcessHandle != (HANDLE)0xffffffffffffffff)
	{
		ULONG newflProtect = Protect;
		// 去除可执行权限

		if (Protect & PAGE_EXECUTE) newflProtect = PAGE_NOACCESS;
		if (Protect & PAGE_EXECUTE_READ) newflProtect = PAGE_READONLY;
		if (Protect & PAGE_EXECUTE_READWRITE) newflProtect = PAGE_READWRITE;
		if (Protect & PAGE_EXECUTE_WRITECOPY) newflProtect = PAGE_WRITECOPY;


		//FLOG_DEBUG("ProcessHandle: %p", ProcessHandle);
		HANDLE dwCurPid = PsGetCurrentProcessId();
		HANDLE dwTargetPid = 0;
		if (!NT_SUCCESS(GetPidFromHandle(ProcessHandle, &dwTargetPid))) {
			FLOG_ERROR("[NtAllocateVirtualMemory] GetPidFromHandle failed");
			return status;
		}

		// 是否为可疑远程内存分配
		if (!AreParentChildProcesses(dwCurPid, dwTargetPid))
		{
			PCHAR CurrentProcessName = GetProcessNameByProcessId(dwCurPid);
			PCHAR TargetProcessName = GetProcessNameByProcessId(dwTargetPid);
			//if (RtlCompareMemory(CurrentProcessName, "1.exe", strlen(CurrentProcessName)) == strlen(CurrentProcessName)) {
			// 去除可执行权限
			if (Protect != newflProtect) {
				status = NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, newflProtect);

				FLOG_INFO("[NtAllocateVirtualMemory] Change Protect to no execte(NtAllocateVirtualMemory).\n");
				FLOG_INFO("[NtAllocateVirtualMemory] %s[%d] ==> %s[%d],[addr:0x%p,%s => %s].\n", CurrentProcessName, dwCurPid, TargetProcessName, dwTargetPid, *BaseAddress, ProtectionString(Protect), ProtectionString(newflProtect));
				FLOG_INFO("[NtAllocateVirtualMemory] Status: %p.\n", status);
				// 附加执行注入
				FLOG_INFO("[NtAllocateVirtualMemory] Inject DLL.\n");
				AttachAndInjectProcess(dwTargetPid, InjectDllPath86, InjectDllPath64);

				return status;
			}
			else
			{
				status = NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
				FLOG_INFO("[NtAllocateVirtualMemory] %s[%d] ==> %s[%d],[addr:0x%p,%s => %s].\n", CurrentProcessName, dwCurPid, TargetProcessName, dwTargetPid, *BaseAddress, ProtectionString(Protect), ProtectionString(Protect));
				return status;
			}
		}
	}
	status = NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	return status;

}

NTSTATUS(*NtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten
	);

NTSTATUS detour_NtWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten
) {
	NTSTATUS status = STATUS_SUCCESS;
	// 是否为自身内存分配
	if (ProcessHandle != (HANDLE)0xffffffffffffffff)
	{
		//LOG_DEBUG("ProcessHandle: %p", ProcessHandle);
		HANDLE dwCurPid = PsGetCurrentProcessId();
		HANDLE dwTargetPid = 0;
		if (!NT_SUCCESS(GetPidFromHandle(ProcessHandle, &dwTargetPid))) {
			FLOG_ERROR("[NtWriteVirtualMemory] GetPidFromHandle failed");
			return status;
		}
		// 是否为可疑远程内存分配
		if (!AreParentChildProcesses(dwCurPid, dwTargetPid))
		{
			PCHAR CurrentProcessName = GetProcessNameByProcessId(dwCurPid);
			PCHAR TargetProcessName = GetProcessNameByProcessId(dwTargetPid);
			if (RtlCompareMemory(CurrentProcessName, "ProcessInjecti", strlen(CurrentProcessName)) == strlen(CurrentProcessName)) {
				status = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
				FLOG_INFO("[NtWriteVirtualMemory] %s[%d] ==> %s[%d],[addr:0x%p].\n", CurrentProcessName, dwCurPid, TargetProcessName, dwTargetPid, BaseAddress);
				//Communication::get_instance()->SendDataToUsermode(dwTargetPid, DataUnion{ BaseAddress });
				return status;
			}
			else
			{
				status = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
				FLOG_INFO("[NtWriteVirtualMemory] %s[%d] ==> %s[%d],[addr:0x%p].\n", CurrentProcessName, dwCurPid, TargetProcessName, dwTargetPid, BaseAddress);
				return status;
			}
		}
	}
	status = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
	return status;
}

NTSTATUS(*NtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T NumberOfBytesToProtect,
	_In_ ULONG NewAccessProtection,
	_Out_ PULONG OldAccessProtection
	);

NTSTATUS detour_NtProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T NumberOfBytesToProtect,
	_In_ ULONG NewAccessProtection,
	_Out_ PULONG OldAccessProtection
) {
	NTSTATUS status = STATUS_SUCCESS;
	// 是否为自身内存操作
	if (ProcessHandle != (HANDLE)0xffffffffffffffff)
	{
		HANDLE dwCurPid = PsGetCurrentProcessId();
		HANDLE dwTargetPid = 0;
		if (!NT_SUCCESS(GetPidFromHandle(ProcessHandle, &dwTargetPid))) {
			LOG_ERROR("[NtProtectVirtualMemory] GetPidFromHandle failed");
			return status;
		}

		// 是否为可疑远程内存操作
		if (!AreParentChildProcesses(dwCurPid, dwTargetPid))
		{
			PCHAR CurrentProcessName = GetProcessNameByProcessId(dwCurPid);
			PCHAR TargetProcessName = GetProcessNameByProcessId(dwTargetPid);

			// 检查是否添加了新的执行权限
			if ((NewAccessProtection & EXECUTE_FLAGS) && !(*OldAccessProtection & EXECUTE_FLAGS)) {
				// 去除执行权限
				ULONG newflProtect = (NewAccessProtection & ~EXECUTE_FLAGS);
				if (NewAccessProtection & PAGE_EXECUTE_READ) newflProtect |= PAGE_READONLY;
				if (NewAccessProtection & PAGE_EXECUTE_READWRITE) newflProtect |= PAGE_READWRITE;
				if (NewAccessProtection & PAGE_EXECUTE_WRITECOPY) newflProtect |= PAGE_WRITECOPY;
				if (NewAccessProtection == 0) {
					newflProtect = PAGE_READONLY; // 避免无权限
				}
				// 重设权限
				status = NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, newflProtect, OldAccessProtection);
				FLOG_INFO("[NtProtectVirtualMemory] Change Protect to no execte(NtProtectVirtualMemory)");
				FLOG_INFO("[NtProtectVirtualMemory] %s[%d] ==> %s[%d],[addr:0x%p,%s => %s].\n", CurrentProcessName, dwCurPid, TargetProcessName, dwTargetPid, *BaseAddress, ProtectionString(*OldAccessProtection), ProtectionString(newflProtect));
				FLOG_INFO("[NtAllocateVirtualMemory] Inject DLL.\n");
				AttachAndInjectProcess(dwTargetPid, InjectDllPath86, InjectDllPath64);

				return status;
			}
			else
			{
				status = NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
				FLOG_INFO("[NtProtectVirtualMemory] %s[%d] ==> %s[%d],[addr:0x%p,%s => %s].\n", CurrentProcessName, dwCurPid, TargetProcessName, dwTargetPid, *BaseAddress, ProtectionString(*OldAccessProtection), ProtectionString(NewAccessProtection));
				return status;
			}
		}
	}
	status = NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	return status;
}

NTSTATUS(*pNtQueryVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_writes_bytes_(MemoryInformationLength) MEMORY_BASIC_INFORMATION* MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
	);
NTSTATUS detour_NtQueryVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_writes_bytes_(MemoryInformationLength) MEMORY_BASIC_INFORMATION* MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
) {
	NTSTATUS status = STATUS_SUCCESS;
	// 是否为自身内存操作
	if (ProcessHandle != (HANDLE)0xffffffffffffffff)
	{
		HANDLE dwCurPid = PsGetCurrentProcessId();
		HANDLE dwTargetPid = 0;
		if (!NT_SUCCESS(GetPidFromHandle(ProcessHandle, &dwTargetPid))) {
			LOG_ERROR("[NtProtectVirtualMemory] GetPidFromHandle failed");
			return status;
		}

		// 是否为可疑远程内存操作
		if (!AreParentChildProcesses(dwCurPid, dwTargetPid))
		{
			PCHAR CurrentProcessName = GetProcessNameByProcessId(dwCurPid);
			PCHAR TargetProcessName = GetProcessNameByProcessId(dwTargetPid);

			status = pNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
			MemoryInformation->Protect = PAGE_EXECUTE_READWRITE;
			FLOG_INFO("Return Protect to PAGE_EXECUTE_READWRITE(NtQueryVirtualMemory)");
			FLOG_INFO("[NtQueryVirtualMemory] %s[%d] ==> %s[%d],[addr:0x%p,%s].\n", CurrentProcessName, dwCurPid, TargetProcessName, dwTargetPid, BaseAddress, ProtectionString(MemoryInformation->Protect));
			return status;
		}
	}
	status = pNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	return status;
}

NTSTATUS(*pNtMapViewOfSection)(
	_In_ HANDLE SectionHandle,
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset,
	_Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
	);

NTSTATUS detour_NtMapViewOfSection(
	_In_ HANDLE SectionHandle,
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset,
	_Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
) {
	NTSTATUS status = STATUS_SUCCESS;
	status = pNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
	return status;
}

NTSTATUS(*pNtMapViewOfSectionEx)(
	_In_ HANDLE SectionHandle,
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset,
	_Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect,
	_In_ ULONG Win32Protect
	);

NTSTATUS detour_NtMapViewOfSectionEx(
	_In_ HANDLE SectionHandle,
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset,
	_Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect,
	_In_ ULONG Win32Protect
) {
	NTSTATUS status = STATUS_SUCCESS;
	status = pNtMapViewOfSectionEx(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect, Win32Protect);
	return status;
}

// 驱动绑定默认派遣函数
NTSTATUS DispatchDefault(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}

// IRP_MJ_CREATE 对应的处理例程，一般不用管它
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("[kernel] 驱动处理例程载入 \n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_CLOSE 对应的处理例程，一般不用管它
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("[kernel] # 关闭派遣 \n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_READ 对应的处理例程，用于读取内核层数据
NTSTATUS DispatchRead(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	//缓冲区长度
	ULONG len = stack->Parameters.Read.Length;

	ULONG count = 0;

	NT_ASSERT(pIrp->MdlAddress);

	//获取缓冲区地址
	//此函数返回MdlAddress描述的缓冲区非分页系统虚拟机地址
	UCHAR* buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	if (!buffer) {
		DbgPrint(("[kernel] 获取缓冲区非分页虚拟地址失败。\n"));
		return STATUS_UNSUCCESSFUL;
	}

	ExAcquireFastMutex(&global.Mutex);

	//一次性将链表中的内容读出来
	while (1) {

		if (IsListEmpty(&global.Header)) break;

		PLIST_ENTRY entry = RemoveHeadList(&global.Header);//去除第一个

		Item* info = CONTAINING_RECORD(entry, Item, Entry);//找到Item结构体地址

		ULONG size = sizeof(ThreadData);

		if (len < size) {

			//如果缓冲区长度不够 就将原数据插回去 然后在退出
			InsertTailList(&global.Header, entry);
			break;
		}

		global.ItemCount--;

		//复制到缓冲区
		memcpy(buffer, &info->Data, size);

		buffer += size;

		len -= size;

		count += size;

		ExFreePool(info);

	}

	ExReleaseFastMutex(&global.Mutex);
	//向用户进程响应请求完成的代码
	pIrp->IoStatus.Information = count;

	pIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// IRP_MJ_CONTROL 对应的处理例程，自定义通信
NTSTATUS DispatchControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	// 获取输入/输出缓冲区
	PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
	// 获取输入缓冲区数据长度
	ULONG ulInputLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	// 获取输出缓冲区数据长度
	ULONG ulOutputLength = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
	// 实际输出数据长度
	ULONG ulInfo = 0;
	// 获取控制码
	ULONG ulControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	DbgPrint("[kernel] 接收到控制码（%02x）\n", ulControlCode);

	switch (ulControlCode)
	{
		break;
	}

	return status;
}

// SYSCALL HOOK函数
NTSTATUS HookSyscall(const char* SyscallName, void** org_syscall, void* detour_routine)
{
	SHORT SyscallNumber;
	if (!Syscall::GetNtSyscallNumber(&SyscallNumber, SyscallName)) {
		FLOG_INFO(("failed to find %s syscall number.\n"), SyscallName);
		return STATUS_UNSUCCESSFUL;
	}

	FLOG_INFO("%s syscall #: %hi\n", SyscallName, SyscallNumber);

	*org_syscall = Syscall::GetNtSyscallFunc((_SSDT*)KeServiceDescriptorTable, SyscallNumber);
	FLOG_INFO("%s: < ? dml ? ><exec cmd = \"ln %p\">0x%p</exec>\n", SyscallName, *org_syscall, *org_syscall);
	FLOG_INFO("Hooking %s syscall\n", SyscallName);


	EtwHookManager::get_instance()->add_hook(*org_syscall, detour_routine);
	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING symLink;

	DbgPrint("[kernel] 驱动卸载.\r\n");
	RtlInitUnicodeString(&symLink, LINK_NAME);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(pDriverObject->DeviceObject);

	//清除整个链表
	while (!IsListEmpty(&global.Header)) {
		PLIST_ENTRY item = RemoveHeadList(&global.Header);
		Item* fullitem = CONTAINING_RECORD(item, Item, Entry);
		ExFreePool(fullitem);
	}
	EtwHookManager::get_instance()->destory();
	kstd::Logger::destory();
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING)
{
	auto status = STATUS_SUCCESS;


	kstd::Logger::init("etw_hook", L"\\??\\C:\\log.txt");

	FLOG_INFO("init...\r\n");
	pDriverObject->DriverUnload = UnloadDriver;

	//// 获取SSDT表基址
	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable64(pDriverObject);
	FLOG_INFO("SSDT: <?dml?><exec cmd=\"ln %p\">0x%p</exec>\n", KeServiceDescriptorTable, KeServiceDescriptorTable);

	auto ssdt = Syscall::GetSSDT();
	if (!ssdt) {
		FLOG_INFO(("failed to find SSDT\n"));
	}

	status = EtwHookManager::get_instance()->init();

	//SHORT NtProtectVirtualMemorySyscallNumber;
	//if (!Syscall::GetNtSyscallNumber(&NtProtectVirtualMemorySyscallNumber, "NtProtectVirtualMemory")) {
	//	FLOG_INFO(("failed to find NtProtectVirtualMemory syscall number.\n"));
	//}

	//FLOG_INFO("NtProtectVirtualMemory syscall #: %hi.\n", NtProtectVirtualMemorySyscallNumber);


	//FLOG_INFO("SSDT: <?dml?><exec cmd=\"ln %p\">0x%p</exec>.\n", ssdt, ssdt);
	//NtProtectVirtualMemory = (decltype(NtProtectVirtualMemory))Syscall::GetNtSyscallFunc(ssdt, NtProtectVirtualMemorySyscallNumber);
	//FLOG_INFO("NtProtectVirtualMemory: < ? dml ? ><exec cmd = \"ln %p\">0x%p</exec>.\n", NtProtectVirtualMemory, NtProtectVirtualMemory);


	//EtwHookManager::get_instance()->add_hook(NtCreateFile, detour_NtCreateFile);
	//EtwHookManager::get_instance()->add_hook(NtClose, detour_NtClose);
	//EtwHookManager::get_instance()->add_hook(NtAllocateVirtualMemory, detour_NtAllocateVirtualMemory);
	//EtwHookManager::get_instance()->add_hook(NtProtectVirtualMemory, detour_NtProtectVirtualMemory);

	void* ori_syscall = NtAllocateVirtualMemory;
	HookSyscall("NtAllocateVirtualMemory", &ori_syscall, detour_NtAllocateVirtualMemory);
	HookSyscall("NtProtectVirtualMemory", ((void**)&NtProtectVirtualMemory), detour_NtProtectVirtualMemory);
	HookSyscall("NtWriteVirtualMemory", ((void**)&NtWriteVirtualMemory), detour_NtWriteVirtualMemory);
	//HookSyscall("NtQueryVirtualMemory", ((void**)&pNtQueryVirtualMemory), detour_NtQueryVirtualMemory);
	//HookSyscall("NtMapViewOfSection", ((void**)&pNtMapViewOfSection), detour_NtMapViewOfSection);
	//HookSyscall("NtMapViewOfSectionEx", ((void**)&pNtMapViewOfSectionEx), detour_NtMapViewOfSectionEx);

	//创建设备对象
	DbgPrint("[kernel] 创建设备对象...\n");
	UNICODE_STRING DevName;
	UNICODE_STRING SymbolicLink;
	PDEVICE_OBJECT pDeviceObject;
	RtlInitUnicodeString(&DevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObject, sizeof(4096), &DevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(status)) {
		FLOG_INFO("[kernel] 设备对象创建失败 (0x%08X).\n", status);
		return status;
	}
	pDeviceObject->Flags |= DO_DIRECT_IO;

	//提供符号链接使得设备能够被用户态的调用者访问
	//下面创建了一个符号链接并将其与我们的设备对象连接起来
	DbgPrint("[kernel] 创建符号链接...\n");
	RtlInitUnicodeString(&SymbolicLink, LINK_NAME);
	status = IoCreateSymbolicLink(&SymbolicLink, &DevName);

	if (!NT_SUCCESS(status)) {
		FLOG_INFO("[kernel] 符号链接创建失败 (0x%08X).\n", status);
		//创建失败时 要销毁设备对象
		IoDeleteDevice(pDeviceObject);
		return status;
	}

	InitializeListHead(&global.Header);//初始化链表头 LIST_ENTRY结构的双向链表
	ExInitializeFastMutex(&global.Mutex);

	// 初始化默认分发例程
	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DbgPrint("[kernel] 初始化分发历程: %d \n", i);
		pDriverObject->MajorFunction[i] = DispatchDefault;
	}

	//指定Create 分发例程
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;

	//指定读设备对象的分发例程
	pDriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;

	//指定控制分发例程
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;

	return status;
}