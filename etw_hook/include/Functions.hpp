#pragma once
//#include <ntddk.h>
#include <ntifs.h>

/* Function中定义驱动功能实现，是驱动主体部分 */

// -----------------------------------------------------------------------------------
// 声明相关结构体
// -----------------------------------------------------------------------------------


// 定义可疑内存页结构体
typedef struct SusMemPageNode {
	PVOID lpAddr; // 内存页起始地址
	SIZE_T dwSize; // 内存页大小，单位字节
	DWORD  curflProtect; // 当前内存页权限
	DWORD  oriflProtect; // 原始内存页权限
	//TODO:可以内存页是否存在外部写入的情况，脏位
	BOOL DIRTY;
	HANDLE targetPid; // 目前进程 ID
	HANDLE initiatorPid; // 发起进程 ID

}SusMemPage, * PSusMemPage;


// 内存页链表节点
typedef struct {
	// 定义双向链表
	LIST_ENTRY Entry;
	SusMemPage Data;
}MemItem, * PMemItem;

// 每个进程的内存页链表
typedef struct {
	LIST_ENTRY Entry;        // 进程链表指针
	HANDLE targetPid;        // 进程 ID
	ULONG ItemCount;
	LIST_ENTRY MemPageHeader;  // 存储可疑内存页的双向链表
}ProcessItem, * PProcessItem;

typedef struct {
	FAST_MUTEX Mutex;
	ULONG ItemCount;
	LIST_ENTRY Header;
}Global;//全局变量

Global global;


//找到进程和内存页所对应的节点
PMemItem FindProcessAndMemNode(HANDLE processId, PVOID lpAddr)
{
	PLIST_ENTRY pEntry, pMemEntry;
	PProcessItem pProcessItem;
	PMemItem pMemItem;

	ExAcquireFastMutex(&global.Mutex);
	pEntry = global.Header.Flink;
	while (pEntry != &global.Header) {
		pProcessItem = CONTAINING_RECORD(pEntry, ProcessItem, Entry);
		if (pProcessItem->targetPid == processId) {
			pMemEntry = pProcessItem->MemPageHeader.Flink;
			while (pMemEntry != &pProcessItem->MemPageHeader) {
				pMemItem = CONTAINING_RECORD(pMemEntry, MemItem, Entry);
				if (pMemItem->Data.lpAddr == lpAddr)
				{
					ExReleaseFastMutex(&global.Mutex);
					return pMemItem;
				}
				pMemEntry = pMemEntry->Flink;
			}
			ExReleaseFastMutex(&global.Mutex);
			return NULL;
		}
		pEntry = pEntry->Flink;
	}
	ExReleaseFastMutex(&global.Mutex);
	return NULL;
}

// 找到进程所对应的节点
PProcessItem FindProcessNode(HANDLE ProcessId) {
	PLIST_ENTRY pEntry;
	PProcessItem pProcessNode = NULL;

	ExAcquireFastMutex(&global.Mutex);
	pEntry = global.Header.Flink;

	while (pEntry != &global.Header) {
		pProcessNode = CONTAINING_RECORD(pEntry, ProcessItem, Entry);
		if (pProcessNode->targetPid == ProcessId) {
			ExReleaseFastMutex(&global.Mutex);
			return pProcessNode;
		}
		pEntry = pEntry->Flink;
	}

	ExReleaseFastMutex(&global.Mutex);
	return NULL;
}

NTSTATUS PushItem(HANDLE ProcessId, LIST_ENTRY* entry) {
	PLIST_ENTRY pEntry;
	PProcessItem pProcessNode = NULL;

	ExAcquireFastMutex(&global.Mutex);

	//查找是否存在该进程
	pEntry = global.Header.Flink;

	while (pEntry != &global.Header) {
		pProcessNode = CONTAINING_RECORD(pEntry, ProcessItem, Entry);
		if (pProcessNode->targetPid == ProcessId) {
			break;
		}
		pEntry = pEntry->Flink;
	}

	if (pEntry == &global.Header) {
		//不存在则创建新的进程节点
		pProcessNode = (PProcessItem)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ProcessItem), 'Pit');
		if (pProcessNode == NULL) {
			ExReleaseFastMutex(&global.Mutex);
			return STATUS_UNSUCCESSFUL;
		}
		pProcessNode->targetPid = ProcessId;
		pProcessNode->ItemCount = 0;
		InitializeListHead(&pProcessNode->MemPageHeader);


		if (global.ItemCount > 1024) { //大于1024个就删除第一个添加的程序

			PLIST_ENTRY pitem = RemoveHeadList(&global.Header);
			//CONTAINING_RECORD 根据结构体成员变量的地址计算出结构体地址
			ExFreePool(CONTAINING_RECORD(pitem, ProcessItem, Entry));

			global.ItemCount--;

		}
		//插入新数据
		InsertTailList(&global.Header, &pProcessNode->Entry);
		global.ItemCount++;
	}

	if (pProcessNode->ItemCount > 1024) { //大于1024个就删除第一个添加的程序

		PLIST_ENTRY pitem = RemoveHeadList(&global.Header);
		//CONTAINING_RECORD 根据结构体成员变量的地址计算出结构体地址
		ExFreePool(CONTAINING_RECORD(pitem, ProcessItem, Entry));

		pProcessNode->ItemCount--;

	}
	pProcessNode->ItemCount++;
	InsertTailList(&pProcessNode->MemPageHeader, entry);
	ExReleaseFastMutex(&global.Mutex);
	return STATUS_SUCCESS;

}