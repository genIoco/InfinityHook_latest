#pragma once
//#include <ntddk.h>
#include <ntifs.h>

/* Function�ж�����������ʵ�֣����������岿�� */

// -----------------------------------------------------------------------------------
// ������ؽṹ��
// -----------------------------------------------------------------------------------


// ��������ڴ�ҳ�ṹ��
typedef struct SusMemPageNode {
	PVOID lpAddr; // �ڴ�ҳ��ʼ��ַ
	SIZE_T dwSize; // �ڴ�ҳ��С����λ�ֽ�
	DWORD  curflProtect; // ��ǰ�ڴ�ҳȨ��
	DWORD  oriflProtect; // ԭʼ�ڴ�ҳȨ��
	//TODO:�����ڴ�ҳ�Ƿ�����ⲿд����������λ
	BOOL DIRTY;
	HANDLE targetPid; // Ŀǰ���� ID
	HANDLE initiatorPid; // ������� ID

}SusMemPage, * PSusMemPage;


// �ڴ�ҳ����ڵ�
typedef struct {
	// ����˫������
	LIST_ENTRY Entry;
	SusMemPage Data;
}MemItem, * PMemItem;

// ÿ�����̵��ڴ�ҳ����
typedef struct {
	LIST_ENTRY Entry;        // ��������ָ��
	HANDLE targetPid;        // ���� ID
	ULONG ItemCount;
	LIST_ENTRY MemPageHeader;  // �洢�����ڴ�ҳ��˫������
}ProcessItem, * PProcessItem;

typedef struct {
	FAST_MUTEX Mutex;
	ULONG ItemCount;
	LIST_ENTRY Header;
}Global;//ȫ�ֱ���

Global global;


//�ҵ����̺��ڴ�ҳ����Ӧ�Ľڵ�
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

// �ҵ���������Ӧ�Ľڵ�
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

	//�����Ƿ���ڸý���
	pEntry = global.Header.Flink;

	while (pEntry != &global.Header) {
		pProcessNode = CONTAINING_RECORD(pEntry, ProcessItem, Entry);
		if (pProcessNode->targetPid == ProcessId) {
			break;
		}
		pEntry = pEntry->Flink;
	}

	if (pEntry == &global.Header) {
		//�������򴴽��µĽ��̽ڵ�
		pProcessNode = (PProcessItem)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ProcessItem), 'Pit');
		if (pProcessNode == NULL) {
			ExReleaseFastMutex(&global.Mutex);
			return STATUS_UNSUCCESSFUL;
		}
		pProcessNode->targetPid = ProcessId;
		pProcessNode->ItemCount = 0;
		InitializeListHead(&pProcessNode->MemPageHeader);


		if (global.ItemCount > 1024) { //����1024����ɾ����һ����ӵĳ���

			PLIST_ENTRY pitem = RemoveHeadList(&global.Header);
			//CONTAINING_RECORD ���ݽṹ���Ա�����ĵ�ַ������ṹ���ַ
			ExFreePool(CONTAINING_RECORD(pitem, ProcessItem, Entry));

			global.ItemCount--;

		}
		//����������
		InsertTailList(&global.Header, &pProcessNode->Entry);
		global.ItemCount++;
	}

	if (pProcessNode->ItemCount > 1024) { //����1024����ɾ����һ����ӵĳ���

		PLIST_ENTRY pitem = RemoveHeadList(&global.Header);
		//CONTAINING_RECORD ���ݽṹ���Ա�����ĵ�ַ������ṹ���ַ
		ExFreePool(CONTAINING_RECORD(pitem, ProcessItem, Entry));

		pProcessNode->ItemCount--;

	}
	pProcessNode->ItemCount++;
	InsertTailList(&pProcessNode->MemPageHeader, entry);
	ExReleaseFastMutex(&global.Mutex);
	return STATUS_SUCCESS;

}