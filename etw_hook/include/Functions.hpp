#pragma once
//#include <ntddk.h>
#include <ntifs.h>

/* Function�ж�����������ʵ�֣����������岿�� */

// -----------------------------------------------------------------------------------
// ������ؽṹ��
// -----------------------------------------------------------------------------------

typedef struct {

	ULONG ThreadId;
	ULONG CreateProcessId;
	ULONG ParentProcessId;

}ThreadData;

typedef struct {
	LIST_ENTRY Entry;
	ThreadData Data;
}Item;

typedef struct {
	FAST_MUTEX Mutex;
	ULONG ItemCount;
	LIST_ENTRY Header;
}Global;//ȫ�ֱ���

Global global;