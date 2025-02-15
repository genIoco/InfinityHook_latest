#pragma once
//#include <ntddk.h>
#include <ntifs.h>

/* Function中定义驱动功能实现，是驱动主体部分 */

// -----------------------------------------------------------------------------------
// 声明相关结构体
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
}Global;//全局变量

Global global;