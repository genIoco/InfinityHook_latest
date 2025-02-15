
#pragma once
#include <ntifs.h>
#include <minwindef.h>
#include <etwhook_base.hpp>


// 发送数据类型
union DataUnion
{
	PVOID* BaseAddress;
};


class Communication :public EtwBase
{
public:
	// 获取单例
	static Communication* get_instance();

	void SendInit();
	void ReceiveInit();
	NTSTATUS SendDataToUsermode(HANDLE dwTargetPid, DataUnion data);
	NTSTATUS ReceiveDataFromUsermode();
private:
	Communication() {};
	~Communication();
	static Communication* __instance;
};