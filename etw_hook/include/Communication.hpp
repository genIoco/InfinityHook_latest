
#pragma once
#include <ntifs.h>
#include <minwindef.h>
#include <etwhook_base.hpp>


// ������������
union DataUnion
{
	PVOID* BaseAddress;
};


class Communication :public EtwBase
{
public:
	// ��ȡ����
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