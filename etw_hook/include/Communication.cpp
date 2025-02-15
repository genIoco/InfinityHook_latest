#include "Communication.hpp"

Communication* Communication::__instance;

Communication* Communication::get_instance()
{
	if (!__instance) __instance = new Communication;
	return __instance;
}

NTSTATUS Communication::SendDataToUsermode(HANDLE dwTargetPid, DataUnion data)
{
	DbgPrint("SendDataToUsermode\r\n");
	return STATUS_SUCCESS;
}
