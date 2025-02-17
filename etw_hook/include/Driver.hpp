// 定义符号链接，一般来说修改为驱动的名字即可
#define LOG_NAME 	  "etw_hook"
#define	FLOG_NAME		L"\\??\\C:\\log.txt"	
#define DEVICE_NAME        L"\\Device\\etw_hook"
#define LINK_NAME          L"\\DosDevices\\etw_hook"

// 定义驱动操作码
#define IOCTL_PIT_DEVICE_BASE 0x1000
#define IOCTL_PIT_FUNCTION_BASE 0x800
#define IOCTL_PIT_CODE(x) CTL_CODE(IOCTL_PIT_DEVICE_BASE, (IOCTL_PIT_FUNCTION_BASE + x), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PIT_TEST	IOCTL_PIT_CODE(0)
#define IOCTL_PIT_SET_PPL IOCTL_PIT_CODE(1)
#define IOCTL_PIT_GET_MEM_PAGE IOCTL_PIT_CODE(2)
