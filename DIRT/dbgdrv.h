#pragma once

#include "global.h"

class DIRT::DebugDriver
{
	HANDLE                   hnd_debug_device;

	NTOPENPROCESSTOKEN       NtOpenProcessToken;
	NTADJUSTPRIVILEGESTOKEN  NtAdjustPrivilegesToken;
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
	NTCLOSE                  NtClose;

public:
	DebugDriver();
	~DebugDriver();

	bool IsDebugModeOn();
	bool EnableDebugPrivilege();

	bool ReadSystemMemory(_Out_ PVOID destination_address, PVOID source_address, size_t source_size);

private:
	bool   InitializeService(const char* ptr_service, const char* ptr_relative_path);
	bool   TerminateService(const char* ptr_service);
	HANDLE LoadDebugDriver(const PWCHAR ptr_device_symlink);
};

#define IOCTL_KD_PASS_THROUGH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_NEITHER, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN KernelDebuggerEnabled;
	BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef enum _SYSDBG_COMMAND {
	SysDbgQueryModuleInformation,
	SysDbgQueryTraceInformation,
	SysDbgSetTracepoint,
	SysDbgSetSpecialCall,
	SysDbgClearSpecialCalls,
	SysDbgQuerySpecialCalls,
	SysDbgBreakPoint,
	SysDbgQueryVersion,
	SysDbgReadVirtual,
	SysDbgWriteVirtual,
	SysDbgReadPhysical,
	SysDbgWritePhysical,
	SysDbgReadControlSpace,
	SysDbgWriteControlSpace,
	SysDbgReadIoSpace,
	SysDbgWriteIoSpace,
	SysDbgReadMsr,
	SysDbgWriteMsr,
	SysDbgReadBusData,
	SysDbgWriteBusData,
	SysDbgCheckLowMemory,
	SysDbgEnableKernelDebugger,
	SysDbgDisableKernelDebugger,
	SysDbgGetAutoKdEnable,
	SysDbgSetAutoKdEnable,
	SysDbgGetPrintBufferSize,
	SysDbgSetPrintBufferSize,
	SysDbgGetKdUmExceptionEnable,
	SysDbgSetKdUmExceptionEnable,
	SysDbgGetTriageDump,
	SysDbgGetKdBlockEnable,
	SysDbgSetKdBlockEnable,
	SysDbgRegisterForUmBreakInfo,
	SysDbgGetUmBreakPid,
	SysDbgClearUmBreakPid,
	SysDbgGetUmAttachPid,
	SysDbgClearUmAttachPid,
	SysDbgGetLiveKernelDump
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef struct _KLDBG {
	SYSDBG_COMMAND SysDbgRequest;
	PVOID OutputBuffer;
	DWORD OutputBufferSize;
} KLDBG, *PKLDBG;

typedef struct _SYSDBG_VIRTUAL {
	PVOID Address;
	PVOID Buffer;
	ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

#define SE_DEBUG_PRIVILEGE (20L)