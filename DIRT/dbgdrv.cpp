#include "stdafx.h"
#include "dbgdrv.h"

#include <iostream>

DIRT::DebugDriver::DebugDriver()
{
	HMODULE _hModule = LoadLibrary(_T("ntdll.dll"));
	NtOpenProcessToken = (NTOPENPROCESSTOKEN)GetProcAddress(_hModule, "NtOpenProcessToken");
	NtAdjustPrivilegesToken = (NTADJUSTPRIVILEGESTOKEN)GetProcAddress(_hModule, "NtAdjustPrivilegesToken");
	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(_hModule, "NtQuerySystemInformation");
	NtClose = (NTCLOSE)GetProcAddress(_hModule, "NtClose");

	enableDebugPrivilege();

	terminateService("kldbgdrv");
	initializeService("kldbgdrv", "kldbgdrv.sys");

	hDebugDevice = loadDebugDriver(L"\\\\.\\kldbgdrv");
}

DIRT::DebugDriver::~DebugDriver()
{
	terminateService("kldbgdrv");
}

bool DIRT::DebugDriver::isDebugModeOn()
{
	SYSTEM_KERNEL_DEBUGGER_INFORMATION kdInfo;
	RtlSecureZeroMemory(&kdInfo, sizeof(kdInfo));
	NtQuerySystemInformation(SystemKernelDebuggerInformation, &kdInfo, sizeof(kdInfo), NULL);
	return kdInfo.KernelDebuggerEnabled;
}

bool DIRT::DebugDriver::enableDebugPrivilege()
{
	NTSTATUS         status;
	HANDLE           hToken;
	TOKEN_PRIVILEGES TokenPrivileges;

	status = NtOpenProcessToken(
		NtCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken
	);

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
	TokenPrivileges.Privileges[0].Luid.HighPart = 0;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	status = NtAdjustPrivilegesToken(
		hToken,
		FALSE,
		&TokenPrivileges,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL, NULL
	);

	NtClose(hToken);

	return true;
}

bool DIRT::DebugDriver::initializeService(const char *szService, const char *szPath)
{
	bool isServiceInstalled = FALSE;

	char szFullPath[MAX_PATH] = { 0 };
	_fullpath(szFullPath, szPath, MAX_PATH);

	SC_HANDLE hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (!hManager)
		return FALSE;

	SC_HANDLE hService = CreateServiceA(
		hManager,
		szService,
		szService,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		szFullPath,
		NULL, NULL, NULL, NULL, NULL
	);

	if (hService)
	{
		isServiceInstalled = StartServiceA(hService, 0, NULL);
		CloseServiceHandle(hService);
	}

	CloseServiceHandle(hManager);

	return isServiceInstalled;
}

bool DIRT::DebugDriver::terminateService(const char *szService)
{
	bool isServiceRemoved = FALSE;

	SERVICE_STATUS_PROCESS ssp;
	DWORD dwBytesNeeded;
	SC_HANDLE hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (!hManager)
		return FALSE;

	SC_HANDLE hService = OpenServiceA(hManager, szService, SERVICE_ALL_ACCESS);

	if (hService)
	{
		if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
		{
			ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
			isServiceRemoved = DeleteService(hService);
			CloseServiceHandle(hService);
		}
	}

	CloseServiceHandle(hManager);

	return isServiceRemoved;
}

HANDLE DIRT::DebugDriver::loadDebugDriver(const PWCHAR deviceSymbolicLink)
{
	HANDLE hDevice = CreateFile(
		deviceSymbolicLink,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	return hDevice;
}

bool DIRT::DebugDriver::readSystemMemory(_Out_ PVOID destinationAddress, PVOID sourceAddress, size_t sourceSize)
{
	DWORD          bytesIO = 0;
	KLDBG          kldbg;
	SYSDBG_VIRTUAL dbgRequest;

	// fill parameters for KdSystemDebugControl
	dbgRequest.Address = sourceAddress;
	dbgRequest.Buffer = destinationAddress;
	dbgRequest.Request = sourceSize;

	// fill parameters for kldbgdrv ioctl
	kldbg.SysDbgRequest = SysDbgReadVirtual;
	kldbg.OutputBuffer = &dbgRequest;
	kldbg.OutputBufferSize = sizeof(SYSDBG_VIRTUAL);

	return DeviceIoControl(
		hDebugDevice,
		IOCTL_KD_PASS_THROUGH,
		&kldbg,
		sizeof(kldbg),
		&dbgRequest,
		sizeof(dbgRequest),
		&bytesIO,
		NULL
	);
}