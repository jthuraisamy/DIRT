#include "stdafx.h"
#include "dbgdrv.h"

#include <iostream>

DIRT::DebugDriver::DebugDriver()
{
	HMODULE hnd_module = LoadLibrary(_T("ntdll.dll"));
	NtOpenProcessToken = (NTOPENPROCESSTOKEN)GetProcAddress(hnd_module, "NtOpenProcessToken");
	NtAdjustPrivilegesToken = (NTADJUSTPRIVILEGESTOKEN)GetProcAddress(hnd_module, "NtAdjustPrivilegesToken");
	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hnd_module, "NtQuerySystemInformation");
	NtClose = (NTCLOSE)GetProcAddress(hnd_module, "NtClose");

	if (IsDebugModeOn())
	{
		EnableDebugPrivilege();
	}
	else
	{
		cerr << "ERROR: Debug mode is not on. Please enable it with bcdedit -debug on." << endl;
		exit(1);
	}
		

	bool is_service_terminated  = TerminateService("kldbgdrv");
	bool is_service_initialized = InitializeService("kldbgdrv", "C:\\Windows\\System32\\kldbgdrv.sys");

	//std::cout << "is_service_terminated  = " << is_service_terminated << std::endl;
	//std::cout << "is_service_initialized = " << is_service_initialized << std::endl;

	if (!is_service_initialized)
	{
		cerr << "ERROR: Could not load kldbgdrv.sys. Is another application using it?" << endl;
		exit(1);
	}

	hnd_debug_device = LoadDebugDriver(L"\\\\.\\kldbgdrv");
}

DIRT::DebugDriver::~DebugDriver()
{
	TerminateService("kldbgdrv");
}

bool DIRT::DebugDriver::IsDebugModeOn()
{
	SYSTEM_KERNEL_DEBUGGER_INFORMATION kd_info;
	RtlSecureZeroMemory(&kd_info, sizeof(kd_info));
	NtQuerySystemInformation(SystemKernelDebuggerInformation, &kd_info, sizeof(kd_info), NULL);
	return kd_info.KernelDebuggerEnabled;
}

bool DIRT::DebugDriver::EnableDebugPrivilege()
{
	NTSTATUS         status;
	HANDLE           hnd_token;
	TOKEN_PRIVILEGES token_privileges;

	status = NtOpenProcessToken(
		NtCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hnd_token
	);

	token_privileges.PrivilegeCount = 1;
	token_privileges.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
	token_privileges.Privileges[0].Luid.HighPart = 0;
	token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	status = NtAdjustPrivilegesToken(
		hnd_token,
		FALSE,
		&token_privileges,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		NULL
	);

	NtClose(hnd_token);

	return true;
}

bool DIRT::DebugDriver::InitializeService(const char* ptr_service, const char* ptr_relative_path)
{
	bool is_service_installed = FALSE;

	char ptr_full_path[MAX_PATH] = { 0 };
	_fullpath(ptr_full_path, ptr_relative_path, MAX_PATH);

	SC_HANDLE hnd_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (!hnd_manager)
		return FALSE;

	SC_HANDLE hnd_service = CreateServiceA(
		hnd_manager,
		ptr_service,
		ptr_service,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		ptr_full_path,
		NULL, NULL, NULL, NULL, NULL
	);

	if (hnd_service)
	{
		is_service_installed = StartServiceA(hnd_service, 0, NULL);
		CloseServiceHandle(hnd_service);
	}

	CloseServiceHandle(hnd_manager);

	return is_service_installed;
}

bool DIRT::DebugDriver::TerminateService(const char* ptr_service)
{
	bool is_service_removed = FALSE;

	SERVICE_STATUS_PROCESS ssp;
	DWORD bytes_needed;
	SC_HANDLE hnd_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (!hnd_manager)
		return FALSE;

	SC_HANDLE hnd_service = OpenServiceA(hnd_manager, ptr_service, SERVICE_ALL_ACCESS);

	if (hnd_service)
	{
		if (QueryServiceStatusEx(hnd_service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed))
		{
			ControlService(hnd_service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
			is_service_removed = DeleteService(hnd_service);
			CloseServiceHandle(hnd_service);
		}
	}

	CloseServiceHandle(hnd_manager);

	return is_service_removed;
}

HANDLE DIRT::DebugDriver::LoadDebugDriver(const PWCHAR ptr_device_symlink)
{
	HANDLE hDevice = CreateFile(
		ptr_device_symlink,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	return hDevice;
}

bool DIRT::DebugDriver::ReadSystemMemory(_Out_ PVOID destination_address, PVOID source_address, ULONG source_size)
{
	DWORD          bytes_returned = 0;
	KLDBG          kldbg;
	SYSDBG_VIRTUAL debug_request;

	// fill parameters for KdSystemDebugControl
	debug_request.Address = source_address;
	debug_request.Buffer = destination_address;
	debug_request.Request = source_size;

	// fill parameters for kldbgdrv ioctl
	kldbg.SysDbgRequest = SysDbgReadVirtual;
	kldbg.OutputBuffer = &debug_request;
	kldbg.OutputBufferSize = sizeof(SYSDBG_VIRTUAL);

	return DeviceIoControl(
		hnd_debug_device,
		IOCTL_KD_PASS_THROUGH,
		&kldbg,
		sizeof(kldbg),
		&debug_request,
		sizeof(debug_request),
		&bytes_returned,
		NULL
	);
}