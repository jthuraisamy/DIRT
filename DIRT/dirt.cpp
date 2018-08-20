// DIRT.cpp : Defines the entry point for the console application.
//

#pragma comment(lib, "ntdll.lib")

#include "stdafx.h"
#include "global.h"
#include "dirt.h"

#include <iostream>
#include <sstream>
#include <string>

DIRT::Main::Main()
{
	HMODULE hnd_module = LoadLibrary(_T("ntdll.dll"));

	NtOpenFile = (NTOPENFILE)GetProcAddress(hnd_module, "NtOpenFile");
	NtOpenDirectoryObject = (NTOPENDIRECTORYOBJECT)GetProcAddress(hnd_module, "NtOpenDirectoryObject");
	NtQueryDirectoryObject = (NTQUERYDIRECTORYOBJECT)GetProcAddress(hnd_module, "NtQueryDirectoryObject");
	NtOpenSymbolicLinkObject = (NTOPENSYMBOLICLINKOBJECT)GetProcAddress(hnd_module, "NtOpenSymbolicLinkObject");
	NtQuerySymbolicLinkObject = (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(hnd_module, "NtQuerySymbolicLinkObject");
	NtQuerySecurityObject = (NTQUERYSECURITYOBJECT)GetProcAddress(hnd_module, "NtQuerySecurityObject");
	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hnd_module, "NtQuerySystemInformation");
	NtClose = (NTCLOSE)GetProcAddress(hnd_module, "NtClose");
	RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(hnd_module, "RtlInitUnicodeString");
}

/// <summary>
/// Populate the m_drivers object.
/// </summary>
void DIRT::Main::PopulateDrivers()
{
	PopulateDevices();

	vector<POBJECT_DIRECTORY_INFORMATION> ptr_driver_objects = m_object_manager.GetDirectoryObjects(L"\\Driver");

	for (POBJECT_DIRECTORY_INFORMATION ptr_objdir_info : ptr_driver_objects)
	{
		if (wcscmp(ptr_objdir_info->TypeName.Buffer, L"Driver") == 0)
		{
			DRIVER driver;

			driver.ServiceName = ptr_objdir_info->Name.Buffer;
			driver.FilePath = m_object_manager.GetDriverFileName(driver.ServiceName);
			driver.ServiceConfig = GetDriverServiceConfig(driver.ServiceName);
			driver.IrpMjDeviceControl = m_object_manager.GetDriverMajorFunction(driver.ServiceName, IRP_MJ_DEVICE_CONTROL);

			wcerr << L"Querying driver: " << driver.ServiceName << setw(80) << "\r";
			wcerr.flush();
			
			for (DEVICE ptr_device : m_devices)
			{
				if (wcscmp(ptr_device.DriverServiceName, driver.ServiceName) == 0)
				{
					driver.Devices.push_back(ptr_device);
				}
			}

			m_drivers.push_back(driver);
		}
	}
}

void DIRT::Main::PopulateDevices()
{
	PopulateDevices(L"\\Device");
}

/// <summary>
/// Populate the m_devices object.
/// </summary>
/// <param name="ptr_directory_path">Path of the directory (e.g. "\\Device").</param>
void DIRT::Main::PopulateDevices(const PWCHAR ptr_directory_path)
{
	// Cache the symbolic links in \\Global??.
	vector<UNICODE_STRING> symbolic_links;
	HANDLE hnd_global_directory = m_object_manager.GetObjectDirectoryHandle(L"\\Global??");
	vector<POBJECT_DIRECTORY_INFORMATION> ptr_global_objects = m_object_manager.GetDirectoryObjects(L"\\Global??");
	for (POBJECT_DIRECTORY_INFORMATION ptr_objdir_info : ptr_global_objects)
		symbolic_links.push_back(ptr_objdir_info->Name);

	vector<POBJECT_DIRECTORY_INFORMATION> ptr_device_objects = m_object_manager.GetDirectoryObjects(ptr_directory_path);

	for (POBJECT_DIRECTORY_INFORMATION ptr_objdir_info : ptr_device_objects)
	{
		if (wcscmp(ptr_objdir_info->TypeName.Buffer, L"Directory") == 0)
		{
			// ToDo: recursive functionality for subdirectories.
		}
		else if (wcscmp(ptr_objdir_info->TypeName.Buffer, L"Device") == 0)
		{
			PTCHAR driver_service_name = m_object_manager.GetDriverServiceNameFromDevice(ptr_directory_path, ptr_objdir_info->Name.Buffer);

			if (driver_service_name == nullptr)
				continue;
			
			DEVICE device;

			device.DriverServiceName = driver_service_name;

			device.ObjectPath = (PTCHAR)malloc(MAX_PATH);
			swprintf(device.ObjectPath, MAX_PATH, L"%s\\%s", ptr_directory_path, ptr_objdir_info->Name.Buffer);
			wcerr << L"Querying device: " << device.ObjectPath << setw(80) << "\r";
			wcerr.flush();

			ULONG entry_count = 0;
			PEXPLICIT_ACCESS ptr_entries = nullptr;
			GetObjectDACL(device.ObjectPath, &ptr_entries, &entry_count);
			device.OpenDACL = IsObjectPubliclyWritable(&ptr_entries, entry_count);

			for (UNICODE_STRING symbolic_link : symbolic_links)
				if (wcscmp(device.ObjectPath, GetLinkTarget(hnd_global_directory, &symbolic_link)) == 0)
					device.SymbolicLinks.push_back(symbolic_link.Buffer);

			m_devices.push_back(device);
		}
	}
}

/// <summary>
/// Print out driver info in human readable format.
/// </summary>
/// <param name="is_lowpriv_accessible">True if low-priv users can create a handle.</param>
void DIRT::Main::ExportHumanReadable(const bool is_lowpriv_accessible)
{
	for (int i = 0; i < m_drivers.size(); i++)
	{
		DRIVER driver = m_drivers[i];

		//if (driver.Devices.size() == 0)
		//	continue;

		if (driver.ServiceConfig != nullptr)
			wcout << driver.ServiceName << ": " << driver.ServiceConfig->lpDisplayName << endl;
		else
			wcout << driver.ServiceName << endl;

		wcout << "Path: " << &driver.FilePath[4] << endl;
		
		if (driver.IrpMjDeviceControl == nullptr)
			wcout << "IRP_MJ_DEVICE_CONTROL: N/A" << endl;
		else
			wcout << "IRP_MJ_DEVICE_CONTROL: 0x" << hex << driver.IrpMjDeviceControl << endl;

		wcout << "Devices: " << driver.Devices.size() << endl;

		for (int j = 0; j < driver.Devices.size(); j++)
		{
			DEVICE device = driver.Devices[j];

			//if ((device.SymbolicLinks.size() == 0) || (device.OpenDACL == false))
			//	continue;

			if (j == driver.Devices.size() - 1)
				wcout << L"└── " << device.ObjectPath;
			else
				wcout << L"├── " << device.ObjectPath;

			wcout << " (" << (device.OpenDACL ? "open DACL" : "closed DACL") << ", " << device.SymbolicLinks.size() << " symlinks)" << endl;

			if (device.SymbolicLinks.size() > 0)
			{
				for (PTCHAR symbolic_link : device.SymbolicLinks)
				{
					if (j == driver.Devices.size() - 1)
						wcout << L"    └── " << L"\\\\.\\Global\\" << symbolic_link << endl;
					else
						wcout << L"│   └── " << L"\\\\.\\Global\\" << symbolic_link << endl;
				}
			}
		}

		wcout << endl;
	}
}

void DIRT::Main::ExportCSV()
{
	cout << "SymbolicLink,DeviceObjectPath,DriverObjectPath,DriverFilePath,DriverDescription,OpenDACL" << endl;

	vector<POBJECT_DIRECTORY_INFORMATION> ptr_global_objects = m_object_manager.GetDirectoryObjects(L"\\Global??");

	for (POBJECT_DIRECTORY_INFORMATION ptr_objdir_info : ptr_global_objects)
	{
		if (wcscmp(ptr_objdir_info->TypeName.Buffer, L"SymbolicLink") == 0)
		{
			// Print SymbolicLink.
			wcout << L"\\\\.\\Global\\" << ptr_objdir_info->Name.Buffer << ",";

			// Print DeviceObjectPath.
			HANDLE hnd_directory = m_object_manager.GetObjectDirectoryHandle(L"\\Global??");
			PWCHAR ptr_device_object_path = GetLinkTarget(hnd_directory, &ptr_objdir_info->Name);
			if (ptr_device_object_path != nullptr)
			{
				wcout << ptr_device_object_path << ",";

				// Print DriverObjectPath.
				PWCHAR ptr_device_object_name = &ptr_device_object_path[8];
				PWCHAR ptr_device_service_name = m_object_manager.GetDriverServiceNameFromDevice(L"\\Device", ptr_device_object_name);
				if (ptr_device_service_name != nullptr)
				{
					wcout << L"\\Driver\\" << ptr_device_service_name << ",";

					// Print DriverFilePath.
					PWCHAR ptr_driver_file_name = m_object_manager.GetDriverFileName(ptr_device_service_name);
					wcout << &ptr_driver_file_name[4] << ",";

					// Print DriverDescription.
					LPQUERY_SERVICE_CONFIG ptr_driver_service_config = GetDriverServiceConfig(ptr_device_service_name);
					
					if (ptr_driver_service_config != nullptr)
					{
						wcout << ptr_driver_service_config->lpDisplayName << ",";
					}
					else
					{
						wcout << ",,";
					}

					free(ptr_driver_file_name);
					free(ptr_driver_service_config);
				}
				else
				{
					wcout << ",,,";
				}

				// Print InsecureDACL.
				ULONG entry_count = 0;
				PEXPLICIT_ACCESS ptr_entries = nullptr;
				GetObjectDACL(ptr_device_object_path, &ptr_entries, &entry_count);
				wcout << IsObjectPubliclyWritable(&ptr_entries, entry_count) << endl;
			}
			else
			{
				wcout << ",,,," << endl;
			}
		}
	}
}

LPQUERY_SERVICE_CONFIG DIRT::Main::GetDriverServiceConfig(const PWCHAR ptr_driver_service_name)
{
	LPQUERY_SERVICE_CONFIG ptr_service_config = nullptr;
	SC_HANDLE hnd_sc_manager = NULL;
	SC_HANDLE hnd_sc_service = NULL;

	hnd_sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (hnd_sc_manager == NULL)
	{
		return nullptr;
	}

	hnd_sc_service = OpenService(hnd_sc_manager, ptr_driver_service_name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
	if (hnd_sc_service == NULL)
	{
		CloseServiceHandle(hnd_sc_manager);
		return nullptr;
	}

	// Get size of QUERY_SERVICE_CONFIG.
	DWORD bytes_needed = 0;
	QueryServiceConfig(hnd_sc_service, NULL, 0, &bytes_needed);

	// Populate pServiceConfig.
	ptr_service_config = (LPQUERY_SERVICE_CONFIG)malloc(bytes_needed);
	QueryServiceConfig(hnd_sc_service, ptr_service_config, bytes_needed, &bytes_needed);

	CloseServiceHandle(hnd_sc_service);
	CloseServiceHandle(hnd_sc_manager);

	return ptr_service_config;
}

bool DIRT::Main::IsObjectPubliclyWritable(PEXPLICIT_ACCESS* ptr_entries, const ULONG entry_count)
{
	PEXPLICIT_ACCESS ptr_entry = *ptr_entries;

	for (ULONG i = 0; i < entry_count; i++, ptr_entry++)
	{
		if (ptr_entry->Trustee.TrusteeForm == TRUSTEE_IS_SID)
		{
			DWORD sid_size = GetLengthSid((SID*)ptr_entry->Trustee.ptstrName);
			SID* sid = (SID*)malloc(sid_size);
			SID_NAME_USE snu;
			CopySid(sid_size, sid, (SID *)ptr_entry->Trustee.ptstrName);

			DWORD user_size = BUFSIZ - 1;
			DWORD domain_size = BUFSIZ - 1;
			WCHAR user_name[BUFSIZ] = { 0 };
			WCHAR domain_name[BUFSIZ] = { 0 };
			LookupAccountSid(NULL, sid, user_name, &user_size, domain_name, &domain_size, &snu);
			free(sid);

			if ((*domain_name == NULL) && (wcscmp(user_name, L"Everyone") == 0))
			{
				if ((ptr_entry->grfAccessMode == GRANT_ACCESS) && (ptr_entry->grfAccessPermissions & STANDARD_RIGHTS_WRITE))
				{
					return true;
				}
			}
		}
	}

	return false;
}

int DIRT::Main::GetObjectDACL(const PWCHAR ptr_path, _Out_ PEXPLICIT_ACCESS* ptr_entries, _Out_ PULONG ptr_entry_count)
{
	HANDLE hnd_object = NULL;
	IO_STATUS_BLOCK iosb = { 0 };

	PUNICODE_STRING ptr_path_us = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
	RtlSecureZeroMemory(ptr_path_us, sizeof(ptr_path_us));
	RtlInitUnicodeString(ptr_path_us, ptr_path);

	OBJECT_ATTRIBUTES object_attributes;
	InitializeObjectAttributes(&object_attributes, ptr_path_us, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS status = NtOpenFile(
		&hnd_object,
		READ_CONTROL,
		&object_attributes,
		&iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL
	);

	ULONG length = 0;
	PSECURITY_DESCRIPTOR ptr_security_descriptor = (PSECURITY_DESCRIPTOR)malloc(length);
	status = NtQuerySecurityObject(
		hnd_object,
		DACL_SECURITY_INFORMATION,
		ptr_security_descriptor,
		length,
		&length // Collect the actual length of the SECURITY_DESCRIPTOR first.
	);

	if (status == STATUS_BUFFER_TOO_SMALL)
	{
		ptr_security_descriptor = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 0, length);
		status = NtQuerySecurityObject(
			hnd_object,
			DACL_SECURITY_INFORMATION,
			ptr_security_descriptor,
			length, // Provide the actual length here.
			&length
		);
	}

	BOOL is_dacl_present = 0;
	PACL ptr_dacl = nullptr;
	BOOL is_dacl_defaulted = 0;
	status = GetSecurityDescriptorDacl(
		ptr_security_descriptor,
		&is_dacl_present,
		&ptr_dacl,
		&is_dacl_defaulted
	);

	GetExplicitEntriesFromAcl(
		ptr_dacl,
		ptr_entry_count,
		ptr_entries
	);

	return 0;
}

/// <summary>
/// Resolve target of provided symbolic link/path.
/// </summary>
/// <param name="hnd_root_directory">Use DIRT::ObjectManager::GetObjectDirectoryHandle for this.</param>
/// <param name="ptr_object_name"></param>
/// <returns></returns>
PWCHAR DIRT::Main::GetLinkTarget(const HANDLE hnd_root_directory, const PUNICODE_STRING ptr_object_name)
{
	OBJECT_ATTRIBUTES object_attributes;
	InitializeObjectAttributes(&object_attributes, ptr_object_name, OBJ_CASE_INSENSITIVE, hnd_root_directory, NULL);

	HANDLE hnd_symlink = NULL;
	NTSTATUS status = NtOpenSymbolicLinkObject(&hnd_symlink, SYMBOLIC_LINK_QUERY, &object_attributes);

	if (status != STATUS_SUCCESS)
		throw status;

	ULONG buffer_size = 0;
	UNICODE_STRING target_name;
	RtlSecureZeroMemory(&target_name, sizeof(UNICODE_STRING));

	status = NtQuerySymbolicLinkObject(hnd_symlink, &target_name, &buffer_size);

	if (status == STATUS_BUFFER_TOO_SMALL)
	{
		target_name.Buffer = (PWCHAR)malloc(buffer_size);
		target_name.Length = (USHORT)buffer_size;
		target_name.MaximumLength = (USHORT)buffer_size;

		status = NtQuerySymbolicLinkObject(hnd_symlink, &target_name, &buffer_size);
	}

	NtClose(hnd_symlink);

	return target_name.Buffer;
}

int main(int argc, wchar_t* argv[])
{
	_setmode(_fileno(stdout), _O_U16TEXT);

	cerr << "DIRT v0.1.0: Driver Initial Reconnaisance Tool (@Jackson_T)" << endl;
	cerr << "Repository:  https://github.com/jthuraisamy/DIRT" << endl;
	cerr << "Compiled on: " << __DATE__ << " " << __TIME__ << endl << endl;
	
	DIRT::Main dirt;
	dirt.PopulateDrivers();

	dirt.ExportHumanReadable(false);
	//dirt.ExportCSV();

	cerr.flush();
	cerr << "Complete!" << setw(80) << endl;

	return 0;
}
