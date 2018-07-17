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

void DIRT::Main::PopulateDrivers()
{
	PopulateDevices();

	vector<POBJECT_DIRECTORY_INFORMATION> ptr_driver_objects = m_object_manager.GetDirectoryObjects(L"\\Driver");

	for (POBJECT_DIRECTORY_INFORMATION ptr_objdir_info : ptr_driver_objects)
	{
		if (wcscmp(ptr_objdir_info->TypeName.Buffer, L"Driver") == 0)
		{
			PDRIVER ptr_driver = (PDRIVER)malloc(sizeof(DRIVER));

			ptr_driver->ServiceName = ptr_objdir_info->Name.Buffer;
			ptr_driver->FilePath = m_object_manager.GetDriverFileName(ptr_driver->ServiceName);
			ptr_driver->ServiceConfig = GetDriverServiceConfig(ptr_driver->ServiceName);

			//wcout << ptr_driver->ServiceName << ": " << ptr_driver->FilePath << endl;
			
			for (PDEVICE ptr_device : m_devices)
			{
				if (wcscmp(ptr_device->DriverServiceName, ptr_driver->ServiceName) == 0)
				{
					ptr_driver->Devices.push_back(ptr_device);
				}
			}

			m_drivers.push_back(ptr_driver);
		}
	}
}

void DIRT::Main::PopulateDevices()
{
	PopulateDevices(L"\\Device");
}

void DIRT::Main::PopulateDevices(const PWCHAR ptr_directory_path)
{
	vector<POBJECT_DIRECTORY_INFORMATION> ptr_driver_objects = m_object_manager.GetDirectoryObjects(ptr_directory_path);

	for (POBJECT_DIRECTORY_INFORMATION ptr_objdir_info : ptr_driver_objects)
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
			
			PDEVICE ptr_device = (PDEVICE)malloc(sizeof(DEVICE));

			ptr_device->DriverServiceName = driver_service_name;

			ptr_device->ObjectPath = (PTCHAR)malloc(MAX_PATH);
			swprintf(ptr_device->ObjectPath, L"%s\\%s", ptr_directory_path, ptr_objdir_info->Name.Buffer);

			//wcout << ptr_device->DriverServiceName << ": " << ptr_device->ObjectPath;

			ULONG entry_count = 0;
			PEXPLICIT_ACCESS ptr_entries = nullptr;
			GetObjectDACL(ptr_device->ObjectPath, &ptr_entries, &entry_count);
			ptr_device->OpenDACL = IsObjectPubliclyWritable(&ptr_entries, entry_count);

			//wcout << " (" << ptr_device->OpenDACL << ")" << endl;

			// ToDo: populate symbolic paths.

			m_devices.push_back(ptr_device);
		}
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

int main()
{
	DIRT::Main dirt;

	dirt.ExportCSV();

	return 0;
}
