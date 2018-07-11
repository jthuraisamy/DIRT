// DIRT.cpp : Defines the entry point for the console application.
//

#pragma comment(lib, "ntdll.lib")

#include "stdafx.h"
#include "dirt.h"

#include <iostream>

DIRT::Main::Main()
{
	HMODULE _hModule = LoadLibrary(_T("ntdll.dll"));

	NtOpenFile = (NTOPENFILE)GetProcAddress(_hModule, "NtOpenFile");
	NtOpenDirectoryObject = (NTOPENDIRECTORYOBJECT)GetProcAddress(_hModule, "NtOpenDirectoryObject");
	NtQueryDirectoryObject = (NTQUERYDIRECTORYOBJECT)GetProcAddress(_hModule, "NtQueryDirectoryObject");
	NtOpenSymbolicLinkObject = (NTOPENSYMBOLICLINKOBJECT)GetProcAddress(_hModule, "NtOpenSymbolicLinkObject");
	NtQuerySymbolicLinkObject = (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(_hModule, "NtQuerySymbolicLinkObject");
	NtQuerySecurityObject = (NTQUERYSECURITYOBJECT)GetProcAddress(_hModule, "NtQuerySecurityObject");
	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(_hModule, "NtQuerySystemInformation");
	NtClose = (NTCLOSE)GetProcAddress(_hModule, "NtClose");
	RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(_hModule, "RtlInitUnicodeString");
}

void DIRT::Main::PrintCSV()
{
	cout << "SymbolicLink,DeviceObjectPath,DriverObjectPath,DriverFilePath,DriverDescription,OpenDACL" << endl;

	vector<POBJECT_DIRECTORY_INFORMATION> globalObjects = m_object_manager.GetDirectoryObjects(L"\\Global??");

	for (POBJECT_DIRECTORY_INFORMATION pObjDirInfo : globalObjects)
	{
		if (wcscmp(pObjDirInfo->TypeName.Buffer, L"SymbolicLink") == 0)
		{
			// Print SymbolicLink.
			wcout << L"\\\\.\\Global\\" << pObjDirInfo->Name.Buffer << ",";

			// Print DeviceObjectPath.
			HANDLE hDirectory = m_object_manager.GetObjectDirectoryHandle(L"\\Global??");
			PWCHAR pDeviceObjectPath = GetLinkTarget(hDirectory, &pObjDirInfo->Name);
			if (pDeviceObjectPath != nullptr)
			{
				wcout << pDeviceObjectPath << ",";

				// Print DriverObjectPath.
				PWCHAR pDeviceObjectName = &pDeviceObjectPath[8];
				PWCHAR pDriverServiceName = m_object_manager.GetDriverServiceNameFromDevice(L"\\Device", pDeviceObjectName);
				if (pDriverServiceName != nullptr)
				{
					wcout << L"\\Driver\\" << pDriverServiceName << ",";

					// Print DriverFilePath.
					PWCHAR pDriverFileName = m_object_manager.GetDriverFileName(pDriverServiceName);
					wcout << &pDriverFileName[4] << ",";

					// Print DriverDescription.
					LPQUERY_SERVICE_CONFIG pDriverServiceConfig = GetDriverServiceConfig(pDriverServiceName);
					if (pDriverServiceConfig != nullptr)
					{
						wcout << pDriverServiceConfig->lpDisplayName << ",";
					}
					else
					{
						wcout << ",,";
					}
				}
				else
				{
					wcout << ",,,";
				}

				// Print InsecureDACL.
				ULONG ulEntryCount = 0;
				EXPLICIT_ACCESS *eaEntries;
				GetObjectDACL(pDeviceObjectPath, &eaEntries, &ulEntryCount);
				wcout << IsObjectPubliclyWritable(&eaEntries, ulEntryCount) << endl;
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

	dirt.PrintCSV();

	return 0;
}
