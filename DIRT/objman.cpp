#include "stdafx.h"
#include "objman.h"

#include <iostream>
#include <vector>

using namespace std;

namespace DIRT
{
	class Main;
	class DebugDriver;
	class ObjectManager;
};

DIRT::ObjectManager::ObjectManager()
{
	HMODULE hnd_module = LoadLibrary(_T("ntdll.dll"));

	NtOpenFile = (NTOPENFILE)GetProcAddress(hnd_module, "NtOpenFile");
	NtCreateFile = (NTCREATEFILE)GetProcAddress(hnd_module, "NtCreateFile");
	NtOpenDirectoryObject = (NTOPENDIRECTORYOBJECT)GetProcAddress(hnd_module, "NtOpenDirectoryObject");
	NtQueryDirectoryObject = (NTQUERYDIRECTORYOBJECT)GetProcAddress(hnd_module, "NtQueryDirectoryObject");
	NtOpenSymbolicLinkObject = (NTOPENSYMBOLICLINKOBJECT)GetProcAddress(hnd_module, "NtOpenSymbolicLinkObject");
	NtQuerySymbolicLinkObject = (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(hnd_module, "NtQuerySymbolicLinkObject");
	NtQuerySecurityObject = (NTQUERYSECURITYOBJECT)GetProcAddress(hnd_module, "NtQuerySecurityObject");
	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hnd_module, "NtQuerySystemInformation");
	RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(hnd_module, "RtlInitUnicodeString");
}

PVOID DIRT::ObjectManager::GetDriverMajorFunction(const PWCHAR ptr_driver_service_name, const int major_function_idx)
{
	PDRIVER_OBJECT ptr_driver_object = GetDriverObject(L"\\Driver", ptr_driver_service_name);
	return ptr_driver_object->MajorFunction[major_function_idx];
}

PWCHAR DIRT::ObjectManager::GetDriverFileName(const PWCHAR ptr_driver_service_name)
{
	PDRIVER_OBJECT ptr_driver_object = GetDriverObject(L"\\Driver", ptr_driver_service_name);
	return GetDriverFileName(ptr_driver_object);
}

PWCHAR DIRT::ObjectManager::GetDriverFileName(const PDRIVER_OBJECT ptr_driver_object)
{
	PVOID ptr_driver_file_address = ptr_driver_object->DriverStart;

	PRTL_PROCESS_MODULES ptr_modules = nullptr;
	PRTL_PROCESS_MODULE_INFORMATION ptr_module = nullptr;

	// ToDo: DRY.
	NTSTATUS status;
	ULONG buffer_size = BUFFER_SIZE;

	// Get a list of process modules using NtQuerySystemInformation with
	// the SystemModuleInformation argument.
	do
	{
		ptr_modules = (PRTL_PROCESS_MODULES)malloc(buffer_size);
		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
			ptr_modules,
			buffer_size,
			NULL
		);

		// NtQuerySystemInformation won't give us the correct buffer size,
		// so we have to guess by doubling the buffer size and looping.
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(ptr_modules);
			ptr_modules = nullptr;
			buffer_size *= 2;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	for (unsigned long i = 0; i < ptr_modules->NumberOfModules; i++)
	{
		ptr_module = &ptr_modules->Modules[i];

		if (ptr_module->ImageBase == ptr_driver_object->DriverStart)
		{
			size_t return_value;
			WCHAR nt_path[MAX_PATH] = { 0 };
			mbstowcs_s(
				&return_value,
				nt_path,
				MAX_PATH,
				(const char*)ptr_module->FullPathName,
				strlen((const char*)ptr_module->FullPathName)
			);

			free(ptr_modules);

			return ConvertNtPathToWin32Path(nt_path);
		}
	}

	return NULL;
}

PWCHAR DIRT::ObjectManager::GetDriverServiceNameFromDevice(const PWCHAR ptr_target_directory_path, const PWCHAR ptr_target_object_name)
{
	PDEVICE_OBJECT ptr_device_object = GetDeviceObject(ptr_target_directory_path, ptr_target_object_name);
	PWCHAR ptr_driver_name = GetObjectNameFromAddress(L"\\Driver", ptr_device_object->DriverObject);
	return ptr_driver_name;
}

PDRIVER_OBJECT DIRT::ObjectManager::GetDriverObject(const PWCHAR ptr_target_directory_path, const PWCHAR ptr_target_object_name)
{
	PDRIVER_OBJECT ptr_device_object = (PDRIVER_OBJECT)malloc(sizeof(DRIVER_OBJECT));
	RtlSecureZeroMemory(ptr_device_object, sizeof(DRIVER_OBJECT));
	PVOID ptr_object_address = GetObjectAddressFromName(ptr_target_directory_path, ptr_target_object_name);
	debug_driver.ReadSystemMemory(ptr_device_object, ptr_object_address, sizeof(DRIVER_OBJECT));

	return ptr_device_object;
}

PDEVICE_OBJECT DIRT::ObjectManager::GetDeviceObject(const PWCHAR ptr_target_directory_path, const PWCHAR ptr_target_object_name)
{
	PDEVICE_OBJECT ptr_device_object = (PDEVICE_OBJECT)malloc(sizeof(DEVICE_OBJECT));
	RtlSecureZeroMemory(ptr_device_object, sizeof(DEVICE_OBJECT));
	PVOID ptr_object_address = GetObjectAddressFromName(ptr_target_directory_path, ptr_target_object_name);
	debug_driver.ReadSystemMemory(ptr_device_object, ptr_object_address, sizeof(DEVICE_OBJECT));

	return ptr_device_object;
}

PWCHAR DIRT::ObjectManager::GetObjectNameFromAddress(const PWCHAR ptr_target_directory_path, const PVOID ptr_target_object_address)
{
	PWCHAR ptr_object_name = nullptr;

	HANDLE hnd_directory = GetObjectDirectoryHandle(ptr_target_directory_path);
	PVOID  ptr_directory = GetObjectDirectoryAddress(hnd_directory);

	// Walk through directory to find the address for the object.
	OBJECT_HEADER          object_header;
	OBJECT_DIRECTORY       object_directory;
	OBJECT_DIRECTORY_ENTRY object_directory_entry;
	RtlSecureZeroMemory(&object_directory, sizeof(OBJECT_DIRECTORY));
	debug_driver.ReadSystemMemory(&object_directory, ptr_directory, sizeof(OBJECT_DIRECTORY));

	for (int i = 0; i < 0x25; i++)
	{
		// Read OBJECT_DIRECTORY_ENTRY.
		RtlSecureZeroMemory(&object_directory_entry, sizeof(OBJECT_DIRECTORY_ENTRY));
		debug_driver.ReadSystemMemory(&object_directory_entry, object_directory.HashBuckets[i], sizeof(OBJECT_DIRECTORY_ENTRY));

		do
		{
			if (object_directory_entry.Object != ptr_target_object_address)
				goto next_entry;

			// Read OBJECT_HEADER.
			RtlSecureZeroMemory(&object_header, sizeof(OBJECT_HEADER));
			PVOID object_header_address = OBJECT_TO_OBJECT_HEADER(object_directory_entry.Object);
			debug_driver.ReadSystemMemory(&object_header, object_header_address, sizeof(OBJECT_HEADER));

			// Check if the object has a name.
			BYTE header_offset = (BYTE)sizeof(OBJECT_HEADER_NAME_INFO);
			ULONG_PTR ptr_info_header_address = (ULONG_PTR)object_header_address - header_offset;

			// Query the object name.
			OBJECT_HEADER_NAME_INFO object_header_name_info;
			ULONG                   object_name_size = 0;

			RtlSecureZeroMemory(&object_header_name_info, sizeof(OBJECT_HEADER_NAME_INFO));
			debug_driver.ReadSystemMemory(&object_header_name_info, (PVOID)ptr_info_header_address, sizeof(OBJECT_HEADER_NAME_INFO));

			object_name_size = object_header_name_info.Name.Length;
			ptr_object_name = (PWCHAR)calloc(sizeof(WCHAR), object_name_size);
			debug_driver.ReadSystemMemory(ptr_object_name, object_header_name_info.Name.Buffer, object_name_size);

			if ((ptr_object_name == nullptr) || (object_name_size == 0))
				return NULL;
			else
				return ptr_object_name;

		next_entry:
			if (object_directory_entry.ChainLink != nullptr)
				debug_driver.ReadSystemMemory(&object_directory_entry, object_directory_entry.ChainLink, sizeof(OBJECT_DIRECTORY_ENTRY));
			else
				break;
		} while (true);
	}

	return NULL;
}

PVOID DIRT::ObjectManager::GetObjectAddressFromName(const PWCHAR ptr_target_directory_path, const PWCHAR ptr_target_object_name)
{
	HANDLE hnd_directory = GetObjectDirectoryHandle(ptr_target_directory_path);
	PVOID  ptr_directory = GetObjectDirectoryAddress(hnd_directory);

	// Walk through directory to find the address for the object.
	OBJECT_HEADER          object_header;
	OBJECT_DIRECTORY       object_directory;
	OBJECT_DIRECTORY_ENTRY object_directory_entry;
	RtlSecureZeroMemory(&object_directory, sizeof(OBJECT_DIRECTORY));
	debug_driver.ReadSystemMemory(&object_directory, ptr_directory, sizeof(OBJECT_DIRECTORY));

	for (int i = 0; i < 0x25; i++)
	{
		// Read OBJECT_DIRECTORY_ENTRY.
		RtlSecureZeroMemory(&object_directory_entry, sizeof(OBJECT_DIRECTORY_ENTRY));
		debug_driver.ReadSystemMemory(&object_directory_entry, object_directory.HashBuckets[i], sizeof(OBJECT_DIRECTORY_ENTRY));

		do
		{
			// Read OBJECT_HEADER.
			RtlSecureZeroMemory(&object_header, sizeof(OBJECT_HEADER));
			PVOID ptr_object_header_address = OBJECT_TO_OBJECT_HEADER(object_directory_entry.Object);
			debug_driver.ReadSystemMemory(&object_header, ptr_object_header_address, sizeof(OBJECT_HEADER));

			// Check if the object has a name.
			BYTE header_offset = (BYTE)sizeof(OBJECT_HEADER_NAME_INFO);
			ULONG_PTR ptr_info_header_address = (ULONG_PTR)ptr_object_header_address - header_offset;

			// Query the object name.
			OBJECT_HEADER_NAME_INFO object_header_name_info;
			WCHAR                   object_name_found[BUFSIZ] = { 0 };
			ULONG                   object_name_size = 0;

			RtlSecureZeroMemory(&object_header_name_info, sizeof(OBJECT_HEADER_NAME_INFO));
			debug_driver.ReadSystemMemory(&object_header_name_info, (PVOID)ptr_info_header_address, sizeof(OBJECT_HEADER_NAME_INFO));

			object_name_size = object_header_name_info.Name.Length;
			debug_driver.ReadSystemMemory(&object_name_found, object_header_name_info.Name.Buffer, object_name_size);

			if ((object_name_found == NULL) || (object_name_size == 0))
				goto next_entry;
			else if (wcscmp(ptr_target_object_name, (PWCHAR)&object_name_found) == 0)
				return object_directory_entry.Object;

		next_entry:
			if (object_directory_entry.ChainLink != nullptr)
				debug_driver.ReadSystemMemory(&object_directory_entry, object_directory_entry.ChainLink, sizeof(OBJECT_DIRECTORY_ENTRY));
			else
				break;
		} while (true);
	}

	return nullptr;
}

vector<POBJECT_DIRECTORY_INFORMATION> DIRT::ObjectManager::GetDirectoryObjects(const PWCHAR ptr_path)
{
	vector<POBJECT_DIRECTORY_INFORMATION> objects;

	HANDLE hnd_directory = GetObjectDirectoryHandle(ptr_path);

	DWORD object_index = 0;
	DWORD return_length = 0;

	NTSTATUS status;
	POBJECT_DIRECTORY_INFORMATION ptr_objdir_info = nullptr;

	while (NtQueryDirectoryObject(hnd_directory, NULL, 0, TRUE, FALSE, &object_index, &return_length) == STATUS_BUFFER_TOO_SMALL)
	{
		ptr_objdir_info = (POBJECT_DIRECTORY_INFORMATION)malloc(return_length);
		status = NtQueryDirectoryObject(hnd_directory, ptr_objdir_info, return_length, TRUE, FALSE, &object_index, &return_length);

		if (status != STATUS_SUCCESS)
			throw status;
		else
			objects.push_back(ptr_objdir_info);
	}

	return objects;
}

HANDLE DIRT::ObjectManager::GetObjectDirectoryHandle(const PWCHAR ptr_path)
{
	HANDLE hnd_directory = NULL;

	UNICODE_STRING object_name;
	RtlSecureZeroMemory(&object_name, sizeof(object_name));
	RtlInitUnicodeString(&object_name, ptr_path);

	OBJECT_ATTRIBUTES path_attributes;
	InitializeObjectAttributes(&path_attributes, &object_name, 0, NULL, NULL);

	NTSTATUS status = NtOpenDirectoryObject(&hnd_directory, DIRECTORY_QUERY, &path_attributes);

	if (status != 0)
		return NULL;

	return hnd_directory;
}

PVOID DIRT::ObjectManager::GetObjectDirectoryAddress(const HANDLE hDirectory)
{
	// ToDo: DRY.
	NTSTATUS status = 0;
	PSYSTEM_HANDLE_INFORMATION_EX ptr_handles = nullptr;
	ULONG buffer_size = BUFFER_SIZE;

	// Get a list of handles using NtQuerySystemInformation with
	// the SystemExtendedHandleInformation argument.
	do
	{
		ptr_handles = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(buffer_size);
		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
			ptr_handles,
			buffer_size,
			NULL
		);

		// NtQuerySystemInformation won't give us the correct buffer size,
		// so we have to guess by doubling the buffer size and looping.
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(ptr_handles);
			ptr_handles = nullptr;
			buffer_size *= 2;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	// Search through the handles to find one for the handle that represents
	// pwcDirectoryPath (hDirectory) and get the address for it.
	DWORD current_pid = GetCurrentProcessId();
	for (ULONG i = 0; i < ptr_handles->NumberOfHandles; i++)
	{
		if (ptr_handles->Handles[i].UniqueProcessId == current_pid)
		{
			if (ptr_handles->Handles[i].HandleValue == (ULONG_PTR)hDirectory)
			{
				return ptr_handles->Handles[i].Object;
			}
		}
	}

	return nullptr;
}

PWCHAR DIRT::ObjectManager::ConvertNtPathToWin32Path(const PWCHAR ptr_nt_path)
{
	UNICODE_STRING    nt_path;
	OBJECT_ATTRIBUTES object_attributes;
	IO_STATUS_BLOCK   iosb;
	HANDLE            hnd_file;

	RtlSecureZeroMemory(&nt_path, sizeof(nt_path));
	RtlInitUnicodeString(&nt_path, ptr_nt_path);
	InitializeObjectAttributes(&object_attributes, &nt_path, OBJ_CASE_INSENSITIVE, 0, NULL);

	NTSTATUS status = NtCreateFile(
		&hnd_file,
		SYNCHRONIZE,
		&object_attributes,
		&iosb,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL,
		0
	);

	PWCHAR ptr_win32_path = (PWCHAR)calloc(MAX_PATH, sizeof(WCHAR));
	GetFinalPathNameByHandle(hnd_file, ptr_win32_path, MAX_PATH, FILE_NAME_OPENED);

	return ptr_win32_path;
}