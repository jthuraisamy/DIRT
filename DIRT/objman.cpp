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
	HMODULE _hModule = LoadLibrary(_T("ntdll.dll"));

	NtOpenFile = (NTOPENFILE)GetProcAddress(_hModule, "NtOpenFile");
	NtCreateFile = (NTCREATEFILE)GetProcAddress(_hModule, "NtCreateFile");
	NtOpenDirectoryObject = (NTOPENDIRECTORYOBJECT)GetProcAddress(_hModule, "NtOpenDirectoryObject");
	NtQueryDirectoryObject = (NTQUERYDIRECTORYOBJECT)GetProcAddress(_hModule, "NtQueryDirectoryObject");
	NtOpenSymbolicLinkObject = (NTOPENSYMBOLICLINKOBJECT)GetProcAddress(_hModule, "NtOpenSymbolicLinkObject");
	NtQuerySymbolicLinkObject = (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(_hModule, "NtQuerySymbolicLinkObject");
	NtQuerySecurityObject = (NTQUERYSECURITYOBJECT)GetProcAddress(_hModule, "NtQuerySecurityObject");
	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(_hModule, "NtQuerySystemInformation");
	RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(_hModule, "RtlInitUnicodeString");
}

PWCHAR DIRT::ObjectManager::getDriverFileName(const PWCHAR pDriverServiceName)
{
	PDRIVER_OBJECT pDriverObject = getDriverObject(L"\\Driver", pDriverServiceName);
	return getDriverFileName(pDriverObject);
}

PWCHAR DIRT::ObjectManager::getDriverFileName(const PDRIVER_OBJECT pDriverObject)
{
	PVOID driverFileAddress = pDriverObject->DriverStart;

	PRTL_PROCESS_MODULES            pModules = nullptr;
	PRTL_PROCESS_MODULE_INFORMATION pModule = nullptr;

	NTSTATUS nsCode;
	ULONG ulBufferSize = BUFFER_SIZE;

	// Get a list of process modules using NtQuerySystemInformation with
	// the SystemModuleInformation argument.
	do
	{
		pModules = (PRTL_PROCESS_MODULES)malloc(ulBufferSize);
		nsCode = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
			pModules,
			ulBufferSize,
			NULL
		);

		// NtQuerySystemInformation won't give us the correct buffer size,
		// so we have to guess by doubling the buffer size and looping.
		if (nsCode == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(pModules);
			pModules = nullptr;
			ulBufferSize *= 2;
		}
	} while (nsCode == STATUS_INFO_LENGTH_MISMATCH);

	for (unsigned long i = 0; i < pModules->NumberOfModules; i++)
	{
		pModule = &pModules->Modules[i];

		if (pModule->ImageBase == pDriverObject->DriverStart)
		{
			WCHAR ntPath[MAX_PATH] = { 0 };
			mbstowcs(ntPath, (const char*)pModule->FullPathName, strlen((const char*)pModule->FullPathName));
			return convertNtPathToWin32Path(ntPath);
		}
	}

	return NULL;
}

PWCHAR DIRT::ObjectManager::getDriverServiceNameFromDevice(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName)
{
	PDEVICE_OBJECT pDeviceObject = getDeviceObject(targetDirectoryPath, targetObjectName);
	PWCHAR pDriverName = getObjectNameFromAddress(L"\\Driver", pDeviceObject->DriverObject);
	return pDriverName;
}

PDRIVER_OBJECT DIRT::ObjectManager::getDriverObject(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName)
{
	PDRIVER_OBJECT pDeviceObject = (PDRIVER_OBJECT)malloc(sizeof(DRIVER_OBJECT));
	RtlSecureZeroMemory(pDeviceObject, sizeof(DRIVER_OBJECT));
	PVOID pObjectAddress = getObjectAddressFromName(targetDirectoryPath, targetObjectName);
	dbgDriver.readSystemMemory(pDeviceObject, pObjectAddress, sizeof(DRIVER_OBJECT));

	return pDeviceObject;
}

PDEVICE_OBJECT DIRT::ObjectManager::getDeviceObject(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName)
{
	PDEVICE_OBJECT pDeviceObject = (PDEVICE_OBJECT)malloc(sizeof(DEVICE_OBJECT));
	RtlSecureZeroMemory(pDeviceObject, sizeof(DEVICE_OBJECT));
	PVOID pObjectAddress = getObjectAddressFromName(targetDirectoryPath, targetObjectName);
	dbgDriver.readSystemMemory(pDeviceObject, pObjectAddress, sizeof(DEVICE_OBJECT));

	return pDeviceObject;
}

PWCHAR DIRT::ObjectManager::getObjectNameFromAddress(const PWCHAR targetDirectoryPath, const PVOID targetObjectAddress)
{
	PWCHAR pObjectName = nullptr;

	HANDLE hDirectory = getObjectDirectoryHandle(targetDirectoryPath);
	PVOID  pDirectory = getObjectDirectoryAddress(hDirectory);

	// Walk through directory to find the address for the object.
	OBJECT_HEADER          objectHeader;
	OBJECT_DIRECTORY       objectDirectory;
	OBJECT_DIRECTORY_ENTRY objectDirectoryEntry;
	RtlSecureZeroMemory(&objectDirectory, sizeof(OBJECT_DIRECTORY));
	dbgDriver.readSystemMemory(&objectDirectory, pDirectory, sizeof(OBJECT_DIRECTORY));

	for (int i = 0; i < 0x25; i++)
	{
		// Read OBJECT_DIRECTORY_ENTRY.
		RtlSecureZeroMemory(&objectDirectoryEntry, sizeof(OBJECT_DIRECTORY_ENTRY));
		dbgDriver.readSystemMemory(&objectDirectoryEntry, objectDirectory.HashBuckets[i], sizeof(OBJECT_DIRECTORY_ENTRY));

		do
		{
			if (objectDirectoryEntry.Object != targetObjectAddress)
				goto nextEntry;

			// Read OBJECT_HEADER.
			RtlSecureZeroMemory(&objectHeader, sizeof(OBJECT_HEADER));
			PVOID objectHeaderAddress = OBJECT_TO_OBJECT_HEADER(objectDirectoryEntry.Object);
			dbgDriver.readSystemMemory(&objectHeader, objectHeaderAddress, sizeof(OBJECT_HEADER));

			// Check if the object has a name.
			BYTE headerOffset = (BYTE)sizeof(OBJECT_HEADER_NAME_INFO);
			ULONG_PTR infoHeaderAddress = (ULONG_PTR)objectHeaderAddress - headerOffset;

			// Query the object name.
			OBJECT_HEADER_NAME_INFO objectHeaderNameInfo;
			SIZE_T                  objectNameSize = 0;

			RtlSecureZeroMemory(&objectHeaderNameInfo, sizeof(OBJECT_HEADER_NAME_INFO));
			dbgDriver.readSystemMemory(&objectHeaderNameInfo, (PVOID)infoHeaderAddress, sizeof(OBJECT_HEADER_NAME_INFO));

			objectNameSize = objectHeaderNameInfo.Name.Length;
			pObjectName = (PWCHAR)calloc(sizeof(WCHAR), objectNameSize);
			dbgDriver.readSystemMemory(pObjectName, objectHeaderNameInfo.Name.Buffer, objectNameSize);

			if ((pObjectName == nullptr) || (objectNameSize == 0))
				return NULL;
			else
				return pObjectName;

		nextEntry:
			if (objectDirectoryEntry.ChainLink != nullptr)
				dbgDriver.readSystemMemory(&objectDirectoryEntry, objectDirectoryEntry.ChainLink, sizeof(OBJECT_DIRECTORY_ENTRY));
			else
				break;
		} while (true);
	}

	return NULL;
}

PVOID DIRT::ObjectManager::getObjectAddressFromName(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName)
{
	HANDLE hDirectory = getObjectDirectoryHandle(targetDirectoryPath);
	PVOID  pDirectory = getObjectDirectoryAddress(hDirectory);

	// Walk through directory to find the address for the object.
	OBJECT_HEADER          objectHeader;
	OBJECT_DIRECTORY       objectDirectory;
	OBJECT_DIRECTORY_ENTRY objectDirectoryEntry;
	RtlSecureZeroMemory(&objectDirectory, sizeof(OBJECT_DIRECTORY));
	dbgDriver.readSystemMemory(&objectDirectory, pDirectory, sizeof(OBJECT_DIRECTORY));

	for (int i = 0; i < 0x25; i++)
	{
		// Read OBJECT_DIRECTORY_ENTRY.
		RtlSecureZeroMemory(&objectDirectoryEntry, sizeof(OBJECT_DIRECTORY_ENTRY));
		dbgDriver.readSystemMemory(&objectDirectoryEntry, objectDirectory.HashBuckets[i], sizeof(OBJECT_DIRECTORY_ENTRY));

		do
		{
			// Read OBJECT_HEADER.
			RtlSecureZeroMemory(&objectHeader, sizeof(OBJECT_HEADER));
			PVOID objectHeaderAddress = OBJECT_TO_OBJECT_HEADER(objectDirectoryEntry.Object);
			dbgDriver.readSystemMemory(&objectHeader, objectHeaderAddress, sizeof(OBJECT_HEADER));

			// Check if the object has a name.
			BYTE headerOffset = (BYTE)sizeof(OBJECT_HEADER_NAME_INFO);
			ULONG_PTR infoHeaderAddress = (ULONG_PTR)objectHeaderAddress - headerOffset;

			// Query the object name.
			OBJECT_HEADER_NAME_INFO objectHeaderNameInfo;
			WCHAR                   objectNameFound[BUFSIZ] = { 0 };
			SIZE_T                  objectNameSize = 0;

			RtlSecureZeroMemory(&objectHeaderNameInfo, sizeof(OBJECT_HEADER_NAME_INFO));
			dbgDriver.readSystemMemory(&objectHeaderNameInfo, (PVOID)infoHeaderAddress, sizeof(OBJECT_HEADER_NAME_INFO));

			objectNameSize = objectHeaderNameInfo.Name.Length;
			dbgDriver.readSystemMemory(&objectNameFound, objectHeaderNameInfo.Name.Buffer, objectNameSize);

			if ((objectNameFound == NULL) || (objectNameSize == 0))
				goto nextEntry;
			else if (wcscmp(targetObjectName, (PWCHAR)&objectNameFound) == 0)
				return objectDirectoryEntry.Object;

		nextEntry:
			if (objectDirectoryEntry.ChainLink != nullptr)
				dbgDriver.readSystemMemory(&objectDirectoryEntry, objectDirectoryEntry.ChainLink, sizeof(OBJECT_DIRECTORY_ENTRY));
			else
				break;
		} while (true);
	}

	return nullptr;
}

vector<POBJECT_DIRECTORY_INFORMATION> DIRT::ObjectManager::getDirectoryObjects(const PWCHAR path)
{
	vector<POBJECT_DIRECTORY_INFORMATION> objects;

	HANDLE hDirectory = getObjectDirectoryHandle(path);

	DWORD objectIndex = 0;
	DWORD returnLength = 0;

	NTSTATUS nsCode;
	POBJECT_DIRECTORY_INFORMATION podi = nullptr;

	while (NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &objectIndex, &returnLength) == STATUS_BUFFER_TOO_SMALL)
	{
		podi = (POBJECT_DIRECTORY_INFORMATION)malloc(returnLength);
		nsCode = NtQueryDirectoryObject(hDirectory, podi, returnLength, TRUE, FALSE, &objectIndex, &returnLength);

		if (nsCode != STATUS_SUCCESS)
			throw nsCode;
		else
			objects.push_back(podi);
	}

	return objects;
}

PWCHAR DIRT::ObjectManager::convertNtPathToWin32Path(const PWCHAR inputPath)
{
	UNICODE_STRING    ntPath;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK   iosb;
	HANDLE            hFile;

	RtlSecureZeroMemory(&ntPath, sizeof(ntPath));
	RtlInitUnicodeString(&ntPath, inputPath);
	InitializeObjectAttributes(&objAttr, &ntPath, OBJ_CASE_INSENSITIVE, 0, NULL);

	NTSTATUS nsCode = NtCreateFile(
		&hFile,
		SYNCHRONIZE,
		&objAttr,
		&iosb,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL,
		0
	);

	PWCHAR pWin32Path = (PWCHAR)calloc(MAX_PATH, sizeof(WCHAR));
	GetFinalPathNameByHandle(hFile, pWin32Path, MAX_PATH, FILE_NAME_OPENED);

	return pWin32Path;
}

HANDLE DIRT::ObjectManager::getObjectDirectoryHandle(const PWCHAR path)
{
	HANDLE hDirectory = NULL;

	UNICODE_STRING object_name;
	RtlSecureZeroMemory(&object_name, sizeof(object_name));
	RtlInitUnicodeString(&object_name, path);

	OBJECT_ATTRIBUTES path_attributes;
	InitializeObjectAttributes(&path_attributes, &object_name, 0, NULL, NULL);

	NTSTATUS status_code = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &path_attributes);

	if (status_code != 0)
		return NULL;

	return hDirectory;
}

PVOID DIRT::ObjectManager::getObjectDirectoryAddress(const HANDLE hDirectory)
{
	NTSTATUS nsCode = 0;
	USHORT SystemExtendedHandleInformation = 64;
	PSYSTEM_HANDLE_INFORMATION_EX pHandles = nullptr;
	ULONG ulBufferSize = BUFFER_SIZE;

	// Get a list of handles using NtQuerySystemInformation with
	// the SystemExtendedHandleInformation argument.
	do
	{
		pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(ulBufferSize);
		nsCode = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
			pHandles,
			ulBufferSize,
			NULL
		);

		// NtQuerySystemInformation won't give us the correct buffer size,
		// so we have to guess by doubling the buffer size and looping.
		if (nsCode == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(pHandles);
			pHandles = nullptr;
			ulBufferSize *= 2;
		}
	} while (nsCode == STATUS_INFO_LENGTH_MISMATCH);

	// Search through the handles to find one for the handle that represents
	// pwcDirectoryPath (hDirectory) and get the address for it.
	DWORD dwCurrentPID = GetCurrentProcessId();
	for (ULONG i = 0; i < pHandles->NumberOfHandles; i++)
	{
		if (pHandles->Handles[i].UniqueProcessId == dwCurrentPID)
		{
			if (pHandles->Handles[i].HandleValue == (ULONG_PTR)hDirectory)
			{
				return pHandles->Handles[i].Object;
			}
		}
	}

	return nullptr;
}