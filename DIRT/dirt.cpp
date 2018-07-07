// DIRT.cpp : Defines the entry point for the console application.
//

#pragma comment(lib, "ntdll.lib")

#include "stdafx.h"
#include "dirt.h"

#include <iostream>

#define BUFFER_SIZE 0x800

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

LPQUERY_SERVICE_CONFIG DIRT::Main::getDriverServiceConfig(const PWCHAR driverServiceName)
{
	LPQUERY_SERVICE_CONFIG psc = nullptr;
	SC_HANDLE schManager = NULL;
	SC_HANDLE schService = NULL;

	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (schManager == NULL)
	{
		return NULL;
	}

	schService = OpenService(schManager, driverServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
	if (schService == NULL)
	{
		std::wcout << ",,";
		CloseServiceHandle(schManager);
		return NULL;
	}

	DWORD bytesNeeded;
	QueryServiceConfig(schService, NULL, 0, &bytesNeeded);

	psc = (LPQUERY_SERVICE_CONFIG)malloc(bytesNeeded);
	QueryServiceConfig(schService, psc, bytesNeeded, &bytesNeeded);

	std::wcout << psc->lpBinaryPathName << ",";
	std::wcout << psc->lpDisplayName << ",";
	//std::wcout << psc->dwServiceType << ",";
	//std::wcout << psc->dwStartType << ",";
	//ToDo: get current state (started, stopped, etc.).

	free(psc);
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return psc;
}

int DIRT::Main::getLinkTarget(const HANDLE hDirectory, const PUNICODE_STRING objectName, _Out_ PWCHAR wcTargetName)
{
	OBJECT_ATTRIBUTES object_attributes;
	InitializeObjectAttributes(&object_attributes, objectName, OBJ_CASE_INSENSITIVE, hDirectory, NULL);

	HANDLE hLink = NULL;
	NTSTATUS status_code = NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &object_attributes);

	if (status_code != 0)
		return ERROR_UNIDENTIFIED_ERROR;

	ULONG bufferSize;
	UNICODE_STRING usTargetName;
	RtlSecureZeroMemory(&usTargetName, sizeof(UNICODE_STRING));

	status_code = NtQuerySymbolicLinkObject(hLink, &usTargetName, &bufferSize);

	if (status_code == STATUS_BUFFER_TOO_SMALL)
	{
		usTargetName.Buffer = (PWSTR)malloc(bufferSize);
		usTargetName.Length = (USHORT)bufferSize;
		usTargetName.MaximumLength = (USHORT)bufferSize;

		status_code = NtQuerySymbolicLinkObject(hLink, &usTargetName, &bufferSize);
	}

	NtClose(hLink);

	wcscpy(wcTargetName, usTargetName.Buffer);

	return 0;
}

int DIRT::Main::getObjectDACL(const PWCHAR wcPath, _Out_ PEXPLICIT_ACCESS* peaEntries, _Out_ PULONG pulEntryCount)
{
	HANDLE hObject = NULL;
	IO_STATUS_BLOCK iosb = { 0 };

	PUNICODE_STRING usPath = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
	RtlSecureZeroMemory(usPath, sizeof(usPath));
	RtlInitUnicodeString(usPath, wcPath);

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, usPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS nsCode = NtOpenFile(
		&hObject,
		READ_CONTROL,
		&oa,
		&iosb,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL
	);

	ULONG ulLength = 0;
	PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 0, ulLength);
	nsCode = NtQuerySecurityObject(
		hObject,
		DACL_SECURITY_INFORMATION,
		psd,
		ulLength,
		&ulLength // Collect the actual length of the SECURITY_DESCRIPTOR first.
	);

	if (nsCode == STATUS_BUFFER_TOO_SMALL)
	{
		psd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 0, ulLength);
		nsCode = NtQuerySecurityObject(
			hObject,
			DACL_SECURITY_INFORMATION,
			psd,
			ulLength, // Provide the actual length here.
			&ulLength
		);
	}

	BOOL bDACLPresent = 0;
	PACL pDACL = nullptr;
	BOOL bDACLDefaulted = 0;
	nsCode = GetSecurityDescriptorDacl(
		psd,
		&bDACLPresent,
		&pDACL,
		&bDACLDefaulted
	);

	GetExplicitEntriesFromAcl(
		pDACL,
		pulEntryCount,
		peaEntries
	);

	return 0;
}

bool DIRT::Main::isObjectPubliclyWritable(PEXPLICIT_ACCESS* peaEntries, const ULONG ulEntryCount)
{
	EXPLICIT_ACCESS *eaEntry = *peaEntries;

	for (ULONG i = 0; i < ulEntryCount; i++, eaEntry++)
	{
		if (eaEntry->Trustee.TrusteeForm == TRUSTEE_IS_SID)
		{
			DWORD dwSIDSize = GetLengthSid((SID*)eaEntry->Trustee.ptstrName);
			SID* sid = (SID*)malloc(dwSIDSize);
			SID_NAME_USE snu;
			CopySid(dwSIDSize, sid, (SID *)eaEntry->Trustee.ptstrName);

			DWORD UserSize = BUFSIZ - 1, DomainSize = BUFSIZ - 1;
			WCHAR UserName[BUFSIZ] = { 0 };
			WCHAR DomainName[BUFSIZ] = { 0 };
			LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &snu);
			free(sid);

			if ((*DomainName == NULL) && (wcscmp(UserName, L"Everyone") == 0))
			{
				if ((eaEntry->grfAccessMode == GRANT_ACCESS) && (eaEntry->grfAccessPermissions & STANDARD_RIGHTS_WRITE))
				{
					return true;
				}
			}
		}
	}

	return false;
}

int DIRT::Main::getDeviceDriver(const PWCHAR pwcPath)
{
	return 0;
}

int main()
{
	DIRT::Main dirt;

	return 0;
}
