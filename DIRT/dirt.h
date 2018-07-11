#pragma once

#include "global.h"
#include "objman.h"

#include <aclapi.h>

class DIRT::Main
{
	DIRT::ObjectManager       m_object_manager;
	vector<DIRT::PDRIVER>     m_drivers;
	vector<DIRT::PDEVICE>     m_devices;

	NTOPENFILE                NtOpenFile;
	NTOPENDIRECTORYOBJECT     NtOpenDirectoryObject;
	NTQUERYDIRECTORYOBJECT    NtQueryDirectoryObject;
	NTOPENSYMBOLICLINKOBJECT  NtOpenSymbolicLinkObject;
	NTQUERYSYMBOLICLINKOBJECT NtQuerySymbolicLinkObject;
	NTQUERYSECURITYOBJECT     NtQuerySecurityObject;
	NTQUERYSYSTEMINFORMATION  NtQuerySystemInformation;
	NTCLOSE                   NtClose;
	RTLINITUNICODESTRING      RtlInitUnicodeString;

public:
	DIRT::Main();
	void                   PrintCSV();

private:
	LPQUERY_SERVICE_CONFIG GetDriverServiceConfig(const PWCHAR ptr_driver_service_name);
	bool                   IsObjectPubliclyWritable(PEXPLICIT_ACCESS* ptr_entries, const ULONG entry_count);
	int                    GetObjectDACL(const PWCHAR ptr_path, _Out_ PEXPLICIT_ACCESS* ptr_entries, _Out_ PULONG ptr_entry_count);
	PWCHAR                 GetLinkTarget(const HANDLE hnd_root_directory, const PUNICODE_STRING ptr_object_name);
};