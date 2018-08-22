#pragma once

#include "global.h"
#include "objman.h"

#include <aclapi.h>
#include <iomanip>
#include <io.h>
#include <fcntl.h>
#include <winver.h>

#pragma comment(lib, "Version.lib")

class DIRT::Main
{
	DIRT::ObjectManager       m_object_manager;

	vector<DRIVER>            m_drivers;
	vector<DEVICE>            m_devices;

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
	void                   PopulateDrivers();
	void                   PopulateDevices();
	void                   PopulateDevices(const PWCHAR ptr_directory_path);
	void                   ExportHumanReadable(const bool lowpriv_accessible_only, const bool no_microsoft);
	void                   ExportCSV();
	void                   ExportJSON();

private:
	LPQUERY_SERVICE_CONFIG GetDriverServiceConfig(const PWCHAR ptr_driver_service_name);
	bool                   IsObjectPubliclyWritable(PEXPLICIT_ACCESS* ptr_entries, const ULONG entry_count);
	int                    GetObjectDACL(const PWCHAR ptr_path, _Out_ PEXPLICIT_ACCESS* ptr_entries, _Out_ PULONG ptr_entry_count);
	void                   PopulateDeviceToSymLinks(vector<PDEVICE> ptr_devices);
	PWCHAR                 GetLinkTarget(const HANDLE hnd_root_directory, const PUNICODE_STRING ptr_object_name);
	PWCHAR                 GetFileVersionInformationValue(const PWCHAR file_path, const PWCHAR property);
};
