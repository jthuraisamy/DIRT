#pragma once

#include "global.h"
#include "dbgdrv.h"

#include <vector>

using namespace std;

class DIRT::ObjectManager
{
private:
	DIRT::DebugDriver debug_driver;

	NTOPENFILE                NtOpenFile;
	NTCREATEFILE              NtCreateFile;
	NTOPENDIRECTORYOBJECT     NtOpenDirectoryObject;
	NTQUERYDIRECTORYOBJECT    NtQueryDirectoryObject;
	NTOPENSYMBOLICLINKOBJECT  NtOpenSymbolicLinkObject;
	NTQUERYSYMBOLICLINKOBJECT NtQuerySymbolicLinkObject;
	NTQUERYSECURITYOBJECT     NtQuerySecurityObject;
	NTQUERYSYSTEMINFORMATION  NtQuerySystemInformation;
	RTLINITUNICODESTRING      RtlInitUnicodeString;

public:
	DIRT::ObjectManager();
	PWCHAR                                GetDriverFileName(const PWCHAR ptr_driver_service_name);
	PWCHAR                                GetDriverFileName(const PDRIVER_OBJECT ptr_driver_object);
	PWCHAR                                GetDriverServiceNameFromDevice(const PWCHAR ptr_target_directory_path, const PWCHAR ptr_target_object_name);
	PDRIVER_OBJECT                        GetDriverObject(const PWCHAR ptr_target_directory_path, const PWCHAR ptr_target_object_name);
	PDEVICE_OBJECT                        GetDeviceObject(const PWCHAR ptr_target_directory_path, const PWCHAR ptr_target_object_name);
	PWCHAR                                GetObjectNameFromAddress(const PWCHAR ptr_target_directory_path, const PVOID ptr_target_object_address);
	PVOID                                 GetObjectAddressFromName(const PWCHAR ptr_target_directory_path, const PWCHAR ptr_target_object_name);
	vector<POBJECT_DIRECTORY_INFORMATION> GetDirectoryObjects(const PWCHAR ptr_path);
	HANDLE                                GetObjectDirectoryHandle(const PWCHAR ptr_path);
	PVOID                                 GetObjectDirectoryAddress(const HANDLE hnd_directory);

protected:
	PWCHAR ConvertNtPathToWin32Path(const PWCHAR ptr_nt_path);
};