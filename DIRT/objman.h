#pragma once

#include "global.h"
#include "dbgdrv.h"

#include <vector>

using namespace std;

class DIRT::ObjectManager
{
private:
	DIRT::DebugDriver dbgDriver;

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
	PWCHAR                                getDriverFileName(const PWCHAR driverServiceName);
	PWCHAR                                getDriverFileName(const PDRIVER_OBJECT driverObject);
	PWCHAR                                getDriverServiceNameFromDevice(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName);
	PDRIVER_OBJECT                        getDriverObject(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName);
	PDEVICE_OBJECT                        getDeviceObject(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName);
	PWCHAR                                getObjectNameFromAddress(const PWCHAR targetDirectoryPath, const PVOID targetObjectAddress);
	PVOID                                 getObjectAddressFromName(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName);
	HANDLE                                getObjectDirectoryHandle(const PWCHAR path);
	PVOID                                 getObjectDirectoryAddress(const HANDLE hDirectory);
	vector<POBJECT_DIRECTORY_INFORMATION> getDirectoryObjects(const PWCHAR path);

protected:
	PWCHAR convertNtPathToWin32Path(const PWCHAR ntPath);
};