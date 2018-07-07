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
	NTOPENDIRECTORYOBJECT     NtOpenDirectoryObject;
	NTQUERYDIRECTORYOBJECT    NtQueryDirectoryObject;
	NTOPENSYMBOLICLINKOBJECT  NtOpenSymbolicLinkObject;
	NTQUERYSYMBOLICLINKOBJECT NtQuerySymbolicLinkObject;
	NTQUERYSECURITYOBJECT     NtQuerySecurityObject;
	NTQUERYSYSTEMINFORMATION  NtQuerySystemInformation;
	RTLINITUNICODESTRING      RtlInitUnicodeString;

public:
	DIRT::ObjectManager();
	PWCHAR                                getDriverName(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName);
	PDEVICE_OBJECT                        getDeviceObject(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName);
	PWCHAR                                getObjectName(const PWCHAR targetDirectoryPath, const PVOID targetObjectAddress);
	PVOID                                 getObjectAddress(const PWCHAR targetDirectoryPath, const PWCHAR targetObjectName);
	HANDLE                                getObjectDirectoryHandle(const PWCHAR path);
	PVOID                                 getObjectDirectoryAddress(const HANDLE hDirectory);
	vector<POBJECT_DIRECTORY_INFORMATION> getDirectoryObjects(const PWCHAR path);
};