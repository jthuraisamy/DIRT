#pragma once

#include "global.h"
#include "objman.h"

#include <aclapi.h>

class DIRT::Main
{
	DIRT::ObjectManager       om;
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
	LPQUERY_SERVICE_CONFIG getDriverServiceConfig(const PWCHAR driverServiceName);
	bool                   isObjectPubliclyWritable(PEXPLICIT_ACCESS* peaEntries, const ULONG ulEntryCount);
	int                    getObjectDACL(const PWCHAR path, _Out_ PEXPLICIT_ACCESS* peaEntries, _Out_ PULONG pulEntryCount);
	int                    getLinkTarget(const HANDLE rootDirectory, const PUNICODE_STRING objectName, _Out_ PWCHAR wcTargetName);
	int                    getDeviceDriver(const PWCHAR pwcPath);

private:
	//int getDriverObject(const PWCHAR pwcPath) const;
};