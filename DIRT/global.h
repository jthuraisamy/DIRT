#pragma once

#include "ntos.h"

#include <vector>

using namespace std;

namespace DIRT
{
	class Main;
	class DebugDriver;
	class ObjectManager;

	typedef struct _DEVICE {
		PWCHAR         ObjectPath;
		PWCHAR         DriverServiceName;
		vector<PWCHAR> SymbolicLinks;
		BOOL           OpenDACL;
	} DEVICE, *PDEVICE;

	typedef struct _DRIVER {
		PWCHAR                 ServiceName;
		PWCHAR                 CompanyName;
		PWCHAR                 FilePath;
		LPQUERY_SERVICE_CONFIG ServiceConfig;
		PDRIVER_OBJECT         DriverObject;
		vector<DEVICE>         Devices;
	} DRIVER, *PDRIVER;
}

#define BUFFER_SIZE 0x1000
