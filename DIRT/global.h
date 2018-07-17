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
		PTCHAR         ObjectPath;
		PTCHAR         DriverServiceName;
		vector<PTCHAR> SymbolicLinks;
		BOOL           OpenDACL;
	} DEVICE, *PDEVICE;

	typedef struct _DRIVER {
		PTCHAR                 ServiceName;
		PTCHAR                 FilePath;
		LPQUERY_SERVICE_CONFIG ServiceConfig;
		vector<PDEVICE>        Devices;
	} DRIVER, *PDRIVER;
}

#define BUFFER_SIZE 0x1000