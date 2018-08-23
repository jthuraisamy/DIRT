# DIRT: Driver Initial Reconnaissance Tool

I'm writing this tool to learn C++ and get an initial assessment of drivers installed on a Windows system (e.g. master images developed by OEMs or enterprises). It's supposed to help with target selection, finding low-hanging fruit, and some assistance with deep-dive binary analysis. **Currently unstable, undergoing active development.**

[![](https://ci.appveyor.com/api/projects/status/github/jthuraisamy/DIRT?branch=master&svg=true&passingText=Download)](https://ci.appveyor.com/project/jthuraisamy/dirt/build/artifacts)

## Primary Features

- [x] **Listing of kernel-mode drivers non-administrative users can interact with via DeviceIoControl.**
  - This can be useful to narrow down on drivers that can potentially be used toward LPE.
- [x] **Retrieval of company names associated with drivers to determine ownership.**
  - This can be useful in target selection to separate third-party drivers from Microsoft drivers.
- [x] **Resolution of the DispatchDeviceControl routine used to handle requests from DeviceIoControl.**
  - This makes it easier to find the function in IDA (versus relying on heuristics in static analysis).
  - The function can be analyzed to enumerate IOCTL codes and perform attack surface analysis.
- [ ] **Enumeration of the IOCTL codes supported by DispatchDeviceControl.**
  - There might be an opportunity for symbolic execution like [this](http://jackson.thuraisamy.me/pyexz3-hevd.html), but not sure how robust it can be.
- [ ] **Enumeration of user-mode drivers that make calls to a given kernel-mode driver.**

## Secondary Features

- [ ] CLI and GUI modes.
- [ ] Output formats: JSON, CSV, and human readable text.

## Alternative Tools

I've used a combination of DeviceTree, WinObjEx64, and WinDbg for these use-cases. It's more of a tedious manual process that doesn't scale easily, so DIRT just attempts to make it more convenient.

## Building

This should compile with Visual Studio 2015 or greater.

## Usage

1. Enable debug mode with `bcdedit -debug on` with an administrative Command Prompt.
2. Place [`kldbgdrv.sys`](https://github.com/hfiref0x/WinObjEx64/raw/master/Source/drvstore/kldbgdrv.sys) (found with WinDbg) in the same directory as `DIRT.exe`.
3. Run `DIRT.exe > output.txt` with administrative privileges.

The `--lp-only` and `--no-msft` switches can be used to filter results.

Below is some sample output to know what to expect:

```
DIRT v0.1.0: Driver Initial Reconnaisance Tool (@Jackson_T)
Repository:  https://github.com/jthuraisamy/DIRT
Compiled on: Aug 22 2018 00:01:04

INFO: Hiding Microsoft drivers (--no-msft).
INFO: Only showing drivers that low-privileged users can interface with (--lp-only).

Capcom: Capcom
Path: C:\Windows\System32\Capcom.sys
DispatchDeviceControl: 0xFFFFF8024C9A0590
Devices: 1
└── \Device\Htsysm72FB (open DACL, 1 symlinks)
    └── \\.\Global\Htsysm72FB

SmbDrvI: SmbDrvI (Synaptics Incorporated)
Path: C:\WINDOWS\System32\drivers\Smb_driver_Intel.sys - Hooked by Wdf01000 (Microsoft Corporation)
DispatchDeviceControl: 0xFFFFF808212C72B0
Devices: 1
└── \Device\SmbDriver (open DACL, 1 symlinks)
    └── \\.\Global\SmbDriver

nvlddmkm: nvlddmkm
Path: C:\Windows\System32\DriverStore\FileRepository\nvlt.inf_amd64_ed3ba3fb30d4dd86\nvlddmkm.sys
DispatchDeviceControl: 0xFFFFF80822D074D0
Devices: 2
├── \Device\NvAdminDevice (open DACL, 1 symlinks)
│   └── \\.\Global\NvAdminDevice
└── \Device\UVMLiteController0x1 (open DACL, 1 symlinks)
    └── \\.\Global\UVMLiteController
```

There is also a CSV output available using `DIRT::Main::ExportCSV()`:

![](https://i.imgur.com/lTefDUR.png)

## Authors

Jackson Thuraisamy (2018). The code is heavily derived from the [WinObjEx64](https://github.com/hfiref0x/WinObjEx64) project by [@hFireF0X](https://twitter.com/hfiref0x?lang=en).

## Licence

MIT
