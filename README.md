# DIRT: Driver Initial Reconnaissance Tool
This tool can be used to get an initial assessment of drivers installed on a Windows system (e.g. master images developed by OEMs or enterprises). It's supposed to make it easier to find targets, low-hanging fruit and provide some help with deep-dive binary analysis.

🚧 **Currently unstable, undergoing active development.** 🚧

## Planned Features

- **Listing of kernel-mode drivers non-administrative users can interact with via DeviceIoControl.**
  - This can be useful to narrow down on (third-party) drivers that can potentially be used toward LPE.
- **Resolution of the IRP_MJ_DEVICE_CONTROL function used to handle requests from DeviceIoControl.**
  - This makes it easier to find the function in IDA (versus relying on heuristics in static analysis).
  - The function can be analyzed to enumerate IOCTL codes and perform attack surface analysis.
- **Enumeration of the IOCTL codes supported by IRP_MJ_DEVICE_CONTROL.**
  - There might be an opportunity for symbolic execution like [this](http://jackson.thuraisamy.me/pyexz3-hevd.html), but not sure how robust it can be.
- **Enumeration of user-mode drivers that make calls to a given kernel-mode driver.**

## Alternative Tools

Currently a combination of DeviceTree, WinObjEx64, and WinDbg are used. It's more of a tedious manual process that doesn't scale easily, so DIRT just attempts to make it more convenient.

## Authorship

Jackson Thuraisamy (2018). The code is heavily derived from the [WinObjEx64](https://github.com/hfiref0x/WinObjEx64) project by [@hFireF0X](https://twitter.com/hfiref0x?lang=en).

## Licence

MIT