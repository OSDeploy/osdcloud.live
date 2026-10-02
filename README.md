# osdcloud.live

Documentation on how to use this repository is posted at:

<https://www.osdcloud.com/osdcloud-live/about>

## Privacy

osdcloud.live Privacy Policy is shared with OSDCloud. Please review the Privacy statement at:

<https://github.com/OSDeploy/OSDCloud/blob/main/PRIVACY.md>

## Overview

This repository contains the working files that support the osdcloud.live experience. It is currently focused on validating installation flows, device preparation, and OOBE/WinPE automation before promoting them to production use.

## Exporting OEM drivers

[`scripts/exportoem.ps1`](scripts/exportoem.ps1) exports installed device drivers from the current Windows installation for reuse in OSDCloud. Run it from an elevated PowerShell session:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod -Uri 'https://exportoem.osdcloud.live')"
```

The script enumerates connected devices with `pnputil.exe` and exports their installed OEM drivers with `pnputil.exe /export-driver`. It creates separate Windows and WinPE driver collections, organized by device class, manufacturer, and device description. WinPE exports are limited to driver classes selected for WinPE; the Windows collection includes the enumerated OEM drivers. Each collection also includes a `pnputil.txt` inventory.

### Export destination

The script uses the first volume it finds that meets all of these conditions:

- Its volume label is `OSDCloud`.
- It contains an `OSDCloud` directory at its root.
- It has **more than 10 GB** of free space.

On a qualifying USB volume, Windows drivers are exported to `<drive>:\OSDCloud\ModelDrivers\<manufacturer>_<modelId>_<model>_<build>`, regardless of architecture. WinPE drivers are exported to `<drive>:\OSDCloud\OSDeployCore\boot-assets\winpedrivers-<arch>\<manufacturer>_<modelId>_<model>_<build>`. The WinPE architecture segment is `winpedrivers-amd64` or `winpedrivers-arm64`.

If no USB volume qualifies, the existing `%TEMP%` destinations are used:

```text
%TEMP%\ExportOEM\
├── drivers-<arch>\<manufacturer>_<modelId>_<model>_<build>\
└── winpedrivers-<arch>\<manufacturer>_<modelId>_<model>_<build>\
```

The Temp fallback uses `amd64` or `arm64` for both collections. The device folder suffix includes the Windows build number and update revision, such as `26100.9168`. For example, Windows drivers are exported to `%TEMP%\ExportOEM\drivers-amd64\Contoso_X1_Model_One_26100.9168`; WinPE drivers use the parallel `winpedrivers-amd64` path. Each device folder contains class and manufacturer subfolders with the exported driver packages.

The script requires administrator privileges, displays a diagnostic-data consent notice, and writes a transcript under `%SystemRoot%\Temp`. Review the [OSDCloud privacy policy](https://github.com/OSDeploy/OSDCloud/blob/main/PRIVACY.md) before running it.

## What to expect during testing

- Frequent changes while workflows and scripts stabilize
- Limited documentation depth; some modules may be undocumented or in flux
- Potential breaking changes without migration guidance until the test phase completes

## Contributing and feedback

- File issues with clear repro steps and logs where possible.
- When proposing changes, include updates to documentation alongside code updates.
- Expect iteration while we collect feedback and harden the flows.
