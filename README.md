# osdcloud.live

> Status: early testing; expect breaking changes and incomplete coverage.

## Overview

This repository contains the working files that support the osdcloud.live experience. It is currently focused on validating installation flows, device preparation, and OOBE/WinPE automation before promoting them to production use.

## What to expect during testing

- Frequent changes while workflows and scripts stabilize
- Limited documentation depth; some modules may be undocumented or in flux
- Potential breaking changes without migration guidance until the test phase completes

## Quick start

1) Clone this repository locally.
2) Review the scripts in the `modules/` and `archive/` directories to understand current coverage.
3) Run test workflows in an isolated lab environment only; do not use in production yet.

## Contributing and feedback

- File issues with clear repro steps and logs where possible.
- When proposing changes, include updates to documentation alongside code updates.
- Expect iteration while we collect feedback and harden the flows.

## Next steps

- Expand usage documentation once test scenarios finalize.
- Add validated end-to-end examples for OOBE and WinPE once stable.
