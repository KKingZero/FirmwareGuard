# FirmwareGuard Current Status

This file tracks what is verified in the current tree versus what is prototype
or planned. It is intentionally build-focused and should be updated whenever
features move into or out of the default CLI.

## Verified In This Tree

| Area | Status | Verification |
| --- | --- | --- |
| Main userspace CLI | Builds | `make CC=/usr/bin/gcc` |
| Help UX | Works as standalone command | `./firmwareguard --help` |
| Safety and UEFI safety tests | Pass | `CC=/usr/bin/gcc ./tools/run-tests.sh` |
| ARM-safe sidecar binary | Builds/tests | `make -f Makefile.arm test CC=/usr/bin/gcc` |
| Kernel module | Builds on tested Fedora kernel | `make CC=/usr/bin/gcc` from `kernel/` |
| HECI standalone test program | Builds standalone | `make CC=/usr/bin/gcc` from `src/monitor/` |

## Default CLI Surface

These commands are currently wired through `src/main.c` and built into
`./firmwareguard`:

- `scan`
- `block`
- `report`
- `panic`
- `smm-scan`
- `uefi-enum`
- `uefi-extract`
- `bootguard-status`
- `bootguard-policy`
- `secureboot-audit`
- `txt-audit`
- `sgx-enum`
- `tpm-measurements`
- `trusted-boot-full`
- `baseline-capture`
- `baseline-compare`
- `implant-scan`
- `compliance`

## Source Present But Not Default-CLI Wired

These modules exist in source form but are not exposed as default CLI commands
yet. Some may compile as support objects while their command wiring remains
deferred:

- Ghidra wrapper
- checksum database
- CVE database
- threat intelligence database
- firmware rootkit scanner
- live dump module
- HECI monitor CLI integration
- SPI userspace monitor CLI integration
- UEFI runtime integrity CLI integration
- coreboot migration CLI integration

## Planned Or Deferred

- PDF reporting
- scheduled/systemd timer scans
- RISC-V support
- ARM parity with x86 blocking
- release packaging refresh
