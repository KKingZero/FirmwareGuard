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
| Tier-1 hardening dry-run/rollback code | Wired | `./firmwareguard harden`, `./firmwareguard rollback --list-backups` |
| ARM-safe sidecar binary | Builds/tests | `make -f Makefile.arm test CC=/usr/bin/gcc` |
| Kernel module | Builds on tested Fedora kernel | `make CC=/usr/bin/gcc` from `kernel/` |
| HECI standalone test program | Builds standalone | `make CC=/usr/bin/gcc` from `src/monitor/` |
| Phase-4 module commands | Wired + functional | `./firmwareguard cve-check "Intel Management Engine (ME)" 6.0.0` |

## Default CLI Surface

These commands are dispatched through the command table in `src/cli/` (see
`cli_table.c`) and built into `./firmwareguard`:

- `scan`
- `block`
- `harden`
- `rollback`
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
- `baseline-drift`
- `implant-scan`
- `acpi-scan`
- `nic-scan`
- `intel-me`
- `amd-psp`
- `compliance`
- `cve-check` — CVE correlation database (`src/database/cve_db.c`)
- `threat-scan` — threat-intel IOC database (`src/database/threat_intel.c`)
- `rootkit-scan` — firmware rootkit scanner (`src/rootkit/rootkit_detect.c`)
- `integrity-verify` — supply-chain checksum DB (`src/integrity/checksum_db.c`)
- `heci-monitor` — Intel ME/HECI monitor (`src/monitor/heci_monitor.c`)
- `spi-status` — SPI flash protection monitor (`src/monitor/spi_monitor.c`)

The database commands seed an empty SQLite store on first run from the bundled
JSON corpora in `data/` (`cve_firmware.json`, `threat_intel.json`,
`known_firmware.json`). The `.db` files are runtime artifacts (gitignored).
The HECI and SPI monitors degrade gracefully when `/dev/mei0` / `/dev/fwguard`
are absent.

## Source Present But Not Default-CLI Wired (Deferred)

These modules remain in-tree but are intentionally not linked into the default
binary, each with a concrete blocker:

- Ghidra wrapper — requires an external Ghidra install + Python scripts; large
  attack surface, unusable in headless/restricted environments.
- live dump module — SMRAM/ME dump paths are stubbed (`DUMP_STATUS_NOT_SUPPORTED`)
  and depend on a kernel-module IOCTL that is not yet implemented.
- coreboot migration — functional but depends on a manually-maintained board
  compatibility database; niche, better as a standalone tool.
- UEFI runtime integrity CLI integration — module compiles; command wiring
  deferred.
- Dangerous-tier remediation — ME HAP/UEFI variable modification remains gated
  behind explicit dangerous selection and Secure-Boot checks; no firmware
  flashing or ME-cleaner style writes are wired.

## Planned Or Deferred

- PDF reporting
- scheduled/systemd timer scans
- RISC-V support
- ARM parity with x86 blocking
- release packaging refresh
