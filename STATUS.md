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
| Graduated advisory/analysis modules | Wired + smoke-tested | `./tools/test-graduated-cli.sh` |

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
- `uefi-integrity` — read-only UEFI runtime integrity scan
- `coreboot-check` — read-only Coreboot/Libreboot compatibility advisory
- `ghidra-analyze` — local Ghidra firmware analysis
- `live-dump` — dump capability dry-run by default; explicit targets only

The database commands seed an empty SQLite store on first run from the bundled
JSON corpora in `data/` (`cve_firmware.json`, `threat_intel.json`,
`known_firmware.json`). The `.db` files are runtime artifacts (gitignored).
The HECI and SPI monitors degrade gracefully when `/dev/mei0` / `/dev/fwguard`
are absent.

## Graduated Module Safety Notes

- `uefi-integrity` reads EFI sysfs state only. It returns a supported/unsupported
  assessment without requiring root for the default scan path.
- `coreboot-check` loads `data/coreboot_boards.json` through `FG_DATA_DIR` or the
  repository `data/` directory and provides advisory output only. Backup,
  flashing, and migration write paths are not exposed through this command.
- `ghidra-analyze <firmware.bin>` uses only local Ghidra installations
  (`GHIDRA_HOME` or common install paths) and bundled scripts.
- `live-dump` is a dry-run capability check unless `--acpi`, `--optionrom`,
  `--spi`, or `--smram` is selected. SPI and SMRAM require `--dangerous`, root,
  and confirmation unless `--yes` is supplied. Unsupported devices/tools are
  reported cleanly.

## Source Present But Not Default-CLI Wired (Deferred)

These items remain intentionally deferred:

- Dangerous-tier remediation — ME HAP/UEFI variable modification remains gated
  behind explicit dangerous selection and Secure-Boot checks; no firmware
  flashing or ME-cleaner style writes are wired.
- PDF reporting
- scheduled/systemd timer scans

## Planned Or Deferred

- RISC-V support
- ARM parity with x86 blocking
- release packaging refresh
