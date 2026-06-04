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
| Phase-4 module commands | Wired + functional | `./firmwareguard cve-check "Intel Management Engine (ME)" 6.0.0` |

## Default CLI Surface

These commands are dispatched through the command table in `src/cli/` (see
`cli_table.c`) and built into `./firmwareguard`:

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

## ARM / aarch64 Build (this branch)

On `aarch64`/`arm*`/`arm64` hosts (or with `make ARCH=aarch64`), the Makefile
builds a reduced, architecture-neutral binary. The x86-only modules (MSR, SMM,
Boot Guard, TXT/SGX, ME/PSP, baseline, implant, compliance, HECI/SPI) use
CPUID/RDMSR and are excluded from the build entirely; their command names remain
registered but resolve to a clean "not applicable on this architecture" stub.

### macOS (Apple Silicon)

The same ARM build runs on macOS: Apple Silicon reports `arm64` from `uname -m`,
so `make` selects the reduced build automatically. The Makefile is OS-aware
(`uname -s`): on Darwin it drops the GNU-only hardening/linker flags clang/ld64
rejects and links against Homebrew OpenSSL (`brew install openssl@3`; macOS ships
libsqlite3). The OS-portable commands — `cve-check`, `threat-scan`,
`rootkit-scan`, `integrity-verify` (pure SQLite/OpenSSL/file IO) — are the
meaningful surface on macOS; the Linux-sysfs probes (`acpi-scan`, `nic-scan`,
`uefi-enum`, `arm-detect`) compile and run but find nothing without `/sys`.
Validated by the `macos-build` CI job. (macOS Intel is out of scope — it would
select the x86 build, which needs Linux MSR/sysfs.)

ARM commands with real handlers:

- `arm-detect` — ARM firmware-surface detection (UEFI/ACPI/DeviceTree/TEE/OP-TEE)
- `acpi-scan`, `nic-scan`, `uefi-enum` — architecture-neutral telemetry/probes
- `cve-check`, `threat-scan`, `rootkit-scan`, `integrity-verify` — DB/file based
- `panic` — mitigation guidance

Deferred for ARM: `baseline-capture/compare/drift` (reads x86 CPUID/MSR; an ARM
`/proc/cpuinfo` path is planned) and `compliance` (x86-centric control mapping).
The standalone `firmwareguard-arm` sidecar (`make -f Makefile.arm`) is unchanged.

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

## Planned Or Deferred

- PDF reporting
- scheduled/systemd timer scans
- RISC-V support
- ARM parity with x86 blocking
- release packaging refresh
