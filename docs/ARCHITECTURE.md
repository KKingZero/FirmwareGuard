# FirmwareGuard Architecture

## Overview

FirmwareGuard is a modular, low-level framework for detecting firmware telemetry components on x86/x64 systems. This document describes the technical architecture and design decisions.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       CLI Interface                          │
│                      (src/main.c)                            │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────┼────────────┬─────────────┐
        │            │            │             │
        ▼            ▼            ▼             ▼
   ┌────────┐  ┌─────────┐  ┌─────────┐  ┌──────────┐
   │ Probe  │  │ Blocker │  │Reporter │  │  Audit   │
   │ Module │  │ Module  │  │ Module  │  │  Engine  │
   └────┬───┘  └─────────┘  └─────────┘  └──────────┘
        │
   ┌────┴────────────────────┐
   │    Probe Orchestrator   │
   │     (probe.c)           │
   └────┬────────────────────┘
        │
   ┌────┴────────┬───────┬──────┬──────┐
   │             │       │      │      │
   ▼             ▼       ▼      ▼      ▼
┌─────┐     ┌──────┐ ┌─────┐ ┌────┐ ┌──────┐
│ MSR │     │ME/PSP│ │ACPI │ │NIC │ │UEFI  │
│     │     │      │ │     │ │    │ │(TBD) │
└─────┘     └──────┘ └─────┘ └────┘ └──────┘
```

---

## Core Modules

### 1. MSR Module (`src/core/msr.c`)

**Purpose:** Direct access to CPU Model-Specific Registers

**Key Functions:**
- `msr_init()` - Opens `/dev/cpu/*/msr` devices
- `msr_read()` - Reads 64-bit MSR value
- `msr_write()` - Writes MSR (used cautiously)

**Hardware Access:**
- Device files: `/dev/cpu/N/msr`
- Requires: `msr` kernel module
- Privilege: Root

**Use Cases:**
- CPU feature detection
- Vendor-specific telemetry bits
- ME/PSP status registers (on some platforms)

---

### 2. ME/PSP Module (`src/core/me_psp.c`)

**Purpose:** Detect Intel Management Engine and AMD PSP

#### Intel ME Detection

**Method 1: PCI Configuration Space**
- Bus 0, Device 22, Function 0 (MEI/HECI device)
- Reads vendor/device ID via I/O ports 0xCF8/0xCFC
- Confirms Intel vendor ID (0x8086)

**Method 2: MMIO Registers**
- Base address: 0xFED10000
- Reads ME_FW_STATUS1 (offset 0x40)
- Parses operation mode bits:
  - 0 = Normal operation
  - 3 = Temporary disable
  - 4 = HAP/AltMeDisable (fully disabled)

**Method 3: Sysfs**
- `/sys/kernel/debug/mei/mei0/devstate`
- Extracts version string

#### AMD PSP Detection

**Method 1: CPUID**
- Leaf 0x8000001F - SEV capabilities
- Presence of SEV implies PSP is active

**Method 2: MSRs**
- Reads AMD patch level MSR (0x8B)
- Detects secure VM support

---

### 3. ACPI Module (`src/core/acpi.c`)

**Purpose:** Parse ACPI tables for telemetry indicators

**Data Source:** `/sys/firmware/acpi/tables/`

**Tables of Interest:**
- **FPDT** (Firmware Performance Data Table) - Boot metrics collection
- **TPM2** - Trusted Platform Module 2.0
- **DMAR** - Intel VT-d (DMA remapping, can leak data)
- **IVRS** - AMD IOMMU
- **OEM Tables** - Vendor-specific (potential telemetry)

**Detection Logic:**
```c
// Scan /sys/firmware/acpi/tables
// For each table:
//   - Check signature against known telemetry tables
//   - Flag suspicious OEM tables (prefixed with _ or OEM*)
//   - Extract table contents if needed
```

---

### 4. NIC Module (`src/core/nic.c`)

**Purpose:** Detect network interface telemetry capabilities

**Data Sources:**
- `/sys/class/net/*` - Interface enumeration
- `/sys/class/net/*/device/vendor` - PCI vendor ID
- `/sys/class/net/*/device/driver` - Driver name
- ethtool GDRVINFO ioctl - Firmware version

**Capabilities Detected:**
1. **Wake-on-LAN**
   - Source: `/sys/class/net/*/device/power/wakeup`
   - Risk: Remote wake (potential data exfil channel)

2. **Intel AMT** (Active Management Technology)
   - Heuristic: Intel vendor ID + device ID in vPro range
   - Device IDs: 0x1502-0x1533, 0x153A-0x153B
   - Risk: Out-of-band management, independent network stack

3. **Statistics Reporting**
   - All NICs with drivers report stats to kernel
   - Low risk, but can leak usage patterns

---

### 5. Probe Orchestrator (`src/core/probe.c`)

**Purpose:** Coordinate all detection modules

**Workflow:**
```
1. Initialize subsystems (MSR, ACPI, NIC)
2. Detect CPU vendor (Intel vs AMD)
3. Probe appropriate chipset (ME or PSP)
4. Scan ACPI tables
5. Enumerate NICs
6. Calculate risk score
7. Generate summary
```

**Risk Scoring Algorithm:**
```
score = 0
if (Intel ME active):        score += 3
if (Intel ME has AMT):       score += 2
if (AMD PSP active):         score += 2
if (TPM present):            score += 2
if (FPDT present):           score += 1
for each NIC with remote mgmt: score += 3

Risk Level:
  CRITICAL: score >= 8
  HIGH:     score >= 5
  MEDIUM:   score >= 3
  LOW:      score >= 1
  NONE:     score == 0
```

---

### 6. Blocker Module (`src/block/blocker.c`)

**Purpose:** Generate mitigation recommendations (MVP: non-destructive)

**Current Capabilities:**
- Intel ME: HAP bit, me_cleaner, BIOS settings
- AMD PSP: Kernel parameters, BIOS options
- Wake-on-LAN: ethtool disable (temporary)

**Future (Phase 2):**
- MSR writes for soft-disable
- UEFI variable modification
- Kernel module for DMA restriction

---

### 7. Reporter Module (`src/audit/reporter.c`)

**Purpose:** Generate human-readable and JSON reports

**Output Formats:**

#### JSON Format
```json
{
  "firmwareguard_version": "0.1.0-MVP",
  "timestamp": 1731974400,
  "overall_risk": "HIGH",
  "components": [...]
}
```

#### Text Format
```
========================================
  FIRMWAREGUARD AUDIT REPORT v0.1.0-MVP
========================================
[Component details with risk levels]
```

---

## Data Flow

### Scan Command
```
User → CLI
  → probe_init()
  → probe_scan_hardware()
    → detect_cpu_vendor()
    → probe_intel_me() OR probe_amd_psp()
    → acpi_scan_telemetry()
    → nic_scan()
    → probe_assess_risk()
  → probe_to_audit()
  → reporter_generate_audit_report()
```

### Block Command
```
User → CLI
  → probe_scan_hardware()
  → blocker_attempt_blocking()
    → blocker_disable_intel_me() (recommendation)
    → blocker_disable_amd_psp() (recommendation)
    → blocker_disable_wol() (actual attempt via ethtool)
  → reporter_generate_combined_report()
```

---

## Security Design

### Privilege Requirements

**Root Required For:**
- `/dev/mem` - MMIO access (ME registers)
- `/dev/cpu/*/msr` - MSR reads
- I/O ports 0xCF8/0xCFC - PCI config space
- ethtool - NIC configuration

### Safety Guarantees

**MVP (Current Release):**
- Read-only hardware access
- No firmware modifications
- No MSR writes (msr_write exists but unused)
- No PCI config writes
- Temporary WoL disable (non-persistent)

**Future Phases:**
- User confirmation for destructive operations
- Backup mechanisms for UEFI variables
- Rollback capability

---

## Error Handling

### Return Codes
```c
#define FG_SUCCESS          0
#define FG_ERROR           -1
#define FG_NO_PERMISSION   -2
#define FG_NOT_FOUND       -3
#define FG_NOT_SUPPORTED   -4
```

### Graceful Degradation
- If MSR access fails, continue with other probes
- If ACPI tables inaccessible, report limitation
- If NIC enumeration fails, skip NIC checks

---

## Performance Considerations

**Execution Time:** ~100-500ms for full scan

**Breakdown:**
- MSR init: ~10ms (module load + file opens)
- PCI scan: ~20ms
- ACPI parse: ~50ms (directory traversal)
- NIC scan: ~100ms (sysfs reads + ethtool)
- Report generation: ~10ms

**Optimization:**
- Lazy MSR device opening (only when needed)
- Cached CPU count
- Single-pass directory scans

---

## Future Architecture

### Phase 2: Active Blocking

```
┌────────────────┐
│ Kernel Module  │  ← DMA restriction
└────────────────┘  ← MMIO write protection
        ↕
┌────────────────┐
│  FirmwareGuard │
│   Userspace    │
└────────────────┘
```

### Phase 3: Distributed Scanning

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│ Agent 1  │────→│ Central  │←────│ Agent N  │
└──────────┘     │Dashboard │     └──────────┘
                 └──────────┘
```

---

## Build System

**Makefile Targets:**
- `make` - Build binary
- `make clean` - Remove artifacts
- `make install` - Install to /usr/local/bin
- `make debug` - Build with debug symbols

**Dependencies:**
- GCC or compatible C compiler
- Linux headers (for MSR/MMIO access)
- ethtool (runtime, for NIC control)

---

## Testing Strategy

**Unit Tests (Future):**
- MSR read/write validation
- ACPI parsing edge cases
- Risk scoring algorithm

**Integration Tests:**
- Full scan on known hardware
- JSON output validation
- Privilege checks

**Manual Testing:**
- Intel platforms (ME present)
- AMD platforms (PSP present)
- Virtual machines (ME absent)

---

## Contribution Guidelines

**Code Style:**
- K&R style C
- 4-space indentation
- Descriptive function names
- Comments for complex hardware interactions

**Adding New Probes:**
1. Create `src/core/newprobe.c` and `.h`
2. Add to `probe_scan_hardware()`
3. Update risk scoring in `probe_assess_risk()`
4. Add to Makefile
5. Document in README

---

**Document Version:** 1.0
**Last Updated:** 2025-11-19
**Status:** Phase 1 MVP Complete
