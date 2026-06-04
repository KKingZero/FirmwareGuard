# FirmwareGuard v1.1.0 - Next Steps & Roadmap

## Test Results Summary

### Working Commands (Tested 2025-12-08)

| Command | Status | Notes |
|---------|--------|-------|
| `uefi-enum` | Working | Found 143 variables, Secure Boot status detected |
| `sgx-enum` | Working | SGX not supported on test system |
| `secureboot-audit` | Working | Shows key enrollment status, risk assessment |
| `implant-scan` | Working | DMA/IOMMU analysis, 7 findings detected |
| `baseline-capture` | Partial | Works but MSR errors without root |
| `smm-scan` | Requires Root | Expected behavior |
| `bootguard-status` | Requires Root | Expected behavior |
| `txt-audit` | Requires Root | Expected behavior |

### Known Issues

1. **MSR Access Errors** (Low Priority)
   - Error: `CPU 0 out of range (max: -1)` when running without root
   - Location: `src/core/msr.c`
   - Impact: Confusing error message, functionality works as expected
   - Fix: Improve error handling to show cleaner "requires root" message

2. **Help Flag UX** (Low Priority)
   - `./firmwareguard --help` shows error before help text
   - Should recognize `--help` as valid standalone argument
   - Location: `src/main.c:print_usage()`

---

## Remaining Phase 3 Tasks

### 1. PDF Report Generation
- **Status**: Pending
- **Dependency**: libharu library
- **Features**:
  - Executive summary with risk overview
  - Pie charts for risk distribution
  - Detailed findings with evidence
  - Compliance mapping tables
  - Timeline of baseline changes

**Implementation Steps**:
```
1. Add libharu dependency to Makefile
2. Create src/report/pdf_generator.h
3. Create src/report/pdf_generator.c
4. Add chart rendering functions
5. Integrate with existing scan results
6. Add `--pdf` output option
```

### 2. NIST 800-171 & GDPR Art.32 Compliance Mapping
- **Status**: Pending
- **Features**:
  - Map findings to NIST 800-171 controls
  - Map findings to GDPR Article 32 requirements
  - Compliance score calculation
  - Gap analysis reporting

**Control Mappings**:
```
SMM Security     -> NIST 3.4.1, 3.14.1
Secure Boot      -> NIST 3.4.5, GDPR Art.32(1)(b)
Boot Guard       -> NIST 3.4.5, 3.13.1
IOMMU/DMA        -> NIST 3.1.1, 3.13.1
Baseline Changes -> NIST 3.4.4, 3.14.6
```

### 3. Event-Driven & Scheduled Scanning
- **Status**: Pending
- **Features**:
  - Systemd timer integration
  - udev rule hooks for USB/PCI hotplug
  - Configurable scan schedules
  - Alert notifications (syslog, email templates)

**Files to Create**:
```
systemd/firmwareguard-scan.timer
systemd/firmwareguard-scan.service
udev/99-firmwareguard.rules
src/scheduler/scheduler.c
```

### 4. ARM Ampere Altra Support
- **Status**: Pending
- **Features**:
  - ARM64 MSR equivalents
  - SBSA compliance checks
  - Arm SystemReady certification validation
  - RAS (Reliability, Availability, Serviceability) detection

**Architecture Changes**:
```
1. Add #ifdef __aarch64__ blocks
2. Implement ARM-specific MSR access
3. Add ACPI PPTT table parsing
4. Test on Ampere Altra hardware
```

### 5. RISC-V SiFive Support
- **Status**: Pending
- **Features**:
  - RISC-V CSR access
  - PMP (Physical Memory Protection) detection
  - OpenSBI version detection
  - SiFive-specific security features

---

## Phase 4 Features (Future)

### High Priority
- [ ] Ghidra scripting suite for firmware analysis
- [ ] Supply chain checksum database
- [ ] Rootkit detection (behavioral + signatures)
- [ ] Live firmware memory dump

### Medium Priority
- [ ] Intel ME traffic monitoring (HECI)
- [ ] UEFI runtime integrity checks
- [ ] SPI write protection alerts
- [ ] Coreboot migration assistant

### Lower Priority
- [ ] CVE correlation database
- [ ] Threat intelligence integration
- [ ] AI/ML anomaly detection (deferred)

---

## Quick Fixes Queue

### Bug Fixes
```c
// src/core/msr.c - Improve error message
// Current: "CPU 0 out of range (max: -1)"
// Fix: Check if cpu_count <= 0 before attempting read
if (cpu_count <= 0) {
    FG_LOG_ERROR("MSR driver not available - run with sudo");
    return FG_NO_PERMISSION;
}
```

### UX Improvements
```c
// src/main.c - Handle --help as standalone
// Add before command check:
if (argc >= 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
    print_usage(argv[0]);
    return 0;
}
```

---

## Build & Test Commands

```bash
# Full build
make clean && make

# Debug build
make debug

# Run all tests (as root)
sudo ./firmwareguard scan
sudo ./firmwareguard smm-scan
sudo ./firmwareguard bootguard-status
sudo ./firmwareguard txt-audit
sudo ./firmwareguard baseline-capture -o baseline.dat
sudo ./firmwareguard baseline-compare -o baseline.dat

# Non-root tests
./firmwareguard uefi-enum
./firmwareguard sgx-enum
./firmwareguard secureboot-audit
./firmwareguard implant-scan

# JSON output tests
./firmwareguard uefi-enum --json
./firmwareguard implant-scan --json
./firmwareguard secureboot-audit --json
```

---

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for contribution guidelines.

Priority areas for contribution:
1. ARM64 platform testing
2. Additional pattern definitions
3. PDF report templates
4. Compliance mapping documentation

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v1.1.0 | 2025-12-08 | Phase 3: Detection modules, baseline capture, implant detection |
| v1.0.0 | - | Phase 2: Safety framework, blocking, UEFI/GRUB manipulation |
| v0.2.0-beta | - | Phase 1: Initial detection framework |
