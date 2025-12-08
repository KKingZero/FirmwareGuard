# FirmwareGuard Phase 3 & 4 Implementation Plan
**Generated:** 2025-12-07
**Priority Order:** Detection First

---

## Implementation Summary

Based on project requirements, this document outlines the concrete implementation approach for Phase 3 and Phase 4 features.

### Key Decisions
- **Offline-only:** Skip all features requiring network connectivity
- **Linux-first:** Defer Windows/macOS to future phases
- **Detection priority:** Build detection capabilities before pattern database
- **Minimal dependencies:** Use lightweight libraries, avoid heavy frameworks

---

## Phase 3: Advanced Local Analysis & Hardening

### 3.1 Deep Firmware Analysis

#### 3.1.1 SMM (System Management Mode) Detection
**Approach:** MSR-based detection (document SMRAM parsing for future)

**Implementation:**
```c
// src/detection/smm_detect.c
- Read SMBASE from MSR 0x9E (IA32_SMBASE)
- Enumerate SMM entry points via MSR reads
- Detect SMM handler count via performance counters
- Report SMM configuration status
```

**CLI Command:**
```bash
firmwareguard smm-scan          # Full SMM analysis
firmwareguard smm-scan --brief  # Quick status check
```

**Future Enhancement (documented):**
- SMRAM region parsing (requires kernel module enhancement)
- Runtime SMM call monitoring via SMI counters

**Files to create/modify:**
- `src/detection/smm_detect.c` (new)
- `src/detection/smm_detect.h` (new)
- `include/firmwareguard.h` (add SMM structures)
- `src/cli/commands.c` (add smm-scan command)

---

#### 3.1.2 UEFI Driver Extraction & Analysis
**Approach:** Both methods combined (runtime + SPI analysis)

**Implementation:**

**Method 1: EFI Runtime Enumeration**
```c
// src/detection/uefi_enum.c
- Access EFI variables via /sys/firmware/efi/efivars/
- Enumerate loaded UEFI drivers
- Extract driver GUIDs and metadata
- Flag unsigned or unknown drivers
```

**Method 2: SPI Flash Analysis**
```c
// src/extraction/spi_extract.c
- Integration with flashrom for SPI dump
- Parse firmware volume structure
- Extract individual UEFI drivers (PE32/PE32+)
- Generate driver inventory with hashes
```

**CLI Commands:**
```bash
firmwareguard uefi-enum              # Runtime enumeration
firmwareguard uefi-extract           # SPI-based extraction
firmwareguard uefi-extract --output /path/to/dir
```

**Files to create/modify:**
- `src/detection/uefi_enum.c` (new)
- `src/extraction/spi_extract.c` (new)
- `src/extraction/uefi_parser.c` (new)
- `tools/uefi_analyze.sh` (wrapper script)

---

#### 3.1.3 Boot Guard Configuration Detection
**Approach:** Three separate commands for different analysis levels

**Implementation:**

**Command 1: Status Detection**
```c
// src/detection/bootguard_status.c
- Read MSR 0x13A (IA32_FEATURE_CONTROL)
- Detect Boot Guard enable/disable status
- Report enforcement policy (measured/verified boot)
```

**Command 2: Full Policy Analysis**
```c
// src/detection/bootguard_policy.c
- Extract Boot Guard policy from FIT
- Parse Key Manifest (KM) structure
- Validate ACM (Authenticated Code Module)
- Report policy details and key hashes
```

**Command 3: Secure Boot Audit**
```c
// src/detection/secureboot_audit.c
- Enumerate Secure Boot keys (PK, KEK, db, dbx)
- Validate certificate chains
- Detect custom/suspicious keys
- Check for known vulnerable signatures
```

**CLI Commands:**
```bash
firmwareguard bootguard-status    # Quick status
firmwareguard bootguard-policy    # Full policy analysis
firmwareguard secureboot-audit    # Secure Boot key audit
```

**Files to create/modify:**
- `src/detection/bootguard_status.c` (new)
- `src/detection/bootguard_policy.c` (new)
- `src/detection/secureboot_audit.c` (new)
- `include/bootguard.h` (structures)

---

#### 3.1.4 TXT/SGX Capability Detection
**Approach:** Research-grade analysis (full scope)

**Implementation:**
```c
// src/detection/txt_sgx_detect.c

// TXT Analysis:
- CPUID leaf 0x1 (SMX capability)
- MSR 0x3A (IA32_FEATURE_CONTROL) TXT bits
- TXT configuration space parsing
- SINIT ACM validation and version check
- TXT heap structure analysis

// SGX Analysis:
- CPUID leaf 0x12 (SGX capabilities)
- SGX enclave enumeration via /dev/sgx_enclave
- EPC (Enclave Page Cache) size detection
- SGX sealing key derivation audit
- Launch Control configuration

// TPM Integration:
- Parse TPM measurement log (TCG event log)
- Verify PCR values against expected state
- Detect measurement tampering
```

**CLI Commands:**
```bash
firmwareguard txt-audit           # TXT configuration audit
firmwareguard sgx-enum            # SGX enclave enumeration
firmwareguard tpm-measurements    # TPM PCR analysis
firmwareguard trusted-boot-full   # Complete trusted boot audit
```

**Files to create/modify:**
- `src/detection/txt_detect.c` (new)
- `src/detection/sgx_detect.c` (new)
- `src/detection/tpm_audit.c` (new)
- `include/trusted_boot.h` (new)

---

#### 3.1.5 Firmware Binary Extraction
**Approach:** flashrom integration only

**Implementation:**
```c
// src/extraction/flashrom_wrapper.c
- Detect supported flash chips via flashrom -p internal
- Full SPI flash dump to file
- Region-specific extraction (BIOS, ME, GbE, etc.)
- Checksum verification of dumps
```

**CLI Commands:**
```bash
firmwareguard flash-dump                    # Full SPI dump
firmwareguard flash-dump --region bios      # BIOS region only
firmwareguard flash-dump --region me        # ME region only
firmwareguard flash-verify <file>           # Verify dump integrity
```

**Dependencies:**
- `flashrom` (system package, not bundled)

**Files to create/modify:**
- `src/extraction/flashrom_wrapper.c` (new)
- `src/extraction/flash_regions.c` (new)
- `tools/flash_dump.sh` (convenience wrapper)

---

### 3.2 Local Telemetry Pattern Database

#### 3.2.1 SQLite Database with JSON Schema
**Approach:** Extensible JSON-based schema

**Schema Design:**
```sql
-- patterns/schema.sql

CREATE TABLE patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT UNIQUE NOT NULL,        -- e.g., "INTEL_ME_TELEMETRY_001"
    category TEXT NOT NULL,                  -- "me", "psp", "nic", "acpi", "uefi"
    severity TEXT NOT NULL,                  -- "critical", "high", "medium", "low", "info"
    name TEXT NOT NULL,
    description TEXT,
    signature BLOB,                          -- Raw byte pattern
    signature_hex TEXT,                      -- Hex representation
    regex_pattern TEXT,                      -- Optional regex
    metadata JSON,                           -- Extensible JSON metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    source TEXT,                             -- "official", "community", "research"
    verified BOOLEAN DEFAULT 0
);

CREATE TABLE pattern_metadata (
    pattern_id TEXT REFERENCES patterns(pattern_id),
    key TEXT NOT NULL,
    value JSON,
    PRIMARY KEY (pattern_id, key)
);

CREATE TABLE threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT REFERENCES patterns(pattern_id),
    ioc_type TEXT,                           -- "hash", "behavior", "attribution"
    ioc_value TEXT,
    confidence INTEGER,                      -- 0-100
    metadata JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_patterns_category ON patterns(category);
CREATE INDEX idx_patterns_severity ON patterns(severity);
CREATE INDEX idx_threat_intel_pattern ON threat_intel(pattern_id);
```

**JSON Metadata Structure:**
```json
{
  "vendor": "Intel",
  "affected_versions": ["11.x", "12.x"],
  "cve_ids": ["CVE-2020-XXXX"],
  "mitre_attack": ["T1542.001"],
  "remediation": "Disable via HAP bit",
  "references": ["https://..."],
  "wildcard_positions": [4, 8, 12],
  "match_context": {
    "min_offset": 0,
    "max_offset": 1048576,
    "region": "me_region"
  }
}
```

**Files to create:**
- `patterns/schema.sql`
- `patterns/default_patterns.json`
- `src/database/pattern_db.c`
- `src/database/pattern_db.h`
- `include/database.h`

---

#### 3.2.2 Pattern Matching Engine
**Approach:** Regex + wildcards support

**Implementation:**
```c
// src/matching/pattern_engine.c

typedef struct {
    uint8_t *signature;
    size_t sig_len;
    uint8_t *wildcard_mask;      // 0xFF = match, 0x00 = wildcard
    char *regex_pattern;
    int flags;
} fw_pattern_t;

// Core functions:
int pattern_match_exact(const uint8_t *data, size_t len, fw_pattern_t *pattern);
int pattern_match_wildcard(const uint8_t *data, size_t len, fw_pattern_t *pattern);
int pattern_match_regex(const char *data, fw_pattern_t *pattern);
int pattern_scan_region(const uint8_t *region, size_t len, fw_pattern_t **patterns, int count);

// Pattern format: "4D 5A ?? ?? 50 45"  where ?? is wildcard
```

**Features:**
- Exact byte matching (fast path)
- Wildcard byte support (`??` notation)
- PCRE2 regex for complex patterns
- Multi-pattern scanning (Aho-Corasick for performance)
- Confidence scoring based on match quality

**Files to create:**
- `src/matching/pattern_engine.c`
- `src/matching/pattern_engine.h`
- `src/matching/regex_match.c`
- `src/matching/aho_corasick.c` (multi-pattern optimization)

---

#### 3.2.3 Manual JSON Pattern Import
**Approach:** CLI-based JSON import

**JSON Import Format:**
```json
{
  "version": "1.0",
  "patterns": [
    {
      "pattern_id": "INTEL_ME_BEACON_001",
      "category": "me",
      "severity": "high",
      "name": "Intel ME Telemetry Beacon",
      "description": "Detects ME phone-home beacon pattern",
      "signature_hex": "4D45 5445 4C45 4D ?? ?? 0001",
      "metadata": {
        "vendor": "Intel",
        "references": ["https://example.com/research"]
      }
    }
  ]
}
```

**CLI Commands:**
```bash
firmwareguard patterns import <file.json>     # Import patterns
firmwareguard patterns list                   # List all patterns
firmwareguard patterns list --category me     # Filter by category
firmwareguard patterns export <file.json>     # Export for sharing
firmwareguard patterns verify                 # Validate database integrity
```

**Files to create:**
- `src/cli/patterns_cmd.c`
- `src/database/json_import.c`
- `patterns/README.md` (format documentation)

---

### 3.3 Offline Anomaly Detection

#### 3.3.1 Baseline State Capture
**Approach:** Comprehensive snapshot

**Captured State:**
```c
// src/baseline/baseline_capture.c

typedef struct {
    // Firmware checksums
    uint8_t bios_sha256[32];
    uint8_t me_sha256[32];
    uint8_t psp_sha256[32];
    uint8_t acpi_sha256[32];

    // Hardware state
    pci_device_t *pci_devices;
    int pci_device_count;
    msr_value_t *msr_snapshot;
    int msr_count;

    // Memory map
    e820_entry_t *memory_map;
    int memory_map_count;

    // UEFI variables
    efi_var_t *efi_variables;
    int efi_var_count;

    // Boot configuration
    char *boot_cmdline;
    char *grub_config_hash;

    // TPM state
    uint8_t pcr_values[24][32];  // PCR 0-23, SHA256

    // Loaded drivers
    driver_info_t *loaded_drivers;
    int driver_count;

    // Timestamps
    time_t capture_time;
    char *kernel_version;
    char *firmware_version;
} baseline_state_t;
```

**Storage Format:**
- Binary format for efficiency
- JSON export for human review
- SQLite table for historical baselines

**CLI Commands:**
```bash
firmwareguard baseline capture                # Create new baseline
firmwareguard baseline capture --name "clean_install"
firmwareguard baseline compare                # Compare to current state
firmwareguard baseline compare --baseline <id>
firmwareguard baseline list                   # List stored baselines
firmwareguard baseline export <id> <file>     # Export baseline
```

**Files to create:**
- `src/baseline/baseline_capture.c`
- `src/baseline/baseline_compare.c`
- `src/baseline/baseline_storage.c`
- `include/baseline.h`

---

#### 3.3.2 Hardware Implant Detection
**Approach:** Full implant scan

**Detection Methods:**
```c
// src/detection/implant_detect.c

// 1. PCI Device Fingerprinting
- Enumerate all PCI devices
- Validate vendor/device IDs against known database
- Detect devices with suspicious class codes
- Flag devices not in baseline

// 2. DMA + IOMMU Audit
- Enumerate DMA-capable devices
- Check IOMMU (VT-d/AMD-Vi) configuration
- Detect devices bypassing IOMMU
- Flag unexpected DMA windows

// 3. BAR Anomaly Detection
- Scan PCI BARs for unexpected mappings
- Detect overlapping memory regions
- Flag BARs pointing to suspicious addresses

// 4. Hidden Device Detection
- Scan for devices responding to non-standard addresses
- Detect hidden PCI functions
- Check for phantom devices

// 5. Bus Anomaly Detection
- Verify PCI topology against expected
- Detect unexpected bridges
- Flag hot-plugged suspicious devices

// 6. MMIO Region Audit
- Enumerate all MMIO regions
- Compare against baseline
- Flag unexpected memory-mapped regions
```

**CLI Commands:**
```bash
firmwareguard implant-scan                    # Full implant scan
firmwareguard implant-scan --quick            # Fast PCI-only scan
firmwareguard implant-scan --paranoid         # Maximum scrutiny
firmwareguard pci-audit                       # PCI device audit only
firmwareguard dma-audit                       # DMA/IOMMU audit only
```

**Files to create:**
- `src/detection/implant_detect.c`
- `src/detection/pci_fingerprint.c`
- `src/detection/dma_audit.c`
- `src/detection/mmio_audit.c`
- `patterns/known_pci_devices.json`

---

### 3.4 Enhanced Reporting

#### 3.4.1 PDF Report Generation
**Approach:** libharu with charts

**Implementation:**
```c
// src/reports/pdf_report.c

// Dependencies: libharu (HPDF)

// Report sections:
1. Executive Summary
   - Overall risk score (visual gauge)
   - Critical findings count
   - Remediation priority list

2. Hardware Inventory
   - CPU/chipset information
   - Detected firmware versions
   - PCI device table

3. Detection Results
   - ME/PSP status (with charts)
   - ACPI telemetry findings
   - NIC analysis results

4. Risk Assessment
   - Risk breakdown by category (pie chart)
   - Severity distribution (bar chart)
   - Trend analysis (if historical data)

5. Remediation Steps
   - Prioritized action items
   - Step-by-step instructions
   - Expected risk reduction

6. Compliance Status
   - NIST 800-171 mapping
   - GDPR Art.32 mapping
   - Control-by-control status

7. Technical Details
   - Raw detection data
   - Configuration dumps
   - Baseline comparisons
```

**Chart Types (via libharu):**
- Pie charts (risk distribution)
- Bar charts (severity counts)
- Gauge visualizations (risk score)
- Tables with color coding

**CLI Commands:**
```bash
firmwareguard report pdf                      # Generate PDF report
firmwareguard report pdf --output report.pdf
firmwareguard report pdf --template executive # Executive summary only
firmwareguard report pdf --template technical # Full technical detail
```

**Files to create:**
- `src/reports/pdf_report.c`
- `src/reports/pdf_charts.c`
- `src/reports/report_data.c`
- `templates/pdf_executive.h`
- `templates/pdf_technical.h`

---

#### 3.4.2 Compliance Mapping
**Approach:** NIST 800-171 + GDPR Article 32

**NIST 800-171 Controls:**
```c
// src/compliance/nist_800_171.c

// Mapped controls:
- 3.4.1: Baseline configurations
- 3.4.2: Security configuration settings
- 3.4.5: Access restrictions for change
- 3.4.6: Least functionality
- 3.4.7: Nonessential programs/functions
- 3.4.8: Application execution policies
- 3.13.1: Monitor communications at boundaries
- 3.13.2: Architectural designs/techniques
- 3.14.1: Flaw remediation
- 3.14.6: Monitor for security alerts
- 3.14.7: Identify unauthorized use
```

**GDPR Article 32 Technical Measures:**
```c
// src/compliance/gdpr_art32.c

// Mapped measures:
- Art.32(1)(a): Pseudonymisation and encryption
- Art.32(1)(b): Confidentiality, integrity, availability
- Art.32(1)(c): Restore availability after incident
- Art.32(1)(d): Regular testing/evaluation
- Art.32(2): Risk assessment appropriate security
```

**Output Format:**
```json
{
  "framework": "NIST 800-171",
  "assessment_date": "2025-12-07",
  "controls": [
    {
      "control_id": "3.4.1",
      "title": "Baseline Configurations",
      "status": "partial",
      "findings": ["ME enabled", "PSP active"],
      "recommendations": ["Implement HAP bit", "Enable psp.disabled"],
      "evidence": ["scan_result_id_123"]
    }
  ]
}
```

**CLI Commands:**
```bash
firmwareguard compliance nist                 # NIST 800-171 report
firmwareguard compliance gdpr                 # GDPR Art.32 report
firmwareguard compliance all                  # All frameworks
firmwareguard compliance --format json        # JSON output
```

**Files to create:**
- `src/compliance/nist_800_171.c`
- `src/compliance/gdpr_art32.c`
- `src/compliance/compliance_report.c`
- `data/nist_controls.json`
- `data/gdpr_measures.json`

---

### 3.5 Platform Expansion

#### 3.5.1 ARM Ampere Altra Support
**Approach:** Ampere Altra/AmpereOne first

**Implementation:**
```c
// src/platform/arm_ampere.c

// Detection:
- Identify Ampere CPU via /proc/cpuinfo
- Read ARM system registers for security state
- Detect ARM TrustZone configuration
- Enumerate Secure World components

// ARM-specific features:
- EL3 (Secure Monitor) detection
- TrustZone memory partitioning audit
- Secure boot chain validation
- PSCI (Power State Coordination Interface) audit
- GIC (Generic Interrupt Controller) security

// Telemetry detection:
- BMC (Baseboard Management Controller) audit
- IPMI/Redfish interface detection
- Out-of-band management analysis
```

**CLI Commands:**
```bash
firmwareguard arm-audit                       # Full ARM security audit
firmwareguard trustzone-scan                  # TrustZone analysis
firmwareguard bmc-detect                      # BMC/IPMI detection
```

**Files to create:**
- `src/platform/arm_ampere.c`
- `src/platform/arm_trustzone.c`
- `src/platform/arm_bmc.c`
- `include/arm_platform.h`

---

#### 3.5.2 RISC-V SiFive Support
**Approach:** SiFive boards only

**Implementation:**
```c
// src/platform/riscv_sifive.c

// Detection:
- Identify SiFive CPU via device tree
- Read RISC-V CSRs for security configuration
- Detect Physical Memory Protection (PMP) settings
- Enumerate S-mode/M-mode configuration

// RISC-V specific:
- PMP (Physical Memory Protection) audit
- ePMP (enhanced PMP) if available
- Secure boot chain (if implemented)
- Debug interface security (JTAG)
```

**CLI Commands:**
```bash
firmwareguard riscv-audit                     # RISC-V security audit
firmwareguard pmp-scan                        # PMP configuration scan
```

**Files to create:**
- `src/platform/riscv_sifive.c`
- `src/platform/riscv_pmp.c`
- `include/riscv_platform.h`

---

### 3.6 Automation

#### 3.6.1 Event-Driven + Scheduled Scanning
**Approach:** Systemd timers + udev triggers

**Systemd Timer Configuration:**
```ini
# /etc/systemd/system/firmwareguard-daily.timer
[Unit]
Description=Daily FirmwareGuard Quick Scan

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/firmwareguard-weekly.timer
[Unit]
Description=Weekly FirmwareGuard Full Audit

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

**Event Triggers (udev):**
```
# /etc/udev/rules.d/99-firmwareguard.rules

# Trigger on firmware update
ACTION=="change", SUBSYSTEM=="firmware", RUN+="/usr/bin/firmwareguard event firmware-change"

# Trigger on PCI device hotplug
ACTION=="add", SUBSYSTEM=="pci", RUN+="/usr/bin/firmwareguard event pci-hotplug %k"

# Trigger on USB device (optional)
ACTION=="add", SUBSYSTEM=="usb", ATTR{authorized}=="1", RUN+="/usr/bin/firmwareguard event usb-hotplug %k"
```

**Event Handler:**
```c
// src/events/event_handler.c

typedef enum {
    EVENT_FIRMWARE_CHANGE,
    EVENT_PCI_HOTPLUG,
    EVENT_USB_HOTPLUG,
    EVENT_BOOT,
    EVENT_SCHEDULED_QUICK,
    EVENT_SCHEDULED_FULL
} event_type_t;

void handle_event(event_type_t type, const char *details);
```

**CLI Commands:**
```bash
firmwareguard schedule enable                 # Enable scheduled scans
firmwareguard schedule disable                # Disable scheduled scans
firmwareguard schedule status                 # Show schedule status
firmwareguard event <type> [details]          # Manual event trigger
firmwareguard events list                     # List recent events
```

**Files to create:**
- `src/events/event_handler.c`
- `src/events/scheduler.c`
- `systemd/firmwareguard-daily.timer`
- `systemd/firmwareguard-daily.service`
- `systemd/firmwareguard-weekly.timer`
- `systemd/firmwareguard-weekly.service`
- `udev/99-firmwareguard.rules`

---

## Phase 4: Research & Advanced Features

### 4.1 Ghidra Integration
**Approach:** Full scripting suite

**Implementation:**
```python
# tools/ghidra/fw_analyze.py (Ghidra Python script)

# Automated analysis scripts:
1. uefi_driver_analysis.py - UEFI driver decompilation
2. me_firmware_analysis.py - Intel ME firmware analysis
3. psp_firmware_analysis.py - AMD PSP analysis
4. smm_handler_analysis.py - SMM handler extraction
5. symbol_recovery.py - Function/variable naming

# Integration wrapper:
# tools/ghidra_runner.sh
analyzeHeadless /path/to/project FWProject \
    -import $FIRMWARE_FILE \
    -postScript fw_analyze.py \
    -scriptPath /usr/share/firmwareguard/ghidra/
```

**CLI Commands:**
```bash
firmwareguard analyze --ghidra <firmware.bin>      # Run Ghidra analysis
firmwareguard analyze --ghidra --script uefi       # Specific script
firmwareguard analyze --export-ghidra <project>    # Export to Ghidra project
```

**Files to create:**
- `tools/ghidra/fw_analyze.py`
- `tools/ghidra/uefi_driver_analysis.py`
- `tools/ghidra/me_firmware_analysis.py`
- `tools/ghidra/symbol_recovery.py`
- `tools/ghidra_runner.sh`
- `docs/GHIDRA_INTEGRATION.md`

---

### 4.2 Supply Chain Integrity
**Approach:** Checksum database

**Implementation:**
```c
// src/integrity/checksum_db.c

// Database schema addition:
CREATE TABLE known_firmware (
    id INTEGER PRIMARY KEY,
    vendor TEXT NOT NULL,
    model TEXT NOT NULL,
    version TEXT NOT NULL,
    region TEXT,                    -- "bios", "me", "full"
    sha256 TEXT NOT NULL,
    sha512 TEXT,
    source TEXT,                    -- "vendor", "community", "research"
    verified BOOLEAN,
    metadata JSON,
    created_at DATETIME
);

// Verification flow:
1. Dump firmware via flashrom
2. Calculate checksums
3. Query database for match
4. Report verification status
```

**CLI Commands:**
```bash
firmwareguard integrity verify                # Verify current firmware
firmwareguard integrity add <file> --vendor X # Add known-good hash
firmwareguard integrity import <hashes.json>  # Import hash database
firmwareguard integrity report                # Integrity status report
```

**Files to create:**
- `src/integrity/checksum_db.c`
- `src/integrity/verify.c`
- `data/known_firmware.json` (seed data)

---

### 4.3 Rootkit Detection
**Approach:** Behavioral + signatures

**Implementation:**
```c
// src/rootkit/rootkit_detect.c

// Signature-based detection:
- Known SMM rootkit signatures
- Known UEFI bootkit signatures
- MBR/GPT manipulation patterns
- Persistent firmware implants

// Behavioral detection:
- Unusual MSR access patterns
- Suspicious SMI frequency
- Unexpected MMIO writes
- Hidden memory regions
- Hooked system calls
- Modified interrupt handlers
```

**CLI Commands:**
```bash
firmwareguard rootkit-scan                    # Full rootkit scan
firmwareguard rootkit-scan --signatures       # Signature-only scan
firmwareguard rootkit-scan --behavioral       # Behavioral-only scan
```

**Files to create:**
- `src/rootkit/rootkit_detect.c`
- `src/rootkit/signature_scan.c`
- `src/rootkit/behavioral_detect.c`
- `patterns/rootkit_signatures.json`

---

### 4.4 Live Firmware Dumping
**Approach:** Full firmware dump (ME/PSP + SMRAM + Option ROMs)

**Implementation:**
```c
// src/dump/live_dump.c

// ME/PSP memory dump:
- Access via HECI/mailbox interface
- Dump ME/PSP visible memory regions
- Extract runtime firmware state

// SMRAM dump (requires kernel module):
- Access SMRAM via SMM relay
- Dump SMM handler code
- Extract SMM data structures

// Option ROM extraction:
- Enumerate PCI Option ROMs
- Dump each Option ROM
- Validate signatures

// UEFI runtime dump:
- Dump UEFI runtime services memory
- Extract runtime driver code
```

**Safety:**
- Dry-run mode by default
- Extensive warnings for SMRAM access
- System stability monitoring

**CLI Commands:**
```bash
firmwareguard dump-live --me                  # ME memory dump
firmwareguard dump-live --smram               # SMRAM dump (dangerous)
firmwareguard dump-live --optionrom           # Option ROM dump
firmwareguard dump-live --uefi-runtime        # UEFI runtime dump
firmwareguard dump-live --all                 # Everything (very risky)
```

**Files to create:**
- `src/dump/live_dump.c`
- `src/dump/me_dump.c`
- `src/dump/smram_dump.c`
- `src/dump/optionrom_dump.c`
- `kernel/smram_access.c` (kernel module addition)

---

### 4.5 HECI Monitoring
**Approach:** HECI interface monitoring

**Implementation:**
```c
// src/monitor/heci_monitor.c

// Monitor ME communications via HECI:
- Intercept HECI messages
- Log ME command/response pairs
- Detect unauthorized ME activity
- Alert on suspicious patterns

// HECI message types to monitor:
- MKHI (ME Kernel Host Interface)
- ICC (Integrated Clock Controller)
- HCI (Host Communication Interface)
- PAVP (Protected Audio Video Path)
```

**CLI Commands:**
```bash
firmwareguard heci-monitor                    # Start HECI monitoring
firmwareguard heci-monitor --duration 60      # Monitor for 60 seconds
firmwareguard heci-log                        # Show HECI log
firmwareguard heci-analyze <log>              # Analyze captured log
```

**Files to create:**
- `src/monitor/heci_monitor.c`
- `src/monitor/heci_parser.c`
- `src/monitor/heci_analyzer.c`
- `include/heci.h`

---

### 4.6 UEFI Hook Detection
**Approach:** Full integrity check

**Implementation:**
```c
// src/detection/uefi_hooks.c

// Call table validation:
- Snapshot Boot Services table
- Snapshot Runtime Services table
- Compare against known-good pointers
- Detect redirected functions

// Inline patch detection:
- Hash known UEFI service functions
- Detect inline hooks/patches
- Identify trampoline code

// Runtime integrity:
- Periodic table verification
- Memory region monitoring
- Alert on modifications
```

**CLI Commands:**
```bash
firmwareguard uefi-integrity                  # Full UEFI integrity check
firmwareguard uefi-integrity --tables         # Table validation only
firmwareguard uefi-integrity --inline         # Inline patch detection
firmwareguard uefi-integrity --monitor        # Continuous monitoring
```

**Files to create:**
- `src/detection/uefi_hooks.c`
- `src/detection/uefi_inline.c`
- `src/detection/uefi_monitor.c`
- `data/uefi_known_good.json`

---

### 4.7 SPI Flash Write Monitoring
**Approach:** Alert on writes

**Implementation:**
```c
// src/monitor/spi_monitor.c

// Detection methods:
- Monitor SPI controller registers
- Detect write enable commands
- Log flash write operations
- Alert on unexpected writes

// Alert types:
- Flash write detected
- BIOS region modified
- ME region modified
- Unknown region written
```

**CLI Commands:**
```bash
firmwareguard spi-monitor                     # Start SPI monitoring
firmwareguard spi-monitor --alert-only        # Alert mode (no logging)
firmwareguard spi-status                      # Current SPI protection status
```

**Files to create:**
- `src/monitor/spi_monitor.c`
- `src/monitor/spi_alert.c`
- `kernel/spi_intercept.c` (kernel module addition)

---

### 4.8 Coreboot/Libreboot Migration
**Approach:** Assisted migration

**Implementation:**
```c
// src/migration/coreboot_migrate.c

// Compatibility check:
- Query Coreboot supported boards database
- Check current board against supported list
- Report compatibility status
- Identify required blobs (if any)

// Migration assistance:
- Backup current firmware (SPI dump)
- Download appropriate Coreboot image
- Verify image signatures
- Guided flashing process
- Rollback capability

// Risk assessment:
- Warn about bricking risks
- Hardware-specific warnings
- ME region handling advice
```

**CLI Commands:**
```bash
firmwareguard coreboot-check                  # Check compatibility
firmwareguard coreboot-migrate                # Start migration wizard
firmwareguard coreboot-migrate --backup-only  # Backup current firmware
firmwareguard coreboot-rollback               # Restore from backup
```

**Files to create:**
- `src/migration/coreboot_migrate.c`
- `src/migration/coreboot_db.c`
- `src/migration/flash_backup.c`
- `data/coreboot_boards.json`
- `docs/COREBOOT_MIGRATION.md`

---

### 4.9 CVE Discovery Program
**Approach:** CVE program only

**Implementation:**
- Systematic firmware vulnerability research
- Responsible disclosure process
- CVE assignment workflow
- Security advisory publication

**Documentation:**
- `SECURITY.md` - Vulnerability reporting process
- `docs/CVE_PROGRAM.md` - CVE discovery workflow
- Template for security advisories

**Files to create:**
- `SECURITY.md`
- `docs/CVE_PROGRAM.md`
- `docs/ADVISORY_TEMPLATE.md`
- `.github/SECURITY.md`

---

### 4.10 Threat Intelligence Database
**Approach:** Full threat intel (hashes + behavioral indicators + IOCs)

**Schema Addition:**
```sql
CREATE TABLE threat_indicators (
    id INTEGER PRIMARY KEY,
    indicator_type TEXT,          -- "hash", "behavior", "network", "registry"
    indicator_value TEXT,
    malware_family TEXT,
    attribution TEXT,
    confidence INTEGER,
    first_seen DATETIME,
    last_seen DATETIME,
    metadata JSON
);

CREATE TABLE malware_families (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    description TEXT,
    category TEXT,                -- "bootkit", "rootkit", "implant"
    references JSON,
    ttps JSON                     -- MITRE ATT&CK TTPs
);
```

**Files to create:**
- `src/database/threat_intel.c`
- `data/threat_intel_seed.json`
- `patterns/malware_families.json`

---

## Implementation Priority Order

### Phase 3 Priority (Detection First)

1. **Week 1-2:** SMM Detection Module
2. **Week 3-4:** UEFI Driver Extraction (both methods)
3. **Week 5-6:** Boot Guard Detection (3 commands)
4. **Week 7-8:** TXT/SGX Research-grade Analysis
5. **Week 9-10:** flashrom Integration
6. **Week 11-12:** SQLite Pattern Database + JSON Schema
7. **Week 13-14:** Pattern Matching Engine (regex + wildcards)
8. **Week 15-16:** Baseline Capture (comprehensive)
9. **Week 17-18:** Hardware Implant Detection (full scan)
10. **Week 19-20:** PDF Reports (libharu + charts)
11. **Week 21-22:** Compliance Mapping (NIST + GDPR)
12. **Week 23-24:** Event-driven + Scheduled Scanning
13. **Week 25-26:** ARM Ampere Altra Support
14. **Week 27-28:** RISC-V SiFive Support

### Phase 4 Priority

1. Ghidra Integration (scripting suite)
2. Supply Chain Checksum Database
3. Rootkit Detection (behavioral + signatures)
4. Live Firmware Dumping
5. HECI Monitoring
6. UEFI Hook Detection
7. SPI Flash Write Monitoring
8. Coreboot/Libreboot Migration
9. CVE Discovery Program
10. Threat Intelligence Database

---

## Dependencies

### Required Libraries
- `libsqlite3` - Pattern database
- `libharu (HPDF)` - PDF generation
- `libpcre2` - Regex pattern matching
- `flashrom` - SPI flash access (system package)

### Optional Dependencies
- `ghidra` - Firmware binary analysis
- `radare2` - Quick binary analysis

### Build Requirements
- GCC 9+ or Clang 10+
- Linux kernel headers (for kernel module)
- pkg-config

---

## File Structure Addition

```
src/
├── detection/
│   ├── smm_detect.c          (new)
│   ├── uefi_enum.c           (new)
│   ├── bootguard_status.c    (new)
│   ├── bootguard_policy.c    (new)
│   ├── secureboot_audit.c    (new)
│   ├── txt_detect.c          (new)
│   ├── sgx_detect.c          (new)
│   ├── tpm_audit.c           (new)
│   ├── implant_detect.c      (new)
│   ├── uefi_hooks.c          (new)
│   └── rootkit_detect.c      (new)
├── extraction/
│   ├── spi_extract.c         (new)
│   ├── uefi_parser.c         (new)
│   └── flashrom_wrapper.c    (new)
├── database/
│   ├── pattern_db.c          (new)
│   ├── json_import.c         (new)
│   ├── checksum_db.c         (new)
│   └── threat_intel.c        (new)
├── matching/
│   ├── pattern_engine.c      (new)
│   ├── regex_match.c         (new)
│   └── aho_corasick.c        (new)
├── baseline/
│   ├── baseline_capture.c    (new)
│   ├── baseline_compare.c    (new)
│   └── baseline_storage.c    (new)
├── reports/
│   ├── pdf_report.c          (new)
│   ├── pdf_charts.c          (new)
│   └── report_data.c         (new)
├── compliance/
│   ├── nist_800_171.c        (new)
│   ├── gdpr_art32.c          (new)
│   └── compliance_report.c   (new)
├── platform/
│   ├── arm_ampere.c          (new)
│   ├── arm_trustzone.c       (new)
│   ├── riscv_sifive.c        (new)
│   └── riscv_pmp.c           (new)
├── events/
│   ├── event_handler.c       (new)
│   └── scheduler.c           (new)
├── monitor/
│   ├── heci_monitor.c        (new)
│   ├── spi_monitor.c         (new)
│   └── uefi_monitor.c        (new)
├── dump/
│   ├── live_dump.c           (new)
│   ├── me_dump.c             (new)
│   ├── smram_dump.c          (new)
│   └── optionrom_dump.c      (new)
├── migration/
│   ├── coreboot_migrate.c    (new)
│   └── flash_backup.c        (new)
├── integrity/
│   ├── checksum_db.c         (new)
│   └── verify.c              (new)
└── rootkit/
    ├── signature_scan.c      (new)
    └── behavioral_detect.c   (new)

patterns/
├── schema.sql                (new)
├── default_patterns.json     (new)
├── rootkit_signatures.json   (new)
├── known_pci_devices.json    (new)
└── malware_families.json     (new)

data/
├── nist_controls.json        (new)
├── gdpr_measures.json        (new)
├── known_firmware.json       (new)
├── coreboot_boards.json      (new)
└── threat_intel_seed.json    (new)

tools/ghidra/
├── fw_analyze.py             (new)
├── uefi_driver_analysis.py   (new)
├── me_firmware_analysis.py   (new)
└── symbol_recovery.py        (new)

systemd/
├── firmwareguard-daily.timer   (new)
├── firmwareguard-daily.service (new)
├── firmwareguard-weekly.timer  (new)
└── firmwareguard-weekly.service (new)

udev/
└── 99-firmwareguard.rules    (new)

docs/
├── GHIDRA_INTEGRATION.md     (new)
├── COREBOOT_MIGRATION.md     (new)
├── CVE_PROGRAM.md            (new)
└── ADVISORY_TEMPLATE.md      (new)
```

---

**Document Version:** 1.0
**Created:** 2025-12-07
**Status:** Ready for Implementation
