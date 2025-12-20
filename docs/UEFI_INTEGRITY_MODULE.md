# UEFI Runtime Integrity Checking Module

## Overview

The UEFI Integrity module provides comprehensive runtime integrity checking for UEFI-based systems. It monitors UEFI Runtime Services tables, detects modifications to service function pointers, identifies inline hooks/patches, and assesses memory protection configurations.

**Security Focus**: This module is designed to detect UEFI rootkits, firmware implants, and runtime service tampering.

## Architecture

### Key Components

1. **Runtime Region Analysis**
   - Reads EFI runtime memory regions from `/sys/firmware/efi/runtime-map/`
   - Analyzes memory protection attributes (W^X violations)
   - Identifies writable code and executable data regions

2. **Table Snapshotting**
   - Captures UEFI Runtime Services table state
   - Records function pointer values
   - Generates cryptographic hash for integrity verification

3. **Hook Detection**
   - Analyzes service function prologues for suspicious patterns
   - Detects common hooking techniques:
     - Direct JMP hooks (0xE9)
     - Indirect JMP hooks (0xFF 0x25)
     - PUSH+RET trampolines
     - Register-based redirections
   - Identifies abnormal function prologues

4. **Integrity Verification**
   - Compares current state against saved baseline
   - Detects table modifications
   - Identifies pointer changes
   - Reports code modifications

## Security Features

### Input Validation
- All file paths validated to prevent directory traversal
- Bounds checking on all buffer operations
- Integer overflow protection in size calculations
- Strict validation of sysfs data parsing

### Memory Safety
- Safe string functions (strncpy with explicit null termination)
- Defensive copying with size limits
- Stack buffer protection
- No dynamic memory allocation in hot paths

### Offline-Only Operation
- **No network connectivity** - purely local analysis
- Reads from `/sys/firmware/efi/` filesystem only
- All data processing happens offline
- No external dependencies for core functionality

### Defense in Depth
- Multiple detection methods for hooks
- Cross-validation of integrity data
- Risk-based threat assessment
- Detailed audit logging

## API Reference

### Initialization

```c
int uefi_integrity_init(void);
void uefi_integrity_cleanup(void);
```

Initialize and cleanup the UEFI integrity subsystem. Requires root privileges.

**Returns**:
- `FG_SUCCESS` - Initialized successfully
- `FG_NOT_SUPPORTED` - EFI not available on system
- `FG_NO_PERMISSION` - Insufficient privileges

### Scanning Functions

```c
int uefi_integrity_scan(uefi_integrity_result_t *result);
```

Performs comprehensive UEFI integrity scan including:
- Runtime memory region analysis
- Security property assessment (W^X)
- Table snapshotting
- Hook detection
- Baseline comparison (if available)

```c
int uefi_integrity_check_brief(uefi_integrity_result_t *result);
```

Quick integrity check for rapid assessment.

### Table Management

```c
int uefi_snapshot_tables(uefi_runtime_table_snapshot_t *snapshot);
```

Captures current UEFI Runtime Services table state.

```c
int uefi_verify_tables(const uefi_runtime_table_snapshot_t *baseline,
                       const uefi_runtime_table_snapshot_t *current,
                       uefi_integrity_verification_t *result);
```

Compares two snapshots to detect modifications.

### Hook Detection

```c
int uefi_detect_hooks(const uefi_runtime_table_snapshot_t *snapshot,
                      uefi_hook_detection_t *hooks, int max_hooks,
                      int *num_detected);
```

Analyzes service function pointers for hooking patterns.

### Baseline Management

```c
int uefi_save_baseline(const uefi_runtime_table_snapshot_t *snapshot,
                       const char *path);
int uefi_load_baseline(uefi_runtime_table_snapshot_t *snapshot,
                       const char *path);
```

Save and restore baseline snapshots for continuous monitoring.

### Reporting

```c
void uefi_integrity_print_result(const uefi_integrity_result_t *result,
                                 bool verbose);
int uefi_integrity_to_json(const uefi_integrity_result_t *result,
                           char *buffer, size_t size);
int uefi_integrity_report(const uefi_integrity_result_t *result,
                          char *buffer, size_t buffer_size);
```

## Data Structures

### uefi_integrity_result_t

Complete scan result structure containing:
- EFI system information
- Runtime memory regions
- Baseline and current snapshots
- Hook detection results
- Integrity verification data
- Risk assessment
- Detailed findings

### uefi_runtime_region_t

EFI runtime memory region:
```c
typedef struct {
    uint32_t type;               /* EFI memory type */
    uint64_t phys_addr;          /* Physical address */
    uint64_t virt_addr;          /* Virtual address */
    uint64_t num_pages;          /* Number of 4KB pages */
    uint64_t attribute;          /* Memory attributes */
    uint64_t size;               /* Size in bytes */
    bool writable;               /* Is writable */
    bool executable;             /* Is executable */
    bool runtime;                /* Runtime region */
} uefi_runtime_region_t;
```

### hook_signature_t

Hook detection signature pattern:
```c
typedef struct {
    uint8_t pattern[16];         /* x86-64 instruction pattern */
    uint8_t mask[16];            /* Pattern matching mask */
    size_t pattern_len;          /* Pattern length */
    char description[128];       /* Detection description */
} hook_signature_t;
```

## Usage Examples

### Basic Integrity Scan

```c
#include "detection/uefi_integrity.h"

int main(void) {
    uefi_integrity_result_t result;

    /* Initialize */
    if (uefi_integrity_init() != FG_SUCCESS) {
        return 1;
    }

    /* Scan */
    if (uefi_integrity_scan(&result) == FG_SUCCESS) {
        uefi_integrity_print_result(&result, true);

        if (result.num_hooks_detected > 0) {
            printf("WARNING: Potential UEFI rootkit detected!\n");
        }
    }

    /* Cleanup */
    uefi_integrity_cleanup();
    return 0;
}
```

### Baseline Monitoring

```c
/* First run - establish baseline */
uefi_runtime_table_snapshot_t baseline;
uefi_snapshot_tables(&baseline);
uefi_save_baseline(&baseline, "/var/lib/firmwareguard/uefi_baseline.dat");

/* Subsequent runs - verify against baseline */
uefi_runtime_table_snapshot_t current;
uefi_integrity_verification_t verification;

uefi_snapshot_tables(&current);
uefi_verify_tables(&baseline, &current, &verification);

if (verification.num_changes > 0) {
    printf("ALERT: UEFI modifications detected!\n");
    for (int i = 0; i < verification.num_changes; i++) {
        printf("  - %s\n", verification.changes[i]);
    }
}
```

## Risk Assessment

The module assigns risk levels based on findings:

- **CRITICAL**: Hooks detected, W+X runtime code, table modifications
- **HIGH**: Code modifications, pointer changes, writable code
- **MEDIUM**: Configuration issues, unexpected memory attributes
- **LOW**: Minor anomalies
- **NONE**: No issues detected

## Threat Detection

### UEFI Rootkits

The module can detect:
- **LoJax** - Hooks to UEFI runtime services
- **MosaicRegressor** - Modified firmware components
- **ESPecter** - EFI System Partition backdoors
- **BlackLotus** - Bootkit modifications

Detection methods:
1. Function prologue analysis
2. Pointer integrity verification
3. Memory protection validation
4. Baseline comparison

### Detection Limitations

**Important**: Due to Linux kernel restrictions on direct memory access:
- Cannot directly read kernel virtual memory from userspace
- Service function code analysis is limited
- Some detection requires kernel module integration

For full functionality, consider:
- Using with FirmwareGuard kernel module
- Integration with `/dev/mem` (requires kernel configuration)
- Firmware extraction and offline analysis

## Security Considerations

### Privilege Requirements

- **Root access required** for:
  - Reading `/sys/firmware/efi/`
  - Accessing runtime memory information
  - Saving/loading baseline files

### File System Access

Baseline files stored at:
```
/var/lib/firmwareguard/uefi_baseline.dat
```

Permissions: `0600` (root read/write only)

### Memory Safety

All operations are bounds-checked:
- Buffer overflow prevention
- Integer overflow checks in size calculations
- Safe string handling
- Path traversal validation

## Integration with FirmwareGuard

The UEFI Integrity module integrates with:

1. **Baseline Capture** - Automated baseline establishment
2. **Audit Reporter** - Centralized finding aggregation
3. **Pattern Database** - Known malware signature matching
4. **Safety Framework** - Backup/restore operations

## Testing

Test tool: `tools/test-uefi-integrity.c`

```bash
sudo ./test-uefi-integrity -v          # Verbose scan
sudo ./test-uefi-integrity -s          # Save baseline
sudo ./test-uefi-integrity -j          # JSON output
sudo ./test-uefi-integrity -b          # Brief check
```

## Performance

Typical scan performance:
- Brief check: < 100ms
- Full scan: < 500ms
- Memory usage: < 2MB

All operations are designed for minimal system impact.

## Limitations

1. **Userspace Constraints**
   - Cannot directly access kernel virtual memory
   - Limited code inspection without kernel module
   - Relies on sysfs interface availability

2. **Platform Specific**
   - UEFI-based systems only
   - Requires Linux kernel with EFI support
   - `/sys/firmware/efi/` must be available

3. **Detection Scope**
   - Focuses on runtime services only
   - Does not analyze boot services (already terminated)
   - Cannot detect firmware-level implants without extraction

## Future Enhancements

Planned improvements:
- Kernel module integration for direct memory access
- Enhanced signature database
- Machine learning-based anomaly detection
- Firmware extraction integration
- UEFI Secure Boot verification

## References

- UEFI Specification 2.9
- Linux EFI Runtime Services Documentation
- MITRE ATT&CK: Firmware Corruption (T1542.001)
- NSA UEFI Security Guidelines

## Authors

FirmwareGuard Development Team

## License

See LICENSE file in repository root.
