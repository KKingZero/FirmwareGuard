# FirmwareGuard Telemetry Pattern Database

This directory contains the offline telemetry pattern database for FirmwareGuard. Patterns are stored as JSON files and used to detect firmware-level telemetry, backdoors, and privacy-invasive features.

## Directory Structure

```
patterns/
├── schema.json              # JSON schema for pattern validation
├── intel-me/                # Intel Management Engine patterns
├── amd-psp/                 # AMD Platform Security Processor patterns
├── acpi/                    # ACPI table telemetry patterns
├── nic/                     # Network interface firmware patterns
├── uefi/                    # UEFI driver patterns
├── smm/                     # System Management Mode patterns
├── bios/                    # BIOS/firmware patterns
└── general/                 # Cross-platform patterns
```

## Pattern Format

Each pattern is a JSON file following the schema defined in `schema.json`. Here's a minimal example:

```json
{
  "id": "my-pattern-id",
  "name": "My Pattern Name",
  "version": "1.0.0",
  "firmware_type": "intel-me",
  "detection": {
    "method": "file-exists",
    "criteria": {
      "file": {
        "path": "/sys/firmware/acpi/tables/EXAMPLE"
      }
    }
  },
  "risk_level": "MEDIUM",
  "confidence": 80,
  "blockable": false,
  "metadata": {
    "description": "Detects example telemetry component",
    "created_at": "2025-11-29"
  }
}
```

## Detection Methods

### 1. PCI Device Detection
Detects firmware by PCI vendor/device ID:

```json
"detection": {
  "method": "pci-device",
  "criteria": {
    "pci": {
      "vendor_id": "0x8086",
      "device_id": "0x1e3a",
      "bus": "0",
      "device": "22",
      "function": "0"
    }
  }
}
```

### 2. MSR Register
Checks CPU Model-Specific Registers:

```json
"detection": {
  "method": "msr-register",
  "criteria": {
    "msr": {
      "register": "0x8000001F",
      "mask": "0x00000001",
      "expected_value": "0x00000001"
    }
  }
}
```

### 3. File Existence
Checks if a file exists:

```json
"detection": {
  "method": "file-exists",
  "criteria": {
    "file": {
      "path": "/sys/firmware/acpi/tables/FPDT"
    }
  }
}
```

### 4. File Content
Checks file content against regex or string:

```json
"detection": {
  "method": "file-content",
  "criteria": {
    "file": {
      "path": "/proc/cpuinfo",
      "regex": "GenuineIntel.*ME",
      "contains": "Intel"
    }
  }
}
```

### 5. ACPI Table
Detects ACPI tables:

```json
"detection": {
  "method": "acpi-table",
  "criteria": {
    "acpi_table": {
      "signature": "FPDT",
      "path": "/sys/firmware/acpi/tables/FPDT"
    }
  }
}
```

### 6. Sysfs Value
Checks sysfs attribute values:

```json
"detection": {
  "method": "sysfs-value",
  "criteria": {
    "sysfs": {
      "path": "/sys/class/net/eth0/device/power/wakeup",
      "expected_value": "enabled"
    }
  }
}
```

## Risk Levels

- **CRITICAL**: Immediate privacy/security threat (e.g., active remote management)
- **HIGH**: Significant privacy concern (e.g., ME active, PSP enabled)
- **MEDIUM**: Moderate concern (e.g., Wake-on-LAN enabled)
- **LOW**: Minor telemetry (e.g., performance metrics)
- **INFO**: Informational only, no privacy impact

## Contributing New Patterns

### Quick Start

1. Fork the FirmwareGuard repository
2. Create a new JSON file in the appropriate category directory
3. Validate against schema: `jsonschema -i your-pattern.json schema.json`
4. Test locally: `sudo ./firmwareguard scan --patterns=./patterns`
5. Submit a pull request

### Contribution Guidelines

**Pattern ID Naming:**
- Use lowercase with hyphens
- Format: `<category>-<component>-<feature>`
- Examples: `intel-me-amt-active`, `amd-psp-ftpm-enabled`

**Version Control:**
- Start at version `1.0.0`
- Increment patch version for bug fixes (1.0.1)
- Increment minor version for enhancements (1.1.0)
- Increment major version for breaking changes (2.0.0)

**Metadata Requirements:**
- **description**: Clear explanation of what is detected (min 20 chars)
- **technical_details**: How detection works (recommended)
- **remediation**: Step-by-step mitigation instructions (recommended)
- **references**: Links to documentation, research papers, CVEs
- **platforms**: List affected hardware/software
- **created_at**: ISO 8601 date format (YYYY-MM-DD)

**Confidence Levels:**
- 90-100: Definitive detection (e.g., PCI device ID match)
- 70-89: Reliable detection (e.g., sysfs value check)
- 50-69: Moderate confidence (e.g., heuristic-based)
- <50: Experimental or low-confidence patterns

### Testing Your Pattern

```bash
# Validate JSON syntax
python3 -m json.tool your-pattern.json

# Validate against schema (requires jsonschema package)
pip3 install jsonschema
jsonschema -i your-pattern.json schema.json

# Test detection locally
sudo ./firmwareguard scan --patterns=./patterns --verbose

# Dry-run test
sudo ./firmwareguard scan --pattern-id=your-pattern-id --dry-run
```

### Pattern Quality Checklist

- [ ] Valid JSON syntax
- [ ] Passes schema validation
- [ ] Unique pattern ID (no conflicts)
- [ ] Clear, descriptive name
- [ ] Appropriate risk level
- [ ] Detailed description (>20 chars)
- [ ] Remediation steps provided
- [ ] At least one reference link
- [ ] Tested on actual hardware
- [ ] No false positives on test systems
- [ ] Confidence level justified

## Pattern Submission Process

1. **Create**: Write your pattern JSON file
2. **Validate**: Run schema validation and syntax checks
3. **Test**: Verify detection on real hardware
4. **Document**: Ensure all metadata fields are complete
5. **Submit**: Create PR with:
   - Pattern file in correct directory
   - Testing results in PR description
   - Hardware tested on
   - False positive analysis

## Pattern Review Criteria

Maintainers will review submissions for:

- **Accuracy**: Does it detect what it claims?
- **Reliability**: Low false positive rate
- **Documentation**: Complete metadata
- **Novelty**: Not duplicate of existing pattern
- **Privacy Value**: Helps users understand firmware telemetry
- **Safety**: Won't cause system instability

## Examples

See existing patterns in subdirectories:
- `intel-me/me-device-active.json` - PCI device detection
- `intel-me/amt-enabled.json` - Combined detection method
- `amd-psp/psp-active.json` - MSR register check
- `acpi/fpdt-performance-tracking.json` - ACPI table detection
- `nic/wake-on-lan-enabled.json` - Sysfs value check

## Advanced: Custom Detection Logic

For complex detection scenarios requiring multiple checks, use the `combination` method:

```json
"detection": {
  "method": "combination",
  "criteria": {
    "pci": { "vendor_id": "0x8086" },
    "file": { "path": "/sys/kernel/debug/mei/mei0/devstate" },
    "sysfs": { "path": "/sys/class/mei/mei0/fw_status" }
  }
}
```

## Community Pattern Database

High-quality contributed patterns will be included in official releases. Contributors will be credited in:
- Pattern metadata (`discovered_by` field)
- Release notes
- Project README contributors section

## License

All pattern contributions are licensed under MIT License, same as FirmwareGuard core.

## Questions?

- GitHub Discussions: https://github.com/KKingZero/FirmwareGuard/discussions
- Issues: https://github.com/KKingZero/FirmwareGuard/issues
- Documentation: https://firmwareguard.dev/docs/patterns

---

**Last Updated:** 2025-11-29
**Pattern Database Version:** 1.0.0
