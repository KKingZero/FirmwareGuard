# FirmwareGuard Usage Examples

Quick reference guide for common FirmwareGuard operations.

---

## Installation

```bash
cd /home/zero/FirmwareGuard
sudo make install
```

This installs:
- Binary to `/usr/local/bin/firmwareguard`
- Config directory at `/etc/firmwareguard/`
- State directory at `/var/lib/firmwareguard/backups/`
- Systemd service file

---

## Basic Commands

### 1. Basic System Scan

Scan your system for firmware telemetry components:

```bash
sudo firmwareguard scan
```

**Expected Output:**
```
========================================
  FIRMWARE TELEMETRY SCAN RESULTS
========================================

Components Detected: 3
Risk Level: CRITICAL

FINDINGS:
---------

[1] Intel Management Engine (ME)
    Status:      ACTIVE
    Version:     11.8.65.3590
    Risk:        CRITICAL
    Details:     Full network stack, out-of-band management capable

[2] AMD Platform Security Processor (PSP)
    Status:      ACTIVE
    Version:     Unknown
    Risk:        HIGH
    Details:     Cryptographic coprocessor with system access

[3] ACPI Telemetry Tables
    Status:      PRESENT
    Risk:        MEDIUM
    Details:     Firmware collects boot performance metrics
```

---

### 2. Scan with JSON Output

Generate machine-readable scan results:

```bash
sudo firmwareguard scan --json
```

**Save to file:**
```bash
sudo firmwareguard scan --json -o /var/log/firmware-audit.json
```

---

### 3. Check Blocking Options

See what can be blocked or disabled:

```bash
sudo firmwareguard block
```

**Expected Output:**
```
========================================
  BLOCKING ACTIONS REPORT
========================================

Actions Generated: 3
Successful: 0
Failed/Recommendations: 3
Reboot Required: Yes

ACTIONS:
--------

[1] Intel Management Engine
    Status:         RECOMMENDATION
    Method:         Soft-disable via HAP bit or me_cleaner
    Recommendation: To disable Intel ME:
                   - Check BIOS/UEFI settings for 'Intel ME' or 'AMT' options
                   - Use me_cleaner: https://github.com/corna/me_cleaner
                   - WARNING: Disabling ME may cause system instability

[2] AMD Platform Security Processor
    Status:         RECOMMENDATION
    Method:         Kernel parameter: psp.psp_disabled=1
    Recommendation: Add 'psp.psp_disabled=1' to kernel boot parameters

[3] Network Interface Card Telemetry
    Status:         RECOMMENDATION
    Method:         Disable Wake-on-LAN and Intel AMT
    Recommendation: ethtool -s eth0 wol d
```

---

### 4. Show All Mitigation Options

Display all possible mitigations (emergency reference):

```bash
sudo firmwareguard panic
```

This shows comprehensive steps to disable all detected components.

---

## Phase 3 Security Features (NEW!)

### 5. Secure Boot Detection

Check if Secure Boot is enabled (prevents accidental bricking):

```bash
sudo firmwareguard scan --verbose
```

**Output includes:**
```
[SECURITY CHECK]
Secure Boot Status: ENABLED
Setup Mode: DISABLED
WARNING: UEFI variable modification may fail with Secure Boot enabled
```

---

### 6. HAP Platform Support Check

Verify if your Intel CPU supports HAP bit (ME disable):

```bash
sudo firmwareguard detect-platform
```

**Expected Output:**
```
========================================
  PLATFORM DETECTION REPORT
========================================

CPU Vendor:           Intel
CPU Generation:       Skylake (6th Gen)
ME Disable Support:   YES (HAP bit available)
Recommendation:       Safe to attempt Intel ME soft-disable

Platform Details:
- CPUID: 0x506E3
- Family: 6, Model: 94
- HAP Bit: Supported (Skylake and newer)
```

**For older platforms:**
```
CPU Generation:       Haswell (4th Gen)
ME Disable Support:   NO (HAP bit not available)
WARNING:              Do NOT attempt HAP bit modification on this platform
Recommendation:       Use me_cleaner or BIOS settings only
```

---

## Advanced Operations

### 7. Apply Persistent Blocking (Phase 2)

Apply blocking actions that survive reboots:

```bash
sudo firmwareguard apply --persistent
```

**With dry-run (recommended first):**
```bash
sudo firmwareguard apply --persistent --dry-run
```

---

### 8. Generate Audit Report

Create a detailed audit report from previous scan:

```bash
sudo firmwareguard report
```

**With output file:**
```bash
sudo firmwareguard report -o firmware-audit-$(date +%Y%m%d).txt
```

---

### 9. Verbose Mode

Get detailed debugging information:

```bash
sudo firmwareguard scan --verbose
```

Shows:
- Secure Boot status
- Platform generation details
- Additional hardware information
- Detailed risk analysis

---

## CI/CD Integration (Phase 3)

### 10. GitHub Actions Workflow

Add to `.github/workflows/hardware-validation.yml`:

```yaml
name: Hardware Security Validation

on: [push, pull_request]

jobs:
  firmware-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install FirmwareGuard
        run: |
          sudo make install

      - name: Run Firmware Scan
        run: |
          sudo firmwareguard scan --json -o scan-results.json

      - name: Check Risk Level
        run: |
          # Fail if CRITICAL risks detected
          if grep -q "CRITICAL" scan-results.json; then
            echo "CRITICAL firmware risks detected!"
            exit 1
          fi
```

---

## Systemd Service (Scheduled Scanning)

### 11. Enable Automatic Scanning

```bash
# Enable service
sudo systemctl enable firmwareguard

# Start service
sudo systemctl start firmwareguard

# Check status
sudo systemctl status firmwareguard

# View logs
journalctl -u firmwareguard -f
```

**Configure scan interval:**
Edit `/etc/firmwareguard/config.conf`:
```ini
[scanning]
interval = 86400  # Scan every 24 hours
```

---

## Troubleshooting

### Command Not Found

```bash
# Check if installed
which firmwareguard

# If not found, install:
cd /home/zero/FirmwareGuard
sudo make install
```

### Permission Denied

All operations require root privileges:

```bash
# Always use sudo
sudo firmwareguard scan
```

### Kernel Module Issues

If kernel module fails to load:

```bash
# Check module status
lsmod | grep fwguard

# Load manually
sudo modprobe fwguard_km

# Check dmesg for errors
dmesg | grep fwguard
```

---

## Safety Tips

### Before Making Changes

1. **Always run dry-run first:**
   ```bash
   sudo firmwareguard apply --dry-run
   ```

2. **Create backups:**
   ```bash
   # Backups stored in:
   /var/lib/firmwareguard/backups/
   ```

3. **Check Secure Boot status:**
   ```bash
   sudo firmwareguard scan --verbose
   # Disable Secure Boot before UEFI modifications
   ```

4. **Verify platform support:**
   ```bash
   sudo firmwareguard detect-platform
   # Ensure your CPU supports the operation
   ```

---

## Example Workflows

### Security Audit Workflow

```bash
# 1. Initial scan
sudo firmwareguard scan --json -o initial-scan.json

# 2. Check what can be blocked
sudo firmwareguard block

# 3. Verify platform support
sudo firmwareguard detect-platform

# 4. Test blocking (dry-run)
sudo firmwareguard apply --persistent --dry-run

# 5. Apply blocking (if safe)
sudo firmwareguard apply --persistent

# 6. Verify changes
sudo firmwareguard scan --json -o post-block-scan.json

# 7. Compare results
diff initial-scan.json post-block-scan.json
```

### Pre-Deployment Hardware Validation

```bash
# Run comprehensive check
sudo firmwareguard scan --verbose > hardware-report.txt
sudo firmwareguard detect-platform >> hardware-report.txt

# Check for critical risks
if grep -q "CRITICAL" hardware-report.txt; then
  echo "Hardware requires firmware hardening"
  sudo firmwareguard panic
fi
```

---

## Getting Help

- **Built-in help:** `firmwareguard --help`
- **Documentation:** `/home/zero/FirmwareGuard/docs/`
- **Issues:** https://github.com/KKingZero/FirmwareGuard/issues
- **Discussions:** https://github.com/KKingZero/FirmwareGuard/discussions

---

**Last Updated:** 2025-11-22
**Version:** 0.3.0
