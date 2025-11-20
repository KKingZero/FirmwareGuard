# FirmwareGuard Quick Start Guide

## Installation

### Prerequisites Check

```bash
# Check if running Linux
uname -s

# Check if MSR module is available
lsmod | grep msr

# If not loaded, load it
sudo modprobe msr

# Verify MSR device exists
ls /dev/cpu/0/msr
```

### Build

```bash
cd /home/zero/FirmwareGuard
make
```

### Test

```bash
./firmwareguard panic
```

---

## Basic Usage

### 1. Quick Scan (No Root - Limited Info)

```bash
./firmwareguard panic
```

Shows theoretical mitigation options without scanning hardware.

### 2. Full System Scan (Requires Root)

```bash
sudo ./firmwareguard scan
```

**Expected Output:**
```
[INFO] MSR subsystem initialized (8 CPUs)
[INFO] ACPI subsystem initialized (15 tables found)
[INFO] NIC subsystem initialized
[INFO] CPU Vendor: Intel
[INFO] Intel ME device detected (PCI ID: 0x80861c3a)
...

========================================
  FIRMWAREGUARD AUDIT REPORT v0.1.0-MVP
========================================

Overall Risk: HIGH
Components Found: 3

DETECTED COMPONENTS:
--------------------

[1] Intel Management Engine
    Type:      Intel ME
    Status:    ACTIVE
    Risk:      HIGH
    Blockable: Yes
    Details:   Version: Unknown, Capabilities: Normal operation mode
...
```

### 3. Generate JSON Report

```bash
sudo ./firmwareguard scan --json -o report.json
```

**Inspect JSON:**
```bash
cat report.json | jq .
```

### 4. Get Blocking Recommendations

```bash
sudo ./firmwareguard block
```

**Output:**
```
[INFO] Scanning hardware to identify blockable components...
[INFO] Generating blocking recommendations...

========================================
  BLOCKING ACTIONS REPORT
========================================

Actions Generated: 2
Successful: 0
Failed/Recommendations: 2
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
...
```

---

## Common Scenarios

### Scenario 1: Check if Intel ME is Active

```bash
sudo ./firmwareguard scan --json | jq '.components[] | select(.type=="Intel ME")'
```

**Interpretation:**
- If `"active": true` → ME is running
- If `"blockable": true` → Mitigation possible
- Check `"details"` for version and mode

### Scenario 2: Audit New Hardware Before Deployment

```bash
# Run full scan
sudo ./firmwareguard scan -o audit-$(hostname)-$(date +%F).txt

# Generate JSON for automation
sudo ./firmwareguard scan --json -o audit-$(hostname)-$(date +%F).json

# Review
cat audit-*.txt
```

### Scenario 3: Check for Remote Management Capabilities

```bash
sudo ./firmwareguard scan --json | jq '.components[] | select(.name | contains("Remote"))'
```

**Look for:**
- Intel AMT
- Wake-on-LAN
- IPMI/BMC (future support)

### Scenario 4: Disable Wake-on-LAN

```bash
# Scan to identify interfaces with WoL
sudo ./firmwareguard scan | grep -A5 "NIC:"

# Run blocker (will attempt WoL disable)
sudo ./firmwareguard block

# Verify (WoL should be disabled)
sudo ethtool eth0 | grep Wake-on
```

**Note:** WoL disable is temporary (until reboot). Make persistent by:
```bash
echo "ethtool -s eth0 wol d" >> /etc/rc.local
```

---

## Troubleshooting

### Error: "This operation requires root privileges"

**Problem:** Not running as root
**Solution:**
```bash
sudo ./firmwareguard scan
```

### Error: "Failed to open MSR device"

**Problem:** MSR kernel module not loaded
**Solution:**
```bash
sudo modprobe msr
# Then retry
sudo ./firmwareguard scan
```

**Make persistent:**
```bash
echo "msr" | sudo tee -a /etc/modules
```

### Warning: "ACPI tables not accessible"

**Problem:** `/sys/firmware/acpi/tables` doesn't exist
**Cause:** Very old kernel or non-UEFI system
**Impact:** ACPI probes will be skipped (other probes continue)

### Warning: "Intel ME device not found via PCI"

**Possible Reasons:**
1. Not an Intel system (check with `lscpu | grep Vendor`)
2. ME disabled in BIOS (good!)
3. Virtual machine (ME not exposed to guest)

**Action:** Check if AMD PSP was detected instead

---

## Integration Examples

### CI/CD Pipeline

```bash
#!/bin/bash
# hardware-audit.sh

# Run scan
sudo /usr/local/bin/firmwareguard scan --json -o /tmp/fw-audit.json

# Parse risk level
RISK=$(jq -r '.overall_risk' /tmp/fw-audit.json)

# Fail build if CRITICAL
if [ "$RISK" = "CRITICAL" ]; then
    echo "CRITICAL firmware telemetry detected!"
    exit 1
fi

echo "Firmware audit passed (Risk: $RISK)"
```

### Security Monitoring

```bash
#!/bin/bash
# Daily audit cron job

DATE=$(date +%F)
REPORT_DIR="/var/log/firmwareguard"

mkdir -p $REPORT_DIR

# Generate daily report
sudo firmwareguard scan --json -o $REPORT_DIR/audit-$DATE.json

# Alert if risk increases
PREV_RISK=$(jq -r '.overall_risk' $REPORT_DIR/audit-$(date -d yesterday +%F).json 2>/dev/null || echo "NONE")
CURR_RISK=$(jq -r '.overall_risk' $REPORT_DIR/audit-$DATE.json)

if [ "$CURR_RISK" != "$PREV_RISK" ]; then
    echo "Firmware risk level changed: $PREV_RISK → $CURR_RISK" | mail -s "FirmwareGuard Alert" admin@example.com
fi
```

### Ansible Playbook

```yaml
---
- name: Audit firmware telemetry
  hosts: all
  become: yes
  tasks:
    - name: Install FirmwareGuard
      copy:
        src: firmwareguard
        dest: /usr/local/bin/firmwareguard
        mode: '0755'

    - name: Load MSR module
      modprobe:
        name: msr
        state: present

    - name: Run scan
      command: /usr/local/bin/firmwareguard scan --json
      register: audit_result

    - name: Parse results
      set_fact:
        audit_json: "{{ audit_result.stdout | from_json }}"

    - name: Fail if critical risk
      fail:
        msg: "CRITICAL firmware telemetry detected"
      when: audit_json.overall_risk == "CRITICAL"
```

---

## Next Steps

### After First Scan

1. **Review detected components**
   - Understand what each component does
   - Assess if risk level is acceptable for your threat model

2. **Check BIOS/UEFI settings**
   - Look for ME/AMT disable options
   - Disable telemetry/analytics options
   - Disable Wake-on-LAN if not needed

3. **Consider me_cleaner (Intel systems)**
   - Research: https://github.com/corna/me_cleaner
   - **WARNING:** Can brick some systems
   - Always have recovery plan (programmer, backup ROM)

4. **Monitor over time**
   - Run periodic scans
   - Alert on changes
   - Track firmware updates

### Advanced Usage

**Custom risk scoring:**
```bash
# Get components with HIGH or CRITICAL risk
sudo ./firmwareguard scan --json | jq '.components[] | select(.risk | IN("HIGH", "CRITICAL"))'
```

**Compare scans:**
```bash
# Generate baseline
sudo ./firmwareguard scan --json -o baseline.json

# After firmware update, compare
sudo ./firmwareguard scan --json -o current.json
diff <(jq -S . baseline.json) <(jq -S . current.json)
```

**Fleet summary:**
```bash
# On management server, collect from all hosts
for HOST in server1 server2 server3; do
    ssh root@$HOST "firmwareguard scan --json" > audit-$HOST.json
done

# Aggregate
jq -s '.' audit-*.json > fleet-audit.json
```

---

## Getting Help

**Check logs:**
```bash
# Verbose stderr output shows probe details
sudo ./firmwareguard scan 2>&1 | less
```

**Debug build:**
```bash
make debug
sudo ./firmwareguard scan
```

**Report issues:**
- GitHub: https://github.com/yourusername/firmwareguard/issues
- Include: System info, firmware version, full output

---

**Last Updated:** 2025-11-19
**Version:** 0.1.0-MVP
