# HECI Monitor - Security Analysis & Reverse Engineering Notes

## Executive Summary

The HECI Monitor provides deep visibility into Intel Management Engine (ME) communications at the MKHI protocol layer. This document covers security implications, OPSEC considerations, reverse engineering techniques used, and threat modeling.

---

## Intel ME Architecture Overview

### What is Intel ME?

Intel Management Engine is a dedicated microprocessor embedded in Intel chipsets that runs independently of the main CPU:

- **Independent execution:** ARM/x86 core running MINIX-based OS
- **Always-on:** Runs even when system is "off" (if AC power connected)
- **Ring -3 access:** Below hypervisor, OS kernel, and SMM
- **Network access:** Can communicate independently via NIC
- **Firmware storage:** Stored in SPI flash ME region

### HECI/MEI Interface

Host Embedded Controller Interface (HECI) / Management Engine Interface (MEI):

```
┌──────────────┐
│  User Space  │  (This module)
└──────┬───────┘
       │
┌──────▼───────┐
│  MEI Driver  │  (Linux kernel: drivers/misc/mei/)
└──────┬───────┘
       │
┌──────▼───────┐
│ HECI Hardware│  (Chipset registers)
└──────┬───────┘
       │
┌──────▼───────┐
│  Intel ME    │  (Independent processor)
└──────────────┘
```

**Communication flow:**
1. Userspace writes to `/dev/mei0`
2. MEI driver translates to HECI hardware registers
3. HECI hardware signals ME firmware
4. ME processes request and responds via same path

---

## MKHI Protocol Reverse Engineering

### Discovery Methodology

The MKHI (ME Kernel Host Interface) protocol was reverse-engineered through:

1. **Static Analysis:**
   - Disassembly of ME firmware modules (using UEFITool, me_cleaner analysis)
   - Ghidra/IDA analysis of extracted ME binaries
   - UEFI BIOS ME client drivers decompilation

2. **Dynamic Analysis:**
   - Sniffing HECI traffic during boot and OS operation
   - Correlating known ME operations with captured traffic
   - Fuzzing ME endpoints to discover command structure

3. **Public Sources:**
   - Intel datasheets (limited information)
   - Open-source tools (MEInfo, intelmetool, me_cleaner)
   - Security research papers and presentations

### MKHI Header Structure

**Reverse-engineered header format (8 bytes):**

```
Offset | Size | Field       | Description
-------|------|-------------|----------------------------------
0x00   | 1    | group_id    | Command group (0x00-0xFF)
0x01   | 1    | command     | Command within group
0x02   | 1    | is_response | 0=request, 1=response
0x03   | 1    | reserved    | Always 0 (padding/alignment)
0x04   | 1    | result      | Result code (for responses)
0x05   | 3    | reserved2   | Always 0 (padding)
```

**Key insights:**
- Little-endian byte order
- Fixed 8-byte header on all MKHI messages
- Group ID determines message family
- Result code semantics vary by group

### Known MKHI Groups

| Group | Name | Purpose | Sensitivity |
|-------|------|---------|-------------|
| 0x00 | BUP | Bring-Up Platform init | Medium |
| 0x02 | PM | Power management | Low |
| 0x03 | FWCAPS | Firmware capabilities query | Low |
| 0x05 | HMRFPO | Flash protection override | **CRITICAL** |
| 0x07 | MDES | Manageability and Security | High |
| 0x0A | MCA | Memory configuration | Medium |
| 0x0F | DEBUG | Debug/diagnostic commands | High |
| 0xF0 | VER | Version information | Low |
| 0xF1 | GEN2 | General commands v2 | Medium |
| 0xFF | GEN | General/common commands | Medium |

**Note:** Many groups are undocumented and discovered through RE.

---

## Critical Security Commands

### HMRFPO (Group 0x05) - Flash Protection Override

**Most dangerous ME functionality** - allows host to bypass ME region flash write protection.

#### HMRFPO_ENABLE (0x05:0x01)

**Purpose:** Temporarily disable ME region flash protection.

**Legitimate uses:**
- BIOS updates that modify ME region
- Manufacturing/OEM provisioning
- RMA (Return Merchandise Authorization) procedures

**Attack vectors:**
- Implanting malicious ME firmware
- Persistent rootkits below OS level
- Backdoor installation in firmware
- Secure Boot bypass via ME tampering

**Detection indicators:**
- HMRFPO_ENABLE command observed
- Typically only during BIOS update
- Unusual if seen during normal operation
- Should be followed by HMRFPO_LOCK

**Request structure:**
```c
struct hmrfpo_enable_request {
    mkhi_header_t header;  /* group=0x05, cmd=0x01 */
    uint64_t nonce;        /* Authentication nonce */
    /* Additional auth data varies by platform */
};
```

**Response codes:**
- 0x00: Success - flash protection disabled
- 0x01: Invalid nonce/authentication failed
- 0x10: Not allowed (already locked)

#### HMRFPO_LOCK (0x05:0x02)

**Purpose:** Re-enable and lock ME region flash protection.

**Significance:**
- Should always follow HMRFPO_ENABLE
- Prevents further flash modifications
- Cannot be unlocked without reboot

**Suspicious pattern:**
- HMRFPO_ENABLE without subsequent LOCK
- Multiple ENABLE commands in short time
- LOCK without preceding ENABLE

---

### ME Unconfigure (0xFF:0x0D)

**Purpose:** Disable ME functionality (HAP/AltDisable mode).

**Background:**
- HAP = High Assurance Platform
- Originally for NSA/government use
- Allows ME disable for high-security environments
- Discovered publicly via leaked documents

**Legitimate uses:**
- Privacy-focused configurations
- Air-gapped systems
- Government/defense applications

**Attack implications:**
- Attacker may try to disable ME monitoring
- Could indicate attempt to evade ME-based security
- May precede SMM-level attacks

**Detection value:**
- Rare in consumer systems
- Expected only in specific enterprise configs
- Unexpected execution = suspicious

---

## Threat Model

### Adversary Capabilities

**Low-skill attacker:**
- Limited ME knowledge
- May not trigger HECI traffic
- Unlikely to be detected by this module

**Medium-skill attacker:**
- Uses public ME tools (me_cleaner, etc.)
- May trigger HMRFPO or unconfigure commands
- **High detection probability**

**Advanced attacker:**
- Custom ME firmware implants
- Direct SPI flash modification (bypasses HECI)
- May use undocumented ME groups
- Partial detection (depends on technique)

**Nation-state / APT:**
- Full ME firmware understanding
- Zero-day ME vulnerabilities
- May communicate via channels this module cannot observe
- Limited detection capability

### Attack Scenarios

#### Scenario 1: Firmware Implant via HMRFPO

**Attack flow:**
1. Attacker gains root on host OS
2. Sends HMRFPO_ENABLE command
3. Modifies ME region in SPI flash
4. Sends HMRFPO_LOCK (or reboots)
5. Malicious ME firmware persists across reinstalls

**Detection:**
- HMRFPO_ENABLE command observed
- Alert raised as CRITICAL risk
- Admin can investigate and verify legitimacy
- If unexpected: system compromised

**Mitigation:**
- This module provides visibility but not blocking
- Integrate with FirmwareGuard blocker for prevention
- Require multi-factor auth for HMRFPO commands

#### Scenario 2: ME Disable Attempt

**Attack flow:**
1. Attacker wants to evade ME-based security
2. Sends ME unconfigure command
3. ME functionality disabled
4. Proceed with SMM or firmware-level attacks

**Detection:**
- UNCONFIGURE command observed
- Alert raised as HIGH risk
- Unexpected in most environments

**Mitigation:**
- Policy enforcement: block unconfigure in production
- Alert SOC/admin for investigation
- Correlate with other firmware events

#### Scenario 3: Reconnaissance

**Attack flow:**
1. Attacker probes ME capabilities
2. Sends FWCAPS, version queries
3. Maps ME attack surface
4. Identifies vulnerabilities

**Detection:**
- Excessive query traffic
- Unknown MKHI groups (fuzzing attempts)
- Pattern: multiple groups queried rapidly

**Mitigation:**
- Rate limiting on ME commands
- Behavioral analysis (ML-based anomaly detection)
- Alerting on unusual traffic patterns

---

## OPSEC Considerations

### Design Philosophy

**Stealth monitoring** - minimal system footprint:

1. **No network traffic:** All logging is local only
2. **Low CPU overhead:** 100ms poll interval (~1% CPU)
3. **Fixed memory:** No dynamic allocation (prevents memory forensics)
4. **Restrictive permissions:** Logs created with 0600 (owner-only)
5. **Optional export:** JSON export only on-demand

### Operational Security Features

#### 1. Local-Only Operation

**Implementation:**
- No network sockets opened
- No DNS queries
- No remote logging/telemetry
- All data stored in memory or local filesystem

**Rationale:**
- Prevents lateral movement detection
- No IOC (Indicator of Compromise) in network logs
- Suitable for air-gapped environments
- Complies with offline security requirements

#### 2. Minimal Forensic Footprint

**Memory management:**
```c
/* Static allocation - no heap fragmentation */
static heci_monitor_t g_monitor;

/* Fixed-size buffers - no realloc patterns */
heci_traffic_entry_t entries[1024];  /* Circular */
heci_alert_t alerts[256];            /* Circular */
```

**Benefits:**
- No malloc/free patterns in memory forensics
- Predictable memory layout
- Circular buffers overwrite old data (auto-cleanup)

#### 3. Privileged Access Control

**Requirements:**
- Root privileges (UID 0)
- Read/write access to `/dev/mei0`
- Kernel module `mei_me` loaded

**Security implications:**
- High privilege = high trust requirement
- Compromised monitoring process = full system access
- Implement least-privilege where possible

#### 4. Log File Security

**JSON export:**
```c
/* Create file with restrictive permissions */
fp = fopen(filepath, "w");
chmod(filepath, 0600);  /* Owner read/write only */
```

**Best practices:**
- Store logs on encrypted filesystem (LUKS/dm-crypt)
- Use secure deletion (shred/wipe) when done
- Set filesystem-level encryption (ecryptfs)
- Consider tmpfs for volatile logs (disappear on reboot)

---

## Reverse Engineering Deep Dive

### MEI Driver Internals

**Linux kernel driver:** `drivers/misc/mei/`

Key files:
- `mei-main.c` - Character device interface
- `client.c` - MKHI client management
- `hw-me.c` - HECI hardware abstraction
- `hbm.c` - Host Bus Message protocol (layer below MKHI)

**IOCTL interface:**

```c
/* Connect to specific ME client UUID */
#define IOCTL_MEI_CONNECT_CLIENT _IOWR('H', 0x01, struct mei_connect_client_data)
```

**This module's usage:**
```c
/* MKHI client GUID (discovered via reverse engineering) */
static const uint8_t mei_mkhi_guid[16] = {
    0x8e, 0x6a, 0xa7, 0xf4, 0x57, 0x4b, 0x40, 0x82,
    0xa6, 0x99, 0xfc, 0xb0, 0x54, 0xef, 0x68, 0x13
};

/* Connect to MKHI client */
memcpy(connect_data.in_client_uuid.guid, mei_mkhi_guid, 16);
ioctl(fd, IOCTL_MEI_CONNECT_CLIENT, &connect_data);
```

**GUID discovery:**
- Extracted from Intel reference code
- Also visible in MEInfo tool source
- Consistent across ME versions 6.x - 15.x

### MKHI Command Decoding

**Example: Get Firmware Version (0xF0:0x02)**

Request:
```
00 00 00 F0 02 00 00 00  | Header: group=0xF0, cmd=0x02
```

Response:
```
00 00 00 F0 02 01 00 00  | Header: group=0xF0, cmd=0x02, response=1
0C 00 00 00              | Platform: 12 (ME 12.x)
00 00 08 00              | Major: 8
1E 00                    | Minor: 30
00 0B                    | Hotfix: 11
47 04                    | Build: 1095
```

**Decoding logic:**
```c
struct fw_version_response {
    mkhi_header_t header;
    uint32_t platform;
    uint32_t major;
    uint16_t minor;
    uint16_t hotfix;
    uint16_t build;
};
/* Version: 8.30.11.1095 */
```

**Discovery method:**
- Run MEInfo tool under strace
- Capture ioctl() calls to /dev/mei0
- Hexdump of read/write buffers
- Correlate with MEInfo output
- Reverse-engineer structure from patterns

### Undocumented Groups

**Discovery via fuzzing:**

```c
/* Brute-force all group IDs */
for (uint8_t group = 0; group < 256; group++) {
    for (uint8_t cmd = 0; cmd < 256; cmd++) {
        send_mkhi_command(group, cmd, NULL, 0);
        /* Check for valid response vs error */
    }
}
```

**Results:**
- Many groups return "Invalid Group" error
- Some groups exist but undocumented
- Error codes reveal group existence
- Further fuzzing reveals command structure

**Ethical considerations:**
- Fuzzing production systems = bad idea
- Use dedicated test hardware
- Risk of bricking ME firmware
- Vendor may consider CFAA violation

---

## Attack Surface Analysis

### This Module's Attack Surface

**Input vectors:**
1. `/dev/mei0` data (kernel-controlled)
2. Command-line arguments (for test program)
3. Filesystem paths (JSON export)

**Vulnerabilities to consider:**

#### Buffer Overflow
```c
/* POTENTIAL ISSUE (mitigated): */
read(fd, msg->data, sizeof(msg->data));  /* Fixed-size buffer */

/* MITIGATION: */
/* - sizeof() ensures bounds */
/* - Kernel driver enforces max message size */
/* - No user-controlled length parameter */
```

#### Integer Overflow
```c
/* SAFE: */
size_t pos = (log->head + HECI_LOG_MAX_ENTRIES - total) % HECI_LOG_MAX_ENTRIES;

/* Modulo prevents overflow */
/* Unsigned arithmetic well-defined */
```

#### Race Conditions
```c
/* MITIGATION: */
pthread_mutex_lock(&g_monitor.log.lock);
/* ... access shared data ... */
pthread_mutex_unlock(&g_monitor.log.lock);

/* All shared state protected by mutex */
```

#### Path Traversal (JSON export)
```c
/* VULNERABILITY: */
heci_export_log_json(&log, user_controlled_path);

/* MITIGATION (caller's responsibility): */
/* - Validate filepath before calling */
/* - Use absolute paths */
/* - Check for "../" sequences */
```

**Recommendation:** Add path validation in export function.

---

## Integration with FirmwareGuard

### Blocking vs Monitoring

**Current implementation:** Monitoring only (passive)

**Future enhancement:** Integrate with blocker module

**Blocking strategy:**

```c
/* In heci_process_message(): */
if (msg->header.group_id == MKHI_HMRFPO_GROUP_ID &&
    msg->header.command == MKHI_CMD_HMRFPO_ENABLE) {

    /* Check policy: should we allow this? */
    if (!policy_allow_flash_override()) {
        /* Send error response to host */
        send_error_response(msg, 0x10 /* Not allowed */);

        /* Alert admin */
        syslog(LOG_ALERT, "BLOCKED: HMRFPO enable attempt");

        return; /* Don't forward to ME */
    }
}

/* Forward to ME */
forward_to_me(msg);
```

**Challenges:**
- Requires kernel driver modification (not userspace)
- Or: LD_PRELOAD interception of MEI ioctl
- Or: Firewall-style filtering in kernel module

### Correlation with Other Modules

**Example: Correlate with UEFI variable changes**

```c
/* HECI monitor detects HMRFPO_ENABLE */
heci_alert_t alert = detect_hmrfpo_enable();

/* Check if UEFI variables changed recently */
uefi_change_log_t *changes = uefi_get_recent_changes(60); /* 60 sec */

if (changes->num_changes > 0) {
    /* Suspicious: Flash override + UEFI changes */
    raise_critical_alert("Potential firmware implant attempt");
}
```

**Other correlation opportunities:**
- SMM intrusion detection
- Rootkit detection module
- Live firmware dump analysis
- Bootguard status changes

---

## Evasion Techniques (Adversary Perspective)

### How an attacker might evade this module:

#### 1. Direct SPI Flash Access
- Use external programmer (Ch341A, etc.)
- Bypass HECI entirely
- **Mitigation:** This module won't detect; use SPI monitor instead

#### 2. Kernel Module Compromise
- Rootkit modifies MEI driver
- Filters out malicious commands
- **Mitigation:** Use kernel integrity monitoring (IMA/EVM)

#### 3. ME-Direct Communication
- Some ME functionality doesn't use HECI
- Example: AMT network stack (out-of-band)
- **Mitigation:** Network monitoring, AMT-specific tools

#### 4. Timing Attacks
- Send malicious commands before monitor starts
- During boot, before OS loads
- **Mitigation:** Early-boot monitoring (UEFI DXE driver)

#### 5. Undocumented Protocols
- Use non-MKHI ME communication
- HBM (Host Bus Messages), raw HECI
- **Mitigation:** Extend module to monitor HBM layer

---

## Detection Engineering

### Behavioral Analysis

**Baseline establishment:**

```python
# Typical system baseline (examples)
- FWCAPS queries: ~5-10 per boot
- PM commands: ~20-50 during power state changes
- BUP commands: ~2-5 during POST
- HMRFPO: 0 (unless BIOS update)
- UNCONFIGURE: 0
```

**Anomaly detection:**

```python
if msg_count['HMRFPO'] > 0 and not in_bios_update_window():
    raise_alert(CRITICAL, "Unexpected HMRFPO activity")

if msg_count['UNKNOWN_GROUPS'] > 5:
    raise_alert(MEDIUM, "Possible ME fuzzing/recon")

if total_msg_rate > 100/sec:
    raise_alert(LOW, "Excessive ME traffic")
```

### Signature-Based Detection

**Known malicious patterns:**

```c
/* Pattern: Specific exploit sequences */
if (prev_msg.group == 0x0F && prev_msg.cmd == 0x33 &&
    curr_msg.group == 0x05 && curr_msg.cmd == 0x01) {
    /* Known exploit chain for CVE-XXXX-YYYY */
    raise_alert(CRITICAL, "Known ME exploit attempt");
}
```

---

## Forensic Analysis

### Log Analysis Workflow

**1. Export log:**
```bash
sudo ./heci_test 300  # Monitor for 5 minutes
# Exports to /tmp/heci_traffic.json
```

**2. Analyze with jq:**
```bash
# Get all alerts
jq '.heci_monitor_log.alerts' /tmp/heci_traffic.json

# Count by group
jq '.heci_monitor_log.messages_by_group' /tmp/heci_traffic.json

# Find high-risk alerts
jq '.heci_monitor_log.alerts[] | select(.risk_level >= 3)' /tmp/heci_traffic.json
```

**3. Correlate with system logs:**
```bash
# Check for BIOS updates around HMRFPO events
grep -i "bios\|firmware" /var/log/syslog | grep -A5 -B5 "$(date -d @$(jq -r '.alerts[0].timestamp' log.json))"
```

**4. Incident response:**
- If unexpected HMRFPO: assume compromise, dump firmware
- If UNCONFIGURE: verify against policy
- If unknown groups: research and update signatures

---

## Future Research Directions

### 1. Machine Learning Anomaly Detection

**Approach:**
- Collect baseline traffic from known-good systems
- Train autoencoder on normal HECI patterns
- Flag deviations as anomalous

**Challenges:**
- High false-positive rate
- ME behavior varies by platform
- Limited training data

### 2. Full Protocol Decoding

**Current limitation:** Only MKHI header decoded, payloads opaque

**Enhancement:**
- Decode common command payloads
- Extract firmware version, capabilities
- Parse HMRFPO authentication data

**Benefit:** Deeper visibility into ME state

### 3. Real-Time Blocking

**Implementation options:**
- Kernel module: intercept ioctl calls
- LD_PRELOAD: hook MEI library functions
- HECI firewall: filter at hardware level (requires custom firmware)

### 4. Cross-Platform Support

**Expand beyond Intel:**
- AMD PSP monitoring (via similar mechanisms)
- ARM TrustZone (TEE) monitoring
- Other proprietary coprocessors

---

## Conclusion

This HECI monitor provides unprecedented visibility into Intel ME activity from userspace. While it cannot prevent all attacks, it significantly raises the bar for firmware-level adversaries and provides critical forensic data for incident response.

**Key takeaways:**
- ✅ Detects flash protection override attempts
- ✅ Identifies ME unconfigure operations
- ✅ Behavioral anomaly detection
- ✅ OPSEC-focused design (offline, minimal footprint)
- ⚠️ Cannot block attacks (monitoring only)
- ⚠️ Userspace limitation (can be evaded by rootkits)
- ⚠️ Requires root privileges

**Recommended use cases:**
- Firmware security auditing
- Incident response and forensics
- Research and reverse engineering
- Enterprise endpoint monitoring
- Air-gapped high-security environments

---

## References

### Academic Papers
- "Intel ME: The Way of the Static Analysis" (Positive Technologies)
- "Disabling Intel ME 11 via Undocumented Mode" (Positive Technologies)
- "Intel ME Manufacturing Mode Override" (ME Unlock)

### Tools
- `me_cleaner` - ME firmware modification tool
- `MEInfo` - Intel's official ME info utility
- `intelmetool` - Open-source ME analysis (coreboot project)
- `UEFITool` - UEFI firmware parser

### Documentation
- Intel Management Engine BIOS Writer's Guide (limited availability)
- MEI Driver source code (`drivers/misc/mei/`)
- Intel PCH datasheets (public sections)

### Security Research
- Trammell Hudson (coreboot/LinuxBoot)
- Igor Skochinsky (ME firmware analysis)
- Maxim Goryachy & Mark Ermolov (Positive Technologies)
- Nicola Corna (me_cleaner author)

---

**Document Version:** 1.0
**Last Updated:** 2025-12-19
**Classification:** Technical Reference - Defensive Security
