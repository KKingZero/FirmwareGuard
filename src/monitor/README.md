# HECI/MEI Traffic Monitor

## Overview

The HECI Monitor module provides real-time monitoring and analysis of Intel Management Engine (ME) Host Embedded Controller Interface (HECI/MEI) traffic. This enables detection of suspicious ME activity patterns including:

- Flash protection override attempts (HMRFPO)
- ME unconfigure/disable commands (HAP/AltDisable)
- Firmware update activity
- Unusual traffic patterns
- Unknown or undocumented MKHI command groups

## Architecture

### Components

1. **heci_monitor.h** - Public API and data structures
2. **heci_monitor.c** - Core implementation with background monitoring thread

### Design Principles

- **OFFLINE-ONLY**: No network connectivity - all logging is local
- **OPSEC-focused**: Minimal system footprint, restrictive file permissions
- **Thread-safe**: Background monitoring thread with mutex-protected log
- **Circular buffers**: Fixed memory footprint (1024 traffic entries, 256 alerts)
- **Pattern detection**: Real-time analysis of suspicious ME commands

## Usage

### Basic Usage

```c
#include "monitor/heci_monitor.h"

int main(void) {
    int ret;
    heci_log_t log;

    /* Initialize HECI monitor (requires root) */
    ret = heci_init();
    if (ret != FG_SUCCESS) {
        fprintf(stderr, "Failed to initialize HECI monitor\n");
        return 1;
    }

    /* Start monitoring with pattern detection enabled */
    ret = heci_start_monitor(true);
    if (ret != FG_SUCCESS) {
        fprintf(stderr, "Failed to start monitoring\n");
        heci_cleanup();
        return 1;
    }

    /* Monitor for 60 seconds */
    sleep(60);

    /* Stop monitoring and get log */
    heci_stop_monitor();
    heci_get_log(&log);

    /* Print summary */
    heci_print_summary(&log);

    /* Export to JSON for offline analysis */
    heci_export_log_json(&log, "/var/log/heci_traffic.json");

    /* Cleanup */
    heci_cleanup();

    return 0;
}
```

### Pattern Detection

```c
heci_log_t log;
heci_alert_t alerts[256];
size_t num_alerts;

/* Get current log */
heci_get_log(&log);

/* Analyze for suspicious patterns */
heci_analyze_traffic(&log, alerts, 256, &num_alerts);

/* Process alerts */
for (size_t i = 0; i < num_alerts; i++) {
    printf("[%s] %s: %s\n",
           heci_get_pattern_name(alerts[i].pattern),
           alerts[i].risk == RISK_CRITICAL ? "CRITICAL" : "INFO",
           alerts[i].description);
}
```

### Checking Support

```c
if (!heci_is_supported()) {
    fprintf(stderr, "MEI/HECI device not available\n");
    return;
}
```

## MKHI Protocol Details

### Message Structure

```
+------------------+
| MKHI Header (8B) |
+------------------+
| Payload (var)    |
+------------------+
```

### MKHI Header Format

```c
typedef struct {
    uint8_t  group_id;      /* Command group (e.g., 0x05 = HMRFPO) */
    uint8_t  command;       /* Command within group */
    uint8_t  is_response;   /* 0 = request, 1 = response */
    uint8_t  reserved;
    uint8_t  result;        /* Result code (for responses) */
    uint8_t  reserved2[3];
} mkhi_header_t;
```

### Common MKHI Groups

| Group ID | Name | Description |
|----------|------|-------------|
| 0x00 | BUP | Bring-Up Platform initialization |
| 0x02 | PM | Power Management |
| 0x03 | FWCAPS | Firmware Capabilities query |
| 0x05 | HMRFPO | Host ME Region Flash Protection Override |
| 0x0A | MCA | Memory Configuration & Allocation |
| 0xF1 | GEN2 | General commands (v2) |
| 0xFF | GEN | General/Common commands |

### Suspicious Commands

#### HMRFPO_ENABLE (0x05:0x01)
- **Risk**: CRITICAL
- **Description**: Enables flash protection override, allowing host to modify ME region
- **Legitimate Use**: BIOS updates, manufacturing
- **Attack Vector**: Malicious firmware implants, ME region tampering

#### UNCONFIGURE (0xFF:0x0D)
- **Risk**: HIGH
- **Description**: Disables ME functionality (HAP/AltDisable mode)
- **Legitimate Use**: Privacy-focused configurations
- **Attack Vector**: Attempt to disable security monitoring

#### HMRFPO_LOCK (0x05:0x02)
- **Risk**: HIGH (context-dependent)
- **Description**: Locks flash protection settings
- **Legitimate Use**: Post-update security hardening
- **Suspicious**: Unexpected locking may indicate tampering attempt

## Compilation

### Prerequisites

```bash
# Install MEI driver (if not already present)
sudo modprobe mei_me

# Verify MEI device exists
ls -l /dev/mei0
```

### Build

```bash
# Compile with pthread support
gcc -c heci_monitor.c -o heci_monitor.o -Wall -Wextra -pthread

# Link into FirmwareGuard
gcc main.c heci_monitor.o -o firmwareguard -pthread
```

### Required Permissions

- Root privileges required (`CAP_SYS_ADMIN` or root)
- Read/write access to `/dev/mei0` or `/dev/mei`

## Security Considerations

### OPSEC Features

1. **No Network Traffic**: All monitoring is purely local
2. **Minimal Footprint**: Fixed memory allocation, no dynamic expansion
3. **Restrictive Permissions**: Log files created with 0600 (owner-only)
4. **No Persistent State**: Monitoring state cleared on cleanup
5. **Low Overhead**: Efficient polling with 100ms intervals

### Data Retention

- **Traffic Log**: Max 1024 entries (circular buffer)
- **Alerts**: Max 256 alerts (circular buffer)
- **JSON Export**: Manual export only, user-controlled

### Privacy

- No personally identifiable information (PII) collected
- No network communication
- No remote telemetry
- Local filesystem only

## Limitations

1. **Kernel Driver Required**: Depends on Linux MEI driver (`mei_me`)
2. **Intel-Only**: Only works on Intel platforms with ME
3. **Userspace Monitoring**: Cannot intercept all ME communication (some is internal to ME)
4. **Passive Monitoring**: Read-only observation, cannot block commands
5. **Limited Decoding**: Only MKHI protocol decoded; other ME protocols treated as opaque

## Future Enhancements

- [ ] Support for additional ME protocol families (HECI non-MKHI)
- [ ] Machine learning-based anomaly detection
- [ ] Integration with FirmwareGuard blocking engine
- [ ] Real-time alerting mechanisms (syslog, D-Bus)
- [ ] Enhanced payload decoding for common commands
- [ ] ME version-specific protocol handling

## References

- Intel ME Manufacturing Mode Override (HMRFPO): Intel documentation
- MEI Linux Kernel Driver: `drivers/misc/mei/`
- MKHI Protocol: Reverse-engineered from ME firmware analysis
- HAP (High Assurance Platform): Intel ME disable mode for government/enterprise

## License

Part of FirmwareGuard - see main project LICENSE

## Author

FirmwareGuard Development Team
