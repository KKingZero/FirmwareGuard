# HECI Monitor API Reference

## Quick Start

```c
#include "monitor/heci_monitor.h"

/* Initialize and start monitoring */
heci_init();
heci_start_monitor(true);  /* true = enable pattern detection */

/* Monitor for some time */
sleep(60);

/* Stop and get results */
heci_stop_monitor();
heci_log_t log;
heci_get_log(&log);
heci_print_summary(&log);
heci_cleanup();
```

---

## Core Functions

### `int heci_init(void)`

Initialize the HECI monitor subsystem.

**Returns:**
- `FG_SUCCESS` (0) - Initialization successful
- `FG_NO_PERMISSION` (-2) - Not running as root
- `FG_NOT_SUPPORTED` (-4) - MEI device not available

**Requirements:**
- Root privileges
- MEI kernel driver loaded (`modprobe mei_me`)
- `/dev/mei0` or `/dev/mei` exists

**Notes:**
- Opens MEI device file descriptor
- Attempts to connect to MKHI client
- Initializes internal data structures
- Thread-safe to call multiple times (idempotent)

**Example:**
```c
if (heci_init() != FG_SUCCESS) {
    fprintf(stderr, "Failed to initialize HECI monitor\n");
    return 1;
}
```

---

### `int heci_start_monitor(bool enable_pattern_detection)`

Start background monitoring of HECI traffic.

**Parameters:**
- `enable_pattern_detection` - If `true`, analyze traffic for suspicious patterns

**Returns:**
- `FG_SUCCESS` (0) - Monitoring started
- `FG_ERROR` (-1) - Failed to start (e.g., thread creation failed)

**Behavior:**
- Launches background thread that polls `/dev/mei0`
- Captures all HECI messages (requests and responses)
- Stores messages in circular buffer (max 1024 entries)
- If pattern detection enabled, analyzes each message for suspicious activity

**Notes:**
- Non-blocking - returns immediately after starting thread
- Thread polls with 100ms timeout for low CPU overhead
- Safe to call multiple times (will warn if already running)

**Example:**
```c
/* Start with pattern detection */
if (heci_start_monitor(true) != FG_SUCCESS) {
    fprintf(stderr, "Failed to start monitoring\n");
    heci_cleanup();
    return 1;
}
```

---

### `int heci_stop_monitor(void)`

Stop background monitoring thread.

**Returns:**
- `FG_SUCCESS` (0) - Monitoring stopped

**Behavior:**
- Signals monitoring thread to terminate
- Waits for thread to complete (blocking call)
- Preserves all captured log data
- Safe to call even if not monitoring

**Notes:**
- Blocking call - waits for thread to finish current operation
- Log data remains accessible after stop
- Does not close MEI device (can restart monitoring)

**Example:**
```c
/* Stop monitoring gracefully */
heci_stop_monitor();
```

---

### `int heci_get_log(heci_log_t *log)`

Retrieve a copy of the current traffic log.

**Parameters:**
- `log` - Pointer to caller-allocated `heci_log_t` structure

**Returns:**
- `FG_SUCCESS` (0) - Log retrieved successfully
- `FG_ERROR` (-1) - Invalid parameter or not initialized

**Behavior:**
- Thread-safe - locks log during copy
- Returns complete copy including:
  - Traffic entries (up to 1024)
  - Alerts (up to 256)
  - Statistics
- Can be called while monitoring is active

**Example:**
```c
heci_log_t log;
if (heci_get_log(&log) == FG_SUCCESS) {
    printf("Captured %lu messages\n", log.stats.total_messages);
}
```

---

### `int heci_analyze_traffic(const heci_log_t *log, heci_alert_t *alerts, size_t max_alerts, size_t *num_alerts)`

Analyze traffic log for suspicious patterns.

**Parameters:**
- `log` - Traffic log to analyze (from `heci_get_log`)
- `alerts` - Output array for detected alerts
- `max_alerts` - Maximum number of alerts to return
- `num_alerts` - Output: actual number of alerts found

**Returns:**
- `FG_SUCCESS` (0) - Analysis complete
- `FG_ERROR` (-1) - Invalid parameters

**Detected Patterns:**
- HMRFPO enable/lock commands (flash protection)
- ME unconfigure commands (HAP/AltDisable)
- Excessive traffic rate (>100 msg/sec)
- High orphaned request rate (>10%)
- Unknown MKHI groups
- Failed authentication attempts

**Example:**
```c
heci_alert_t alerts[256];
size_t num_alerts;

heci_analyze_traffic(&log, alerts, 256, &num_alerts);

for (size_t i = 0; i < num_alerts; i++) {
    printf("[%s] %s\n",
           heci_get_pattern_name(alerts[i].pattern),
           alerts[i].description);
}
```

---

### `void heci_cleanup(void)`

Cleanup and release all resources.

**Behavior:**
- Stops monitoring if active
- Closes MEI device file descriptor
- Frees all allocated memory
- Clears log data (not recoverable)
- Destroys mutexes

**Notes:**
- Safe to call multiple times
- Should be called before program exit
- After cleanup, must call `heci_init()` to use module again

**Example:**
```c
/* Always cleanup before exit */
heci_cleanup();
```

---

## Utility Functions

### `bool heci_is_supported(void)`

Check if MEI/HECI device is available.

**Returns:**
- `true` - MEI device exists
- `false` - MEI device not found

**Example:**
```c
if (!heci_is_supported()) {
    fprintf(stderr, "This system does not have Intel ME\n");
    return 1;
}
```

---

### `const char* heci_get_group_name(uint8_t group_id)`

Get human-readable name for MKHI group ID.

**Parameters:**
- `group_id` - MKHI group identifier (0x00-0xFF)

**Returns:**
- String describing the group (e.g., "FWCAPS (Firmware Capabilities)")
- "UNKNOWN" if group_id not recognized

**Example:**
```c
printf("Group: %s\n", heci_get_group_name(0x05));
/* Output: Group: HMRFPO (Flash Protection Override) */
```

---

### `const char* heci_get_pattern_name(heci_pattern_t pattern)`

Get human-readable description of pattern type.

**Parameters:**
- `pattern` - Pattern type enum

**Returns:**
- String describing pattern (e.g., "Flash Protection Override Enable")

**Example:**
```c
printf("Pattern: %s\n", heci_get_pattern_name(PATTERN_HMRFPO_ENABLE));
/* Output: Pattern: Flash Protection Override Enable */
```

---

### `int heci_export_log_json(const heci_log_t *log, const char *filepath)`

Export traffic log to JSON file.

**Parameters:**
- `log` - Log to export
- `filepath` - Output file path

**Returns:**
- `FG_SUCCESS` (0) - Export successful
- `FG_ERROR` (-1) - Failed to write file

**Behavior:**
- Creates JSON file with restrictive permissions (0600)
- Includes statistics, alerts, and message group breakdown
- Timestamps in Unix epoch format

**OPSEC Note:**
- File created with owner-only permissions
- Ensure filepath is on encrypted storage
- No network transmission

**Example:**
```c
heci_export_log_json(&log, "/var/log/heci_traffic.json");
```

**Output Format:**
```json
{
  "heci_monitor_log": {
    "version": "1.0",
    "statistics": {
      "total_messages": 1234,
      "requests": 617,
      "responses": 617,
      ...
    },
    "messages_by_group": {
      "0x03": 450,
      "0x05": 12
    },
    "alerts": [...]
  }
}
```

---

### `void heci_print_summary(const heci_log_t *log)`

Print human-readable traffic summary to stdout.

**Parameters:**
- `log` - Log to summarize

**Output Includes:**
- Total messages, requests, responses
- Orphaned messages count
- Average/max latency
- Top message groups
- All alerts with risk levels

**Example:**
```c
heci_print_summary(&log);
```

**Sample Output:**
```
=== HECI Traffic Summary ===

Statistics:
  Total Messages:     2468
  Requests:           1234
  Responses:          1234
  Orphaned Requests:  0
  Avg Latency:        850 us
  Max Latency:        12000 us

Top Message Groups:
  0x03 (FWCAPS): 450
  0x02 (PM): 320

Alerts: 2 total
  [HIGH] Flash Protection Lock: Flash protection lock command detected
  [LOW] Unknown MKHI Group: Unknown MKHI group 0x7A command 0x01
```

---

## Data Structures

### `mkhi_header_t`

MKHI message header (8 bytes).

```c
typedef struct __attribute__((packed)) {
    uint8_t  group_id;      /* MKHI group (0x00-0xFF) */
    uint8_t  command;       /* Command within group */
    uint8_t  is_response;   /* 0=request, 1=response */
    uint8_t  reserved;      /* Always 0 */
    uint8_t  result;        /* Result code (responses) */
    uint8_t  reserved2[3];  /* Reserved bytes */
} mkhi_header_t;
```

---

### `heci_message_t`

Complete HECI message.

```c
typedef struct {
    mkhi_header_t header;           /* MKHI header */
    uint8_t data[4096];             /* Payload */
    size_t data_len;                /* Actual payload length */
    struct timespec timestamp;      /* Capture timestamp */
} heci_message_t;
```

---

### `heci_traffic_entry_t`

Request-response pair.

```c
typedef struct {
    heci_message_t request;         /* Original request */
    heci_message_t response;        /* Response (if any) */
    bool has_response;              /* True if matched */
    uint64_t latency_us;            /* Latency in microseconds */
} heci_traffic_entry_t;
```

---

### `heci_alert_t`

Suspicious activity alert.

```c
typedef struct {
    heci_pattern_t pattern;         /* Pattern type */
    risk_level_t risk;              /* Risk level */
    char description[256];          /* Details */
    struct timespec timestamp;      /* Detection time */
    heci_traffic_entry_t *related_entry; /* Related traffic */
} heci_alert_t;
```

---

### `heci_stats_t`

Traffic statistics.

```c
typedef struct {
    uint64_t total_messages;        /* Total captured */
    uint64_t requests;              /* Request count */
    uint64_t responses;             /* Response count */
    uint64_t orphaned_requests;     /* No response */
    uint64_t orphaned_responses;    /* No request */
    uint64_t avg_latency_us;        /* Avg latency */
    uint64_t max_latency_us;        /* Max latency */
    uint64_t messages_per_group[256]; /* Per-group count */
    struct timespec start_time;     /* Monitor start */
    struct timespec last_activity;  /* Last message */
} heci_stats_t;
```

---

### `heci_log_t`

Complete traffic log (circular buffers).

```c
typedef struct {
    heci_traffic_entry_t entries[1024]; /* Traffic log */
    size_t count;                   /* Total entries */
    size_t head;                    /* Write position */

    heci_alert_t alerts[256];       /* Alert log */
    size_t alert_count;             /* Total alerts */
    size_t alert_head;              /* Write position */

    heci_stats_t stats;             /* Statistics */
    pthread_mutex_t lock;           /* Thread safety */
} heci_log_t;
```

**Note:** Circular buffers wrap around. If `count > 1024`, oldest entries are overwritten.

---

## Enumerations

### `heci_pattern_t`

Suspicious pattern types.

```c
typedef enum {
    PATTERN_NONE = 0,
    PATTERN_HMRFPO_ENABLE,          /* Flash override enable */
    PATTERN_HMRFPO_LOCK,            /* Flash lock */
    PATTERN_UNCONFIGURE,            /* ME disable */
    PATTERN_EXCESSIVE_TRAFFIC,      /* High msg rate */
    PATTERN_UNUSUAL_TIMING,         /* Timing anomaly */
    PATTERN_UNKNOWN_GROUP,          /* Unknown MKHI group */
    PATTERN_FAILED_AUTH,            /* Auth failure */
    PATTERN_FIRMWARE_UPDATE,        /* FW update */
} heci_pattern_t;
```

---

## Constants

### MKHI Group IDs

```c
#define MKHI_BUP_GROUP_ID       0x00  /* Bring-Up Platform */
#define MKHI_PM_GROUP_ID        0x02  /* Power Management */
#define MKHI_FWCAPS_GROUP_ID    0x03  /* Firmware Capabilities */
#define MKHI_HMRFPO_GROUP_ID    0x05  /* Flash Protection Override */
#define MKHI_MCA_GROUP_ID       0x0A  /* Memory Config */
#define MKHI_GEN2_GROUP_ID      0xF1  /* General 2 */
#define MKHI_GEN_GROUP_ID       0xFF  /* General/Common */
```

### MKHI Commands

```c
#define MKHI_CMD_GET_FW_VERSION     0x02
#define MKHI_CMD_GET_FW_CAPS        0x02
#define MKHI_CMD_HMRFPO_ENABLE      0x01
#define MKHI_CMD_HMRFPO_LOCK        0x02
#define MKHI_CMD_END_OF_POST        0x0C
#define MKHI_CMD_UNCONFIGURE        0x0D
```

---

## Error Codes

From `firmwareguard.h`:

```c
#define FG_SUCCESS          0   /* Success */
#define FG_ERROR           -1   /* Generic error */
#define FG_NO_PERMISSION   -2   /* Not root */
#define FG_NOT_FOUND       -3   /* Not found */
#define FG_NOT_SUPPORTED   -4   /* Not supported */
```

---

## Thread Safety

- All public functions are thread-safe
- Internal log uses `pthread_mutex_t` for protection
- Background monitoring thread can run concurrently with API calls
- `heci_get_log()` creates a consistent snapshot

---

## Memory Management

- **Static allocation:** Main monitor state is global
- **Fixed buffers:** No dynamic allocation during monitoring
- **Cleanup:** Call `heci_cleanup()` to release resources
- **Footprint:** ~1MB for log buffers

---

## Performance Characteristics

- **Poll interval:** 100ms (10 Hz)
- **CPU overhead:** <1% (idle polling)
- **Memory:** ~1MB fixed allocation
- **Latency measurement:** Microsecond precision
- **Buffer capacity:** 1024 traffic entries, 256 alerts

---

## Security Notes

### OPSEC Features
- No network communication
- No remote telemetry
- Local logging only
- Restrictive file permissions (0600)
- Minimal system footprint

### Attack Surface
- Requires root (high privilege)
- Direct hardware access via MEI
- Log buffer overflow protection (circular)
- No dynamic memory allocation during monitoring

---

## Example: Complete Monitoring Session

```c
#include "monitor/heci_monitor.h"
#include <signal.h>

volatile bool running = true;

void sigint_handler(int sig) {
    running = false;
}

int main(void) {
    /* Check support */
    if (!heci_is_supported()) {
        fprintf(stderr, "MEI not available\n");
        return 1;
    }

    /* Initialize */
    if (heci_init() != FG_SUCCESS) {
        fprintf(stderr, "Init failed (need root?)\n");
        return 1;
    }

    /* Start monitoring */
    signal(SIGINT, sigint_handler);
    heci_start_monitor(true);

    printf("Monitoring... (Ctrl+C to stop)\n");
    while (running) sleep(1);

    /* Stop and analyze */
    heci_stop_monitor();

    heci_log_t log;
    heci_get_log(&log);
    heci_print_summary(&log);

    /* Export results */
    heci_export_log_json(&log, "/tmp/heci.json");

    /* Cleanup */
    heci_cleanup();

    return 0;
}
```

Compile: `gcc -pthread example.c heci_monitor.o -o monitor`
Run: `sudo ./monitor`
