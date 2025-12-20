# Threat Intelligence Quick Start Guide

## Installation

```bash
# Install SQLite development headers
sudo apt-get install libsqlite3-dev

# Compile test program
cd /home/zero/FirmwareGuard
gcc -Wall -Wextra -O2 -std=gnu11 -Iinclude -D_GNU_SOURCE \
    -o tools/test-threat-intel \
    tools/test-threat-intel.c \
    src/database/threat_intel.c \
    src/cJSON.c \
    -lsqlite3 -lm
```

## Quick Test

```bash
# Run test program with seed data
./tools/test-threat-intel data/threat_intel.json

# Database will be created at:
/tmp/firmwareguard_threat_intel_test.db
```

## Basic Usage

```c
#include "src/database/threat_intel.h"

// Initialize
threat_intel_init("/var/lib/firmwareguard/threat_intel.db");

// Import threat data
int families, iocs, skipped;
threat_intel_import_json("/etc/firmwareguard/threat_intel.json",
                         &families, &iocs, &skipped);

// Check hash
threat_match_t result;
threat_intel_check_hash("e5262db186c97b14ad5bae895f72ba3e", NULL, &result);

if (result.matched) {
    printf("THREAT: %s (confidence: %d%%)\n",
           result.family_name, result.confidence);
}

// Cleanup
threat_intel_close();
```

## Threat Families Included

1. **LoJax** - APT28 UEFI rootkit
2. **MosaicRegressor** - Chinese APT UEFI implant
3. **MoonBounce** - APT41 firmware rootkit
4. **CosmicStrand** - Long-running UEFI threat
5. **BlackLotus** - Secure Boot bypass bootkit
6. **ESPecter** - ESP-based bootkit
7. **ThunderStrike** - Apple EFI bootkit (PoC)
8. **Computrace** - Persistent firmware agent

## Files

- `src/database/threat_intel.h` - API header
- `src/database/threat_intel.c` - Implementation
- `data/threat_intel.json` - Seed data (8 families, 32 IOCs)
- `tools/test-threat-intel.c` - Test program
- `src/database/THREAT_INTEL.md` - Full documentation

## Key Features

- OFFLINE-ONLY (no network)
- SQLite database
- Hash and pattern matching
- MITRE ATT&CK mapping
- Confidence scoring
- Pattern correlation

## Quick Commands

```bash
# Validate JSON
python3 -m json.tool data/threat_intel.json > /dev/null

# Inspect database
sqlite3 /tmp/firmwareguard_threat_intel_test.db

# Count families
sqlite3 test.db "SELECT COUNT(*) FROM malware_families;"

# List all IOCs
sqlite3 test.db "SELECT family_id, ioc_type, value FROM threat_iocs;"

# Show MITRE techniques
sqlite3 test.db "SELECT * FROM family_mitre;"
```

## Integration Example

```c
// In your detection code:
extern int threat_intel_check_hash(const char *sha256, const char *sha512,
                                     threat_match_t *result);

// After computing firmware hash:
threat_match_t threat;
if (threat_intel_check_hash(firmware_sha256, NULL, &threat) == 0) {
    if (threat.matched) {
        // Handle threat detection
        report_malware_detected(&threat);
    }
}
```

## Documentation

See `src/database/THREAT_INTEL.md` for complete API documentation.
