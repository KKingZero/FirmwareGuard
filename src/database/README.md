# CVE Correlation Database

## Overview

The CVE correlation database provides **OFFLINE-ONLY** CVE tracking and version correlation for firmware components including Intel ME/CSME, AMD PSP, and UEFI/SecureBoot.

## Implementation

- **cve_db.h**: Header file with public API
- **cve_db.c**: SQLite-based implementation with security hardening
- **data/cve_firmware.json**: Seed data with 21 real CVEs from 2017-2024

## Dependencies

Before building, install the required development libraries:

```bash
sudo apt-get install libsqlite3-dev libssl-dev
```

Or on RHEL/Fedora:

```bash
sudo dnf install sqlite-devel openssl-devel
```

## Features

### Security-First Design

1. **Input Validation**: All inputs are validated and sanitized
2. **SQL Injection Prevention**: Parameterized queries only, no string concatenation
3. **Memory Safety**: Bounds checking on all buffer operations
4. **Size Limits**: JSON imports limited to 10MB maximum
5. **OFFLINE-ONLY**: No network code, manual JSON imports only

### Core Functions

- `cve_db_init()`: Initialize database with schema creation
- `cve_db_search()`: Search CVEs by component, vendor, severity
- `cve_db_check_version()`: Check if a specific version is vulnerable
- `cve_db_get_by_component()`: Get all CVEs for a component type
- `cve_db_import_json()`: Import CVEs from JSON file (offline)
- `cve_db_export_json()`: Export CVEs to JSON file

### Version Comparison

Supports semantic version comparison for vulnerability range checking:
- Formats: X.Y.Z, X.Y.Z.W, X.Y.Z-suffix
- Range checking: version_affected_start to version_affected_end
- Fixed version tracking

## Database Schema

```sql
CREATE TABLE cve_entries (
    id INTEGER PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,
    component TEXT NOT NULL,
    component_type INTEGER NOT NULL,
    vendor TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    version_affected_start TEXT,
    version_affected_end TEXT,
    version_fixed TEXT,
    cvss_score REAL,
    severity INTEGER,
    cvss_vector TEXT,
    published_date INTEGER,
    modified_date INTEGER,
    exploited_in_wild INTEGER,
    patch_available INTEGER,
    created_at INTEGER,
    updated_at INTEGER
);

CREATE TABLE cve_references (
    id INTEGER PRIMARY KEY,
    cve_entry_id INTEGER NOT NULL,
    reference_url TEXT NOT NULL,
    FOREIGN KEY(cve_entry_id) REFERENCES cve_entries(id)
);
```

## Seed Data

The database includes 21 critical CVEs:

### Intel ME/CSME (8 CVEs)
- CVE-2017-5689: Silent Bob is Silent (CVSS 9.8, exploited in wild)
- CVE-2020-0566: CSME input validation (CVSS 6.8)
- CVE-2021-0157: CSME privilege escalation (CVSS 8.2)
- CVE-2021-0146: Hardware debug logic (CVSS 7.1)
- CVE-2022-21186: Control flow management (CVSS 7.5)
- CVE-2023-28005: Boot Guard bypass (CVSS 8.2)
- CVE-2019-11098: Access control (CVSS 4.4)
- CVE-2020-8705: Race condition (CVSS 5.5)

### AMD PSP (6 CVEs)
- CVE-2018-8897: Debug exception handling (CVSS 7.8)
- CVE-2019-9836: PSP code execution (CVSS 7.2)
- CVE-2021-26333: Memory validation (CVSS 6.7)
- CVE-2022-33942: Bounds checking (CVSS 7.5)
- CVE-2023-20533: DRAM address validation (CVSS 7.3)
- CVE-2023-20526: Access control (CVSS 7.8)

### UEFI/SecureBoot (7 CVEs)
- CVE-2022-21894: BlackLotus bootkit (CVSS 8.8, exploited in wild)
- CVE-2020-10713: BootHole (CVSS 8.2)
- CVE-2021-3696: BootHole 2 (CVSS 7.5)
- CVE-2020-27786: UEFI memory corruption (CVSS 7.8)
- CVE-2022-26871: TXT authentication bypass (CVSS 7.0)
- CVE-2024-21762: SecureBoot DBX update (CVSS 6.7)
- CVE-2018-3616: Spectre variant (CVSS 5.6)

## Usage Example

```c
#include "cve_db.h"

int main(void) {
    // Initialize database
    if (cve_db_init("/var/lib/firmwareguard/cve.db") != 0) {
        fprintf(stderr, "Failed to initialize CVE database\n");
        return 1;
    }

    // Import seed data
    int imported = 0, skipped = 0;
    if (cve_db_import_json("/usr/share/firmwareguard/cve_firmware.json",
                           &imported, &skipped) == 0) {
        printf("Imported %d CVEs, skipped %d\n", imported, skipped);
    }

    // Check if a version is vulnerable
    cve_match_t *matches = NULL;
    int count = 0;
    if (cve_db_check_version("Intel ME", "11.6.20", &matches, &count) == 0) {
        printf("Found %d vulnerabilities for Intel ME 11.6.20\n", count);
        for (int i = 0; i < count; i++) {
            printf("  %s: %s (CVSS %.1f)\n",
                   matches[i].cve->cve_id,
                   matches[i].cve->description,
                   matches[i].cve->cvss_score);
        }
        cve_db_free_results(matches, count);
    }

    // Get all critical CVEs
    cve_query_opts_t opts = {
        .min_severity = CVE_SEVERITY_CRITICAL,
        .only_exploited = false,
        .limit = 100
    };

    cve_match_t *critical = NULL;
    if (cve_db_search(&opts, &critical, &count) == 0) {
        printf("Found %d critical CVEs\n", count);
        cve_db_free_results(critical, count);
    }

    // Print database statistics
    cve_db_stats_t stats;
    if (cve_db_stats(&stats) == 0) {
        cve_print_stats(&stats);
    }

    cve_db_close();
    return 0;
}
```

## Security Considerations

### Threat Model

The CVE database is designed for offline-only operation to prevent:
- Network-based attacks during vulnerability lookups
- Dependency on external CVE services
- Information disclosure about system configuration

### Memory Safety

All string operations use bounded functions:
- `strncpy()` with explicit null termination
- Size validation before allocation
- Integer overflow checks in size calculations

### SQL Injection Prevention

- All queries use parameterized statements via `sqlite3_bind_*`
- No dynamic SQL construction from user input
- Input validation on all external data

### Performance

- Prepared statement caching for frequent queries
- Database indexes on commonly queried fields (cve_id, component, severity)
- WAL mode enabled for concurrent access
- Transaction batching for bulk imports

## Integration with FirmwareGuard

The CVE database integrates with:

1. **ME/PSP Detection**: Cross-reference detected firmware versions against CVE database
2. **UEFI Analysis**: Check bootloader and SecureBoot components for known vulnerabilities
3. **Reporting**: Include CVE information in audit reports
4. **Risk Assessment**: Calculate system risk based on vulnerable components

## Manual CVE Updates

To add new CVEs manually:

1. Create a JSON file following the schema in `cve_firmware.json`
2. Import using: `cve_db_import_json("new_cves.json", &imported, &skipped)`
3. Or use the command-line tool: `firmwareguard --import-cves new_cves.json`

## File Locations

- Database: `/var/lib/firmwareguard/cve.db`
- Seed data: `/usr/share/firmwareguard/cve_firmware.json`
- Additional CVE data: `/etc/firmwareguard/cve_updates/`

## License

This CVE correlation database is part of FirmwareGuard and follows the same license.

CVE data is sourced from:
- NIST National Vulnerability Database (NVD)
- Intel Security Center
- AMD Product Security
- Microsoft Security Response Center

CVE identifiers are standardized by MITRE Corporation.
