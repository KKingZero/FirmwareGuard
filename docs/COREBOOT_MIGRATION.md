# Coreboot Migration Assistant

## Overview

FirmwareGuard's Coreboot Migration Assistant helps users identify if their hardware is compatible with Coreboot or Libreboot firmware and provides step-by-step migration guidance.

**CRITICAL WARNING**: Flashing firmware can permanently brick your device. This tool provides guidance only - you assume all risk.

## Features

- **OFFLINE-ONLY**: No network connectivity required
- Hardware compatibility detection via DMI/SMBIOS
- Local database of supported boards
- Risk assessment and warnings
- Step-by-step migration instructions
- Firmware backup functionality
- Flash chip detection

## Architecture

### Files

```
src/migration/
├── coreboot_migrate.h          # Header file with data structures
└── coreboot_migrate.c          # Implementation

data/
└── coreboot_boards.json        # Board compatibility database
```

### Key Functions

#### `coreboot_check_compatibility()`
Checks if current hardware is supported by Coreboot/Libreboot.

**Process:**
1. Reads DMI/SMBIOS information from `/sys/class/dmi/id/`
2. Detects CPU vendor and model
3. Checks for Intel ME or AMD PSP presence
4. Queries local board database for compatibility
5. Assesses migration risk level
6. Generates warnings and recommendations

**Returns:**
- `coreboot_compat_result_t` structure containing:
  - Detected hardware information
  - Compatibility status
  - Migration risk level
  - Warnings and requirements
  - Summary

#### `coreboot_get_board_info()`
Retrieves detailed information about a specific board from the database.

**Matching Logic:**
- Primary: System vendor + product name (exact match)
- Fallback: Partial string matching for product name variations
- Secondary: Board name matching

#### `coreboot_migration_steps()`
Generates step-by-step migration instructions for supported hardware.

**Output:**
- Numbered steps specific to the board
- Required tools and hardware
- Risk warnings
- Important notes

#### `coreboot_backup_current()`
Creates a backup of current firmware using flashrom.

**Process:**
1. Verifies flashrom is installed
2. Creates backup directory (`/var/lib/firmwareguard/backups/`)
3. Executes `flashrom -p internal -r <backup_file>`
4. Calculates SHA-256 hash of backup
5. Stores metadata (timestamp, size, hash)

**Requires:** Root privileges, flashrom installed

## Database Format

The `coreboot_boards.json` database contains board compatibility information:

```json
{
  "version": "1.0.0",
  "description": "Coreboot/Libreboot Board Compatibility Database",
  "boards": [
    {
      "vendor": "Lenovo",
      "board_name": "ThinkPad X230",
      "dmi_sys_vendor": "LENOVO",
      "dmi_product_name": "2325",
      "compatibility": "libreboot",
      "fully_free": true,
      "requires_external_flash": true,
      "migration_risk": "medium",
      "migration_steps": [
        "Step 1: Backup firmware...",
        "Step 2: Disassemble laptop..."
      ]
    }
  ]
}
```

### Compatibility Levels

| Level | Description |
|-------|-------------|
| `libreboot` | Fully supported by Libreboot (100% free firmware) |
| `supported` | Supported by Coreboot (may require some blobs) |
| `partial` | Partial support (limited functionality) |
| `experimental` | Work in progress (high risk) |
| `unsupported` | Not supported |

### Migration Risk Levels

| Level | Description |
|-------|-------------|
| `low` | Well-tested, mature support, low brick risk |
| `medium` | Good support, requires care, moderate risk |
| `high` | Limited testing, high brick risk |
| `critical` | Experimental or not supported, very high risk |

## Usage Examples

### Check Compatibility

```c
#include "migration/coreboot_migrate.h"

coreboot_migrate_init();
coreboot_load_database("/path/to/coreboot_boards.json");

coreboot_compat_result_t result;
if (coreboot_check_compatibility(&result) == FG_SUCCESS) {
    coreboot_print_compatibility(&result, true);

    if (result.can_migrate) {
        printf("Migration is possible!\n");
        coreboot_print_migration_steps(&result.board_info);
    }
}

coreboot_migrate_cleanup();
```

### Create Firmware Backup

```c
firmware_backup_t backup;
if (coreboot_backup_current(&backup) == FG_SUCCESS) {
    printf("Backup created: %s\n", backup.backup_path);
    printf("SHA-256: %s\n", backup.hash_sha256);

    // Verify backup
    if (coreboot_verify_backup(&backup) == FG_SUCCESS) {
        printf("Backup verified successfully\n");
    }
}
```

## Supported Boards

The database currently includes:

### Libreboot (Fully Free)
- Lenovo ThinkPad X200, X220, X230
- Lenovo ThinkPad T400
- ASUS KGPE-D16, KCMA-D8 (server boards)
- Various older platforms

### Coreboot (Some Blobs)
- Lenovo ThinkPad T440p
- Google Chromebooks
- Purism Librem laptops
- System76 laptops
- Various desktop motherboards

### Experimental
- Various Intel NUCs
- Some MSI and Dell systems

## Technical Details

### DMI/SMBIOS Detection

The assistant reads hardware information from sysfs:

```
/sys/class/dmi/id/sys_vendor          # System manufacturer
/sys/class/dmi/id/product_name        # System model
/sys/class/dmi/id/board_name          # Motherboard model
/sys/class/dmi/id/bios_vendor         # Current BIOS vendor
/sys/class/dmi/id/bios_version        # Current BIOS version
```

### Flashrom Integration

Uses flashrom for firmware operations:

```bash
# Detect flash chip
flashrom -p internal

# Read firmware (backup)
flashrom -p internal -r firmware_backup.bin

# Write firmware (NOT IMPLEMENTED - too dangerous)
# flashrom -p internal -w new_firmware.bin
```

**Note**: Writing firmware is intentionally NOT implemented. Users must perform actual flashing manually after careful preparation.

## Safety Features

### Multiple Warning Levels

1. **Database Risk Assessment**: Each board has a risk level
2. **Hardware Requirement Warnings**: External programmer, hardware mods
3. **Critical Warning Banner**: Displayed before any migration
4. **Backup Verification**: Hash checking of firmware backups

### No Automatic Flashing

The assistant provides guidance only. It will:
- ✅ Detect compatibility
- ✅ Show migration steps
- ✅ Create backups
- ❌ Never automatically flash firmware

Users must manually execute flashing commands after understanding all risks.

## Updating the Database

The database is maintained manually (offline-only design). To update:

1. Research current Coreboot/Libreboot support at:
   - https://coreboot.org (download for offline use)
   - https://libreboot.org (download for offline use)

2. Edit `data/coreboot_boards.json`:
   - Add new supported boards
   - Update compatibility status
   - Update migration steps

3. Reload the database in FirmwareGuard

**Automatic online updates are NOT supported** by design - this is a security tool that must remain offline.

## Integration with FirmwareGuard

The migration assistant integrates with other FirmwareGuard modules:

### Baseline Capture
- Uses `baseline_capture_dmi()` for hardware detection
- Uses `baseline_capture_cpu()` for CPU information

### ME/PSP Detection
- Uses `probe_intel_me()` to detect Intel ME
- Uses `probe_amd_psp()` to detect AMD PSP
- Provides context for why migration may be desired

### Safety Framework
- Compatible with FirmwareGuard's backup/restore framework
- Follows same safety principles (dry-run, verification)

## Limitations

### What This Tool Does NOT Do

1. **Does not download firmware**: You must build Coreboot/Libreboot yourself or obtain from trusted sources
2. **Does not perform flashing**: Manual flashing required
3. **Does not guarantee success**: Even supported boards can brick
4. **Does not provide recovery**: External programmer needed for recovery
5. **Does not update online**: Database must be manually updated

### Known Issues

1. DMI matching may fail for OEM variations
2. Database may be incomplete or outdated
3. Requires root for flashrom access
4. Cannot detect all hardware requirements automatically

## Migration Workflow

### Recommended Process

1. **Research** (Offline)
   ```bash
   firmwareguard --coreboot-check
   ```
   - Check if board is supported
   - Review migration steps
   - Understand risks

2. **Prepare**
   - Download Coreboot/Libreboot documentation
   - Acquire external SPI programmer if required
   - Ensure stable power supply
   - Have backup hardware available

3. **Backup**
   ```bash
   firmwareguard --coreboot-backup
   ```
   - Create firmware backup
   - Verify backup integrity
   - Store backup safely (USB drive, etc.)

4. **Build Firmware** (External)
   - Build Coreboot/Libreboot using official tools
   - Configure for your specific board
   - Include required payloads (SeaBIOS, GRUB, etc.)

5. **Flash** (Manual)
   - Follow board-specific instructions
   - Use external programmer if required
   - Verify flash success

6. **Test**
   - Boot system
   - Verify all hardware works
   - Run FirmwareGuard scans to verify ME/PSP status

## Troubleshooting

### "Board not found in database"
- Your hardware may not be supported
- Check coreboot.org for current support status
- Update database JSON file if support exists

### "flashrom not found"
```bash
sudo apt install flashrom
```

### "Permission denied" when backing up
- Requires root privileges
- Run with sudo
- Some systems may need additional kernel parameters

### "Flash chip not detected"
- May require iomem=relaxed kernel parameter
- Some chips require external programmer
- Verify hardware is supported by flashrom

## Security Considerations

### Why Offline-Only?

1. **Trust**: No external dependencies or downloads
2. **Reproducibility**: Same behavior every time
3. **Transparency**: All data is local and inspectable
4. **Safety**: No risk of downloading malicious firmware

### Database Integrity

- Store database in read-only location
- Verify database source before updates
- Review all changes to database JSON

### Firmware Backup Security

- Backups contain your current firmware (may include ME/PSP)
- Store backups securely
- Never share backups (may contain unique identifiers)
- Encrypt backup storage if possible

## Contributing

To add boards to the database:

1. Research board support at coreboot.org/libreboot.org
2. Test migration process (optional but recommended)
3. Document migration steps clearly
4. Add entry to `data/coreboot_boards.json`
5. Include risk assessment and known issues

## References

- Coreboot Project: https://coreboot.org
- Libreboot Project: https://libreboot.org
- Flashrom: https://flashrom.org
- me_cleaner: https://github.com/corna/me_cleaner

## License

Same as FirmwareGuard main project.

## Disclaimer

**THIS TOOL PROVIDES GUIDANCE ONLY. FLASHING FIRMWARE CAN PERMANENTLY BRICK YOUR DEVICE. THE AUTHORS ASSUME NO LIABILITY FOR ANY DAMAGE CAUSED BY USING THIS TOOL. YOU PROCEED AT YOUR OWN RISK.**

Always:
- Create verified backups
- Read all documentation
- Understand the risks
- Have recovery hardware ready
- Proceed slowly and carefully
