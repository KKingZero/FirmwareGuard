/*
 * FirmwareGuard - Coreboot Migration Assistant Test
 * Demonstrates the coreboot migration functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/migration/coreboot_migrate.h"

int main(int argc, char *argv[]) {
    int ret;

    printf("\n");
    printf("==============================================\n");
    printf("  FirmwareGuard Coreboot Migration Assistant\n");
    printf("==============================================\n");
    printf("\n");

    /* Initialize migration subsystem */
    ret = coreboot_migrate_init();
    if (ret != FG_SUCCESS) {
        fprintf(stderr, "Failed to initialize migration subsystem\n");
        return 1;
    }

    /* Load board database */
    const char *db_path = "/home/zero/FirmwareGuard/data/coreboot_boards.json";
    printf("Loading board database from: %s\n", db_path);

    ret = coreboot_load_database(db_path);
    if (ret != FG_SUCCESS) {
        fprintf(stderr, "Failed to load board database\n");
        coreboot_migrate_cleanup();
        return 1;
    }

    printf("\n");

    /* Check compatibility */
    coreboot_compat_result_t compat_result;
    printf("Checking hardware compatibility...\n\n");

    ret = coreboot_check_compatibility(&compat_result);
    if (ret != FG_SUCCESS) {
        fprintf(stderr, "Failed to check compatibility\n");
        coreboot_migrate_cleanup();
        return 1;
    }

    /* Display results */
    coreboot_print_compatibility(&compat_result, true);

    /* If compatible, show migration steps */
    if (compat_result.board_found && compat_result.can_migrate) {
        printf("\n");
        printf("==============================================\n");
        printf("  Migration Steps Available\n");
        printf("==============================================\n");

        char steps_output[8192];
        ret = coreboot_migration_steps(&compat_result, steps_output, sizeof(steps_output));

        if (ret == FG_SUCCESS) {
            printf("%s", steps_output);
        }

        /* Show warning banner */
        coreboot_print_warning_banner();

        /* Show backup command */
        printf("Before proceeding with migration:\n");
        printf("  1. Create firmware backup: firmwareguard --coreboot-backup\n");
        printf("  2. Read ALL documentation carefully\n");
        printf("  3. Have external SPI programmer ready if required\n");
        printf("  4. Ensure stable power supply\n");
        printf("\n");
    } else {
        printf("\n");
        printf("Migration is not possible for this hardware.\n");
        printf("Reason: %s\n", compat_result.readiness_reason);
        printf("\n");

        if (!compat_result.board_found) {
            printf("Your hardware is not in the Coreboot/Libreboot database.\n");
            printf("This could mean:\n");
            printf("  - The board is not supported\n");
            printf("  - Support is in development\n");
            printf("  - The database needs updating\n");
            printf("\n");
            printf("Visit https://coreboot.org for latest board support information.\n");
            printf("(Download updated database and place in data/coreboot_boards.json)\n");
        }
    }

    /* Check if flashrom is available */
    printf("\n");
    printf("==============================================\n");
    printf("  System Readiness Check\n");
    printf("==============================================\n");
    printf("\n");

    ret = coreboot_check_flashrom();
    if (ret == FG_SUCCESS) {
        printf("[OK] flashrom is installed and accessible\n");

        /* Try to detect flash chip */
        flash_chip_info_t chip_info;
        if (coreboot_detect_flash_chip(&chip_info) == FG_SUCCESS) {
            printf("[OK] Flash chip detected: %s\n", chip_info.model);
        } else {
            printf("[WARN] Could not detect flash chip (may require root)\n");
        }
    } else {
        printf("[WARN] flashrom is not installed or not accessible\n");
        printf("       Install with: sudo apt install flashrom\n");
    }

    printf("\n");

    /* Cleanup */
    coreboot_migrate_cleanup();

    return 0;
}
