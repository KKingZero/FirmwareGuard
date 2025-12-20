/*
 * FirmwareGuard - Threat Intelligence Database Test Program
 * Demonstrates threat intelligence integration and IOC checking
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../src/database/threat_intel.h"

/* ANSI color codes for output */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

/* Print section header */
static void print_header(const char *title)
{
    printf("\n");
    printf(COLOR_BOLD COLOR_CYAN);
    printf("========================================\n");
    printf("  %s\n", title);
    printf("========================================\n");
    printf(COLOR_RESET);
}

/* Print threat match details */
static void print_threat_match(const threat_match_t *match)
{
    if (!match->matched) {
        printf(COLOR_GREEN "[✓] No threats detected\n" COLOR_RESET);
        return;
    }

    printf(COLOR_BOLD COLOR_RED);
    printf("[!] THREAT DETECTED!\n");
    printf(COLOR_RESET);

    printf(COLOR_RED);
    printf("  Family:      %s\n", match->family_name);
    printf("  Type:        %s\n", threat_type_to_str(match->threat_type));
    printf("  Confidence:  %s (%d%%)\n",
           confidence_level_to_str(match->confidence), match->confidence);
    printf("  IOC Type:    %s\n", ioc_type_to_str(match->ioc_type));
    printf("  Matched:     %s\n", match->matched_value);
    printf(COLOR_RESET);

    printf(COLOR_YELLOW);
    printf("  Description: %s\n", match->description);
    printf(COLOR_RESET);

    if (match->num_mitre_techniques > 0) {
        printf("  MITRE ATT&CK: ");
        for (int i = 0; i < match->num_mitre_techniques; i++) {
            printf("%s%s", match->mitre_techniques[i],
                   (i < match->num_mitre_techniques - 1) ? ", " : "");
        }
        printf("\n");
    }

    printf(COLOR_MAGENTA);
    printf("  Details:     %s\n", match->match_details);
    printf(COLOR_RESET);

    printf(COLOR_BOLD);
    printf("  Remediation: %s\n", match->remediation);
    printf(COLOR_RESET);
}

/* Print database statistics */
static void print_stats(const threat_intel_stats_t *stats)
{
    printf("Database Path:      %s\n", stats->db_path);
    printf("Database Size:      %ld bytes\n", stats->db_size_bytes);
    printf("Total Families:     %ld (%ld active)\n",
           stats->total_families, stats->active_families);
    printf("Total IOCs:         %ld\n", stats->total_iocs);
    printf("  - Hash IOCs:      %ld\n", stats->hash_iocs);
    printf("  - Pattern IOCs:   %ld\n", stats->pattern_iocs);
    printf("Verified IOCs:      %ld\n", stats->verified_iocs);

    if (stats->oldest_ioc > 0) {
        char oldest[64], newest[64];
        strftime(oldest, sizeof(oldest), "%Y-%m-%d", localtime(&stats->oldest_ioc));
        strftime(newest, sizeof(newest), "%Y-%m-%d", localtime(&stats->newest_ioc));
        printf("IOC Date Range:     %s to %s\n", oldest, newest);
    }
}

/* Test hash checking */
static void test_hash_check(void)
{
    print_header("Hash IOC Detection Test");

    /* Test known malicious hash (LoJax) */
    printf("Testing hash: e5262db186c97b14ad5bae895f72ba3e (LoJax)\n");

    threat_match_t result;
    int rc = threat_intel_check_hash("e5262db186c97b14ad5bae895f72ba3e", NULL, &result);

    if (rc == 0) {
        print_threat_match(&result);
    } else {
        printf(COLOR_RED "Error checking hash\n" COLOR_RESET);
    }

    /* Test clean hash */
    printf("\nTesting clean hash: 1234567890abcdef1234567890abcdef\n");
    rc = threat_intel_check_hash("1234567890abcdef1234567890abcdef", NULL, &result);

    if (rc == 0) {
        print_threat_match(&result);
    } else {
        printf(COLOR_RED "Error checking hash\n" COLOR_RESET);
    }
}

/* Test pattern checking */
static void test_pattern_check(void)
{
    print_header("Pattern IOC Detection Test");

    /* Test known malicious pattern */
    printf("Testing pattern: 'RWEverything driver detected'\n");

    threat_match_t result;
    int rc = threat_intel_check_pattern("RWEverything driver detected", NULL, &result);

    if (rc == 0) {
        print_threat_match(&result);
    } else {
        printf(COLOR_RED "Error checking pattern\n" COLOR_RESET);
    }

    /* Test another pattern */
    printf("\nTesting pattern: 'VectorEDK string found in firmware'\n");
    rc = threat_intel_check_pattern("VectorEDK string found in firmware", NULL, &result);

    if (rc == 0) {
        print_threat_match(&result);
    } else {
        printf(COLOR_RED "Error checking pattern\n" COLOR_RESET);
    }

    /* Test clean pattern */
    printf("\nTesting clean pattern: 'Normal boot process'\n");
    rc = threat_intel_check_pattern("Normal boot process", NULL, &result);

    if (rc == 0) {
        print_threat_match(&result);
    } else {
        printf(COLOR_RED "Error checking pattern\n" COLOR_RESET);
    }
}

/* Test batch pattern checking (correlation) */
static void test_batch_check(void)
{
    print_header("Correlated Pattern Detection Test");

    const char *patterns[] = {
        "RWEverything driver detected",
        "NTFS alternate data stream found",
        "Suspicious UEFI module modification",
        "Normal system operation"
    };

    int num_patterns = sizeof(patterns) / sizeof(patterns[0]);
    threat_match_t results[10];
    int matched_count = 0;

    printf("Checking %d patterns for correlation...\n\n", num_patterns);

    int rc = threat_intel_check_patterns_batch(patterns, num_patterns,
                                                results, &matched_count);

    if (rc == 0) {
        printf("Matched %d/%d patterns\n\n", matched_count, num_patterns);

        for (int i = 0; i < matched_count; i++) {
            printf("Match #%d:\n", i + 1);
            print_threat_match(&results[i]);
            printf("\n");
        }

        if (matched_count == 0) {
            printf(COLOR_GREEN "[✓] No correlated threats detected\n" COLOR_RESET);
        }
    } else {
        printf(COLOR_RED "Error in batch check\n" COLOR_RESET);
    }
}

/* Test family info retrieval */
static void test_family_info(void)
{
    print_header("Malware Family Information");

    const char *families[] = {
        "LoJax",
        "MoonBounce",
        "BlackLotus"
    };

    for (int i = 0; i < 3; i++) {
        printf("\n" COLOR_BOLD "Family: %s\n" COLOR_RESET, families[i]);

        malware_family_t family;
        threat_ioc_t *iocs = NULL;
        int ioc_count = 0;

        int rc = threat_intel_get_family_info(families[i], &family, &iocs, &ioc_count);

        if (rc == 0) {
            printf("  Type:            %s\n", threat_type_to_str(family.type));
            printf("  Active:          %s\n", family.active ? "Yes" : "No");
            printf("  First Seen:      %s\n", family.first_seen);
            printf("  Last Seen:       %s\n", family.last_seen);
            printf("  Target Vendors:  %s\n", family.target_vendors);
            printf("  Description:     %.100s...\n", family.description);

            if (family.num_mitre_techniques > 0) {
                printf("  MITRE Techniques: ");
                for (int j = 0; j < family.num_mitre_techniques; j++) {
                    printf("%s%s", family.mitre_techniques[j],
                           (j < family.num_mitre_techniques - 1) ? ", " : "");
                }
                printf("\n");
            }

            printf("  IOCs:            %d total\n", ioc_count);

            /* Print first few IOCs */
            int show_count = (ioc_count > 3) ? 3 : ioc_count;
            for (int j = 0; j < show_count; j++) {
                printf("    [%d] %s: %s (confidence: %d%%)\n",
                       j + 1,
                       ioc_type_to_str(iocs[j].ioc_type),
                       iocs[j].value,
                       iocs[j].confidence);
            }

            if (ioc_count > 3) {
                printf("    ... and %d more IOCs\n", ioc_count - 3);
            }

            threat_intel_free_iocs(iocs, ioc_count);
        } else {
            printf(COLOR_RED "  [!] Family not found\n" COLOR_RESET);
        }
    }
}

int main(int argc, char *argv[])
{
    const char *db_path = "/tmp/firmwareguard_threat_intel_test.db";
    const char *json_path = NULL;

    /* Parse arguments */
    if (argc > 1) {
        json_path = argv[1];
    } else {
        /* Default to data/threat_intel.json */
        json_path = "../data/threat_intel.json";

        /* Try alternative path */
        if (access(json_path, F_OK) != 0) {
            json_path = "./data/threat_intel.json";
        }

        if (access(json_path, F_OK) != 0) {
            fprintf(stderr, "Usage: %s [threat_intel.json]\n", argv[0]);
            fprintf(stderr, "Default JSON file not found at: %s\n", json_path);
            return 1;
        }
    }

    print_header("FirmwareGuard Threat Intelligence Test");

    printf("Initializing threat intelligence database...\n");
    printf("Database: %s\n", db_path);
    printf("JSON:     %s\n", json_path);

    /* Initialize database */
    if (threat_intel_init(db_path) != 0) {
        fprintf(stderr, COLOR_RED "Failed to initialize database\n" COLOR_RESET);
        return 1;
    }

    printf(COLOR_GREEN "[✓] Database initialized\n" COLOR_RESET);

    /* Import threat data */
    print_header("Importing Threat Intelligence");

    int imported_families = 0, imported_iocs = 0, skipped = 0;

    printf("Importing from: %s\n", json_path);

    if (threat_intel_import_json(json_path, &imported_families,
                                  &imported_iocs, &skipped) == 0) {
        printf(COLOR_GREEN);
        printf("[✓] Import successful\n");
        printf("    Families: %d\n", imported_families);
        printf("    IOCs:     %d\n", imported_iocs);
        printf("    Skipped:  %d\n", skipped);
        printf(COLOR_RESET);
    } else {
        fprintf(stderr, COLOR_RED "Failed to import threat data\n" COLOR_RESET);
        threat_intel_close();
        return 1;
    }

    /* Get database statistics */
    print_header("Database Statistics");

    threat_intel_stats_t stats;
    if (threat_intel_stats(&stats) == 0) {
        print_stats(&stats);
    } else {
        fprintf(stderr, COLOR_RED "Failed to get statistics\n" COLOR_RESET);
    }

    /* Run tests */
    test_hash_check();
    test_pattern_check();
    test_batch_check();
    test_family_info();

    /* Cleanup */
    print_header("Cleanup");

    printf("Optimizing database...\n");
    threat_intel_vacuum();

    printf("Closing database...\n");
    threat_intel_close();

    printf(COLOR_GREEN "[✓] Test complete\n" COLOR_RESET);
    printf("\nDatabase saved to: %s\n", db_path);
    printf("You can inspect it with: sqlite3 %s\n", db_path);

    return 0;
}
