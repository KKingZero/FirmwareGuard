/*
 * test-patterns.c - Test program for FirmwareGuard pattern database
 */

#include "../src/patterns/pattern_db.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *patterns_dir = (argc > 1) ? argv[1] : "./patterns";

    printf("\n");
    printf("========================================\n");
    printf("  FirmwareGuard Pattern Database Test\n");
    printf("========================================\n\n");

    // Initialize pattern database
    printf("[1] Initializing pattern database...\n");
    pattern_db_t *db = pattern_db_init(patterns_dir);
    if (!db) {
        fprintf(stderr, "Failed to initialize pattern database\n");
        return 1;
    }

    // Load patterns
    printf("[2] Loading patterns from: %s\n", patterns_dir);
    int loaded = pattern_db_load(db);
    if (loaded < 0) {
        fprintf(stderr, "Failed to load patterns\n");
        pattern_db_free(db);
        return 1;
    }

    // Print statistics
    printf("[3] Printing database statistics...\n\n");
    pattern_db_print_stats(db);

    // Test pattern matching
    printf("[4] Testing pattern matching...\n\n");
    pattern_match_t *results = NULL;
    int matches = pattern_match_all(db, &results);

    if (matches >= 0) {
        printf("\n========================================\n");
        printf("  PATTERN MATCH RESULTS\n");
        printf("========================================\n\n");

        if (matches == 0) {
            printf("No patterns matched on this system.\n\n");
        } else {
            printf("Found %d matches:\n\n", matches);

            for (int i = 0; i < matches; i++) {
                const pattern_t *p = results[i].pattern;

                printf("[%d] %s\n", i + 1, p->name);
                printf("    ID: %s\n", p->id);
                printf("    Risk: %s\n", risk_level_to_str(p->risk_level));
                printf("    Confidence: %d%%\n", results[i].confidence_score);
                printf("    Details: %s\n", results[i].match_details);

                if (p->blockable) {
                    printf("    Blockable: YES\n");
                    if (p->metadata.remediation[0]) {
                        printf("    Remediation: %s\n", p->metadata.remediation);
                    }
                } else {
                    printf("    Blockable: NO\n");
                }

                printf("\n");
            }
        }

        free(results);
    } else {
        fprintf(stderr, "Pattern matching failed\n");
    }

    // Cleanup
    printf("[5] Cleaning up...\n");
    pattern_db_free(db);

    printf("\n========================================\n");
    printf("  Test Complete\n");
    printf("========================================\n\n");

    return 0;
}
