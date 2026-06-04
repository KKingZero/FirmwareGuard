/*
 * FirmwareGuard CLI - Phase-4 module commands
 *
 * Wires the previously-unlinked clean modules into the CLI:
 *   cve-check        -> src/database/cve_db.c
 *   threat-scan      -> src/database/threat_intel.c
 *   rootkit-scan     -> src/rootkit/rootkit_detect.c
 *   integrity-verify -> src/integrity/checksum_db.c
 *   heci-monitor     -> src/monitor/heci_monitor.c
 *   spi-status       -> src/monitor/spi_monitor.c
 *
 * All commands degrade gracefully (and return success) when the backing
 * hardware/device/database is absent, so they are safe to run offline on any
 * host without crashing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#include "cli.h"
#include "../database/cve_db.h"
#include "../database/threat_intel.h"
#include "../rootkit/rootkit_detect.h"
#include "../integrity/checksum_db.h"
#include "../monitor/heci_monitor.h"
#include "../monitor/spi_monitor.h"

/* ---- local helpers ---------------------------------------------------- */

#define FG_DATA_DIR_DEFAULT "data"

static const char *fg_data_dir(void) {
    const char *d = getenv("FG_DATA_DIR");
    return (d && *d) ? d : FG_DATA_DIR_DEFAULT;
}

static void fg_data_path(char *out, size_t n, const char *file) {
    snprintf(out, n, "%s/%s", fg_data_dir(), file);
}

/* SHA-256 a file into a 65-byte lowercase hex buffer. Returns 0 on success. */
static int sha256_file(const char *path, char hex_out[65]) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(f);
        return -1;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        EVP_DigestUpdate(ctx, buf, n);
    }
    fclose(f);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < dlen && i < 32; i++) {
        snprintf(hex_out + (i * 2), 3, "%02x", digest[i]);
    }
    hex_out[64] = '\0';
    return 0;
}

/* ---- cve-check -------------------------------------------------------- */

int cmd_cve_check(int argc, char **argv, const cli_opts_t *o) {
    if (argc < 2) {
        FG_LOG_ERROR("Usage: firmwareguard cve-check <component> <version>");
        return FG_ERROR;
    }
    const char *component = argv[0];
    const char *version = argv[1];

    char db[512];
    fg_data_path(db, sizeof(db), "cve.db");
    if (cve_db_init(db) != 0) {
        FG_LOG_ERROR("Failed to open CVE database: %s", db);
        return FG_ERROR;
    }

    /* Seed an empty database from the bundled JSON corpus, if present. */
    cve_db_stats_t stats;
    if (cve_db_stats(&stats) == 0 && stats.total_cves == 0) {
        char seed[512];
        fg_data_path(seed, sizeof(seed), "cve_firmware.json");
        int imported = 0, skipped = 0;
        if (cve_db_import_json(seed, &imported, &skipped) == 0 && imported > 0) {
            FG_INFO("Imported %d CVE(s) from %s", imported, seed);
        }
    }

    cve_match_t *matches = NULL;
    int count = 0;
    int ret = cve_db_check_version(component, version, &matches, &count);
    if (ret != 0) {
        FG_LOG_ERROR("CVE lookup failed");
        cve_db_close();
        return FG_ERROR;
    }

    if (o->json) {
        printf("{\n  \"component\": \"%s\",\n  \"version\": \"%s\",\n  \"match_count\": %d,\n  \"matches\": [",
               component, version, count);
        for (int i = 0; i < count; i++) {
            cve_entry_t *c = matches[i].cve;
            printf("%s\n    {\"cve\": \"%s\", \"severity\": \"%s\", \"cvss\": %.1f, \"confidence\": %d}",
                   i ? "," : "", c->cve_id, cve_severity_to_str(c->severity),
                   c->cvss_score, matches[i].confidence);
        }
        printf("%s]\n}\n", count ? "\n  " : "");
    } else {
        printf("CVE check: component='%s' version='%s'\n", component, version);
        if (count == 0) {
            printf("  No known CVEs match.\n");
        } else {
            printf("  %d matching CVE(s):\n", count);
            for (int i = 0; i < count; i++) {
                cve_entry_t *c = matches[i].cve;
                printf("   - %s  [%s, CVSS %.1f]  confidence %d%%\n      %s\n",
                       c->cve_id, cve_severity_to_str(c->severity), c->cvss_score,
                       matches[i].confidence, c->description);
            }
        }
    }

    cve_db_free_results(matches, count);
    cve_db_close();
    return FG_SUCCESS;
}

/* ---- threat-scan ------------------------------------------------------ */

int cmd_threat_scan(int argc, char **argv, const cli_opts_t *o) {
    if (argc < 1) {
        FG_LOG_ERROR("Usage: firmwareguard threat-scan <file>");
        return FG_ERROR;
    }
    const char *file = argv[0];

    char hex[65];
    if (sha256_file(file, hex) != 0) {
        FG_LOG_ERROR("Cannot read file: %s", file);
        return FG_ERROR;
    }

    char db[512];
    fg_data_path(db, sizeof(db), "threat.db");
    if (threat_intel_init(db) != 0) {
        FG_LOG_ERROR("Failed to open threat-intel database: %s", db);
        return FG_ERROR;
    }

    threat_intel_stats_t stats;
    if (threat_intel_stats(&stats) == 0 && stats.total_iocs == 0) {
        char seed[512];
        fg_data_path(seed, sizeof(seed), "threat_intel.json");
        int fam = 0, iocs = 0, skip = 0;
        if (threat_intel_import_json(seed, &fam, &iocs, &skip) == 0 && iocs > 0) {
            FG_INFO("Imported %d IOC(s) across %d family(ies) from %s", iocs, fam, seed);
        }
    }

    threat_match_t match;
    memset(&match, 0, sizeof(match));
    int ret = threat_intel_check_hash(hex, NULL, &match);
    if (ret != 0) {
        FG_LOG_ERROR("Threat-intel lookup failed");
        threat_intel_close();
        return FG_ERROR;
    }

    if (o->json) {
        printf("{\n  \"file\": \"%s\",\n  \"sha256\": \"%s\",\n  \"matched\": %s",
               file, hex, match.matched ? "true" : "false");
        if (match.matched) {
            printf(",\n  \"family\": \"%s\",\n  \"threat_type\": \"%s\",\n  \"confidence\": %d",
                   match.family_name, threat_type_to_str(match.threat_type),
                   (int)match.confidence);
        }
        printf("\n}\n");
    } else {
        printf("Threat scan: %s\n  SHA-256: %s\n", file, hex);
        if (match.matched) {
            printf("  !! IOC MATCH: family=%s type=%s confidence=%s\n      %s\n",
                   match.family_name, threat_type_to_str(match.threat_type),
                   confidence_level_to_str(match.confidence), match.description);
        } else {
            printf("  No known IOC matches this hash.\n");
        }
    }

    threat_intel_free_match(&match);
    threat_intel_close();
    return FG_SUCCESS;
}

/* ---- rootkit-scan ----------------------------------------------------- */

int cmd_rootkit_scan(int argc, char **argv, const cli_opts_t *o) {
    if (argc < 1) {
        FG_LOG_ERROR("Usage: firmwareguard rootkit-scan <firmware.bin>");
        return FG_ERROR;
    }
    const char *file = argv[0];

    if (rootkit_init() != 0) {
        FG_LOG_ERROR("Failed to initialize rootkit detection engine");
        return FG_ERROR;
    }

    rk_scan_result_t result;
    memset(&result, 0, sizeof(result));
    int ret = rootkit_scan_file(file, NULL, &result);
    if (ret != 0) {
        FG_LOG_ERROR("Rootkit scan failed: %s",
                     result.error[0] ? result.error : "unknown error");
        rootkit_cleanup();
        return FG_ERROR;
    }

    if (o->json) {
        printf("{\n  \"file\": \"%s\",\n  \"sha256\": \"%s\",\n  \"size\": %llu,\n"
               "  \"findings\": %d,\n  \"risk_score\": %d,\n  \"risk_level\": \"%s\"\n}\n",
               result.filename, result.sha256,
               (unsigned long long)result.file_size,
               result.num_findings, result.risk_score, result.risk_level);
    } else {
        rootkit_print_result(&result);
    }

    rootkit_cleanup();
    return FG_SUCCESS;
}

/* ---- integrity-verify ------------------------------------------------- */

int cmd_integrity_verify(int argc, char **argv, const cli_opts_t *o) {
    if (argc < 1) {
        FG_LOG_ERROR("Usage: firmwareguard integrity-verify <firmware.bin>");
        return FG_ERROR;
    }
    const char *file = argv[0];

    char db[512];
    fg_data_path(db, sizeof(db), "integrity.db");
    if (checksum_db_init(db) != 0) {
        FG_LOG_ERROR("Failed to open integrity database: %s", db);
        return FG_ERROR;
    }

    fw_db_stats_t stats;
    if (checksum_db_stats(&stats) == 0 && stats.total_entries == 0) {
        char seed[512];
        fg_data_path(seed, sizeof(seed), "known_firmware.json");
        int imported = 0, skipped = 0;
        if (checksum_db_import_json(seed, &imported, &skipped) == 0 && imported > 0) {
            FG_INFO("Imported %d checksum(s) from %s", imported, seed);
        }
    }

    fw_verify_result_t result;
    memset(&result, 0, sizeof(result));
    int ret = checksum_db_verify(file, NULL, NULL, NULL, &result);
    if (ret != 0) {
        FG_LOG_ERROR("Integrity verification failed");
        checksum_db_close();
        return FG_ERROR;
    }

    if (o->json) {
        printf("{\n  \"file\": \"%s\",\n  \"sha256\": \"%s\",\n  \"status\": \"%s\",\n  \"message\": \"%s\"\n}\n",
               file, result.computed_sha256,
               checksum_db_status_string(result.status), result.message);
    } else {
        printf("Integrity verify: %s\n  SHA-256: %s\n  Status: %s\n  %s\n",
               file, result.computed_sha256,
               checksum_db_status_string(result.status), result.message);
    }

    checksum_db_free_result(&result);
    checksum_db_close();
    return FG_SUCCESS;
}

/* ---- heci-monitor / spi-status (x86 platform monitors) ---------------- */
#ifndef FG_BUILD_ARM

int cmd_heci_monitor(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv; (void)o;

    if (!heci_is_supported()) {
        printf("HECI/MEI interface not available on this system.\n");
        printf("  (%s / %s not present - Intel ME monitoring unavailable.)\n",
               MEI_DEVICE_PATH_0, MEI_DEVICE_PATH_1);
        return FG_SUCCESS;
    }

    if (heci_init() != FG_SUCCESS) {
        FG_LOG_ERROR("Failed to initialize HECI monitor");
        return FG_ERROR;
    }

    FG_INFO("Capturing HECI/MEI traffic for 2s...");
    heci_start_monitor(true);
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    nanosleep(&ts, NULL);
    heci_stop_monitor();

    heci_log_t *log = malloc(sizeof(*log));
    if (log && heci_get_log(log) == FG_SUCCESS) {
        heci_print_summary(log);
    } else {
        FG_WARN("No HECI traffic captured");
    }
    free(log);

    heci_cleanup();
    return FG_SUCCESS;
}

/* ---- spi-status ------------------------------------------------------- */

int cmd_spi_status(int argc, char **argv, const cli_opts_t *o) {
    (void)argc; (void)argv;

    if (spi_monitor_init() != 0) {
        printf("SPI flash protection monitor unavailable.\n");
        printf("  (/dev/fwguard not present - load kernel module fwguard_km, "
               "or run on an Intel PCH platform with root.)\n");
        return FG_SUCCESS;
    }

    struct spi_protection_status status;
    memset(&status, 0, sizeof(status));
    if (spi_check_protection(&status) != 0) {
        FG_LOG_ERROR("Failed to query SPI protection status");
        spi_monitor_cleanup();
        return FG_ERROR;
    }

    char cntl[128];
    spi_bios_cntl_string(status.bios_cntl, cntl, sizeof(cntl));
    char rec[256];
    spi_get_protection_recommendation(&status, rec, sizeof(rec));
    bool secure = spi_is_protection_secure(&status);

    if (o->json) {
        printf("{\n  \"secure\": %s,\n  \"bios_cntl\": \"%s\",\n  \"pending_events\": %u,\n  \"recommendation\": \"%s\"\n}\n",
               secure ? "true" : "false", cntl, status.pending_events, rec);
    } else {
        printf("SPI flash protection status:\n");
        printf("  BIOS_CNTL: %s\n", cntl);
        printf("  Pending events: %u\n", status.pending_events);
        printf("  Secure: %s\n", secure ? "yes" : "no");
        printf("  %s\n", rec);
    }

    spi_monitor_cleanup();
    return FG_SUCCESS;
}

#endif /* !FG_BUILD_ARM */
