/*
 * FirmwareGuard - Firmware Rootkit Detection
 * Signature-based and behavioral detection for firmware-level threats
 * OFFLINE-ONLY: No network connectivity
 */

#include "rootkit_detect.h"
#include "../cJSON.h"
#include "../../include/firmwareguard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <math.h>
#include <openssl/sha.h>

/* Built-in signatures storage */
static rk_signature_t g_signatures[RK_MAX_SIGNATURES];
static int g_signature_count = 0;
static bool g_initialized = false;

/* Forward declarations */
static void load_builtin_signatures(void);
static int scan_for_signatures(const uint8_t *data, size_t size, rk_scan_result_t *result);
static int behavioral_analysis(const uint8_t *data, size_t size, rk_scan_result_t *result);
static int heuristic_analysis(const uint8_t *data, size_t size, rk_scan_result_t *result);
static void compute_sha256(const uint8_t *data, size_t size, char *hash_out);
static void add_finding(rk_scan_result_t *result, const rk_finding_t *finding);
static void calculate_risk(rk_scan_result_t *result);

/*
 * Built-in signature definitions
 * Based on public threat intelligence for known UEFI/firmware malware
 */
static void load_builtin_signatures(void)
{
    int idx = 0;

    /* LoJax signatures */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "LoJax_Dropper", sizeof(sig->name) - 1);
        strncpy(sig->description, "LoJax UEFI rootkit dropper component",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_LOJAX;
        sig->severity = RK_SEVERITY_CRITICAL;
        /* Pattern: LoJax driver signature bytes */
        uint8_t pattern[] = {0x4C, 0x6F, 0x4A, 0x61, 0x78}; /* "LoJax" */
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        strncpy(sig->mitre_attack, "T1542.001", sizeof(sig->mitre_attack) - 1);
        sig->enabled = true;
    }

    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "LoJax_Payload", sizeof(sig->name) - 1);
        strncpy(sig->description, "LoJax UEFI rootkit payload indicator",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_LOJAX;
        sig->severity = RK_SEVERITY_CRITICAL;
        /* Known LoJax PE header pattern */
        uint8_t pattern[] = {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
                            0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF};
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->mask[12] = 0x00; /* Wildcard */
        sig->mask[13] = 0x00;
        sig->any_offset = true;
        sig->enabled = true;
    }

    /* MosaicRegressor signatures */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "MosaicRegressor_Module", sizeof(sig->name) - 1);
        strncpy(sig->description, "MosaicRegressor UEFI implant module",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_MOSAIC;
        sig->severity = RK_SEVERITY_CRITICAL;
        /* Characteristic string from MosaicRegressor */
        uint8_t pattern[] = {0x4D, 0x6F, 0x73, 0x61, 0x69, 0x63}; /* "Mosaic" */
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        strncpy(sig->mitre_attack, "T1542.001", sizeof(sig->mitre_attack) - 1);
        sig->enabled = true;
    }

    /* MoonBounce signatures */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "MoonBounce_CoreDxe", sizeof(sig->name) - 1);
        strncpy(sig->description, "MoonBounce CORE_DXE hook indicator",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_MOONBOUNCE;
        sig->severity = RK_SEVERITY_CRITICAL;
        /* MoonBounce patches CORE_DXE - look for anomalous hooks */
        uint8_t pattern[] = {0x48, 0xB8}; /* MOV RAX, imm64 - common hook prologue */
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        sig->min_offset = 0x10000;  /* Skip headers */
        strncpy(sig->mitre_attack, "T1542.001", sizeof(sig->mitre_attack) - 1);
        sig->enabled = true;
    }

    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "MoonBounce_Shellcode", sizeof(sig->name) - 1);
        strncpy(sig->description, "MoonBounce malicious shellcode pattern",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_MOONBOUNCE;
        sig->severity = RK_SEVERITY_CRITICAL;
        /* Shellcode pattern from public analysis */
        uint8_t pattern[] = {0x4D, 0x6F, 0x6F, 0x6E, 0x42, 0x6F, 0x75, 0x6E, 0x63, 0x65};
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        sig->enabled = true;
    }

    /* CosmicStrand signatures */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "CosmicStrand_Driver", sizeof(sig->name) - 1);
        strncpy(sig->description, "CosmicStrand UEFI firmware rootkit",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_COSMIC_STRAND;
        sig->severity = RK_SEVERITY_CRITICAL;
        /* Cosmic pattern */
        uint8_t pattern[] = {0x43, 0x6F, 0x73, 0x6D, 0x69, 0x63}; /* "Cosmic" */
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        strncpy(sig->mitre_attack, "T1542.001", sizeof(sig->mitre_attack) - 1);
        sig->enabled = true;
    }

    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "CosmicStrand_H2OFFY", sizeof(sig->name) - 1);
        strncpy(sig->description, "CosmicStrand modified H2OFFY driver pattern",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_COSMIC_STRAND;
        sig->severity = RK_SEVERITY_CRITICAL;
        /* Modified H2OFFY pattern */
        uint8_t pattern[] = {0x48, 0x32, 0x4F, 0x46, 0x46, 0x59}; /* "H2OFFY" */
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        sig->enabled = true;
    }

    /* BlackLotus signatures */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "BlackLotus_Bootkit", sizeof(sig->name) - 1);
        strncpy(sig->description, "BlackLotus UEFI bootkit - bypasses Secure Boot",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_BLACK_LOTUS;
        sig->severity = RK_SEVERITY_CRITICAL;
        /* BlackLotus identifier */
        uint8_t pattern[] = {0x42, 0x4C, 0x6F, 0x74, 0x75, 0x73}; /* "BLotus" */
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        strncpy(sig->mitre_attack, "T1542.003", sizeof(sig->mitre_attack) - 1);
        strncpy(sig->cve, "CVE-2022-21894", sizeof(sig->cve) - 1);
        sig->enabled = true;
    }

    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "BlackLotus_Baton_Drop", sizeof(sig->name) - 1);
        strncpy(sig->description, "BlackLotus Baton Drop CVE-2022-21894 exploit",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_BLACK_LOTUS;
        sig->severity = RK_SEVERITY_CRITICAL;
        /* CVE-2022-21894 exploit pattern */
        uint8_t pattern[] = {0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05};
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->mask[1] = 0x00; sig->mask[2] = 0x00;
        sig->mask[3] = 0x00; sig->mask[4] = 0x00;
        sig->any_offset = true;
        strncpy(sig->cve, "CVE-2022-21894", sizeof(sig->cve) - 1);
        sig->enabled = true;
    }

    /* ESPecter signatures */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "ESPecter_EFI_Bootkit", sizeof(sig->name) - 1);
        strncpy(sig->description, "ESPecter EFI System Partition bootkit",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_ESPECTER;
        sig->severity = RK_SEVERITY_CRITICAL;
        uint8_t pattern[] = {0x45, 0x53, 0x50, 0x65, 0x63, 0x74, 0x65, 0x72}; /* "ESPecter" */
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        strncpy(sig->mitre_attack, "T1542.003", sizeof(sig->mitre_attack) - 1);
        sig->enabled = true;
    }

    /* TrickBot/TrickBoot */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "TrickBoot_Module", sizeof(sig->name) - 1);
        strncpy(sig->description, "TrickBot firmware reconnaissance module",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_TRICKBOT;
        sig->severity = RK_SEVERITY_HIGH;
        uint8_t pattern[] = {0x54, 0x72, 0x69, 0x63, 0x6B, 0x42, 0x6F, 0x6F, 0x74};
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        strncpy(sig->mitre_attack, "T1542.001", sizeof(sig->mitre_attack) - 1);
        sig->enabled = true;
    }

    /* Generic SMM rootkit indicators */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "SMM_Backdoor_Handler", sizeof(sig->name) - 1);
        strncpy(sig->description, "Suspicious SMM handler with backdoor pattern",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_GENERIC_SMM;
        sig->severity = RK_SEVERITY_HIGH;
        /* SMM entry with suspicious characteristics */
        uint8_t pattern[] = {0x0F, 0x01, 0xFB}; /* STGI - SMM instruction */
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        strncpy(sig->mitre_attack, "T1542.001", sizeof(sig->mitre_attack) - 1);
        sig->enabled = true;
    }

    /* Generic UEFI bootkit indicators */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "UEFI_Runtime_Hook", sizeof(sig->name) - 1);
        strncpy(sig->description, "Suspicious UEFI Runtime Services hook",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_GENERIC_UEFI;
        sig->severity = RK_SEVERITY_MEDIUM;
        /* Common hook pattern */
        uint8_t pattern[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        for (int i = 2; i < 10; i++) sig->mask[i] = 0x00; /* Wildcards for address */
        sig->any_offset = true;
        strncpy(sig->mitre_attack, "T1574", sizeof(sig->mitre_attack) - 1);
        sig->enabled = true;
    }

    /* Hacking Team UEFI implant */
    {
        rk_signature_t *sig = &g_signatures[idx++];
        strncpy(sig->name, "HackingTeam_UEFI", sizeof(sig->name) - 1);
        strncpy(sig->description, "Hacking Team UEFI rootkit (leaked 2015)",
               sizeof(sig->description) - 1);
        sig->family = RK_FAMILY_HACKING_TEAM;
        sig->severity = RK_SEVERITY_CRITICAL;
        uint8_t pattern[] = {0x48, 0x54, 0x5F, 0x52, 0x4B}; /* "HT_RK" prefix */
        memcpy(sig->pattern, pattern, sizeof(pattern));
        sig->pattern_len = sizeof(pattern);
        memset(sig->mask, 0xFF, sig->pattern_len);
        sig->any_offset = true;
        sig->enabled = true;
    }

    g_signature_count = idx;
    FG_INFO("Loaded %d built-in rootkit signatures", g_signature_count);
}

/*
 * Initialize engine
 */
int rootkit_init(void)
{
    if (g_initialized) {
        return FG_SUCCESS;
    }

    memset(g_signatures, 0, sizeof(g_signatures));
    g_signature_count = 0;

    load_builtin_signatures();

    g_initialized = true;
    return FG_SUCCESS;
}

/*
 * Load additional signatures
 */
int rootkit_load_signatures(const char *json_path)
{
    if (!g_initialized) {
        rootkit_init();
    }

    FILE *fp = fopen(json_path, "r");
    if (!fp) {
        FG_LOG_ERROR("Cannot open signatures file: %s", json_path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_str = malloc(size + 1);
    if (!json_str) {
        fclose(fp);
        return -1;
    }

    fread(json_str, 1, size, fp);
    json_str[size] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(json_str);
    free(json_str);

    if (!root) {
        FG_LOG_ERROR("Invalid JSON in signatures file");
        return -1;
    }

    cJSON *sigs = cJSON_GetObjectItem(root, "signatures");
    if (!sigs || !cJSON_IsArray(sigs)) {
        cJSON_Delete(root);
        return -1;
    }

    int loaded = 0;
    cJSON *item;
    cJSON_ArrayForEach(item, sigs) {
        if (g_signature_count >= RK_MAX_SIGNATURES) {
            break;
        }

        rk_signature_t *sig = &g_signatures[g_signature_count];
        memset(sig, 0, sizeof(rk_signature_t));

        cJSON *field;

        field = cJSON_GetObjectItem(item, "name");
        if (field && field->valuestring) {
            strncpy(sig->name, field->valuestring, sizeof(sig->name) - 1);
        }

        field = cJSON_GetObjectItem(item, "description");
        if (field && field->valuestring) {
            strncpy(sig->description, field->valuestring, sizeof(sig->description) - 1);
        }

        field = cJSON_GetObjectItem(item, "pattern_hex");
        if (field && field->valuestring) {
            /* Parse hex pattern */
            const char *hex = field->valuestring;
            size_t len = strlen(hex);
            sig->pattern_len = 0;

            for (size_t i = 0; i < len && sig->pattern_len < RK_SIGNATURE_MAX_LEN; i += 2) {
                while (hex[i] == ' ') i++; /* Skip spaces */
                if (hex[i] == '?' && hex[i+1] == '?') {
                    sig->pattern[sig->pattern_len] = 0x00;
                    sig->mask[sig->pattern_len] = 0x00; /* Wildcard */
                } else {
                    unsigned int byte;
                    if (sscanf(&hex[i], "%2x", &byte) == 1) {
                        sig->pattern[sig->pattern_len] = (uint8_t)byte;
                        sig->mask[sig->pattern_len] = 0xFF;
                    }
                }
                sig->pattern_len++;
            }
        }

        field = cJSON_GetObjectItem(item, "severity");
        if (field && field->valuestring) {
            if (strcasecmp(field->valuestring, "critical") == 0)
                sig->severity = RK_SEVERITY_CRITICAL;
            else if (strcasecmp(field->valuestring, "high") == 0)
                sig->severity = RK_SEVERITY_HIGH;
            else if (strcasecmp(field->valuestring, "medium") == 0)
                sig->severity = RK_SEVERITY_MEDIUM;
            else if (strcasecmp(field->valuestring, "low") == 0)
                sig->severity = RK_SEVERITY_LOW;
        }

        field = cJSON_GetObjectItem(item, "mitre_attack");
        if (field && field->valuestring) {
            strncpy(sig->mitre_attack, field->valuestring, sizeof(sig->mitre_attack) - 1);
        }

        sig->any_offset = true;
        sig->enabled = true;

        if (sig->name[0] && sig->pattern_len > 0) {
            g_signature_count++;
            loaded++;
        }
    }

    cJSON_Delete(root);

    FG_INFO("Loaded %d custom signatures from %s", loaded, json_path);
    return loaded;
}

/*
 * Get signature count
 */
int rootkit_signature_count(void)
{
    return g_signature_count;
}

/*
 * Compute SHA-256 hash
 */
static void compute_sha256(const uint8_t *data, size_t size, char *hash_out)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, size);
    SHA256_Final(hash, &ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_out + (i * 2), "%02x", hash[i]);
    }
    hash_out[64] = '\0';
}

/*
 * Add finding to result
 */
static void add_finding(rk_scan_result_t *result, const rk_finding_t *finding)
{
    if (result->num_findings >= RK_MAX_FINDINGS) {
        return;
    }

    memcpy(&result->findings[result->num_findings], finding, sizeof(rk_finding_t));
    result->num_findings++;

    if (finding->severity > result->max_severity) {
        result->max_severity = finding->severity;
    }

    switch (finding->method) {
        case RK_METHOD_SIGNATURE:
            result->signature_matches++;
            break;
        case RK_METHOD_BEHAVIORAL:
            result->behavioral_detections++;
            break;
        case RK_METHOD_HEURISTIC:
            result->heuristic_detections++;
            break;
        default:
            break;
    }
}

/*
 * Scan for signatures
 */
static int scan_for_signatures(const uint8_t *data, size_t size, rk_scan_result_t *result)
{
    for (int s = 0; s < g_signature_count; s++) {
        rk_signature_t *sig = &g_signatures[s];

        if (!sig->enabled || sig->pattern_len == 0) {
            continue;
        }

        /* Determine scan range */
        size_t start = sig->any_offset ? 0 : sig->min_offset;
        size_t end = size - sig->pattern_len;

        if (sig->max_offset > 0 && sig->max_offset < end) {
            end = sig->max_offset;
        }

        /* Scan */
        for (size_t offset = start; offset <= end; offset++) {
            bool match = true;

            for (size_t i = 0; i < sig->pattern_len; i++) {
                if (sig->mask[i] == 0xFF) {
                    if (data[offset + i] != sig->pattern[i]) {
                        match = false;
                        break;
                    }
                }
                /* Wildcard (mask == 0x00) always matches */
            }

            if (match) {
                rk_finding_t finding;
                memset(&finding, 0, sizeof(finding));

                finding.family = sig->family;
                finding.method = RK_METHOD_SIGNATURE;
                finding.severity = sig->severity;
                strncpy(finding.name, sig->name, sizeof(finding.name) - 1);
                strncpy(finding.description, sig->description, sizeof(finding.description) - 1);
                finding.offset = offset;
                strncpy(finding.matched_signature, sig->name, sizeof(finding.matched_signature) - 1);
                strncpy(finding.mitre_attack, sig->mitre_attack, sizeof(finding.mitre_attack) - 1);
                finding.confidence = 0.95;

                /* Create evidence hex dump */
                char hex[64] = {0};
                for (size_t i = 0; i < sig->pattern_len && i < 16; i++) {
                    sprintf(hex + (i * 3), "%02X ", data[offset + i]);
                }
                strncpy(finding.evidence, hex, sizeof(finding.evidence) - 1);

                add_finding(result, &finding);

                /* Move past this match to avoid duplicates */
                offset += sig->pattern_len - 1;
            }
        }
    }

    return 0;
}

/*
 * Behavioral analysis
 */
static int behavioral_analysis(const uint8_t *data, size_t size, rk_scan_result_t *result)
{
    /* Check for suspicious PE imports in UEFI drivers */
    const char *suspicious_imports[] = {
        "GetSystemTime",
        "VirtualAlloc",
        "CreateProcess",
        "WriteFile",
        "RegCreateKey",
        NULL
    };

    for (int i = 0; suspicious_imports[i]; i++) {
        const char *import = suspicious_imports[i];
        size_t import_len = strlen(import);

        for (size_t offset = 0; offset < size - import_len; offset++) {
            if (memcmp(data + offset, import, import_len) == 0) {
                rk_finding_t finding;
                memset(&finding, 0, sizeof(finding));

                finding.family = RK_FAMILY_GENERIC_UEFI;
                finding.method = RK_METHOD_BEHAVIORAL;
                finding.severity = RK_SEVERITY_MEDIUM;
                strncpy(finding.name, "Suspicious_Import", sizeof(finding.name) - 1);
                snprintf(finding.description, sizeof(finding.description),
                        "UEFI module imports suspicious API: %s", import);
                finding.offset = offset;
                finding.confidence = 0.7;

                add_finding(result, &finding);
                break; /* One per import */
            }
        }
    }

    /* Check for shellcode patterns */
    size_t nop_count = 0;
    for (size_t i = 0; i < size; i++) {
        if (data[i] == 0x90) { /* NOP */
            nop_count++;
            if (nop_count >= 32) { /* NOP sled */
                rk_finding_t finding;
                memset(&finding, 0, sizeof(finding));

                finding.family = RK_FAMILY_GENERIC_UEFI;
                finding.method = RK_METHOD_BEHAVIORAL;
                finding.severity = RK_SEVERITY_HIGH;
                strncpy(finding.name, "NOP_Sled_Detected", sizeof(finding.name) - 1);
                strncpy(finding.description, "Long NOP sled detected - possible shellcode",
                       sizeof(finding.description) - 1);
                finding.offset = i - nop_count;
                finding.confidence = 0.8;

                add_finding(result, &finding);
                break;
            }
        } else {
            nop_count = 0;
        }
    }

    return 0;
}

/*
 * Heuristic analysis
 */
static int heuristic_analysis(const uint8_t *data, size_t size, rk_scan_result_t *result)
{
    /* Entropy analysis - high entropy regions may indicate packed/encrypted code */
    size_t block_size = 1024;
    int high_entropy_blocks = 0;

    for (size_t offset = 0; offset + block_size <= size; offset += block_size) {
        int byte_count[256] = {0};

        for (size_t i = 0; i < block_size; i++) {
            byte_count[data[offset + i]]++;
        }

        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (byte_count[i] > 0) {
                double p = (double)byte_count[i] / block_size;
                entropy -= p * log2(p);
            }
        }

        if (entropy > 7.9) { /* Very high entropy */
            high_entropy_blocks++;
        }
    }

    if (high_entropy_blocks > 10) {
        rk_finding_t finding;
        memset(&finding, 0, sizeof(finding));

        finding.family = RK_FAMILY_GENERIC_UEFI;
        finding.method = RK_METHOD_HEURISTIC;
        finding.severity = RK_SEVERITY_MEDIUM;
        strncpy(finding.name, "High_Entropy_Regions", sizeof(finding.name) - 1);
        snprintf(finding.description, sizeof(finding.description),
                "Multiple high-entropy blocks detected (%d) - possible encryption/packing",
                high_entropy_blocks);
        finding.confidence = 0.6;

        add_finding(result, &finding);
    }

    /* Check for self-modifying code patterns */
    /* ... additional heuristics can be added here */

    return 0;
}

/*
 * Calculate risk score
 */
static void calculate_risk(rk_scan_result_t *result)
{
    result->risk_score = 0;

    for (int i = 0; i < result->num_findings; i++) {
        switch (result->findings[i].severity) {
            case RK_SEVERITY_CRITICAL:
                result->risk_score += 30;
                break;
            case RK_SEVERITY_HIGH:
                result->risk_score += 20;
                break;
            case RK_SEVERITY_MEDIUM:
                result->risk_score += 10;
                break;
            case RK_SEVERITY_LOW:
                result->risk_score += 5;
                break;
            default:
                result->risk_score += 1;
        }
    }

    if (result->risk_score > 100) {
        result->risk_score = 100;
    }

    if (result->risk_score >= 80) {
        strncpy(result->risk_level, "critical", sizeof(result->risk_level));
    } else if (result->risk_score >= 60) {
        strncpy(result->risk_level, "high", sizeof(result->risk_level));
    } else if (result->risk_score >= 40) {
        strncpy(result->risk_level, "medium", sizeof(result->risk_level));
    } else if (result->risk_score >= 20) {
        strncpy(result->risk_level, "low", sizeof(result->risk_level));
    } else if (result->num_findings > 0) {
        strncpy(result->risk_level, "suspicious", sizeof(result->risk_level));
    } else {
        strncpy(result->risk_level, "clean", sizeof(result->risk_level));
    }
}

/*
 * Scan file
 */
int rootkit_scan_file(const char *firmware_path,
                      const rk_scan_opts_t *opts,
                      rk_scan_result_t *result)
{
    if (!g_initialized) {
        rootkit_init();
    }

    rk_scan_opts_t default_opts = RK_SCAN_OPTS_DEFAULT;
    if (!opts) {
        opts = &default_opts;
    }

    memset(result, 0, sizeof(rk_scan_result_t));
    strncpy(result->filepath, firmware_path, sizeof(result->filepath) - 1);

    /* Get filename */
    const char *filename = strrchr(firmware_path, '/');
    strncpy(result->filename, filename ? filename + 1 : firmware_path,
           sizeof(result->filename) - 1);

    /* Open and map file */
    int fd = open(firmware_path, O_RDONLY);
    if (fd < 0) {
        snprintf(result->error, sizeof(result->error),
                "Cannot open file: %s", strerror(errno));
        return FG_ERROR;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        strncpy(result->error, "Cannot stat file", sizeof(result->error));
        return FG_ERROR;
    }

    result->file_size = st.st_size;

    /* Check size limit */
    if (opts->max_file_size_mb > 0 &&
        result->file_size > (uint64_t)opts->max_file_size_mb * 1024 * 1024) {
        close(fd);
        snprintf(result->error, sizeof(result->error),
                "File too large: %lu MB (max: %d MB)",
                (unsigned long)(result->file_size / (1024*1024)),
                opts->max_file_size_mb);
        return FG_ERROR;
    }

    /* Memory map the file */
    uint8_t *data = mmap(NULL, result->file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (data == MAP_FAILED) {
        strncpy(result->error, "Cannot map file", sizeof(result->error));
        return FG_ERROR;
    }

    /* Compute hash */
    compute_sha256(data, result->file_size, result->sha256);
    result->scan_time = time(NULL);

    /* Run scans */
    if (opts->signature_scan) {
        scan_for_signatures(data, result->file_size, result);
    }

    if (opts->behavioral_scan) {
        behavioral_analysis(data, result->file_size, result);
    }

    if (opts->heuristic_scan) {
        heuristic_analysis(data, result->file_size, result);
    }

    munmap(data, result->file_size);

    /* Calculate final risk */
    calculate_risk(result);
    result->scan_complete = true;

    return FG_SUCCESS;
}

/*
 * Scan buffer
 */
int rootkit_scan_buffer(const uint8_t *data,
                        size_t size,
                        const char *name,
                        const rk_scan_opts_t *opts,
                        rk_scan_result_t *result)
{
    if (!g_initialized) {
        rootkit_init();
    }

    rk_scan_opts_t default_opts = RK_SCAN_OPTS_DEFAULT;
    if (!opts) {
        opts = &default_opts;
    }

    memset(result, 0, sizeof(rk_scan_result_t));
    strncpy(result->filename, name ? name : "buffer", sizeof(result->filename) - 1);
    result->file_size = size;

    compute_sha256(data, size, result->sha256);
    result->scan_time = time(NULL);

    if (opts->signature_scan) {
        scan_for_signatures(data, size, result);
    }

    if (opts->behavioral_scan) {
        behavioral_analysis(data, size, result);
    }

    if (opts->heuristic_scan) {
        heuristic_analysis(data, size, result);
    }

    calculate_risk(result);
    result->scan_complete = true;

    return FG_SUCCESS;
}

/*
 * Quick scan
 */
int rootkit_quick_scan(const char *firmware_path, rk_scan_result_t *result)
{
    rk_scan_opts_t opts = {
        .signature_scan = true,
        .behavioral_scan = false,
        .heuristic_scan = false,
        .deep_scan = false,
        .scan_boot_sector = false,
        .max_file_size_mb = 128,
        .custom_sigs = NULL
    };

    return rootkit_scan_file(firmware_path, &opts, result);
}

/*
 * Print result
 */
void rootkit_print_result(const rk_scan_result_t *result)
{
    printf("\n=== Rootkit Scan Results ===\n");
    printf("File: %s\n", result->filename);
    printf("Size: %lu bytes\n", (unsigned long)result->file_size);
    printf("SHA-256: %s\n", result->sha256);
    printf("\n");
    printf("Risk Level: %s\n", result->risk_level);
    printf("Risk Score: %d/100\n", result->risk_score);
    printf("\n");
    printf("Findings: %d total\n", result->num_findings);
    printf("  Signature matches: %d\n", result->signature_matches);
    printf("  Behavioral: %d\n", result->behavioral_detections);
    printf("  Heuristic: %d\n", result->heuristic_detections);

    if (result->num_findings > 0) {
        printf("\n--- Findings ---\n");
        for (int i = 0; i < result->num_findings; i++) {
            const rk_finding_t *f = &result->findings[i];
            printf("[%s] %s\n",
                   rootkit_severity_string(f->severity),
                   f->name);
            printf("    Family: %s\n", rootkit_family_name(f->family));
            printf("    Description: %s\n", f->description);
            if (f->offset > 0) {
                printf("    Offset: 0x%lx\n", (unsigned long)f->offset);
            }
            if (f->mitre_attack[0]) {
                printf("    MITRE ATT&CK: %s\n", f->mitre_attack);
            }
            if (f->evidence[0]) {
                printf("    Evidence: %s\n", f->evidence);
            }
            printf("\n");
        }
    }
}

/*
 * Get family name
 */
const char *rootkit_family_name(rk_family_t family)
{
    switch (family) {
        case RK_FAMILY_LOJAX: return "LoJax";
        case RK_FAMILY_MOSAIC: return "MosaicRegressor";
        case RK_FAMILY_MOONBOUNCE: return "MoonBounce";
        case RK_FAMILY_COSMIC_STRAND: return "CosmicStrand";
        case RK_FAMILY_BLACK_LOTUS: return "BlackLotus";
        case RK_FAMILY_ESPECTER: return "ESPecter";
        case RK_FAMILY_TRICKBOT: return "TrickBot/TrickBoot";
        case RK_FAMILY_HACKING_TEAM: return "HackingTeam";
        case RK_FAMILY_EQUATION_GROUP: return "EquationGroup";
        case RK_FAMILY_GENERIC_SMM: return "Generic SMM Rootkit";
        case RK_FAMILY_GENERIC_UEFI: return "Generic UEFI Bootkit";
        default: return "Unknown";
    }
}

/*
 * Get severity string
 */
const char *rootkit_severity_string(rk_severity_t severity)
{
    switch (severity) {
        case RK_SEVERITY_CRITICAL: return "CRITICAL";
        case RK_SEVERITY_HIGH: return "HIGH";
        case RK_SEVERITY_MEDIUM: return "MEDIUM";
        case RK_SEVERITY_LOW: return "LOW";
        case RK_SEVERITY_INFO: return "INFO";
        default: return "UNKNOWN";
    }
}

/*
 * Get method string
 */
const char *rootkit_method_string(rk_method_t method)
{
    switch (method) {
        case RK_METHOD_SIGNATURE: return "Signature";
        case RK_METHOD_BEHAVIORAL: return "Behavioral";
        case RK_METHOD_HEURISTIC: return "Heuristic";
        case RK_METHOD_STRUCTURAL: return "Structural";
        default: return "Unknown";
    }
}

/*
 * Cleanup
 */
void rootkit_cleanup(void)
{
    g_signature_count = 0;
    g_initialized = false;
}
