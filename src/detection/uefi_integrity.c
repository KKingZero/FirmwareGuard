#include "uefi_integrity.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <ctype.h>
#include <stddef.h>

/* Global module state */
static uefi_integrity_state_t g_uefi_state = {0};

/* Forward declarations */
static void add_finding(uefi_integrity_result_t *result, const char *finding);
static int read_sysfs_uint64(const char *path, uint64_t *value);
static int read_sysfs_uint32(const char *path, uint32_t *value);
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash);

int uefi_integrity_init(void) {
    FG_INFO("Initializing UEFI integrity checking subsystem...");

    /* Require root privileges for memory access */
    int ret = fg_require_root();
    if (ret != FG_SUCCESS) {
        return ret;
    }

    /* Check if EFI is supported */
    struct stat st;
    if (stat(UEFI_RUNTIME_PATH, &st) != 0) {
        FG_WARN("EFI runtime services not available - system may not be UEFI-based");
        memset(&g_uefi_state, 0, sizeof(g_uefi_state));
        g_uefi_state.initialized = true;
        return FG_NOT_SUPPORTED;
    }

    memset(&g_uefi_state, 0, sizeof(g_uefi_state));

    /* Initialize hook detection signatures */
    uefi_init_hook_signatures(g_uefi_state.signatures, &g_uefi_state.num_signatures);

    /* Set baseline path */
    snprintf(g_uefi_state.baseline_path, sizeof(g_uefi_state.baseline_path),
             "/var/lib/firmwareguard/uefi_baseline.dat");

    g_uefi_state.initialized = true;
    FG_INFO("UEFI integrity subsystem initialized");

    return FG_SUCCESS;
}

void uefi_integrity_cleanup(void) {
    memset(&g_uefi_state, 0, sizeof(g_uefi_state));
    FG_INFO("UEFI integrity subsystem cleaned up");
}

const char *uefi_get_memory_type_name(uint32_t type) {
    switch (type) {
        case EFI_RESERVED_MEMORY_TYPE:   return "Reserved";
        case EFI_LOADER_CODE:            return "LoaderCode";
        case EFI_LOADER_DATA:            return "LoaderData";
        case EFI_BOOT_SERVICES_CODE:     return "BootServicesCode";
        case EFI_BOOT_SERVICES_DATA:     return "BootServicesData";
        case EFI_RUNTIME_SERVICES_CODE:  return "RuntimeServicesCode";
        case EFI_RUNTIME_SERVICES_DATA:  return "RuntimeServicesData";
        case EFI_CONVENTIONAL_MEMORY:    return "ConventionalMemory";
        case EFI_UNUSABLE_MEMORY:        return "UnusableMemory";
        case EFI_ACPI_RECLAIM_MEMORY:    return "ACPIReclaimMemory";
        case EFI_ACPI_MEMORY_NVS:        return "ACPIMemoryNVS";
        case EFI_MEMORY_MAPPED_IO:       return "MemoryMappedIO";
        case EFI_MEMORY_MAPPED_IO_PORT_SPACE: return "MemoryMappedIOPortSpace";
        case EFI_PAL_CODE:               return "PALCode";
        case EFI_PERSISTENT_MEMORY:      return "PersistentMemory";
        default:                         return "Unknown";
    }
}

const char *uefi_integrity_risk_to_string(risk_level_t risk) {
    switch (risk) {
        case RISK_CRITICAL: return "CRITICAL";
        case RISK_HIGH:     return "HIGH";
        case RISK_MEDIUM:   return "MEDIUM";
        case RISK_LOW:      return "LOW";
        case RISK_NONE:     return "NONE";
        default:            return "UNKNOWN";
    }
}

static void add_finding(uefi_integrity_result_t *result, const char *finding) {
    if (!result || !finding) {
        return;
    }

    if (result->finding_count < 32) {
        strncpy(result->findings[result->finding_count], finding,
                sizeof(result->findings[0]) - 1);
        result->findings[result->finding_count][sizeof(result->findings[0]) - 1] = '\0';
        result->finding_count++;
    }
}

static int read_sysfs_uint64(const char *path, uint64_t *value) {
    FILE *fp = NULL;
    char buffer[64] = {0};
    size_t read_len = 0;

    if (!path || !value) {
        return FG_ERROR;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return FG_ERROR;
    }

    /* Read with bounds checking */
    read_len = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);

    if (read_len == 0) {
        return FG_ERROR;
    }

    buffer[read_len] = '\0';

    /* Parse hex or decimal value with validation */
    char *endptr = NULL;
    unsigned long long parsed = strtoull(buffer, &endptr, 0);

    /* Validate parsing was successful */
    if (endptr == buffer || (*endptr != '\0' && *endptr != '\n' && *endptr != ' ')) {
        return FG_ERROR;
    }

    *value = parsed;
    return FG_SUCCESS;
}

static int read_sysfs_uint32(const char *path, uint32_t *value) {
    uint64_t tmp = 0;
    int ret = read_sysfs_uint64(path, &tmp);
    if (ret == FG_SUCCESS) {
        /* Validate value fits in uint32_t */
        if (tmp > UINT32_MAX) {
            return FG_ERROR;
        }
        *value = (uint32_t)tmp;
    }
    return ret;
}

int uefi_read_runtime_regions(uefi_runtime_region_t *regions,
                              int max_regions, int *num_regions) {
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    int count = 0;
    char path[512] = {0};

    if (!regions || !num_regions || max_regions <= 0) {
        return FG_ERROR;
    }

    *num_regions = 0;
    memset(regions, 0, max_regions * sizeof(uefi_runtime_region_t));

    dir = opendir(UEFI_RUNTIME_MAP_PATH);
    if (!dir) {
        FG_WARN("Cannot open EFI runtime map: %s", strerror(errno));
        return FG_NOT_SUPPORTED;
    }

    while ((entry = readdir(dir)) != NULL && count < max_regions) {
        /* Skip . and .. */
        if (entry->d_name[0] == '.') {
            continue;
        }

        /* Validate entry name is a number */
        bool is_number = true;
        for (size_t i = 0; entry->d_name[i] != '\0'; i++) {
            if (!isdigit(entry->d_name[i])) {
                is_number = false;
                break;
            }
        }

        if (!is_number) {
            continue;
        }

        uefi_runtime_region_t *region = &regions[count];

        /* Read type - SECURITY: Validate path length */
        if (snprintf(path, sizeof(path), "%s/%s/type",
                     UEFI_RUNTIME_MAP_PATH, entry->d_name) >= (int)sizeof(path)) {
            FG_WARN("Path too long for entry %s", entry->d_name);
            continue;
        }
        read_sysfs_uint32(path, &region->type);

        /* Read physical address */
        if (snprintf(path, sizeof(path), "%s/%s/phys_addr",
                     UEFI_RUNTIME_MAP_PATH, entry->d_name) >= (int)sizeof(path)) {
            continue;
        }
        read_sysfs_uint64(path, &region->phys_addr);

        /* Read virtual address */
        if (snprintf(path, sizeof(path), "%s/%s/virt_addr",
                     UEFI_RUNTIME_MAP_PATH, entry->d_name) >= (int)sizeof(path)) {
            continue;
        }
        read_sysfs_uint64(path, &region->virt_addr);

        /* Read number of pages */
        if (snprintf(path, sizeof(path), "%s/%s/num_pages",
                     UEFI_RUNTIME_MAP_PATH, entry->d_name) >= (int)sizeof(path)) {
            continue;
        }
        read_sysfs_uint64(path, &region->num_pages);

        /* Read attributes */
        if (snprintf(path, sizeof(path), "%s/%s/attribute",
                     UEFI_RUNTIME_MAP_PATH, entry->d_name) >= (int)sizeof(path)) {
            continue;
        }
        read_sysfs_uint64(path, &region->attribute);

        /* Calculate size - check for overflow */
        if (region->num_pages > (UINT64_MAX / 4096)) {
            FG_WARN("Invalid num_pages value: %lu", region->num_pages);
            continue;
        }
        region->size = region->num_pages * 4096;

        /* Analyze security properties */
        region->writable = !(region->attribute & EFI_MEMORY_RO) &&
                          !(region->attribute & EFI_MEMORY_WP);
        region->executable = !(region->attribute & EFI_MEMORY_XP);
        region->runtime = (region->attribute & EFI_MEMORY_RUNTIME) != 0;

        count++;
    }

    closedir(dir);
    *num_regions = count;

    FG_INFO("Read %d EFI runtime memory regions", count);
    return FG_SUCCESS;
}

int uefi_analyze_region_security(const uefi_runtime_region_t *region,
                                 char *analysis, size_t analysis_size) {
    if (!region || !analysis || analysis_size == 0) {
        return FG_ERROR;
    }

    int written = 0;
    char *pos = analysis;
    size_t remaining = analysis_size;

    /* Analyze based on memory type */
    if (region->type == EFI_RUNTIME_SERVICES_CODE) {
        if (region->writable && region->executable) {
            written = snprintf(pos, remaining, "CRITICAL: Runtime code is WRITABLE and EXECUTABLE (W+X)");
        } else if (region->writable) {
            written = snprintf(pos, remaining, "HIGH: Runtime code region is WRITABLE");
        } else if (!region->executable) {
            written = snprintf(pos, remaining, "WARNING: Runtime code region is NOT EXECUTABLE");
        } else {
            written = snprintf(pos, remaining, "OK: Runtime code properly protected (RX)");
        }
    } else if (region->type == EFI_RUNTIME_SERVICES_DATA) {
        if (region->executable) {
            written = snprintf(pos, remaining, "HIGH: Runtime data region is EXECUTABLE");
        } else {
            written = snprintf(pos, remaining, "OK: Runtime data is non-executable");
        }
    }

    /* Check for suspicious attributes */
    if (written > 0 && (size_t)written < remaining) {
        pos += written;
        remaining -= written;
    }

    return FG_SUCCESS;
}

risk_level_t uefi_assess_region_risk(const uefi_runtime_region_t *region) {
    if (!region) {
        return RISK_NONE;
    }

    /* Critical: W+X on runtime code */
    if (region->type == EFI_RUNTIME_SERVICES_CODE &&
        region->writable && region->executable) {
        return RISK_CRITICAL;
    }

    /* High: Writable code or executable data */
    if ((region->type == EFI_RUNTIME_SERVICES_CODE && region->writable) ||
        (region->type == EFI_RUNTIME_SERVICES_DATA && region->executable)) {
        return RISK_HIGH;
    }

    /* Medium: Non-executable code (might be a configuration issue) */
    if (region->type == EFI_RUNTIME_SERVICES_CODE && !region->executable) {
        return RISK_MEDIUM;
    }

    return RISK_LOW;
}

void uefi_init_hook_signatures(hook_signature_t *signatures, int *num_sigs) {
    if (!signatures || !num_sigs) {
        return;
    }

    int count = 0;

    /* Signature 1: Direct JMP (0xE9) - common inline hook */
    signatures[count].pattern[0] = 0xE9;
    signatures[count].mask[0] = 0xFF;
    signatures[count].pattern_len = 1;
    snprintf(signatures[count].description, sizeof(signatures[count].description),
             "Direct JMP inline hook");
    count++;

    /* Signature 2: Indirect JMP via register */
    signatures[count].pattern[0] = 0xFF;
    signatures[count].pattern[1] = 0x25;  /* JMP [RIP+offset] */
    signatures[count].mask[0] = 0xFF;
    signatures[count].mask[1] = 0xFF;
    signatures[count].pattern_len = 2;
    snprintf(signatures[count].description, sizeof(signatures[count].description),
             "Indirect JMP hook");
    count++;

    /* Signature 3: PUSH + RET trampoline */
    signatures[count].pattern[0] = 0x68;  /* PUSH imm32 */
    signatures[count].pattern[1] = 0xC3;  /* RET (could be at offset) */
    signatures[count].mask[0] = 0xFF;
    signatures[count].mask[1] = 0x00;  /* Don't require RET immediately after */
    signatures[count].pattern_len = 1;
    snprintf(signatures[count].description, sizeof(signatures[count].description),
             "PUSH+RET trampoline");
    count++;

    /* Signature 4: MOV RAX, imm64; JMP RAX */
    signatures[count].pattern[0] = 0x48;
    signatures[count].pattern[1] = 0xB8;  /* MOV RAX, imm64 */
    signatures[count].mask[0] = 0xFF;
    signatures[count].mask[1] = 0xFF;
    signatures[count].pattern_len = 2;
    snprintf(signatures[count].description, sizeof(signatures[count].description),
             "MOV+JMP register hook");
    count++;

    *num_sigs = count;
    FG_INFO("Initialized %d hook detection signatures", count);
}

bool uefi_analyze_code_for_hooks(const uint8_t *code, size_t code_size,
                                 const hook_signature_t *signatures,
                                 int num_signatures,
                                 uefi_hook_detection_t *detection) {
    if (!code || code_size == 0 || !signatures || !detection) {
        return false;
    }

    memset(detection, 0, sizeof(uefi_hook_detection_t));

    /* Check for suspicious patterns in first few bytes */
    for (int sig_idx = 0; sig_idx < num_signatures; sig_idx++) {
        const hook_signature_t *sig = &signatures[sig_idx];

        if (code_size < sig->pattern_len) {
            continue;
        }

        bool match = true;
        for (size_t i = 0; i < sig->pattern_len; i++) {
            if (sig->mask[i] && (code[i] & sig->mask[i]) != (sig->pattern[i] & sig->mask[i])) {
                match = false;
                break;
            }
        }

        if (match) {
            detection->hook_detected = true;
            strncpy(detection->hook_type, sig->description,
                    sizeof(detection->hook_type) - 1);

            /* Copy hook bytes for analysis */
            size_t copy_len = (code_size < sizeof(detection->hook_bytes)) ?
                             code_size : sizeof(detection->hook_bytes);
            memcpy(detection->hook_bytes, code, copy_len);
            detection->hook_size = copy_len;

            return true;
        }
    }

    /* Additional heuristic: Check if first instruction is unusual for function prologue */
    if (code_size >= 3) {
        /* Normal function prologues often start with: PUSH RBP, MOV RBP RSP, SUB RSP, etc. */
        /* Or with NOP padding (0x90) */
        /* Suspicious if it starts with direct control flow */
        if (code[0] == 0xE9 || /* JMP */
            code[0] == 0xEB || /* JMP short */
            code[0] == 0xC3 || /* RET */
            (code[0] == 0xFF && (code[1] & 0x38) == 0x20) /* JMP indirect */) {
            detection->hook_detected = true;
            strncpy(detection->hook_type, "Suspicious function prologue",
                    sizeof(detection->hook_type) - 1);
            memcpy(detection->hook_bytes, code,
                   code_size < sizeof(detection->hook_bytes) ? code_size : sizeof(detection->hook_bytes));
            detection->hook_size = code_size < sizeof(detection->hook_bytes) ? code_size : sizeof(detection->hook_bytes);
            return true;
        }
    }

    return false;
}

int uefi_read_service_pointer(uint64_t virt_addr, service_pointer_t *pointer) {
    if (!pointer || virt_addr == 0) {
        return FG_ERROR;
    }

    memset(pointer, 0, sizeof(service_pointer_t));
    pointer->address = virt_addr;

    /* Note: Direct memory access from userspace requires /dev/mem or similar.
     * For security, Linux restricts this. This is a placeholder for the structure.
     * In a real implementation, this would use a kernel module or restricted interfaces.
     * For now, we mark it as analyzed but unable to read actual code. */

    pointer->valid = false;  /* Cannot directly read from kernel virtual addresses */
    pointer->analyzed = false;

    FG_DEBUG("Service pointer at 0x%016lX (userspace access limited)", virt_addr);

    return FG_NOT_SUPPORTED;  /* Indicates limitation */
}

int uefi_snapshot_tables(uefi_runtime_table_snapshot_t *snapshot) {
    if (!snapshot) {
        return FG_ERROR;
    }

    memset(snapshot, 0, sizeof(uefi_runtime_table_snapshot_t));

    /* Read runtime services table pointer from sysfs */
    uint64_t runtime_ptr = 0;
    int ret = read_sysfs_uint64(UEFI_RUNTIME_PATH, &runtime_ptr);
    if (ret != FG_SUCCESS) {
        FG_WARN("Cannot read runtime services table pointer");
        return FG_NOT_SUPPORTED;
    }

    snapshot->table_address = runtime_ptr;
    snapshot->snapshot_time = time(NULL);

    /* Note: Full snapshot would require reading the actual table structure
     * from kernel memory, which requires elevated privileges beyond standard
     * userspace access. This implementation captures what's available via sysfs.
     * For production use, consider integrating with a kernel module. */

    snapshot->snapshot_valid = true;

    /* Calculate hash of snapshot for integrity */
    uefi_calculate_snapshot_hash(snapshot, snapshot->snapshot_hash,
                                  sizeof(snapshot->snapshot_hash));

    FG_INFO("UEFI runtime services table snapshot captured (addr: 0x%016lX)",
            runtime_ptr);

    return FG_SUCCESS;
}

int uefi_verify_tables(const uefi_runtime_table_snapshot_t *baseline,
                       const uefi_runtime_table_snapshot_t *current,
                       uefi_integrity_verification_t *result) {
    if (!baseline || !current || !result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(uefi_integrity_verification_t));

    /* Verify table address hasn't changed */
    if (baseline->table_address != current->table_address) {
        result->tables_modified = true;
        result->num_changes++;
        snprintf(result->changes[result->num_changes - 1],
                 sizeof(result->changes[0]),
                 "Runtime services table address changed: 0x%lX -> 0x%lX",
                 baseline->table_address, current->table_address);
    }

    /* Verify snapshot hashes */
    if (memcmp(baseline->snapshot_hash, current->snapshot_hash,
               INTEGRITY_HASH_SIZE) != 0) {
        result->code_modified = true;
        result->num_changes++;
        if (result->num_changes <= 16) {
            snprintf(result->changes[result->num_changes - 1],
                     sizeof(result->changes[0]),
                     "Snapshot integrity hash mismatch detected");
        }
    }

    /* Compare service pointers */
    if (baseline->num_services != current->num_services) {
        result->pointers_changed = true;
        result->num_changes++;
        if (result->num_changes <= 16) {
            snprintf(result->changes[result->num_changes - 1],
                     sizeof(result->changes[0]),
                     "Number of services changed: %d -> %d",
                     baseline->num_services, current->num_services);
        }
    }

    FG_INFO("Table verification complete: %d changes detected", result->num_changes);

    return FG_SUCCESS;
}

int uefi_detect_hooks(const uefi_runtime_table_snapshot_t *snapshot,
                      uefi_hook_detection_t *hooks, int max_hooks,
                      int *num_detected) {
    if (!snapshot || !hooks || !num_detected || max_hooks <= 0) {
        return FG_ERROR;
    }

    *num_detected = 0;
    memset(hooks, 0, max_hooks * sizeof(uefi_hook_detection_t));

    /* Analyze each service pointer for hooks */
    for (int i = 0; i < snapshot->num_services && *num_detected < max_hooks; i++) {
        const service_pointer_t *svc = &snapshot->services[i];

        if (!svc->valid || !svc->analyzed) {
            continue;
        }

        uefi_hook_detection_t detection = {0};

        if (uefi_analyze_code_for_hooks(svc->code_snapshot,
                                       sizeof(svc->code_snapshot),
                                       g_uefi_state.signatures,
                                       g_uefi_state.num_signatures,
                                       &detection)) {
            /* Hook detected */
            strncpy(detection.service_name, svc->name,
                    sizeof(detection.service_name) - 1);
            detection.hook_address = svc->address;

            memcpy(&hooks[*num_detected], &detection, sizeof(detection));
            (*num_detected)++;

            FG_WARN("Potential hook detected in service '%s' at 0x%016lX: %s",
                    svc->name, svc->address, detection.hook_type);
        }
    }

    FG_INFO("Hook detection complete: %d potential hooks found", *num_detected);
    return FG_SUCCESS;
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash) {
    /* Simplified hash for demonstration - in production use OpenSSL or similar */
    /* This creates a deterministic "hash" from the data */
    if (!data || !hash) {
        return;
    }

    /* Simple mixing function - NOT cryptographically secure */
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    for (size_t i = 0; i < len; i++) {
        int idx = i % 8;
        h[idx] = ((h[idx] << 5) | (h[idx] >> 27)) ^ data[i];
        h[(idx + 1) % 8] += h[idx];
    }

    memcpy(hash, h, 32);
}

int uefi_calculate_snapshot_hash(const uefi_runtime_table_snapshot_t *snapshot,
                                 uint8_t *hash, size_t hash_size) {
    if (!snapshot || !hash || hash_size < INTEGRITY_HASH_SIZE) {
        return FG_ERROR;
    }

    /* Hash the critical parts of the snapshot */
    sha256_hash((const uint8_t *)snapshot,
                offsetof(uefi_runtime_table_snapshot_t, snapshot_hash),
                hash);

    return FG_SUCCESS;
}

bool uefi_is_address_in_runtime(uint64_t address,
                                const uefi_runtime_region_t *regions,
                                int num_regions, int *region_index) {
    if (!regions || num_regions <= 0) {
        return false;
    }

    for (int i = 0; i < num_regions; i++) {
        uint64_t region_start = regions[i].virt_addr;
        uint64_t region_end = region_start + regions[i].size;

        if (address >= region_start && address < region_end) {
            if (region_index) {
                *region_index = i;
            }
            return true;
        }
    }

    return false;
}

risk_level_t uefi_assess_integrity_risk(const uefi_integrity_result_t *result) {
    if (!result) {
        return RISK_NONE;
    }

    int risk_score = 0;

    /* Critical: Hooks detected */
    if (result->num_hooks_detected > 0) {
        risk_score += 10;
    }

    /* Critical: Tables modified */
    if (result->integrity.tables_modified) {
        risk_score += 8;
    }

    /* High: Code modifications detected */
    if (result->integrity.code_modified) {
        risk_score += 6;
    }

    /* High: Function pointers changed */
    if (result->integrity.pointers_changed) {
        risk_score += 5;
    }

    /* Medium: Writable runtime code regions */
    for (int i = 0; i < result->num_regions; i++) {
        const uefi_runtime_region_t *region = &result->regions[i];
        if (region->type == EFI_RUNTIME_SERVICES_CODE && region->writable) {
            risk_score += 3;
            break;
        }
    }

    /* Medium: Executable runtime data regions */
    for (int i = 0; i < result->num_regions; i++) {
        const uefi_runtime_region_t *region = &result->regions[i];
        if (region->type == EFI_RUNTIME_SERVICES_DATA && region->executable) {
            risk_score += 2;
            break;
        }
    }

    /* Map score to risk level */
    if (risk_score >= 8) {
        return RISK_CRITICAL;
    } else if (risk_score >= 5) {
        return RISK_HIGH;
    } else if (risk_score >= 3) {
        return RISK_MEDIUM;
    } else if (risk_score >= 1) {
        return RISK_LOW;
    }

    return RISK_NONE;
}

int uefi_integrity_scan(uefi_integrity_result_t *result) {
    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(uefi_integrity_result_t));
    result->scan_time = time(NULL);

    FG_INFO("Starting UEFI integrity scan...");

    /* Check if EFI is supported */
    struct stat st;
    if (stat(UEFI_RUNTIME_PATH, &st) != 0) {
        result->efi_supported = false;
        snprintf(result->summary, sizeof(result->summary),
                 "EFI not supported on this system");
        add_finding(result, "System is not UEFI-based or EFI runtime not available");
        return FG_NOT_SUPPORTED;
    }

    result->efi_supported = true;
    add_finding(result, "EFI runtime services detected");

    /* Read runtime services table pointer */
    int ret = read_sysfs_uint64(UEFI_RUNTIME_PATH, &result->runtime_table_ptr);
    if (ret == FG_SUCCESS) {
        result->runtime_services_available = true;
        char finding[256];
        snprintf(finding, sizeof(finding),
                 "Runtime services table at: 0x%016lX", result->runtime_table_ptr);
        add_finding(result, finding);
    } else {
        add_finding(result, "WARNING: Cannot read runtime services table pointer");
    }

    /* Read runtime memory regions */
    ret = uefi_read_runtime_regions(result->regions, MAX_RUNTIME_REGIONS,
                                    &result->num_regions);
    if (ret == FG_SUCCESS && result->num_regions > 0) {
        char finding[256];
        snprintf(finding, sizeof(finding),
                 "Found %d EFI runtime memory regions", result->num_regions);
        add_finding(result, finding);

        /* Calculate total runtime memory */
        for (int i = 0; i < result->num_regions; i++) {
            result->total_runtime_memory += result->regions[i].size;
        }

        snprintf(finding, sizeof(finding),
                 "Total runtime memory: %lu KB (%lu MB)",
                 result->total_runtime_memory / 1024,
                 result->total_runtime_memory / (1024 * 1024));
        add_finding(result, finding);

        /* Analyze each region for security issues */
        for (int i = 0; i < result->num_regions; i++) {
            const uefi_runtime_region_t *region = &result->regions[i];
            char region_finding[256];

            /* Check for W+X violations */
            if (region->type == EFI_RUNTIME_SERVICES_CODE) {
                if (region->writable && region->executable) {
                    snprintf(region_finding, sizeof(region_finding),
                             "CRITICAL: Runtime code region %d is W+X (writable+executable)", i);
                    add_finding(result, region_finding);
                } else if (region->writable) {
                    snprintf(region_finding, sizeof(region_finding),
                             "WARNING: Runtime code region %d is writable", i);
                    add_finding(result, region_finding);
                }
            }

            if (region->type == EFI_RUNTIME_SERVICES_DATA && region->executable) {
                snprintf(region_finding, sizeof(region_finding),
                         "WARNING: Runtime data region %d is executable", i);
                add_finding(result, region_finding);
            }
        }
    } else {
        add_finding(result, "WARNING: No runtime memory regions found");
    }

    /* Capture current snapshot */
    ret = uefi_snapshot_tables(&result->current_snapshot);
    if (ret == FG_SUCCESS) {
        add_finding(result, "Current UEFI runtime table snapshot captured");

        /* If baseline exists, verify against it */
        if (g_uefi_state.baseline_captured) {
            char verify_finding[256];
            ret = uefi_verify_tables(&g_uefi_state.baseline,
                                    &result->current_snapshot,
                                    &result->integrity);
            if (ret == FG_SUCCESS) {
                if (result->integrity.num_changes > 0) {
                    snprintf(verify_finding, sizeof(verify_finding),
                             "ALERT: %d integrity changes detected since baseline",
                             result->integrity.num_changes);
                    add_finding(result, verify_finding);

                    for (int i = 0; i < result->integrity.num_changes && i < 16; i++) {
                        add_finding(result, result->integrity.changes[i]);
                    }
                } else {
                    add_finding(result, "No changes detected from baseline");
                }
            }
        } else {
            add_finding(result, "No baseline available for comparison");
        }

        /* Detect hooks in current snapshot */
        char hook_finding[256];
        ret = uefi_detect_hooks(&result->current_snapshot, result->hooks,
                               MAX_SERVICE_POINTERS, &result->num_hooks_detected);
        if (ret == FG_SUCCESS) {
            if (result->num_hooks_detected > 0) {
                snprintf(hook_finding, sizeof(hook_finding),
                         "CRITICAL: %d potential hooks detected in UEFI services",
                         result->num_hooks_detected);
                add_finding(result, hook_finding);
            } else {
                add_finding(result, "No hooks detected in accessible services");
            }
        }
    }

    /* Assess overall risk */
    result->risk_level = uefi_assess_integrity_risk(result);

    /* Generate risk reason */
    if (result->num_hooks_detected > 0) {
        snprintf(result->risk_reason, sizeof(result->risk_reason),
                 "CRITICAL: Potential UEFI rootkit detected - %d hooks found",
                 result->num_hooks_detected);
    } else if (result->integrity.tables_modified) {
        snprintf(result->risk_reason, sizeof(result->risk_reason),
                 "Runtime services tables have been modified");
    } else if (result->integrity.code_modified) {
        snprintf(result->risk_reason, sizeof(result->risk_reason),
                 "Runtime service code modifications detected");
    } else {
        snprintf(result->risk_reason, sizeof(result->risk_reason),
                 "UEFI runtime services appear intact");
    }

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
             "UEFI Integrity: %s, %d regions, %lu KB runtime memory, Risk: %s",
             result->efi_supported ? "Available" : "Not Available",
             result->num_regions,
             result->total_runtime_memory / 1024,
             uefi_integrity_risk_to_string(result->risk_level));

    FG_INFO("%s", result->summary);
    return FG_SUCCESS;
}

int uefi_integrity_check_brief(uefi_integrity_result_t *result) {
    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(uefi_integrity_result_t));
    result->scan_time = time(NULL);

    /* Quick EFI support check */
    struct stat st;
    result->efi_supported = (stat(UEFI_RUNTIME_PATH, &st) == 0);

    if (result->efi_supported) {
        /* Read runtime pointer */
        read_sysfs_uint64(UEFI_RUNTIME_PATH, &result->runtime_table_ptr);
        result->runtime_services_available = (result->runtime_table_ptr != 0);

        /* Quick region scan */
        uefi_read_runtime_regions(result->regions, MAX_RUNTIME_REGIONS,
                                  &result->num_regions);

        /* Quick risk assessment */
        result->risk_level = RISK_LOW;  /* Default to low for brief scan */
    } else {
        result->risk_level = RISK_NONE;
    }

    snprintf(result->summary, sizeof(result->summary),
             "UEFI: %s, %d regions",
             result->efi_supported ? "Yes" : "No",
             result->num_regions);

    return FG_SUCCESS;
}

void uefi_integrity_print_result(const uefi_integrity_result_t *result,
                                 bool verbose) {
    if (!result) {
        return;
    }

    printf("\n");
    printf("==================================================\n");
    printf("  UEFI Runtime Integrity Check Results\n");
    printf("==================================================\n");
    printf("\n");

    printf("EFI System Information:\n");
    printf("  EFI Supported: %s\n", result->efi_supported ? "Yes" : "No");

    if (!result->efi_supported) {
        printf("  System is not UEFI-based\n");
        return;
    }

    printf("  Runtime Services: %s\n",
           result->runtime_services_available ? "Available" : "Not Available");

    if (result->runtime_table_ptr) {
        printf("  Runtime Table Pointer: 0x%016lX\n", result->runtime_table_ptr);
    }
    printf("\n");

    printf("Runtime Memory Regions: %d\n", result->num_regions);
    if (result->num_regions > 0) {
        printf("  Total Runtime Memory: %lu KB (%lu MB)\n",
               result->total_runtime_memory / 1024,
               result->total_runtime_memory / (1024 * 1024));
        printf("\n");

        if (verbose) {
            printf("  Region Details:\n");
            for (int i = 0; i < result->num_regions && i < 10; i++) {
                const uefi_runtime_region_t *r = &result->regions[i];
                printf("    [%d] Type: %-20s Virt: 0x%016lX  Size: %6lu KB  ",
                       i, uefi_get_memory_type_name(r->type),
                       r->virt_addr, r->size / 1024);
                printf("%s%s%s\n",
                       r->writable ? "W" : "-",
                       r->executable ? "X" : "-",
                       r->runtime ? "R" : "-");
            }
            if (result->num_regions > 10) {
                printf("    ... and %d more regions\n", result->num_regions - 10);
            }
            printf("\n");
        }
    }

    if (result->num_hooks_detected > 0) {
        printf("Hook Detection:\n");
        printf("  CRITICAL: %d potential hooks detected!\n", result->num_hooks_detected);
        for (int i = 0; i < result->num_hooks_detected && i < 5; i++) {
            const uefi_hook_detection_t *hook = &result->hooks[i];
            printf("    [%d] Service: %s\n", i + 1, hook->service_name);
            printf("        Address: 0x%016lX\n", hook->hook_address);
            printf("        Type: %s\n", hook->hook_type);
        }
        printf("\n");
    }

    if (result->integrity.num_changes > 0) {
        printf("Integrity Verification:\n");
        printf("  Changes Detected: %d\n", result->integrity.num_changes);
        printf("  Tables Modified: %s\n", result->integrity.tables_modified ? "YES" : "No");
        printf("  Pointers Changed: %s\n", result->integrity.pointers_changed ? "YES" : "No");
        printf("  Code Modified: %s\n", result->integrity.code_modified ? "YES" : "No");
        printf("\n");
    }

    printf("Security Assessment:\n");
    printf("  Risk Level: %s\n", uefi_integrity_risk_to_string(result->risk_level));
    printf("  Assessment: %s\n", result->risk_reason);
    printf("\n");

    if (verbose && result->finding_count > 0) {
        printf("Detailed Findings:\n");
        for (int i = 0; i < result->finding_count; i++) {
            printf("  [%d] %s\n", i + 1, result->findings[i]);
        }
        printf("\n");
    }

    printf("Summary: %s\n", result->summary);
    printf("Scan Time: %s", ctime(&result->scan_time));
    printf("\n");
}

int uefi_integrity_report(const uefi_integrity_result_t *result,
                          char *buffer, size_t buffer_size) {
    if (!result || !buffer || buffer_size == 0) {
        return FG_ERROR;
    }

    /* Generate text report */
    size_t offset = 0;
    int written = 0;

    written = snprintf(buffer + offset, buffer_size - offset,
                      "UEFI Runtime Integrity Report\n"
                      "==============================\n\n");
    if (written > 0) offset += written;
    if (offset >= buffer_size) return FG_ERROR;

    written = snprintf(buffer + offset, buffer_size - offset,
                      "EFI Supported: %s\n"
                      "Runtime Services: %s\n"
                      "Runtime Regions: %d\n"
                      "Total Runtime Memory: %lu KB\n\n",
                      result->efi_supported ? "Yes" : "No",
                      result->runtime_services_available ? "Yes" : "No",
                      result->num_regions,
                      result->total_runtime_memory / 1024);
    if (written > 0) offset += written;
    if (offset >= buffer_size) return FG_ERROR;

    written = snprintf(buffer + offset, buffer_size - offset,
                      "Risk Level: %s\n"
                      "Risk Reason: %s\n\n",
                      uefi_integrity_risk_to_string(result->risk_level),
                      result->risk_reason);
    if (written > 0) offset += written;
    if (offset >= buffer_size) return FG_ERROR;

    if (result->num_hooks_detected > 0) {
        written = snprintf(buffer + offset, buffer_size - offset,
                          "CRITICAL: %d potential hooks detected\n",
                          result->num_hooks_detected);
        if (written > 0) offset += written;
    }

    return FG_SUCCESS;
}

int uefi_integrity_to_json(const uefi_integrity_result_t *result,
                           char *buffer, size_t size) {
    if (!result || !buffer || size == 0) {
        return FG_ERROR;
    }

    int written = snprintf(buffer, size,
        "{\n"
        "  \"efi_supported\": %s,\n"
        "  \"runtime_services_available\": %s,\n"
        "  \"runtime_table_ptr\": \"0x%016lX\",\n"
        "  \"num_regions\": %d,\n"
        "  \"total_runtime_memory\": %lu,\n"
        "  \"hooks_detected\": %d,\n"
        "  \"integrity\": {\n"
        "    \"tables_modified\": %s,\n"
        "    \"pointers_changed\": %s,\n"
        "    \"code_modified\": %s,\n"
        "    \"num_changes\": %d\n"
        "  },\n"
        "  \"risk\": {\n"
        "    \"level\": \"%s\",\n"
        "    \"reason\": \"%s\"\n"
        "  },\n"
        "  \"summary\": \"%s\"\n"
        "}\n",
        result->efi_supported ? "true" : "false",
        result->runtime_services_available ? "true" : "false",
        result->runtime_table_ptr,
        result->num_regions,
        result->total_runtime_memory,
        result->num_hooks_detected,
        result->integrity.tables_modified ? "true" : "false",
        result->integrity.pointers_changed ? "true" : "false",
        result->integrity.code_modified ? "true" : "false",
        result->integrity.num_changes,
        uefi_integrity_risk_to_string(result->risk_level),
        result->risk_reason,
        result->summary
    );

    return (written > 0 && (size_t)written < size) ? FG_SUCCESS : FG_ERROR;
}

int uefi_save_baseline(const uefi_runtime_table_snapshot_t *snapshot,
                       const char *path) {
    FILE *fp = NULL;

    if (!snapshot || !path) {
        return FG_ERROR;
    }

    /* Validate path to prevent directory traversal */
    if (strstr(path, "..") != NULL) {
        FG_LOG_ERROR("Invalid baseline path (contains '..')");
        return FG_ERROR;
    }

    fp = fopen(path, "wb");
    if (!fp) {
        FG_LOG_ERROR("Cannot create baseline file: %s", strerror(errno));
        return FG_ERROR;
    }

    size_t written = fwrite(snapshot, sizeof(*snapshot), 1, fp);
    fclose(fp);

    if (written != 1) {
        FG_LOG_ERROR("Failed to write baseline snapshot");
        unlink(path);  /* Remove incomplete file */
        return FG_ERROR;
    }

    FG_INFO("Baseline saved to %s", path);
    return FG_SUCCESS;
}

int uefi_load_baseline(uefi_runtime_table_snapshot_t *snapshot,
                       const char *path) {
    FILE *fp = NULL;
    struct stat st;

    if (!snapshot || !path) {
        return FG_ERROR;
    }

    /* Validate path */
    if (strstr(path, "..") != NULL) {
        FG_LOG_ERROR("Invalid baseline path (contains '..')");
        return FG_ERROR;
    }

    /* Check file exists and size is correct */
    if (stat(path, &st) != 0) {
        FG_LOG_ERROR("Baseline file not found: %s", path);
        return FG_NOT_FOUND;
    }

    if ((size_t)st.st_size != sizeof(*snapshot)) {
        FG_LOG_ERROR("Baseline file has incorrect size");
        return FG_ERROR;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        FG_LOG_ERROR("Cannot open baseline file: %s", strerror(errno));
        return FG_ERROR;
    }

    size_t read_bytes = fread(snapshot, sizeof(*snapshot), 1, fp);
    fclose(fp);

    if (read_bytes != 1) {
        FG_LOG_ERROR("Failed to read baseline snapshot");
        return FG_ERROR;
    }

    /* Verify snapshot validity */
    if (!snapshot->snapshot_valid) {
        FG_LOG_ERROR("Loaded baseline is marked invalid");
        return FG_ERROR;
    }

    FG_INFO("Baseline loaded from %s", path);
    return FG_SUCCESS;
}
