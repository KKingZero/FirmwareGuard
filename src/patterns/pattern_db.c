#include "pattern_db.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

/* Helper function prototypes */
static int parse_pattern_json(const char *json_data, pattern_t *pattern);
static int parse_detection(cJSON *detection_obj, detection_t *detection);
static int parse_metadata(cJSON *metadata_obj, pattern_metadata_t *metadata);
static char* read_file_to_string(const char *filename);
static int scan_directory_recursive(const char *dirpath, pattern_db_t *db);

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

pattern_db_t* pattern_db_init(const char *patterns_dir) {
    pattern_db_t *db = calloc(1, sizeof(pattern_db_t));
    if (!db) {
        fprintf(stderr, "Failed to allocate pattern database\n");
        return NULL;
    }

    db->capacity = 100;  // Initial capacity
    db->patterns = calloc(db->capacity, sizeof(pattern_t));
    if (!db->patterns) {
        fprintf(stderr, "Failed to allocate patterns array\n");
        free(db);
        return NULL;
    }

    db->count = 0;
    strncpy(db->patterns_dir, patterns_dir, sizeof(db->patterns_dir) - 1);

    return db;
}

void pattern_db_free(pattern_db_t *db) {
    if (!db) return;

    if (db->patterns) {
        free(db->patterns);
    }

    free(db);
}

int pattern_db_load(pattern_db_t *db) {
    if (!db || !db->patterns_dir[0]) {
        fprintf(stderr, "Invalid pattern database or patterns directory\n");
        return -1;
    }

    // Check if directory exists
    struct stat st;
    if (stat(db->patterns_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Patterns directory does not exist: %s\n", db->patterns_dir);
        return -1;
    }

    printf("[Pattern DB] Loading patterns from: %s\n", db->patterns_dir);

    int initial_count = db->count;
    if (scan_directory_recursive(db->patterns_dir, db) < 0) {
        return -1;
    }

    int loaded = db->count - initial_count;
    printf("[Pattern DB] Loaded %d patterns\n", loaded);

    return loaded;
}

int pattern_db_load_file(pattern_db_t *db, const char *json_file) {
    if (!db || !json_file) return -1;

    // Check if we need to expand the array
    if (db->count >= db->capacity) {
        int new_capacity = db->capacity * 2;
        pattern_t *new_patterns = realloc(db->patterns, new_capacity * sizeof(pattern_t));
        if (!new_patterns) {
            fprintf(stderr, "Failed to expand patterns array\n");
            return -1;
        }
        db->patterns = new_patterns;
        db->capacity = new_capacity;
    }

    // Read JSON file
    char *json_data = read_file_to_string(json_file);
    if (!json_data) {
        fprintf(stderr, "Failed to read pattern file: %s\n", json_file);
        return -1;
    }

    // Parse pattern
    pattern_t *pattern = &db->patterns[db->count];
    memset(pattern, 0, sizeof(pattern_t));
    pattern->enabled = true;  // Enable by default

    int ret = parse_pattern_json(json_data, pattern);
    free(json_data);

    if (ret == 0) {
        db->count++;
        printf("[Pattern DB]   Loaded: %s (%s)\n", pattern->id, pattern->name);
        return 0;
    } else {
        fprintf(stderr, "[Pattern DB]   Failed to parse: %s\n", json_file);
        return -1;
    }
}

const pattern_t* pattern_db_find_by_id(pattern_db_t *db, const char *id) {
    if (!db || !id) return NULL;

    for (int i = 0; i < db->count; i++) {
        if (strcmp(db->patterns[i].id, id) == 0) {
            return &db->patterns[i];
        }
    }

    return NULL;
}

int pattern_db_get_by_type(pattern_db_t *db, firmware_type_t type,
                           const pattern_t **results, int max_results) {
    if (!db || !results) return 0;

    int count = 0;
    for (int i = 0; i < db->count && count < max_results; i++) {
        if (db->patterns[i].firmware_type == type) {
            results[count++] = &db->patterns[i];
        }
    }

    return count;
}

void pattern_db_print_stats(pattern_db_t *db) {
    if (!db) return;

    printf("\n========================================\n");
    printf("  PATTERN DATABASE STATISTICS\n");
    printf("========================================\n\n");
    printf("Total Patterns: %d\n", db->count);
    printf("Capacity: %d\n", db->capacity);
    printf("Patterns Directory: %s\n\n", db->patterns_dir);

    // Count by firmware type
    int type_counts[FIRMWARE_TYPE_UNKNOWN + 1] = {0};
    for (int i = 0; i < db->count; i++) {
        type_counts[db->patterns[i].firmware_type]++;
    }

    printf("Patterns by Type:\n");
    printf("  Intel ME:     %d\n", type_counts[FIRMWARE_TYPE_INTEL_ME]);
    printf("  AMD PSP:      %d\n", type_counts[FIRMWARE_TYPE_AMD_PSP]);
    printf("  ACPI:         %d\n", type_counts[FIRMWARE_TYPE_ACPI]);
    printf("  NIC:          %d\n", type_counts[FIRMWARE_TYPE_NIC]);
    printf("  UEFI:         %d\n", type_counts[FIRMWARE_TYPE_UEFI]);
    printf("  SMM:          %d\n", type_counts[FIRMWARE_TYPE_SMM]);
    printf("  BIOS:         %d\n", type_counts[FIRMWARE_TYPE_BIOS]);
    printf("  General:      %d\n", type_counts[FIRMWARE_TYPE_GENERAL]);

    // Count by risk level
    int risk_counts[RISK_LEVEL_INFO + 1] = {0};
    for (int i = 0; i < db->count; i++) {
        risk_counts[db->patterns[i].risk_level]++;
    }

    printf("\nPatterns by Risk Level:\n");
    printf("  CRITICAL:     %d\n", risk_counts[RISK_LEVEL_CRITICAL]);
    printf("  HIGH:         %d\n", risk_counts[RISK_LEVEL_HIGH]);
    printf("  MEDIUM:       %d\n", risk_counts[RISK_LEVEL_MEDIUM]);
    printf("  LOW:          %d\n", risk_counts[RISK_LEVEL_LOW]);
    printf("  INFO:         %d\n", risk_counts[RISK_LEVEL_INFO]);

    printf("\n========================================\n\n");
}

/* ============================================================================
 * Helper Functions: Type Conversions
 * ============================================================================ */

firmware_type_t str_to_firmware_type(const char *str) {
    if (!str) return FIRMWARE_TYPE_UNKNOWN;

    if (strcmp(str, "intel-me") == 0) return FIRMWARE_TYPE_INTEL_ME;
    if (strcmp(str, "amd-psp") == 0) return FIRMWARE_TYPE_AMD_PSP;
    if (strcmp(str, "acpi") == 0) return FIRMWARE_TYPE_ACPI;
    if (strcmp(str, "nic") == 0) return FIRMWARE_TYPE_NIC;
    if (strcmp(str, "uefi") == 0) return FIRMWARE_TYPE_UEFI;
    if (strcmp(str, "smm") == 0) return FIRMWARE_TYPE_SMM;
    if (strcmp(str, "bios") == 0) return FIRMWARE_TYPE_BIOS;
    if (strcmp(str, "general") == 0) return FIRMWARE_TYPE_GENERAL;

    return FIRMWARE_TYPE_UNKNOWN;
}

risk_level_t str_to_risk_level(const char *str) {
    if (!str) return RISK_LEVEL_INFO;

    if (strcmp(str, "CRITICAL") == 0) return RISK_LEVEL_CRITICAL;
    if (strcmp(str, "HIGH") == 0) return RISK_LEVEL_HIGH;
    if (strcmp(str, "MEDIUM") == 0) return RISK_LEVEL_MEDIUM;
    if (strcmp(str, "LOW") == 0) return RISK_LEVEL_LOW;
    if (strcmp(str, "INFO") == 0) return RISK_LEVEL_INFO;

    return RISK_LEVEL_INFO;
}

detection_method_t str_to_detection_method(const char *str) {
    if (!str) return DETECTION_METHOD_UNKNOWN;

    if (strcmp(str, "pci-device") == 0) return DETECTION_METHOD_PCI_DEVICE;
    if (strcmp(str, "msr-register") == 0) return DETECTION_METHOD_MSR_REGISTER;
    if (strcmp(str, "file-exists") == 0) return DETECTION_METHOD_FILE_EXISTS;
    if (strcmp(str, "file-content") == 0) return DETECTION_METHOD_FILE_CONTENT;
    if (strcmp(str, "acpi-table") == 0) return DETECTION_METHOD_ACPI_TABLE;
    if (strcmp(str, "sysfs-value") == 0) return DETECTION_METHOD_SYSFS_VALUE;
    if (strcmp(str, "memory-pattern") == 0) return DETECTION_METHOD_MEMORY_PATTERN;
    if (strcmp(str, "combination") == 0) return DETECTION_METHOD_COMBINATION;

    return DETECTION_METHOD_UNKNOWN;
}

const char* firmware_type_to_str(firmware_type_t type) {
    switch (type) {
        case FIRMWARE_TYPE_INTEL_ME: return "intel-me";
        case FIRMWARE_TYPE_AMD_PSP: return "amd-psp";
        case FIRMWARE_TYPE_ACPI: return "acpi";
        case FIRMWARE_TYPE_NIC: return "nic";
        case FIRMWARE_TYPE_UEFI: return "uefi";
        case FIRMWARE_TYPE_SMM: return "smm";
        case FIRMWARE_TYPE_BIOS: return "bios";
        case FIRMWARE_TYPE_GENERAL: return "general";
        default: return "unknown";
    }
}

const char* risk_level_to_str(risk_level_t level) {
    switch (level) {
        case RISK_LEVEL_CRITICAL: return "CRITICAL";
        case RISK_LEVEL_HIGH: return "HIGH";
        case RISK_LEVEL_MEDIUM: return "MEDIUM";
        case RISK_LEVEL_LOW: return "LOW";
        case RISK_LEVEL_INFO: return "INFO";
        default: return "UNKNOWN";
    }
}

const char* detection_method_to_str(detection_method_t method) {
    switch (method) {
        case DETECTION_METHOD_PCI_DEVICE: return "pci-device";
        case DETECTION_METHOD_MSR_REGISTER: return "msr-register";
        case DETECTION_METHOD_FILE_EXISTS: return "file-exists";
        case DETECTION_METHOD_FILE_CONTENT: return "file-content";
        case DETECTION_METHOD_ACPI_TABLE: return "acpi-table";
        case DETECTION_METHOD_SYSFS_VALUE: return "sysfs-value";
        case DETECTION_METHOD_MEMORY_PATTERN: return "memory-pattern";
        case DETECTION_METHOD_COMBINATION: return "combination";
        default: return "unknown";
    }
}

/* ============================================================================
 * Private Helper Functions: JSON Parsing
 * ============================================================================ */

static int parse_pattern_json(const char *json_data, pattern_t *pattern) {
    cJSON *root = cJSON_Parse(json_data);
    if (!root) {
        fprintf(stderr, "JSON parse error: %s\n", cJSON_GetErrorPtr());
        return -1;
    }

    // Required: id
    cJSON *id = cJSON_GetObjectItem(root, "id");
    if (cJSON_IsString(id)) {
        strncpy(pattern->id, id->valuestring, sizeof(pattern->id) - 1);
    } else {
        fprintf(stderr, "Missing or invalid 'id' field\n");
        cJSON_Delete(root);
        return -1;
    }

    // Required: name
    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (cJSON_IsString(name)) {
        strncpy(pattern->name, name->valuestring, sizeof(pattern->name) - 1);
    } else {
        fprintf(stderr, "Missing or invalid 'name' field\n");
        cJSON_Delete(root);
        return -1;
    }

    // Required: version
    cJSON *version = cJSON_GetObjectItem(root, "version");
    if (cJSON_IsString(version)) {
        strncpy(pattern->version, version->valuestring, sizeof(pattern->version) - 1);
    } else {
        strncpy(pattern->version, "1.0.0", sizeof(pattern->version) - 1);
    }

    // Required: firmware_type
    cJSON *fw_type = cJSON_GetObjectItem(root, "firmware_type");
    if (cJSON_IsString(fw_type)) {
        pattern->firmware_type = str_to_firmware_type(fw_type->valuestring);
    } else {
        fprintf(stderr, "Missing or invalid 'firmware_type' field\n");
        cJSON_Delete(root);
        return -1;
    }

    // Required: detection
    cJSON *detection = cJSON_GetObjectItem(root, "detection");
    if (!detection) {
        fprintf(stderr, "Missing 'detection' field\n");
        cJSON_Delete(root);
        return -1;
    }
    if (parse_detection(detection, &pattern->detection) != 0) {
        cJSON_Delete(root);
        return -1;
    }

    // Required: risk_level
    cJSON *risk = cJSON_GetObjectItem(root, "risk_level");
    if (cJSON_IsString(risk)) {
        pattern->risk_level = str_to_risk_level(risk->valuestring);
    } else {
        pattern->risk_level = RISK_LEVEL_INFO;
    }

    // Optional: confidence
    cJSON *confidence = cJSON_GetObjectItem(root, "confidence");
    if (cJSON_IsNumber(confidence)) {
        pattern->confidence = confidence->valueint;
    } else {
        pattern->confidence = 80;  // Default
    }

    // Optional: blockable
    cJSON *blockable = cJSON_GetObjectItem(root, "blockable");
    if (cJSON_IsBool(blockable)) {
        pattern->blockable = cJSON_IsTrue(blockable);
    } else {
        pattern->blockable = false;
    }

    // Required: metadata
    cJSON *metadata = cJSON_GetObjectItem(root, "metadata");
    if (metadata) {
        parse_metadata(metadata, &pattern->metadata);
    }

    cJSON_Delete(root);
    return 0;
}

static int parse_detection(cJSON *detection_obj, detection_t *detection) {
    // Get method
    cJSON *method = cJSON_GetObjectItem(detection_obj, "method");
    if (!cJSON_IsString(method)) {
        fprintf(stderr, "Missing or invalid 'method' in detection\n");
        return -1;
    }

    detection->method = str_to_detection_method(method->valuestring);

    // Get criteria
    cJSON *criteria = cJSON_GetObjectItem(detection_obj, "criteria");
    if (!criteria) {
        fprintf(stderr, "Missing 'criteria' in detection\n");
        return -1;
    }

    // Parse based on method type
    switch (detection->method) {
        case DETECTION_METHOD_PCI_DEVICE: {
            cJSON *pci = cJSON_GetObjectItem(criteria, "pci");
            if (pci) {
                cJSON *vendor = cJSON_GetObjectItem(pci, "vendor_id");
                if (cJSON_IsString(vendor)) {
                    sscanf(vendor->valuestring, "0x%hx", &detection->criteria.pci.vendor_id);
                    detection->criteria.pci.has_vendor = true;
                }

                cJSON *device = cJSON_GetObjectItem(pci, "device_id");
                if (cJSON_IsString(device)) {
                    sscanf(device->valuestring, "0x%hx", &detection->criteria.pci.device_id);
                    detection->criteria.pci.has_device = true;
                }

                cJSON *bus = cJSON_GetObjectItem(pci, "bus");
                if (cJSON_IsString(bus)) {
                    detection->criteria.pci.bus = atoi(bus->valuestring);
                    detection->criteria.pci.has_bus = true;
                }
            }
            break;
        }

        case DETECTION_METHOD_MSR_REGISTER: {
            cJSON *msr = cJSON_GetObjectItem(criteria, "msr");
            if (msr) {
                cJSON *reg = cJSON_GetObjectItem(msr, "register");
                if (cJSON_IsString(reg)) {
                    sscanf(reg->valuestring, "0x%lx", &detection->criteria.msr.register_addr);
                }

                cJSON *mask = cJSON_GetObjectItem(msr, "mask");
                if (cJSON_IsString(mask)) {
                    sscanf(mask->valuestring, "0x%lx", &detection->criteria.msr.mask);
                }

                cJSON *expected = cJSON_GetObjectItem(msr, "expected_value");
                if (cJSON_IsString(expected)) {
                    sscanf(expected->valuestring, "0x%lx", &detection->criteria.msr.expected_value);
                }
            }
            break;
        }

        case DETECTION_METHOD_FILE_EXISTS:
        case DETECTION_METHOD_FILE_CONTENT: {
            cJSON *file = cJSON_GetObjectItem(criteria, "file");
            if (file) {
                cJSON *path = cJSON_GetObjectItem(file, "path");
                if (cJSON_IsString(path)) {
                    strncpy(detection->criteria.file.path, path->valuestring,
                           sizeof(detection->criteria.file.path) - 1);
                }

                cJSON *regex = cJSON_GetObjectItem(file, "regex");
                if (cJSON_IsString(regex)) {
                    strncpy(detection->criteria.file.regex, regex->valuestring,
                           sizeof(detection->criteria.file.regex) - 1);
                }
            }
            break;
        }

        case DETECTION_METHOD_ACPI_TABLE: {
            cJSON *acpi = cJSON_GetObjectItem(criteria, "acpi_table");
            if (acpi) {
                cJSON *sig = cJSON_GetObjectItem(acpi, "signature");
                if (cJSON_IsString(sig)) {
                    strncpy(detection->criteria.acpi.signature, sig->valuestring, 4);
                    detection->criteria.acpi.signature[4] = '\0';
                }

                cJSON *path = cJSON_GetObjectItem(acpi, "path");
                if (cJSON_IsString(path)) {
                    strncpy(detection->criteria.acpi.path, path->valuestring,
                           sizeof(detection->criteria.acpi.path) - 1);
                }
            }
            break;
        }

        case DETECTION_METHOD_SYSFS_VALUE: {
            cJSON *sysfs = cJSON_GetObjectItem(criteria, "sysfs");
            if (sysfs) {
                cJSON *path = cJSON_GetObjectItem(sysfs, "path");
                if (cJSON_IsString(path)) {
                    strncpy(detection->criteria.sysfs.path, path->valuestring,
                           sizeof(detection->criteria.sysfs.path) - 1);
                }

                cJSON *expected = cJSON_GetObjectItem(sysfs, "expected_value");
                if (cJSON_IsString(expected)) {
                    strncpy(detection->criteria.sysfs.expected_value, expected->valuestring,
                           sizeof(detection->criteria.sysfs.expected_value) - 1);
                }
            }
            break;
        }

        default:
            break;
    }

    return 0;
}

static int parse_metadata(cJSON *metadata_obj, pattern_metadata_t *metadata) {
    // Description
    cJSON *desc = cJSON_GetObjectItem(metadata_obj, "description");
    if (cJSON_IsString(desc)) {
        strncpy(metadata->description, desc->valuestring, sizeof(metadata->description) - 1);
    }

    // Technical details
    cJSON *tech = cJSON_GetObjectItem(metadata_obj, "technical_details");
    if (cJSON_IsString(tech)) {
        strncpy(metadata->technical_details, tech->valuestring, sizeof(metadata->technical_details) - 1);
    }

    // Remediation
    cJSON *remedy = cJSON_GetObjectItem(metadata_obj, "remediation");
    if (cJSON_IsString(remedy)) {
        strncpy(metadata->remediation, remedy->valuestring, sizeof(metadata->remediation) - 1);
    }

    // References array
    cJSON *refs = cJSON_GetObjectItem(metadata_obj, "references");
    if (cJSON_IsArray(refs)) {
        int count = cJSON_GetArraySize(refs);
        metadata->num_references = (count > MAX_REFERENCES) ? MAX_REFERENCES : count;

        for (int i = 0; i < metadata->num_references; i++) {
            cJSON *ref = cJSON_GetArrayItem(refs, i);
            if (cJSON_IsString(ref)) {
                strncpy(metadata->references[i], ref->valuestring, 511);
            }
        }
    }

    // Platforms array
    cJSON *platforms = cJSON_GetObjectItem(metadata_obj, "platforms");
    if (cJSON_IsArray(platforms)) {
        int count = cJSON_GetArraySize(platforms);
        metadata->num_platforms = (count > MAX_PLATFORMS) ? MAX_PLATFORMS : count;

        for (int i = 0; i < metadata->num_platforms; i++) {
            cJSON *platform = cJSON_GetArrayItem(platforms, i);
            if (cJSON_IsString(platform)) {
                strncpy(metadata->platforms[i], platform->valuestring, 255);
            }
        }
    }

    // Tags array
    cJSON *tags = cJSON_GetObjectItem(metadata_obj, "tags");
    if (cJSON_IsArray(tags)) {
        int count = cJSON_GetArraySize(tags);
        metadata->num_tags = (count > MAX_TAGS) ? MAX_TAGS : count;

        for (int i = 0; i < metadata->num_tags; i++) {
            cJSON *tag = cJSON_GetArrayItem(tags, i);
            if (cJSON_IsString(tag)) {
                strncpy(metadata->tags[i], tag->valuestring, 63);
            }
        }
    }

    // Discovered by
    cJSON *discovered = cJSON_GetObjectItem(metadata_obj, "discovered_by");
    if (cJSON_IsString(discovered)) {
        strncpy(metadata->discovered_by, discovered->valuestring, sizeof(metadata->discovered_by) - 1);
    }

    // Created at
    cJSON *created = cJSON_GetObjectItem(metadata_obj, "created_at");
    if (cJSON_IsString(created)) {
        strncpy(metadata->created_at, created->valuestring, sizeof(metadata->created_at) - 1);
    }

    // Updated at
    cJSON *updated = cJSON_GetObjectItem(metadata_obj, "updated_at");
    if (cJSON_IsString(updated)) {
        strncpy(metadata->updated_at, updated->valuestring, sizeof(metadata->updated_at) - 1);
    }

    return 0;
}

static char* read_file_to_string(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open file: %s (%s)\n", filename, strerror(errno));
        return NULL;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0 || size > 1024 * 1024) {  // Max 1MB for pattern files
        fprintf(stderr, "Invalid file size: %ld\n", size);
        fclose(fp);
        return NULL;
    }

    // Allocate and read
    char *buffer = malloc(size + 1);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, size, fp);
    buffer[read_size] = '\0';

    fclose(fp);
    return buffer;
}

static int scan_directory_recursive(const char *dirpath, pattern_db_t *db) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Failed to open directory: %s (%s)\n", dirpath, strerror(errno));
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Build full path
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);

        struct stat st;
        if (stat(fullpath, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            // Recurse into subdirectory
            scan_directory_recursive(fullpath, db);
        } else if (S_ISREG(st.st_mode)) {
            // Check if it's a .json file
            size_t len = strlen(entry->d_name);
            if (len > 5 && strcmp(entry->d_name + len - 5, ".json") == 0) {
                // Skip schema.json
                if (strcmp(entry->d_name, "schema.json") == 0) {
                    continue;
                }

                pattern_db_load_file(db, fullpath);
            }
        }
    }

    closedir(dir);
    return 0;
}
