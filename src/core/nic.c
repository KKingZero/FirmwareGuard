#include "nic.h"

#include <dirent.h>
#include <limits.h>

static bool path_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static int read_first_line(const char *path, char *buf, size_t size) {
    FILE *fp;

    if (!path || !buf || size == 0) {
        return FG_ERROR;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return FG_ERROR;
    }

    if (!fgets(buf, size, fp)) {
        fclose(fp);
        return FG_ERROR;
    }
    fclose(fp);
    buf[strcspn(buf, "\r\n")] = '\0';
    return FG_SUCCESS;
}

static void copy_string(char *dst, size_t dst_size, const char *src) {
    size_t len;

    if (!dst || dst_size == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }

    len = strnlen(src, dst_size - 1);
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static void read_link_name(const char *path, char *buf, size_t size) {
    char target[PATH_MAX];
    ssize_t len;
    char *base;

    if (!buf || size == 0) {
        return;
    }
    buf[0] = '\0';

    len = readlink(path, target, sizeof(target) - 1);
    if (len < 0) {
        return;
    }
    target[len] = '\0';
    base = strrchr(target, '/');
    copy_string(buf, size, base ? base + 1 : target);
}

static unsigned int parse_hex_id(const char *value) {
    unsigned int id = 0;

    if (!value || value[0] == '\0') {
        return 0;
    }

    if (sscanf(value, "0x%x", &id) != 1) {
        return 0;
    }

    return id;
}

static bool intel_amt_device_hint(const nic_info_t *nic) {
    unsigned int device_id;

    if (!nic || strcasecmp(nic->vendor, "0x8086") != 0) {
        return false;
    }

    device_id = parse_hex_id(nic->device);
    return (device_id >= 0x1502 && device_id <= 0x1533) ||
           (device_id >= 0x153a && device_id <= 0x153b);
}

int nic_scan(nic_scan_result_t *result) {
    DIR *dir;
    struct dirent *entry;

    if (!result) {
        return FG_ERROR;
    }

    memset(result, 0, sizeof(*result));

    dir = opendir("/sys/class/net");
    if (!dir) {
        return FG_NOT_FOUND;
    }

    while ((entry = readdir(dir)) != NULL && result->count < FG_MAX_NICS) {
        nic_info_t *nic;
        char path[PATH_MAX];
        char wake[32];

        if (entry->d_name[0] == '.' || strcmp(entry->d_name, "lo") == 0) {
            continue;
        }

        nic = &result->nics[result->count];
        memset(nic, 0, sizeof(*nic));
        copy_string(nic->name, sizeof(nic->name), entry->d_name);

        snprintf(path, sizeof(path), "/sys/class/net/%s/device/vendor", entry->d_name);
        read_first_line(path, nic->vendor, sizeof(nic->vendor));

        snprintf(path, sizeof(path), "/sys/class/net/%s/device/device", entry->d_name);
        read_first_line(path, nic->device, sizeof(nic->device));

        snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", entry->d_name);
        read_link_name(path, nic->driver, sizeof(nic->driver));

        snprintf(path, sizeof(path), "/sys/class/net/%s/device/power/wakeup", entry->d_name);
        if (read_first_line(path, wake, sizeof(wake)) == FG_SUCCESS) {
            nic->wake_on_lan = strcmp(wake, "enabled") == 0;
        }

        snprintf(path, sizeof(path), "/sys/class/net/%s/device/firmware_node", entry->d_name);
        nic->firmware_node = path_exists(path);

        nic->intel_amt_hint = intel_amt_device_hint(nic);

        result->count++;
    }

    closedir(dir);
    return FG_SUCCESS;
}

void nic_print_result(const nic_scan_result_t *result, bool verbose) {
    if (!result) {
        return;
    }

    printf("\n=== Network Interface Telemetry Scan ===\n");
    printf("Interfaces found: %d\n", result->count);

    for (int i = 0; i < result->count; i++) {
        const nic_info_t *nic = &result->nics[i];
        printf("\n  [%s]\n", nic->name);
        printf("    vendor:device : %s:%s\n", nic->vendor, nic->device);
        printf("    driver        : %s\n", nic->driver[0] ? nic->driver : "(unknown)");
        printf("    wake-on-lan   : %s\n", nic->wake_on_lan ? "enabled" : "disabled");
        printf("    firmware node : %s\n", nic->firmware_node ? "yes" : "no");
        if (nic->intel_amt_hint) {
            printf("    Intel AMT     : possible (device-ID hint)\n");
        } else if (verbose) {
            printf("    Intel AMT     : not indicated\n");
        }
    }
    printf("\n");
}

int nic_result_to_json(const nic_scan_result_t *result, char *buffer, size_t size) {
    if (!result || !buffer) {
        return FG_ERROR;
    }

    int written = snprintf(buffer, size,
        "{\n  \"count\": %d,\n  \"interfaces\": [", result->count);
    if (written < 0 || (size_t)written >= size) {
        return FG_ERROR;
    }

    for (int i = 0; i < result->count; i++) {
        const nic_info_t *nic = &result->nics[i];
        int n = snprintf(buffer + written, size - written,
            "%s\n    {\n"
            "      \"name\": \"%s\",\n"
            "      \"vendor\": \"%s\",\n"
            "      \"device\": \"%s\",\n"
            "      \"driver\": \"%s\",\n"
            "      \"wake_on_lan\": %s,\n"
            "      \"intel_amt_hint\": %s,\n"
            "      \"firmware_node\": %s\n"
            "    }",
            i == 0 ? "" : ",",
            nic->name, nic->vendor, nic->device, nic->driver,
            nic->wake_on_lan ? "true" : "false",
            nic->intel_amt_hint ? "true" : "false",
            nic->firmware_node ? "true" : "false");
        if (n < 0 || (size_t)(written + n) >= size) {
            return FG_ERROR;
        }
        written += n;
    }

    int n = snprintf(buffer + written, size - written,
                     "%s]\n}\n", result->count > 0 ? "\n  " : "");
    if (n < 0 || (size_t)(written + n) >= size) {
        return FG_ERROR;
    }

    return FG_SUCCESS;
}
