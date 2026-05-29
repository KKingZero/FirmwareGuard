#include "me_psp.h"

#include <cpuid.h>
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

static bool pci_device_is_intel_mei(char *device_out, size_t device_out_size) {
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX];
    char value[64];
    char class_value[64];
    char driver[64];
    bool found = false;

    dir = opendir("/sys/bus/pci/devices");
    if (!dir) {
        return false;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", entry->d_name);
        if (read_first_line(path, value, sizeof(value)) != FG_SUCCESS) {
            continue;
        }

        if (strcasecmp(value, "0x8086") != 0) {
            continue;
        }

        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/class", entry->d_name);
        if (read_first_line(path, class_value, sizeof(class_value)) != FG_SUCCESS) {
            class_value[0] = '\0';
        }

        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/driver", entry->d_name);
        read_link_name(path, driver, sizeof(driver));

        if (strncmp(class_value, "0x0780", 6) == 0 || strstr(driver, "mei") != NULL) {
            if (device_out && device_out_size > 0) {
                snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device", entry->d_name);
                if (read_first_line(path, device_out, device_out_size) != FG_SUCCESS) {
                    snprintf(device_out, device_out_size, "unknown");
                }
            }
            found = true;
            break;
        }
    }

    closedir(dir);
    return found;
}

int probe_intel_me(intel_me_info_t *info) {
    if (!info) {
        return FG_ERROR;
    }

    memset(info, 0, sizeof(*info));
    snprintf(info->version, sizeof(info->version), "unknown");

    info->present = path_exists("/dev/mei0") ||
                    path_exists("/dev/mei/0") ||
                    pci_device_is_intel_mei(info->device_id, sizeof(info->device_id));
    info->active = info->present;

    if (path_exists("/sys/kernel/debug/mei/mei0/devstate")) {
        char state[128];
        if (read_first_line("/sys/kernel/debug/mei/mei0/devstate", state, sizeof(state)) == FG_SUCCESS) {
            snprintf(info->details, sizeof(info->details), "MEI devstate: %s", state);
        }
    }

    info->amt_present = path_exists("/dev/mei0") || path_exists("/dev/mei/0");
    info->hap_available = path_exists("/sys/firmware/efi/efivars");

    if (info->details[0] == '\0') {
        snprintf(info->details, sizeof(info->details),
                 info->present ? "Intel vendor/MEI surface detected" : "Intel ME surface not detected");
    }

    return info->present ? FG_SUCCESS : FG_NOT_FOUND;
}

int probe_amd_psp(amd_psp_info_t *info) {
    unsigned int eax, ebx, ecx, edx;

    if (!info) {
        return FG_ERROR;
    }

    memset(info, 0, sizeof(*info));
    snprintf(info->version, sizeof(info->version), "unknown");

#if defined(__x86_64__) || defined(__i386__)
    if (__get_cpuid_max(0x80000000, NULL) >= 0x8000001f) {
        __cpuid(0x8000001f, eax, ebx, ecx, edx);
        info->sev_supported = (eax & 0x2U) != 0;
    }
#else
    (void)eax;
    (void)ebx;
    (void)ecx;
    (void)edx;
#endif

    info->present = info->sev_supported || path_exists("/sys/module/ccp") ||
                    path_exists("/dev/sev");
    info->active = info->present;
    info->ftpm_hint = path_exists("/sys/class/tpm/tpm0");

    snprintf(info->details, sizeof(info->details),
             info->present ? "AMD PSP/SEV/CCP surface detected" : "AMD PSP surface not detected");

    return info->present ? FG_SUCCESS : FG_NOT_FOUND;
}

void intel_me_print(const intel_me_info_t *info, bool verbose) {
    if (!info) {
        return;
    }

    printf("\n=== Intel Management Engine (ME) ===\n");
    printf("Present:     %s\n", info->present ? "yes" : "no");
    printf("Active:      %s\n", info->active ? "yes" : "no");
    printf("AMT present: %s\n", info->amt_present ? "yes" : "no");
    printf("HAP avail:   %s\n", info->hap_available ? "yes" : "no");
    if (info->version[0]) {
        printf("Version:     %s\n", info->version);
    }
    if (info->device_id[0]) {
        printf("Device ID:   %s\n", info->device_id);
    }
    if (info->details[0] || verbose) {
        printf("Details:     %s\n", info->details);
    }
    printf("\n");
}

void amd_psp_print(const amd_psp_info_t *info, bool verbose) {
    if (!info) {
        return;
    }

    printf("\n=== AMD Platform Security Processor (PSP) ===\n");
    printf("Present:       %s\n", info->present ? "yes" : "no");
    printf("Active:        %s\n", info->active ? "yes" : "no");
    printf("SEV supported: %s\n", info->sev_supported ? "yes" : "no");
    printf("fTPM hint:     %s\n", info->ftpm_hint ? "yes" : "no");
    if (info->version[0]) {
        printf("Version:       %s\n", info->version);
    }
    if (info->details[0] || verbose) {
        printf("Details:       %s\n", info->details);
    }
    printf("\n");
}

int intel_me_to_json(const intel_me_info_t *info, char *buffer, size_t size) {
    if (!info || !buffer) {
        return FG_ERROR;
    }

    int n = snprintf(buffer, size,
        "{\n"
        "  \"present\": %s,\n"
        "  \"active\": %s,\n"
        "  \"amt_present\": %s,\n"
        "  \"hap_available\": %s,\n"
        "  \"version\": \"%s\",\n"
        "  \"device_id\": \"%s\",\n"
        "  \"details\": \"%s\"\n"
        "}\n",
        info->present ? "true" : "false",
        info->active ? "true" : "false",
        info->amt_present ? "true" : "false",
        info->hap_available ? "true" : "false",
        info->version, info->device_id, info->details);

    return (n < 0 || (size_t)n >= size) ? FG_ERROR : FG_SUCCESS;
}

int amd_psp_to_json(const amd_psp_info_t *info, char *buffer, size_t size) {
    if (!info || !buffer) {
        return FG_ERROR;
    }

    int n = snprintf(buffer, size,
        "{\n"
        "  \"present\": %s,\n"
        "  \"active\": %s,\n"
        "  \"sev_supported\": %s,\n"
        "  \"ftpm_hint\": %s,\n"
        "  \"version\": \"%s\",\n"
        "  \"details\": \"%s\"\n"
        "}\n",
        info->present ? "true" : "false",
        info->active ? "true" : "false",
        info->sev_supported ? "true" : "false",
        info->ftpm_hint ? "true" : "false",
        info->version, info->details);

    return (n < 0 || (size_t)n >= size) ? FG_ERROR : FG_SUCCESS;
}
