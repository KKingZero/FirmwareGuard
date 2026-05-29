#include "baseline_capture.h"
#include "msr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* Baseline format version */
#define BASELINE_VERSION 1

/* Risk level to string */
static const char* risk_level_to_str(risk_level_t level) {
    switch (level) {
        case RISK_CRITICAL: return "CRITICAL";
        case RISK_HIGH: return "HIGH";
        case RISK_MEDIUM: return "MEDIUM";
        case RISK_LOW: return "LOW";
        case RISK_NONE: return "NONE";
        default: return "UNKNOWN";
    }
}

/* Helper to compute simple hash (FNV-1a based) */
static void compute_hash(const uint8_t *data, size_t len, char *hex_out) {
    uint64_t h[4] = {0xcbf29ce484222325ULL, 0x84222325cbf29ce4ULL,
                     0xf29ce484222325cbULL, 0x222325cbf29ce484ULL};
    const uint64_t prime = 0x100000001b3ULL;

    for (size_t i = 0; i < len; i++) {
        int idx = i % 4;
        h[idx] ^= data[i];
        h[idx] *= prime;
    }

    snprintf(hex_out, 65, "%016llx%016llx%016llx%016llx",
             (unsigned long long)h[0], (unsigned long long)h[1],
             (unsigned long long)h[2], (unsigned long long)h[3]);
}

/* Read single-line sysfs/procfs value */
static int read_sysfs_value(const char *path, char *buf, size_t size) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    if (fgets(buf, size, fp)) {
        buf[strcspn(buf, "\n")] = 0;
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return -1;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

int baseline_init(void) {
    /* Initialize sub-modules */
    smm_detect_init();
    bootguard_init();
    txt_sgx_init();
    return FG_SUCCESS;
}

void baseline_cleanup(void) {
    smm_detect_cleanup();
    bootguard_cleanup();
    txt_sgx_cleanup();
}

/* ============================================================================
 * CPU Capture
 * ============================================================================ */

int baseline_capture_cpu(cpu_snapshot_t *cpu) {
    memset(cpu, 0, sizeof(cpu_snapshot_t));

    /* Read /proc/cpuinfo */
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) return FG_ERROR;

    char line[256];
    bool first_proc = true;

    while (fgets(line, sizeof(line), fp)) {
        if (!first_proc && strncmp(line, "processor", 9) == 0) {
            break;  /* Only read first CPU */
        }
        first_proc = false;

        if (strncmp(line, "vendor_id", 9) == 0) {
            char *val = strchr(line, ':');
            if (val) {
                val += 2;
                val[strcspn(val, "\n")] = 0;
                strncpy(cpu->vendor, val, sizeof(cpu->vendor) - 1);
            }
        } else if (strncmp(line, "model name", 10) == 0) {
            char *val = strchr(line, ':');
            if (val) {
                val += 2;
                val[strcspn(val, "\n")] = 0;
                strncpy(cpu->model_name, val, sizeof(cpu->model_name) - 1);
            }
        } else if (strncmp(line, "cpu family", 10) == 0) {
            char *val = strchr(line, ':');
            if (val) cpu->family = atoi(val + 2);
        } else if (strncmp(line, "model\t", 6) == 0) {
            char *val = strchr(line, ':');
            if (val) cpu->model = atoi(val + 2);
        } else if (strncmp(line, "stepping", 8) == 0) {
            char *val = strchr(line, ':');
            if (val) cpu->stepping = atoi(val + 2);
        } else if (strncmp(line, "microcode", 9) == 0) {
            char *val = strchr(line, ':');
            if (val) {
                val += 2;
                val[strcspn(val, "\n")] = 0;
                strncpy(cpu->microcode, val, sizeof(cpu->microcode) - 1);
            }
        }
    }
    fclose(fp);

    /* Count cores and threads */
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        int processors = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "processor", 9) == 0) {
                processors++;
            }
        }
        cpu->threads = processors;
        fclose(fp);
    }

    /* Read core count from sysfs */
    char buf[32];
    if (read_sysfs_value("/sys/devices/system/cpu/cpu0/topology/core_cpus_list", buf, sizeof(buf)) == 0 ||
        read_sysfs_value("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list", buf, sizeof(buf)) == 0) {
        /* Estimate cores from threads */
        cpu->cores = cpu->threads;  /* Simplified */
    }

    /* Check CPU features via CPUID */
    uint32_t eax, ebx, ecx, edx;

    /* Check VMX */
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1), "c"(0));
    cpu->vmx_enabled = (ecx & (1 << 5)) != 0;

    /* Check SMX */
    cpu->smx_enabled = (ecx & (1 << 6)) != 0;

    /* Check extended features for SGX */
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(7), "c"(0));
    cpu->sgx_enabled = (ebx & (1 << 2)) != 0;

    /* AMD SEV check */
    if (strstr(cpu->vendor, "AMD")) {
        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0x8000001F), "c"(0));
        cpu->sev_enabled = (eax & 0x2) != 0;
    }

    return FG_SUCCESS;
}

/* ============================================================================
 * DMI/SMBIOS Capture
 * ============================================================================ */

int baseline_capture_dmi(dmi_snapshot_t *dmi) {
    memset(dmi, 0, sizeof(dmi_snapshot_t));

    /* Read from /sys/class/dmi/id/ */
    read_sysfs_value("/sys/class/dmi/id/bios_vendor", dmi->bios_vendor, sizeof(dmi->bios_vendor));
    read_sysfs_value("/sys/class/dmi/id/bios_version", dmi->bios_version, sizeof(dmi->bios_version));
    read_sysfs_value("/sys/class/dmi/id/bios_date", dmi->bios_date, sizeof(dmi->bios_date));
    read_sysfs_value("/sys/class/dmi/id/sys_vendor", dmi->system_manufacturer, sizeof(dmi->system_manufacturer));
    read_sysfs_value("/sys/class/dmi/id/product_name", dmi->system_product, sizeof(dmi->system_product));
    read_sysfs_value("/sys/class/dmi/id/product_version", dmi->system_version, sizeof(dmi->system_version));
    read_sysfs_value("/sys/class/dmi/id/product_serial", dmi->system_serial, sizeof(dmi->system_serial));
    read_sysfs_value("/sys/class/dmi/id/product_uuid", dmi->system_uuid, sizeof(dmi->system_uuid));
    read_sysfs_value("/sys/class/dmi/id/board_vendor", dmi->board_manufacturer, sizeof(dmi->board_manufacturer));
    read_sysfs_value("/sys/class/dmi/id/board_name", dmi->board_product, sizeof(dmi->board_product));
    read_sysfs_value("/sys/class/dmi/id/board_version", dmi->board_version, sizeof(dmi->board_version));
    read_sysfs_value("/sys/class/dmi/id/board_serial", dmi->board_serial, sizeof(dmi->board_serial));
    read_sysfs_value("/sys/class/dmi/id/chassis_type", dmi->chassis_type, sizeof(dmi->chassis_type));
    read_sysfs_value("/sys/class/dmi/id/chassis_vendor", dmi->chassis_manufacturer, sizeof(dmi->chassis_manufacturer));

    return FG_SUCCESS;
}

/* ============================================================================
 * PCI Device Capture
 * ============================================================================ */

int baseline_capture_pci(baseline_snapshot_t *snapshot) {
    DIR *dir = opendir("/sys/bus/pci/devices");
    if (!dir) return FG_ERROR;

    snapshot->pci_device_count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) && snapshot->pci_device_count < MAX_PCI_DEVICES) {
        if (entry->d_name[0] == '.') continue;

        pci_device_snapshot_t *dev = &snapshot->pci_devices[snapshot->pci_device_count];
        memset(dev, 0, sizeof(pci_device_snapshot_t));

        strncpy(dev->bdf, entry->d_name, sizeof(dev->bdf) - 1);

        char path[512];
        char buf[256];

        /* Vendor ID */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", entry->d_name);
        if (read_sysfs_value(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "0x%hx", &dev->vendor_id);
        }

        /* Device ID */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device", entry->d_name);
        if (read_sysfs_value(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "0x%hx", &dev->device_id);
        }

        /* Subsystem vendor */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/subsystem_vendor", entry->d_name);
        if (read_sysfs_value(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "0x%hx", &dev->subsystem_vendor);
        }

        /* Subsystem device */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/subsystem_device", entry->d_name);
        if (read_sysfs_value(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "0x%hx", &dev->subsystem_device);
        }

        /* Class */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/class", entry->d_name);
        if (read_sysfs_value(path, buf, sizeof(buf)) == 0) {
            uint32_t class_code;
            sscanf(buf, "0x%x", &class_code);
            dev->class_code = (class_code >> 16) & 0xFF;
            dev->subclass = (class_code >> 8) & 0xFF;
            dev->prog_if = class_code & 0xFF;
        }

        /* Driver */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/driver", entry->d_name);
        char driver_link[256];
        ssize_t len = readlink(path, driver_link, sizeof(driver_link) - 1);
        if (len > 0) {
            driver_link[len] = '\0';
            char *drv = strrchr(driver_link, '/');
            if (drv) strncpy(dev->driver, drv + 1, sizeof(dev->driver) - 1);
        }

        snapshot->pci_device_count++;
    }

    closedir(dir);
    return FG_SUCCESS;
}

/* ============================================================================
 * USB Device Capture
 * ============================================================================ */

int baseline_capture_usb(baseline_snapshot_t *snapshot) {
    DIR *dir = opendir("/sys/bus/usb/devices");
    if (!dir) return FG_ERROR;

    snapshot->usb_device_count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) && snapshot->usb_device_count < MAX_USB_DEVICES) {
        if (entry->d_name[0] == '.') continue;
        /* Skip interfaces (contain ':') */
        if (strchr(entry->d_name, ':')) continue;
        /* Skip root hubs (start with usb) */
        if (strncmp(entry->d_name, "usb", 3) == 0) continue;

        usb_device_snapshot_t *dev = &snapshot->usb_devices[snapshot->usb_device_count];
        memset(dev, 0, sizeof(usb_device_snapshot_t));

        strncpy(dev->bus_port, entry->d_name, sizeof(dev->bus_port) - 1);

        char path[512];
        char buf[256];

        /* Vendor ID */
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor", entry->d_name);
        if (read_sysfs_value(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "%hx", &dev->vendor_id);
        } else {
            continue;  /* Not a valid USB device */
        }

        /* Product ID */
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct", entry->d_name);
        if (read_sysfs_value(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "%hx", &dev->product_id);
        }

        /* Manufacturer */
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/manufacturer", entry->d_name);
        read_sysfs_value(path, dev->manufacturer, sizeof(dev->manufacturer));

        /* Product */
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/product", entry->d_name);
        read_sysfs_value(path, dev->product, sizeof(dev->product));

        /* Serial */
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/serial", entry->d_name);
        read_sysfs_value(path, dev->serial, sizeof(dev->serial));

        /* Device class */
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/bDeviceClass", entry->d_name);
        if (read_sysfs_value(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "%hhx", &dev->device_class);
        }

        snapshot->usb_device_count++;
    }

    closedir(dir);
    return FG_SUCCESS;
}

/* ============================================================================
 * ACPI Table Capture
 * ============================================================================ */

int baseline_capture_acpi(baseline_snapshot_t *snapshot) {
    DIR *dir = opendir("/sys/firmware/acpi/tables");
    if (!dir) return FG_ERROR;

    snapshot->acpi_table_count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) && snapshot->acpi_table_count < MAX_ACPI_TABLES) {
        if (entry->d_name[0] == '.') continue;
        if (entry->d_type == DT_DIR) continue;

        acpi_table_snapshot_t *tbl = &snapshot->acpi_tables[snapshot->acpi_table_count];
        memset(tbl, 0, sizeof(acpi_table_snapshot_t));

        strncpy(tbl->signature, entry->d_name, 4);

        char path[512];
        snprintf(path, sizeof(path), "/sys/firmware/acpi/tables/%s", entry->d_name);

        struct stat st;
        if (stat(path, &st) == 0) {
            tbl->length = st.st_size;

            /* Read table and compute hash */
            FILE *fp = fopen(path, "rb");
            if (fp) {
                uint8_t *data = malloc(st.st_size);
                if (data) {
                    size_t read = fread(data, 1, st.st_size, fp);
                    if (read > 0) {
                        /* Parse ACPI header if large enough */
                        if (read >= 36) {
                            tbl->revision = data[8];
                            tbl->checksum = data[9];
                            memcpy(tbl->oem_id, &data[10], 6);
                            memcpy(tbl->oem_table_id, &data[16], 8);
                            memcpy(&tbl->oem_revision, &data[24], 4);
                        }
                        compute_hash(data, read, tbl->hash_hex);
                    }
                    free(data);
                }
                fclose(fp);
            }
        }

        snapshot->acpi_table_count++;
    }

    closedir(dir);
    return FG_SUCCESS;
}

/* ============================================================================
 * Kernel Module Capture
 * ============================================================================ */

int baseline_capture_modules(baseline_snapshot_t *snapshot) {
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) return FG_ERROR;

    snapshot->module_count = 0;
    char line[512];

    while (fgets(line, sizeof(line), fp) && snapshot->module_count < MAX_DRIVERS) {
        kernel_module_snapshot_t *mod = &snapshot->modules[snapshot->module_count];
        memset(mod, 0, sizeof(kernel_module_snapshot_t));

        char deps[256] = "";
        int ret = sscanf(line, "%63s %zu %d %255s",
                        mod->name, &mod->size, &mod->num_instances, deps);

        if (ret >= 3) {
            if (deps[0] && strcmp(deps, "-") != 0) {
                strncpy(mod->dependencies, deps, sizeof(mod->dependencies) - 1);
            }

            /* Check if tainted */
            if (strstr(line, "(T)") || strstr(line, "(O)") || strstr(line, "(E)")) {
                mod->tainted = true;
            }

            snapshot->module_count++;
        }
    }

    fclose(fp);
    return FG_SUCCESS;
}

/* ============================================================================
 * Boot Configuration Capture
 * ============================================================================ */

int baseline_capture_boot(baseline_snapshot_t *snapshot) {
    memset(snapshot->kernel_cmdline, 0, sizeof(snapshot->kernel_cmdline));
    snapshot->boot_entry_count = 0;

    /* Read kernel command line */
    read_sysfs_value("/proc/cmdline", snapshot->kernel_cmdline, sizeof(snapshot->kernel_cmdline));

    /* Detect bootloader type */
    if (access("/sys/firmware/efi", F_OK) == 0) {
        strncpy(snapshot->bootloader_type, "UEFI", sizeof(snapshot->bootloader_type) - 1);

        /* Read boot entries from efibootmgr output - skip if not available */
        FILE *fp = popen("efibootmgr 2>/dev/null", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp) && snapshot->boot_entry_count < MAX_BOOT_ENTRIES) {
                if (strncmp(line, "Boot", 4) == 0 && line[4] != 'O' && line[4] != 'C') {
                    boot_entry_snapshot_t *entry = &snapshot->boot_entries[snapshot->boot_entry_count];
                    memset(entry, 0, sizeof(boot_entry_snapshot_t));

                    /* Parse: Boot0000* Ubuntu */
                    int num;
                    char label[128];
                    if (sscanf(line, "Boot%04X%*c %127[^\n]", &num, label) >= 1) {
                        entry->entry_num = num;
                        strncpy(entry->label, label, sizeof(entry->label) - 1);
                        entry->is_active = (line[8] == '*');
                        snapshot->boot_entry_count++;
                    }
                }
            }
            pclose(fp);
        }
    } else {
        strncpy(snapshot->bootloader_type, "Legacy BIOS", sizeof(snapshot->bootloader_type) - 1);
    }

    return FG_SUCCESS;
}

/* ============================================================================
 * Memory Map Capture
 * ============================================================================ */

int baseline_capture_memory(baseline_snapshot_t *snapshot) {
    snapshot->memory_region_count = 0;
    snapshot->total_memory = 0;

    /* Read meminfo for total memory */
    FILE *fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                sscanf(line + 9, "%lu", (unsigned long *)&snapshot->total_memory);
                snapshot->total_memory *= 1024;  /* Convert to bytes */
                break;
            }
        }
        fclose(fp);
    }

    /* Read E820 memory map from iomem */
    fp = fopen("/proc/iomem", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) && snapshot->memory_region_count < 64) {
            /* Only top-level regions */
            if (line[0] != ' ') {
                memory_region_t *reg = &snapshot->memory_regions[snapshot->memory_region_count];
                memset(reg, 0, sizeof(memory_region_t));

                uint64_t start, end;
                char desc[128];
                if (sscanf(line, "%lx-%lx : %127[^\n]",
                          (unsigned long *)&start, (unsigned long *)&end, desc) == 3) {
                    reg->start = start;
                    reg->end = end;
                    strncpy(reg->description, desc, sizeof(reg->description) - 1);

                    /* Classify type */
                    if (strstr(desc, "RAM") || strstr(desc, "System RAM")) {
                        strncpy(reg->type, "RAM", sizeof(reg->type) - 1);
                    } else if (strstr(desc, "reserved")) {
                        strncpy(reg->type, "Reserved", sizeof(reg->type) - 1);
                    } else if (strstr(desc, "ACPI")) {
                        strncpy(reg->type, "ACPI", sizeof(reg->type) - 1);
                    } else {
                        strncpy(reg->type, "Other", sizeof(reg->type) - 1);
                    }

                    snapshot->memory_region_count++;
                }
            }
        }
        fclose(fp);
    }

    return FG_SUCCESS;
}

/* ============================================================================
 * Security Feature Capture
 * ============================================================================ */

int baseline_capture_security(baseline_snapshot_t *snapshot) {
    /* SMM scan */
    if (smm_scan(&snapshot->smm) == FG_SUCCESS) {
        snapshot->smm_captured = true;
    }

    /* Boot Guard status */
    if (bootguard_scan_status(&snapshot->bootguard) == FG_SUCCESS) {
        snapshot->bootguard_captured = true;
    }

    /* TXT configuration */
    if (txt_scan_config(&snapshot->txt) == FG_SUCCESS) {
        snapshot->txt_captured = true;
    }

    /* SGX enumeration */
    if (sgx_scan_config(&snapshot->sgx) == FG_SUCCESS) {
        snapshot->sgx_captured = true;
    }

    /* TPM measurements */
    if (tpm_scan_measurements(&snapshot->tpm) == FG_SUCCESS) {
        snapshot->tpm_captured = true;
    }

    /* Check UEFI/Secure Boot */
    if (access("/sys/firmware/efi", F_OK) == 0) {
        snapshot->uefi_available = true;

        char buf[16];
        if (read_sysfs_value("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                             buf, sizeof(buf)) == 0) {
            /* Simplified check - actually need to read binary */
            snapshot->secure_boot_enabled = true;
        }
    }

    return FG_SUCCESS;
}

/* ============================================================================
 * Full Baseline Capture
 * ============================================================================ */

int baseline_capture(baseline_snapshot_t *snapshot) {
    memset(snapshot, 0, sizeof(baseline_snapshot_t));

    /* Metadata */
    snapshot->version = BASELINE_VERSION;
    snapshot->capture_time = time(NULL);
    strftime(snapshot->capture_time_str, sizeof(snapshot->capture_time_str),
             "%Y-%m-%d %H:%M:%S", localtime(&snapshot->capture_time));

    /* Generate baseline ID */
    snprintf(snapshot->baseline_id, sizeof(snapshot->baseline_id),
             "BL-%ld-%d", snapshot->capture_time, getpid());

    /* Hostname */
    gethostname(snapshot->hostname, sizeof(snapshot->hostname) - 1);

    FG_INFO("Capturing baseline snapshot...");

    /* CPU information */
    FG_INFO("  Capturing CPU information...");
    baseline_capture_cpu(&snapshot->cpu);

    /* DMI/SMBIOS */
    FG_INFO("  Capturing DMI/SMBIOS...");
    baseline_capture_dmi(&snapshot->dmi);

    /* PCI devices */
    FG_INFO("  Capturing PCI devices...");
    baseline_capture_pci(snapshot);

    /* USB devices */
    FG_INFO("  Capturing USB devices...");
    baseline_capture_usb(snapshot);

    /* ACPI tables */
    FG_INFO("  Capturing ACPI tables...");
    baseline_capture_acpi(snapshot);

    /* Kernel modules */
    FG_INFO("  Capturing kernel modules...");
    baseline_capture_modules(snapshot);

    /* Boot configuration */
    FG_INFO("  Capturing boot configuration...");
    baseline_capture_boot(snapshot);

    /* Memory map */
    FG_INFO("  Capturing memory map...");
    baseline_capture_memory(snapshot);

    /* Security features */
    FG_INFO("  Capturing security features...");
    baseline_capture_security(snapshot);

    /* Compute baseline hash */
    baseline_compute_hash(snapshot);

    /* Generate summary */
    snprintf(snapshot->summary, sizeof(snapshot->summary),
             "Baseline captured at %s\n"
             "Host: %s\n"
             "CPU: %s\n"
             "PCI Devices: %d\n"
             "USB Devices: %d\n"
             "ACPI Tables: %d\n"
             "Kernel Modules: %d\n"
             "Total Memory: %lu MB\n"
             "Secure Boot: %s\n"
             "Boot Guard: %s\n"
             "TXT: %s\n"
             "SGX: %s",
             snapshot->capture_time_str,
             snapshot->hostname,
             snapshot->cpu.model_name,
             snapshot->pci_device_count,
             snapshot->usb_device_count,
             snapshot->acpi_table_count,
             snapshot->module_count,
             (unsigned long)(snapshot->total_memory / (1024*1024)),
             snapshot->secure_boot_enabled ? "Enabled" : "Disabled",
             snapshot->bootguard_captured && snapshot->bootguard.bootguard_capable ? "Supported" : "N/A",
             snapshot->txt_captured && snapshot->txt.txt_supported ? "Supported" : "N/A",
             snapshot->sgx_captured && snapshot->sgx.sgx_supported ? "Supported" : "N/A");

    FG_INFO("Baseline capture complete: %s", snapshot->baseline_id);

    return FG_SUCCESS;
}

/* ============================================================================
 * Baseline Hash Computation
 * ============================================================================ */

int baseline_compute_hash(baseline_snapshot_t *snapshot) {
    /* Hash key system data for integrity verification */
    char hash_data[8192];
    int len = 0;

    /* Include critical data in hash */
    len += snprintf(hash_data + len, sizeof(hash_data) - len,
                   "%s|%s|%s|%d|%d|%d|%d",
                   snapshot->cpu.vendor,
                   snapshot->cpu.model_name,
                   snapshot->dmi.bios_version,
                   snapshot->pci_device_count,
                   snapshot->usb_device_count,
                   snapshot->acpi_table_count,
                   snapshot->module_count);

    /* Include all PCI device IDs */
    for (int i = 0; i < snapshot->pci_device_count && len < (int)sizeof(hash_data) - 64; i++) {
        len += snprintf(hash_data + len, sizeof(hash_data) - len,
                       "|%04x:%04x",
                       snapshot->pci_devices[i].vendor_id,
                       snapshot->pci_devices[i].device_id);
    }

    /* Include ACPI table hashes */
    for (int i = 0; i < snapshot->acpi_table_count && len < (int)sizeof(hash_data) - 80; i++) {
        len += snprintf(hash_data + len, sizeof(hash_data) - len,
                       "|%s:%s",
                       snapshot->acpi_tables[i].signature,
                       snapshot->acpi_tables[i].hash_hex);
    }

    compute_hash((uint8_t *)hash_data, len, snapshot->baseline_hash);

    return FG_SUCCESS;
}

/* ============================================================================
 * Baseline Save/Load
 * ============================================================================ */

int baseline_save(const baseline_snapshot_t *snapshot, const char *filepath) {
    FILE *fp = fopen(filepath, "wb");
    if (!fp) {
        FG_LOG_ERROR("Failed to open baseline file for writing: %s", filepath);
        return FG_ERROR;
    }

    /* Write magic and version */
    const char magic[] = "FWGBASE";
    fwrite(magic, 1, 7, fp);
    fwrite(&snapshot->version, sizeof(uint32_t), 1, fp);

    /* Write snapshot */
    fwrite(snapshot, sizeof(baseline_snapshot_t), 1, fp);

    fclose(fp);
    FG_INFO("Baseline saved to: %s", filepath);

    return FG_SUCCESS;
}

int baseline_load(const char *filepath, baseline_snapshot_t *snapshot) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        FG_LOG_ERROR("Failed to open baseline file: %s", filepath);
        return FG_NOT_FOUND;
    }

    /* Verify magic */
    char magic[8];
    if (fread(magic, 1, 7, fp) != 7 || memcmp(magic, "FWGBASE", 7) != 0) {
        FG_LOG_ERROR("Invalid baseline file format");
        fclose(fp);
        return FG_ERROR;
    }

    /* Read version */
    uint32_t version;
    if (fread(&version, sizeof(uint32_t), 1, fp) != 1) {
        fclose(fp);
        return FG_ERROR;
    }

    if (version != BASELINE_VERSION) {
        FG_WARN("Baseline version mismatch (file: %u, expected: %u)", version, BASELINE_VERSION);
    }

    /* Read snapshot */
    if (fread(snapshot, sizeof(baseline_snapshot_t), 1, fp) != 1) {
        FG_LOG_ERROR("Failed to read baseline data");
        fclose(fp);
        return FG_ERROR;
    }

    fclose(fp);
    FG_INFO("Baseline loaded: %s (captured %s)", snapshot->baseline_id, snapshot->capture_time_str);

    return FG_SUCCESS;
}

/* ============================================================================
 * Baseline Comparison
 * ============================================================================ */

static void add_change(baseline_comparison_t *result, const char *type,
                       const char *category, const char *desc,
                       const char *old_val, const char *new_val,
                       risk_level_t severity) {
    if (result->change_count >= 256) return;

    baseline_change_t *change = &result->changes[result->change_count];
    strncpy(change->change_type, type, sizeof(change->change_type) - 1);
    strncpy(change->category, category, sizeof(change->category) - 1);
    strncpy(change->description, desc, sizeof(change->description) - 1);
    if (old_val) strncpy(change->old_value, old_val, sizeof(change->old_value) - 1);
    if (new_val) strncpy(change->new_value, new_val, sizeof(change->new_value) - 1);
    change->severity = severity;

    result->change_count++;

    if (severity < result->overall_risk) {
        result->overall_risk = severity;
    }
}

int baseline_compare(const baseline_snapshot_t *baseline,
                     const baseline_snapshot_t *current,
                     baseline_comparison_t *result) {
    memset(result, 0, sizeof(baseline_comparison_t));
    result->overall_risk = RISK_NONE;

    /* Compare PCI devices */
    for (int i = 0; i < current->pci_device_count; i++) {
        bool found = false;
        for (int j = 0; j < baseline->pci_device_count; j++) {
            if (strcmp(current->pci_devices[i].bdf, baseline->pci_devices[j].bdf) == 0) {
                found = true;
                /* Check if device changed */
                if (current->pci_devices[i].vendor_id != baseline->pci_devices[j].vendor_id ||
                    current->pci_devices[i].device_id != baseline->pci_devices[j].device_id) {
                    char desc[256];
                    snprintf(desc, sizeof(desc), "PCI device at %s changed identity",
                             current->pci_devices[i].bdf);
                    add_change(result, "MODIFIED", "PCI", desc, NULL, NULL, RISK_HIGH);
                }
                break;
            }
        }
        if (!found) {
            char desc[256];
            snprintf(desc, sizeof(desc), "New PCI device: %s (%04x:%04x)",
                     current->pci_devices[i].bdf,
                     current->pci_devices[i].vendor_id,
                     current->pci_devices[i].device_id);
            add_change(result, "ADDED", "PCI", desc, NULL, NULL, RISK_MEDIUM);
            result->pci_added++;
        }
    }

    for (int i = 0; i < baseline->pci_device_count; i++) {
        bool found = false;
        for (int j = 0; j < current->pci_device_count; j++) {
            if (strcmp(baseline->pci_devices[i].bdf, current->pci_devices[j].bdf) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            char desc[256];
            snprintf(desc, sizeof(desc), "PCI device removed: %s (%04x:%04x)",
                     baseline->pci_devices[i].bdf,
                     baseline->pci_devices[i].vendor_id,
                     baseline->pci_devices[i].device_id);
            add_change(result, "REMOVED", "PCI", desc, NULL, NULL, RISK_LOW);
            result->pci_removed++;
        }
    }

    /* Compare USB devices */
    for (int i = 0; i < current->usb_device_count; i++) {
        bool found = false;
        for (int j = 0; j < baseline->usb_device_count; j++) {
            if (current->usb_devices[i].vendor_id == baseline->usb_devices[j].vendor_id &&
                current->usb_devices[i].product_id == baseline->usb_devices[j].product_id) {
                found = true;
                break;
            }
        }
        if (!found) {
            char desc[256];
            snprintf(desc, sizeof(desc), "New USB device: %04x:%04x %s",
                     current->usb_devices[i].vendor_id,
                     current->usb_devices[i].product_id,
                     current->usb_devices[i].product);
            add_change(result, "ADDED", "USB", desc, NULL, NULL, RISK_MEDIUM);
            result->usb_added++;
        }
    }

    /* Compare ACPI tables */
    for (int i = 0; i < current->acpi_table_count; i++) {
        for (int j = 0; j < baseline->acpi_table_count; j++) {
            if (strcmp(current->acpi_tables[i].signature, baseline->acpi_tables[j].signature) == 0) {
                if (strcmp(current->acpi_tables[i].hash_hex, baseline->acpi_tables[j].hash_hex) != 0) {
                    char desc[256];
                    snprintf(desc, sizeof(desc), "ACPI table %s hash changed",
                             current->acpi_tables[i].signature);
                    add_change(result, "MODIFIED", "ACPI", desc,
                              baseline->acpi_tables[j].hash_hex,
                              current->acpi_tables[i].hash_hex, RISK_HIGH);
                    result->firmware_hash_changed = true;
                }
                break;
            }
        }
    }

    /* Compare kernel modules */
    for (int i = 0; i < current->module_count; i++) {
        bool found = false;
        for (int j = 0; j < baseline->module_count; j++) {
            if (strcmp(current->modules[i].name, baseline->modules[j].name) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            char desc[256];
            snprintf(desc, sizeof(desc), "New kernel module: %s%s",
                     current->modules[i].name,
                     current->modules[i].tainted ? " (TAINTED)" : "");
            risk_level_t risk = current->modules[i].tainted ? RISK_HIGH : RISK_MEDIUM;
            add_change(result, "ADDED", "Module", desc, NULL, NULL, risk);
            result->modules_added++;
        }
    }

    /* Compare security features */
    if (baseline->secure_boot_enabled != current->secure_boot_enabled) {
        add_change(result, "MODIFIED", "Security", "Secure Boot status changed",
                  baseline->secure_boot_enabled ? "Enabled" : "Disabled",
                  current->secure_boot_enabled ? "Enabled" : "Disabled",
                  RISK_CRITICAL);
        result->security_config_changed = true;
    }

    /* Compare BIOS version */
    if (strcmp(baseline->dmi.bios_version, current->dmi.bios_version) != 0) {
        add_change(result, "MODIFIED", "Firmware", "BIOS version changed",
                  baseline->dmi.bios_version, current->dmi.bios_version, RISK_MEDIUM);
        result->firmware_hash_changed = true;
    }

    /* Compare kernel command line */
    if (strcmp(baseline->kernel_cmdline, current->kernel_cmdline) != 0) {
        add_change(result, "MODIFIED", "Boot", "Kernel command line changed",
                  NULL, NULL, RISK_HIGH);
        result->boot_config_changed = true;
    }

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
             "Baseline Comparison Results\n"
             "Baseline: %s (captured %s)\n"
             "Current:  %s (captured %s)\n"
             "\n"
             "Changes Detected: %d\n"
             "  PCI Added: %d, Removed: %d\n"
             "  USB Added: %d, Removed: %d\n"
             "  Modules Added: %d, Removed: %d\n"
             "\n"
             "Security Config Changed: %s\n"
             "Firmware Hash Changed: %s\n"
             "Boot Config Changed: %s\n"
             "\n"
             "Overall Risk: %s",
             baseline->baseline_id, baseline->capture_time_str,
             current->baseline_id, current->capture_time_str,
             result->change_count,
             result->pci_added, result->pci_removed,
             result->usb_added, result->usb_removed,
             result->modules_added, result->modules_removed,
             result->security_config_changed ? "YES" : "No",
             result->firmware_hash_changed ? "YES" : "No",
             result->boot_config_changed ? "YES" : "No",
             risk_level_to_str(result->overall_risk));

    return FG_SUCCESS;
}

int baseline_compare_file(const char *baseline_path, baseline_comparison_t *result) {
    baseline_snapshot_t baseline;
    baseline_snapshot_t current;

    /* Load saved baseline */
    int ret = baseline_load(baseline_path, &baseline);
    if (ret != FG_SUCCESS) {
        return ret;
    }

    /* Capture current state */
    ret = baseline_capture(&current);
    if (ret != FG_SUCCESS) {
        return ret;
    }

    /* Compare */
    return baseline_compare(&baseline, &current, result);
}

/* ============================================================================
 * Output Functions
 * ============================================================================ */

void baseline_print_snapshot(const baseline_snapshot_t *snapshot, bool verbose) {
    printf("\n");
    printf("========================================\n");
    printf("  BASELINE SNAPSHOT\n");
    printf("========================================\n");
    printf("ID: %s\n", snapshot->baseline_id);
    printf("Captured: %s\n", snapshot->capture_time_str);
    printf("Host: %s\n", snapshot->hostname);
    printf("Hash: %s\n", snapshot->baseline_hash);
    printf("\n");

    printf("CPU Information:\n");
    printf("  Vendor: %s\n", snapshot->cpu.vendor);
    printf("  Model: %s\n", snapshot->cpu.model_name);
    printf("  Family/Model/Stepping: %u/%u/%u\n",
           snapshot->cpu.family, snapshot->cpu.model, snapshot->cpu.stepping);
    printf("  Microcode: %s\n", snapshot->cpu.microcode);
    printf("  Cores/Threads: %d/%d\n", snapshot->cpu.cores, snapshot->cpu.threads);
    printf("  VMX: %s, SMX: %s, SGX: %s\n",
           snapshot->cpu.vmx_enabled ? "Yes" : "No",
           snapshot->cpu.smx_enabled ? "Yes" : "No",
           snapshot->cpu.sgx_enabled ? "Yes" : "No");
    printf("\n");

    printf("System Information:\n");
    printf("  BIOS: %s %s (%s)\n",
           snapshot->dmi.bios_vendor, snapshot->dmi.bios_version, snapshot->dmi.bios_date);
    printf("  System: %s %s\n",
           snapshot->dmi.system_manufacturer, snapshot->dmi.system_product);
    printf("  Board: %s %s\n",
           snapshot->dmi.board_manufacturer, snapshot->dmi.board_product);
    printf("\n");

    printf("Hardware Summary:\n");
    printf("  PCI Devices: %d\n", snapshot->pci_device_count);
    printf("  USB Devices: %d\n", snapshot->usb_device_count);
    printf("  ACPI Tables: %d\n", snapshot->acpi_table_count);
    printf("  Kernel Modules: %d\n", snapshot->module_count);
    printf("  Memory: %lu MB\n", (unsigned long)(snapshot->total_memory / (1024*1024)));
    printf("\n");

    printf("Security Status:\n");
    printf("  UEFI: %s\n", snapshot->uefi_available ? "Yes" : "No");
    printf("  Secure Boot: %s\n", snapshot->secure_boot_enabled ? "Enabled" : "Disabled");
    printf("  Boot Guard: %s\n",
           snapshot->bootguard_captured && snapshot->bootguard.bootguard_capable ? "Supported" : "N/A");
    printf("  TXT: %s\n",
           snapshot->txt_captured && snapshot->txt.txt_supported ? "Supported" : "N/A");
    printf("  SGX: %s\n",
           snapshot->sgx_captured && snapshot->sgx.sgx_supported ? "Supported" : "N/A");
    printf("  TPM: %s\n",
           snapshot->tpm_captured && snapshot->tpm.tpm_present ? "Present" : "Not found");
    printf("\n");

    printf("Boot Configuration:\n");
    printf("  Bootloader: %s\n", snapshot->bootloader_type);
    printf("  Boot Entries: %d\n", snapshot->boot_entry_count);
    printf("\n");

    if (verbose) {
        printf("PCI Devices:\n");
        for (int i = 0; i < snapshot->pci_device_count; i++) {
            printf("  %s: %04x:%04x %s\n",
                   snapshot->pci_devices[i].bdf,
                   snapshot->pci_devices[i].vendor_id,
                   snapshot->pci_devices[i].device_id,
                   snapshot->pci_devices[i].driver);
        }
        printf("\n");

        printf("USB Devices:\n");
        for (int i = 0; i < snapshot->usb_device_count; i++) {
            printf("  %s: %04x:%04x %s\n",
                   snapshot->usb_devices[i].bus_port,
                   snapshot->usb_devices[i].vendor_id,
                   snapshot->usb_devices[i].product_id,
                   snapshot->usb_devices[i].product);
        }
        printf("\n");

        printf("ACPI Tables:\n");
        for (int i = 0; i < snapshot->acpi_table_count; i++) {
            printf("  %s: %u bytes, OEM: %s\n",
                   snapshot->acpi_tables[i].signature,
                   snapshot->acpi_tables[i].length,
                   snapshot->acpi_tables[i].oem_id);
        }
        printf("\n");
    }

    printf("========================================\n\n");
}

void baseline_print_comparison(const baseline_comparison_t *result, bool verbose) {
    printf("\n");
    printf("========================================\n");
    printf("  BASELINE COMPARISON\n");
    printf("========================================\n\n");

    printf("%s\n", result->summary);

    if (result->change_count > 0) {
        printf("\nDetailed Changes:\n");
        printf("----------------\n");
        for (int i = 0; i < result->change_count; i++) {
            const baseline_change_t *c = &result->changes[i];
            printf("[%s] %s: %s\n",
                   risk_level_to_str(c->severity),
                   c->change_type,
                   c->description);
            if (verbose && c->old_value[0]) {
                printf("    Old: %s\n", c->old_value);
                printf("    New: %s\n", c->new_value);
            }
        }
    }

    printf("\n========================================\n\n");
}

/* ============================================================================
 * JSON Export
 * ============================================================================ */

int baseline_to_json(const baseline_snapshot_t *snapshot, char *buffer, size_t size) {
    int len = 0;

    len += snprintf(buffer + len, size - len,
        "{\n"
        "  \"baseline_id\": \"%s\",\n"
        "  \"hostname\": \"%s\",\n"
        "  \"capture_time\": \"%s\",\n"
        "  \"version\": %u,\n"
        "  \"hash\": \"%s\",\n",
        snapshot->baseline_id,
        snapshot->hostname,
        snapshot->capture_time_str,
        snapshot->version,
        snapshot->baseline_hash);

    len += snprintf(buffer + len, size - len,
        "  \"cpu\": {\n"
        "    \"vendor\": \"%s\",\n"
        "    \"model\": \"%s\",\n"
        "    \"family\": %u,\n"
        "    \"stepping\": %u,\n"
        "    \"cores\": %d,\n"
        "    \"threads\": %d,\n"
        "    \"vmx\": %s,\n"
        "    \"smx\": %s,\n"
        "    \"sgx\": %s\n"
        "  },\n",
        snapshot->cpu.vendor,
        snapshot->cpu.model_name,
        snapshot->cpu.family,
        snapshot->cpu.stepping,
        snapshot->cpu.cores,
        snapshot->cpu.threads,
        snapshot->cpu.vmx_enabled ? "true" : "false",
        snapshot->cpu.smx_enabled ? "true" : "false",
        snapshot->cpu.sgx_enabled ? "true" : "false");

    len += snprintf(buffer + len, size - len,
        "  \"hardware_counts\": {\n"
        "    \"pci_devices\": %d,\n"
        "    \"usb_devices\": %d,\n"
        "    \"acpi_tables\": %d,\n"
        "    \"kernel_modules\": %d\n"
        "  },\n",
        snapshot->pci_device_count,
        snapshot->usb_device_count,
        snapshot->acpi_table_count,
        snapshot->module_count);

    len += snprintf(buffer + len, size - len,
        "  \"security\": {\n"
        "    \"uefi\": %s,\n"
        "    \"secure_boot\": %s,\n"
        "    \"boot_guard\": %s,\n"
        "    \"txt\": %s,\n"
        "    \"sgx\": %s,\n"
        "    \"tpm\": %s\n"
        "  }\n"
        "}\n",
        snapshot->uefi_available ? "true" : "false",
        snapshot->secure_boot_enabled ? "true" : "false",
        (snapshot->bootguard_captured && snapshot->bootguard.bootguard_capable) ? "true" : "false",
        (snapshot->txt_captured && snapshot->txt.txt_supported) ? "true" : "false",
        (snapshot->sgx_captured && snapshot->sgx.sgx_supported) ? "true" : "false",
        (snapshot->tpm_captured && snapshot->tpm.tpm_present) ? "true" : "false");

    return FG_SUCCESS;
}

int baseline_comparison_to_json(const baseline_comparison_t *result, char *buffer, size_t size) {
    int len = 0;

    len += snprintf(buffer + len, size - len,
        "{\n"
        "  \"change_count\": %d,\n"
        "  \"pci_added\": %d,\n"
        "  \"pci_removed\": %d,\n"
        "  \"usb_added\": %d,\n"
        "  \"usb_removed\": %d,\n"
        "  \"security_changed\": %s,\n"
        "  \"firmware_changed\": %s,\n"
        "  \"boot_changed\": %s,\n"
        "  \"risk_level\": \"%s\",\n"
        "  \"changes\": [\n",
        result->change_count,
        result->pci_added,
        result->pci_removed,
        result->usb_added,
        result->usb_removed,
        result->security_config_changed ? "true" : "false",
        result->firmware_hash_changed ? "true" : "false",
        result->boot_config_changed ? "true" : "false",
        risk_level_to_str(result->overall_risk));

    for (int i = 0; i < result->change_count && len < (int)size - 256; i++) {
        const baseline_change_t *c = &result->changes[i];
        len += snprintf(buffer + len, size - len,
            "    {\n"
            "      \"type\": \"%s\",\n"
            "      \"category\": \"%s\",\n"
            "      \"description\": \"%s\",\n"
            "      \"severity\": \"%s\"\n"
            "    }%s\n",
            c->change_type,
            c->category,
            c->description,
            risk_level_to_str(c->severity),
            (i < result->change_count - 1) ? "," : "");
    }

    len += snprintf(buffer + len, size - len, "  ]\n}\n");

    return FG_SUCCESS;
}
