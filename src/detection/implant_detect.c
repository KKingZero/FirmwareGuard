#include "implant_detect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <glob.h>

/* Known suspicious/unusual PCI vendor IDs */
static const suspicious_pci_t g_suspicious_pci[] = {
    /* Known hardware implant patterns */
    {0x1234, 0xFFFF, "QEMU/KVM (virtual - check if expected)", RISK_LOW},
    {0x80EE, 0xFFFF, "VirtualBox (virtual - check if expected)", RISK_LOW},
    {0x15AD, 0xFFFF, "VMware (virtual - check if expected)", RISK_LOW},
    {0x1AF4, 0xFFFF, "Virtio (virtual - check if expected)", RISK_LOW},

    /* Unusual/rare vendors that could indicate custom hardware */
    {0x0001, 0xFFFF, "Unusual vendor ID 0x0001", RISK_MEDIUM},
    {0x0000, 0xFFFF, "Invalid vendor ID 0x0000", RISK_HIGH},
    {0xFFFF, 0xFFFF, "Invalid vendor ID 0xFFFF", RISK_HIGH},

    /* FPGA vendors often used in implants */
    {0x10EE, 0xFFFF, "Xilinx FPGA (verify if expected)", RISK_MEDIUM},
    {0x1172, 0xFFFF, "Altera/Intel FPGA (verify if expected)", RISK_MEDIUM},
    {0x1D0F, 0xFFFF, "AWS FPGA (verify if expected)", RISK_MEDIUM},

    /* FireWire (DMA attack vector) */
    {0x104C, 0x8023, "TI FireWire (DMA capable)", RISK_MEDIUM},
    {0x104C, 0x8024, "TI FireWire (DMA capable)", RISK_MEDIUM},

    /* Thunderbolt (DMA attack vector) */
    {0x8086, 0x1513, "Intel Thunderbolt (DMA capable)", RISK_LOW},
    {0x8086, 0x151A, "Intel Thunderbolt (DMA capable)", RISK_LOW},
    {0x8086, 0x151B, "Intel Thunderbolt (DMA capable)", RISK_LOW},

    {0, 0, NULL, RISK_NONE}  /* Sentinel */
};

/* Known suspicious/unusual USB patterns */
static const suspicious_usb_t g_suspicious_usb[] = {
    /* Invalid/unusual IDs */
    {0x0000, 0xFFFF, "Invalid USB vendor ID", RISK_HIGH},
    {0xFFFF, 0xFFFF, "Invalid USB vendor ID", RISK_HIGH},

    /* Known BadUSB/HID attack tools */
    {0x16C0, 0x27DD, "Teensy (potential BadUSB)", RISK_MEDIUM},
    {0x1B4F, 0xFFFF, "SparkFun (potential BadUSB)", RISK_LOW},
    {0x2341, 0xFFFF, "Arduino (potential BadUSB)", RISK_LOW},
    {0x1A86, 0x7523, "CH340 USB-Serial (potential BadUSB)", RISK_LOW},

    /* USB Rubber Ducky patterns */
    {0x05AC, 0x0221, "Apple keyboard (verify authenticity)", RISK_LOW},

    /* Generic HID with unusual patterns */
    {0x0483, 0x5740, "STM32 USB (potential implant)", RISK_MEDIUM},

    /* USB network adapters (potential data exfil) */
    {0x0B95, 0xFFFF, "ASIX USB Ethernet (verify if expected)", RISK_LOW},

    {0, 0, NULL, RISK_NONE}  /* Sentinel */
};

/* Risk to string helper */
static const char* risk_str(risk_level_t level) {
    switch (level) {
        case RISK_CRITICAL: return "CRITICAL";
        case RISK_HIGH: return "HIGH";
        case RISK_MEDIUM: return "MEDIUM";
        case RISK_LOW: return "LOW";
        case RISK_NONE: return "NONE";
        default: return "UNKNOWN";
    }
}

/* Category to string */
const char* implant_category_str(implant_category_t cat) {
    switch (cat) {
        case IMPLANT_CAT_PCI: return "PCI";
        case IMPLANT_CAT_USB: return "USB";
        case IMPLANT_CAT_FIRMWARE: return "Firmware";
        case IMPLANT_CAT_ACPI: return "ACPI";
        case IMPLANT_CAT_MEMORY: return "Memory";
        case IMPLANT_CAT_DMA: return "DMA";
        case IMPLANT_CAT_NETWORK: return "Network";
        default: return "Unknown";
    }
}

/* Read sysfs value helper */
static int read_sysfs(const char *path, char *buf, size_t size) {
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

/* Add finding */
static void add_finding(implant_scan_result_t *result,
                        implant_category_t category,
                        risk_level_t severity,
                        const char *title,
                        const char *description,
                        const char *evidence) {
    if (result->finding_count >= 128) return;

    implant_finding_t *f = &result->findings[result->finding_count];
    f->category = category;
    f->severity = severity;
    strncpy(f->title, title, sizeof(f->title) - 1);
    strncpy(f->description, description, sizeof(f->description) - 1);
    if (evidence) strncpy(f->evidence, evidence, sizeof(f->evidence) - 1);
    f->confirmed = false;

    result->finding_count++;

    if (severity < result->overall_risk ||
        (severity == RISK_CRITICAL && result->overall_risk != RISK_CRITICAL)) {
        result->overall_risk = severity;
    }
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

int implant_detect_init(void) {
    return FG_SUCCESS;
}

void implant_detect_cleanup(void) {
}

/* ============================================================================
 * Check suspicious devices
 * ============================================================================ */

bool is_suspicious_pci(uint16_t vendor, uint16_t device, const char **reason) {
    for (int i = 0; g_suspicious_pci[i].description; i++) {
        if (g_suspicious_pci[i].vendor_id == vendor) {
            if (g_suspicious_pci[i].device_id == 0xFFFF ||
                g_suspicious_pci[i].device_id == device) {
                if (reason) *reason = g_suspicious_pci[i].description;
                return true;
            }
        }
    }
    return false;
}

bool is_suspicious_usb(uint16_t vendor, uint16_t product, const char **reason) {
    for (int i = 0; g_suspicious_usb[i].description; i++) {
        if (g_suspicious_usb[i].vendor_id == vendor) {
            if (g_suspicious_usb[i].product_id == 0xFFFF ||
                g_suspicious_usb[i].product_id == product) {
                if (reason) *reason = g_suspicious_usb[i].description;
                return true;
            }
        }
    }
    return false;
}

/* ============================================================================
 * PCI Scan
 * ============================================================================ */

int implant_scan_pci(implant_scan_result_t *result) {
    DIR *dir = opendir("/sys/bus/pci/devices");
    if (!dir) return FG_ERROR;

    struct dirent *entry;

    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;

        char path[512];
        char buf[64];
        uint16_t vendor = 0, device = 0;

        /* Read vendor ID */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", entry->d_name);
        if (read_sysfs(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "0x%hx", &vendor);
        }

        /* Read device ID */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device", entry->d_name);
        if (read_sysfs(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "0x%hx", &device);
        }

        /* Check if suspicious */
        const char *reason;
        if (is_suspicious_pci(vendor, device, &reason)) {
            if (result->suspicious_pci_count < 32) {
                pci_device_snapshot_t *dev = &result->suspicious_pci[result->suspicious_pci_count].device;
                strncpy(dev->bdf, entry->d_name, sizeof(dev->bdf) - 1);
                dev->vendor_id = vendor;
                dev->device_id = device;

                strncpy(result->suspicious_pci[result->suspicious_pci_count].reason,
                        reason, 255);

                /* Find risk level */
                for (int i = 0; g_suspicious_pci[i].description; i++) {
                    if (g_suspicious_pci[i].vendor_id == vendor) {
                        result->suspicious_pci[result->suspicious_pci_count].risk = g_suspicious_pci[i].risk;
                        break;
                    }
                }

                result->suspicious_pci_count++;

                /* Add finding */
                char desc[512];
                snprintf(desc, sizeof(desc), "PCI device %s: %s (vendor=%04x, device=%04x)",
                         entry->d_name, reason, vendor, device);
                add_finding(result, IMPLANT_CAT_PCI, RISK_MEDIUM,
                           "Suspicious PCI Device", desc, entry->d_name);
            }
        }

        /* Check for hidden devices (class 0x000000) */
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/class", entry->d_name);
        if (read_sysfs(path, buf, sizeof(buf)) == 0) {
            uint32_t pci_class;
            sscanf(buf, "0x%x", &pci_class);
            if (pci_class == 0) {
                char desc[512];
                snprintf(desc, sizeof(desc), "PCI device %s has null class code (hidden device?)",
                         entry->d_name);
                add_finding(result, IMPLANT_CAT_PCI, RISK_HIGH,
                           "Hidden PCI Device", desc, entry->d_name);
            }
        }
    }

    closedir(dir);
    return FG_SUCCESS;
}

/* ============================================================================
 * USB Scan
 * ============================================================================ */

int implant_scan_usb(implant_scan_result_t *result) {
    DIR *dir = opendir("/sys/bus/usb/devices");
    if (!dir) return FG_ERROR;

    struct dirent *entry;

    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;
        if (strchr(entry->d_name, ':')) continue;  /* Skip interfaces */
        if (strncmp(entry->d_name, "usb", 3) == 0) continue;  /* Skip root hubs */

        char path[512];
        char buf[128];
        uint16_t vendor = 0, product = 0;

        /* Read vendor ID */
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor", entry->d_name);
        if (read_sysfs(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "%hx", &vendor);
        } else {
            continue;  /* Not a valid USB device */
        }

        /* Read product ID */
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct", entry->d_name);
        if (read_sysfs(path, buf, sizeof(buf)) == 0) {
            sscanf(buf, "%hx", &product);
        }

        /* Check if suspicious */
        const char *reason;
        if (is_suspicious_usb(vendor, product, &reason)) {
            if (result->suspicious_usb_count < 32) {
                usb_device_snapshot_t *dev = &result->suspicious_usb[result->suspicious_usb_count].device;
                strncpy(dev->bus_port, entry->d_name, sizeof(dev->bus_port) - 1);
                dev->vendor_id = vendor;
                dev->product_id = product;

                /* Read product name */
                snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/product", entry->d_name);
                read_sysfs(path, dev->product, sizeof(dev->product));

                strncpy(result->suspicious_usb[result->suspicious_usb_count].reason,
                        reason, 255);

                for (int i = 0; g_suspicious_usb[i].description; i++) {
                    if (g_suspicious_usb[i].vendor_id == vendor) {
                        result->suspicious_usb[result->suspicious_usb_count].risk = g_suspicious_usb[i].risk;
                        break;
                    }
                }

                result->suspicious_usb_count++;

                char desc[512];
                snprintf(desc, sizeof(desc), "USB device %s: %s (vendor=%04x, product=%04x)",
                         entry->d_name, reason, vendor, product);
                add_finding(result, IMPLANT_CAT_USB, RISK_MEDIUM,
                           "Suspicious USB Device", desc, entry->d_name);
            }
        }

        /* Check for HID devices (potential keystroke injection) */
        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/bDeviceClass", entry->d_name);
        if (read_sysfs(path, buf, sizeof(buf)) == 0) {
            int dev_class = strtol(buf, NULL, 16);
            if (dev_class == 0x03) {  /* HID class */
                /* Check if recently added (within last boot) */
                /* For now, just note it */
            }
        }
    }

    closedir(dir);
    return FG_SUCCESS;
}

/* ============================================================================
 * DMA/IOMMU Scan
 * ============================================================================ */

int implant_scan_dma(implant_scan_result_t *result) {
    /* Check IOMMU status */
    result->iommu.iommu_present = false;
    result->iommu.iommu_enabled = false;

    /* Check for Intel IOMMU */
    if (access("/sys/class/iommu", F_OK) == 0) {
        DIR *dir = opendir("/sys/class/iommu");
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir))) {
                if (entry->d_name[0] != '.') {
                    result->iommu.iommu_present = true;
                    if (strstr(entry->d_name, "dmar")) {
                        strncpy(result->iommu.iommu_type, "Intel VT-d", sizeof(result->iommu.iommu_type) - 1);
                    } else if (strstr(entry->d_name, "amd")) {
                        strncpy(result->iommu.iommu_type, "AMD-Vi", sizeof(result->iommu.iommu_type) - 1);
                    }
                    break;
                }
            }
            closedir(dir);
        }
    }

    /* Check kernel command line for iommu */
    char cmdline[1024] = {0};
    FILE *fp = fopen("/proc/cmdline", "r");
    if (fp) {
        if (fgets(cmdline, sizeof(cmdline), fp)) {
            if (strstr(cmdline, "intel_iommu=on") || strstr(cmdline, "amd_iommu=on") ||
                strstr(cmdline, "iommu=on")) {
                result->iommu.iommu_enabled = true;
            }
        }
        fclose(fp);
    }

    /* Scan for DMA-capable devices */
    DIR *dir = opendir("/sys/bus/pci/devices");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) && result->iommu.dma_device_count < 64) {
            if (entry->d_name[0] == '.') continue;

            char path[512];
            char buf[64];

            /* Check for DMA capability by looking at class */
            snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/class", entry->d_name);
            if (read_sysfs(path, buf, sizeof(buf)) == 0) {
                uint32_t pci_class;
                sscanf(buf, "0x%x", &pci_class);
                uint8_t base_class = (pci_class >> 16) & 0xFF;

                /* Classes that typically have DMA capability */
                bool dma_capable = false;
                const char *name = "Unknown";

                switch (base_class) {
                    case 0x01: name = "Storage Controller"; dma_capable = true; break;
                    case 0x02: name = "Network Controller"; dma_capable = true; break;
                    case 0x03: name = "Display Controller"; dma_capable = true; break;
                    case 0x04: name = "Multimedia Controller"; dma_capable = true; break;
                    case 0x0C:  /* Serial Bus */
                        if (((pci_class >> 8) & 0xFF) == 0x03) {  /* USB */
                            name = "USB Controller"; dma_capable = true;
                        } else if (((pci_class >> 8) & 0xFF) == 0x00) {  /* FireWire */
                            name = "FireWire Controller"; dma_capable = true;
                        }
                        break;
                }

                if (dma_capable) {
                    dma_device_t *dev = &result->iommu.dma_devices[result->iommu.dma_device_count];
                    strncpy(dev->name, name, sizeof(dev->name) - 1);
                    strncpy(dev->bdf, entry->d_name, sizeof(dev->bdf) - 1);
                    dev->dma_capable = true;

                    /* Read vendor/device */
                    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", entry->d_name);
                    if (read_sysfs(path, buf, sizeof(buf)) == 0) {
                        sscanf(buf, "0x%hx", &dev->vendor_id);
                    }
                    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device", entry->d_name);
                    if (read_sysfs(path, buf, sizeof(buf)) == 0) {
                        sscanf(buf, "0x%hx", &dev->device_id);
                    }

                    /* Check IOMMU group */
                    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/iommu_group", entry->d_name);
                    dev->iommu_protected = (access(path, F_OK) == 0);

                    if (!dev->iommu_protected) {
                        result->iommu.unprotected_count++;
                    }

                    result->iommu.dma_device_count++;
                }
            }
        }
        closedir(dir);
    }

    /* Add findings for IOMMU status */
    if (!result->iommu.iommu_present) {
        add_finding(result, IMPLANT_CAT_DMA, RISK_HIGH,
                   "No IOMMU Present",
                   "System lacks IOMMU/VT-d/AMD-Vi. DMA attacks are possible.",
                   NULL);
    } else if (!result->iommu.iommu_enabled) {
        add_finding(result, IMPLANT_CAT_DMA, RISK_MEDIUM,
                   "IOMMU Not Enabled",
                   "IOMMU is present but not enabled in kernel. Add intel_iommu=on or amd_iommu=on to kernel cmdline.",
                   NULL);
    }

    if (result->iommu.unprotected_count > 0) {
        char desc[256];
        snprintf(desc, sizeof(desc), "%d DMA-capable devices without IOMMU protection",
                 result->iommu.unprotected_count);
        add_finding(result, IMPLANT_CAT_DMA, RISK_MEDIUM,
                   "Unprotected DMA Devices", desc, NULL);
    }

    return FG_SUCCESS;
}

/* ============================================================================
 * Memory Scan
 * ============================================================================ */

int implant_scan_memory(implant_scan_result_t *result) {
    /* Scan /proc/iomem for unusual regions */
    FILE *fp = fopen("/proc/iomem", "r");
    if (!fp) return FG_ERROR;

    char line[256];
    while (fgets(line, sizeof(line), fp) && result->memory_anomaly_count < 32) {
        /* Only look at top-level entries */
        if (line[0] != ' ') {
            uint64_t start, end;
            char desc[128];

            if (sscanf(line, "%lx-%lx : %127[^\n]",
                      (unsigned long *)&start, (unsigned long *)&end, desc) == 3) {

                /* Check for suspicious reserved regions in low memory */
                if (start < 0x100000 && strstr(desc, "reserved")) {
                    /* Reserved region in first MB - could be SMM overlay */
                    if (result->memory_anomaly_count < 32) {
                        memory_anomaly_t *anom = &result->memory_anomalies[result->memory_anomaly_count];
                        anom->address = start;
                        anom->size = end - start + 1;
                        strncpy(anom->type, "Low Memory Reserved", sizeof(anom->type) - 1);
                        strncpy(anom->description, desc, sizeof(anom->description) - 1);
                        anom->suspicious = false;  /* Common, but worth noting */
                        result->memory_anomaly_count++;
                    }
                }

                /* Check for unusual memory-mapped device regions */
                if (strstr(desc, "PCI") && (end - start) > 0x10000000) {  /* > 256MB */
                    /* Large PCI BAR - could be GPU or FPGA */
                    if (result->memory_anomaly_count < 32) {
                        memory_anomaly_t *anom = &result->memory_anomalies[result->memory_anomaly_count];
                        anom->address = start;
                        anom->size = end - start + 1;
                        strncpy(anom->type, "Large PCI BAR", sizeof(anom->type) - 1);
                        snprintf(anom->description, sizeof(anom->description),
                                "%s (%.0f MB)", desc, (double)(end - start + 1) / (1024*1024));
                        anom->suspicious = false;
                        result->memory_anomaly_count++;
                    }
                }
            }
        }
    }

    fclose(fp);
    return FG_SUCCESS;
}

/* ============================================================================
 * Firmware Scan
 * ============================================================================ */

int implant_scan_firmware(implant_scan_result_t *result) {
    /* Check for suspicious ACPI tables */
    DIR *dir = opendir("/sys/firmware/acpi/tables");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (entry->d_name[0] == '.') continue;

            /* Look for unusual/unknown tables */
            const char *known_tables[] = {
                "APIC", "FACP", "FACS", "DSDT", "SSDT", "MCFG", "HPET",
                "DMAR", "BGRT", "FPDT", "UEFI", "MSDM", "SLIC", "IVRS",
                "TPM2", "TCPA", "WSMT", "BERT", "ERST", "EINJ", "ECDT",
                "SRAT", "SLIT", "PMTT", "MPST", "LPIT", "ASF!", "BOOT",
                "DBGP", "DBG2", "PCCT", "SBST", "CPEP", "WDRT", "WAET",
                NULL
            };

            bool is_known = false;
            for (int i = 0; known_tables[i]; i++) {
                if (strncmp(entry->d_name, known_tables[i], 4) == 0) {
                    is_known = true;
                    break;
                }
            }

            if (!is_known && strlen(entry->d_name) >= 4) {
                if (result->firmware_anomaly_count < 32) {
                    strncpy(result->firmware_anomalies[result->firmware_anomaly_count].type,
                            "Unknown ACPI Table", 63);
                    snprintf(result->firmware_anomalies[result->firmware_anomaly_count].description,
                             255, "Non-standard ACPI table: %s", entry->d_name);
                    result->firmware_anomalies[result->firmware_anomaly_count].risk = RISK_LOW;
                    result->firmware_anomaly_count++;

                    add_finding(result, IMPLANT_CAT_FIRMWARE, RISK_LOW,
                               "Unknown ACPI Table",
                               result->firmware_anomalies[result->firmware_anomaly_count - 1].description,
                               entry->d_name);
                }
            }
        }
        closedir(dir);
    }

    /* Check DMI for unusual entries */
    char buf[256];
    if (read_sysfs("/sys/class/dmi/id/bios_vendor", buf, sizeof(buf)) == 0) {
        /* Check for known OEM vendors vs suspicious */
        const char *known_vendors[] = {
            "American Megatrends", "AMI", "Phoenix", "Award", "Insyde",
            "Dell", "HP", "Lenovo", "ASUS", "Gigabyte", "MSI", "ASRock",
            "Intel", "Apple", "Microsoft", "VMware", "QEMU", "SeaBIOS",
            "coreboot", "Libreboot", "OVMF", "EDK II",
            NULL
        };

        bool is_known = false;
        for (int i = 0; known_vendors[i]; i++) {
            if (strstr(buf, known_vendors[i])) {
                is_known = true;
                break;
            }
        }

        if (!is_known && strlen(buf) > 0) {
            char desc[256];
            snprintf(desc, sizeof(desc), "Unknown BIOS vendor: %s", buf);
            add_finding(result, IMPLANT_CAT_FIRMWARE, RISK_MEDIUM,
                       "Unusual BIOS Vendor", desc, buf);
        }
    }

    return FG_SUCCESS;
}

/* ============================================================================
 * Full Scan
 * ============================================================================ */

int implant_full_scan(implant_scan_result_t *result) {
    memset(result, 0, sizeof(implant_scan_result_t));

    result->scan_time = time(NULL);
    strftime(result->scan_time_str, sizeof(result->scan_time_str),
             "%Y-%m-%d %H:%M:%S", localtime(&result->scan_time));
    gethostname(result->hostname, sizeof(result->hostname) - 1);
    result->overall_risk = RISK_NONE;

    FG_INFO("Starting hardware implant detection scan...");

    FG_INFO("  Scanning PCI devices...");
    implant_scan_pci(result);

    FG_INFO("  Scanning USB devices...");
    implant_scan_usb(result);

    FG_INFO("  Scanning DMA/IOMMU status...");
    implant_scan_dma(result);

    FG_INFO("  Scanning memory regions...");
    implant_scan_memory(result);

    FG_INFO("  Scanning firmware tables...");
    implant_scan_firmware(result);

    result->scan_complete = true;

    /* Generate summary */
    snprintf(result->summary, sizeof(result->summary),
             "Hardware Implant Detection Scan Complete\n"
             "Scanned at: %s\n"
             "Host: %s\n\n"
             "Findings: %d total\n"
             "  Suspicious PCI devices: %d\n"
             "  Suspicious USB devices: %d\n"
             "  DMA devices: %d (unprotected: %d)\n"
             "  Memory anomalies: %d\n"
             "  Firmware anomalies: %d\n\n"
             "IOMMU: %s (%s)\n"
             "Overall Risk: %s",
             result->scan_time_str,
             result->hostname,
             result->finding_count,
             result->suspicious_pci_count,
             result->suspicious_usb_count,
             result->iommu.dma_device_count, result->iommu.unprotected_count,
             result->memory_anomaly_count,
             result->firmware_anomaly_count,
             result->iommu.iommu_present ? "Present" : "Not found",
             result->iommu.iommu_enabled ? "Enabled" : "Disabled",
             risk_str(result->overall_risk));

    FG_INFO("Implant scan complete: %d findings, risk level: %s",
            result->finding_count, risk_str(result->overall_risk));

    return FG_SUCCESS;
}

/* ============================================================================
 * Output Functions
 * ============================================================================ */

void implant_print_result(const implant_scan_result_t *result, bool verbose) {
    printf("\n");
    printf("========================================\n");
    printf("  HARDWARE IMPLANT DETECTION SCAN\n");
    printf("========================================\n");
    printf("Scanned: %s\n", result->scan_time_str);
    printf("Host: %s\n", result->hostname);
    printf("\n");

    printf("IOMMU Status:\n");
    printf("  Present: %s\n", result->iommu.iommu_present ? "Yes" : "No");
    printf("  Enabled: %s\n", result->iommu.iommu_enabled ? "Yes" : "No");
    if (result->iommu.iommu_type[0]) {
        printf("  Type: %s\n", result->iommu.iommu_type);
    }
    printf("  DMA Devices: %d\n", result->iommu.dma_device_count);
    printf("  Unprotected: %d\n", result->iommu.unprotected_count);
    printf("\n");

    if (result->suspicious_pci_count > 0) {
        printf("Suspicious PCI Devices (%d):\n", result->suspicious_pci_count);
        for (int i = 0; i < result->suspicious_pci_count; i++) {
            printf("  [%s] %s: %04x:%04x\n",
                   risk_str(result->suspicious_pci[i].risk),
                   result->suspicious_pci[i].device.bdf,
                   result->suspicious_pci[i].device.vendor_id,
                   result->suspicious_pci[i].device.device_id);
            printf("       %s\n", result->suspicious_pci[i].reason);
        }
        printf("\n");
    }

    if (result->suspicious_usb_count > 0) {
        printf("Suspicious USB Devices (%d):\n", result->suspicious_usb_count);
        for (int i = 0; i < result->suspicious_usb_count; i++) {
            printf("  [%s] %s: %04x:%04x %s\n",
                   risk_str(result->suspicious_usb[i].risk),
                   result->suspicious_usb[i].device.bus_port,
                   result->suspicious_usb[i].device.vendor_id,
                   result->suspicious_usb[i].device.product_id,
                   result->suspicious_usb[i].device.product);
            printf("       %s\n", result->suspicious_usb[i].reason);
        }
        printf("\n");
    }

    if (result->finding_count > 0) {
        printf("All Findings (%d):\n", result->finding_count);
        for (int i = 0; i < result->finding_count; i++) {
            const implant_finding_t *f = &result->findings[i];
            printf("  [%s] [%s] %s\n",
                   risk_str(f->severity),
                   implant_category_str(f->category),
                   f->title);
            if (verbose) {
                printf("       %s\n", f->description);
            }
        }
        printf("\n");
    }

    if (verbose && result->iommu.dma_device_count > 0) {
        printf("DMA-Capable Devices:\n");
        for (int i = 0; i < result->iommu.dma_device_count; i++) {
            const dma_device_t *d = &result->iommu.dma_devices[i];
            printf("  %s %s: %04x:%04x %s\n",
                   d->iommu_protected ? "[Protected]" : "[EXPOSED]",
                   d->bdf, d->vendor_id, d->device_id, d->name);
        }
        printf("\n");
    }

    printf("Overall Risk: %s\n", risk_str(result->overall_risk));
    if (result->risk_reason[0]) {
        printf("  %s\n", result->risk_reason);
    }
    printf("\n========================================\n\n");
}

int implant_to_json(const implant_scan_result_t *result, char *buffer, size_t size) {
    int len = 0;

    len += snprintf(buffer + len, size - len,
        "{\n"
        "  \"scan_time\": \"%s\",\n"
        "  \"hostname\": \"%s\",\n"
        "  \"scan_complete\": %s,\n"
        "  \"overall_risk\": \"%s\",\n",
        result->scan_time_str,
        result->hostname,
        result->scan_complete ? "true" : "false",
        risk_str(result->overall_risk));

    len += snprintf(buffer + len, size - len,
        "  \"iommu\": {\n"
        "    \"present\": %s,\n"
        "    \"enabled\": %s,\n"
        "    \"type\": \"%s\",\n"
        "    \"dma_devices\": %d,\n"
        "    \"unprotected\": %d\n"
        "  },\n",
        result->iommu.iommu_present ? "true" : "false",
        result->iommu.iommu_enabled ? "true" : "false",
        result->iommu.iommu_type,
        result->iommu.dma_device_count,
        result->iommu.unprotected_count);

    len += snprintf(buffer + len, size - len,
        "  \"counts\": {\n"
        "    \"suspicious_pci\": %d,\n"
        "    \"suspicious_usb\": %d,\n"
        "    \"memory_anomalies\": %d,\n"
        "    \"firmware_anomalies\": %d,\n"
        "    \"total_findings\": %d\n"
        "  },\n",
        result->suspicious_pci_count,
        result->suspicious_usb_count,
        result->memory_anomaly_count,
        result->firmware_anomaly_count,
        result->finding_count);

    len += snprintf(buffer + len, size - len, "  \"findings\": [\n");
    for (int i = 0; i < result->finding_count && len < (int)size - 256; i++) {
        const implant_finding_t *f = &result->findings[i];
        len += snprintf(buffer + len, size - len,
            "    {\n"
            "      \"category\": \"%s\",\n"
            "      \"severity\": \"%s\",\n"
            "      \"title\": \"%s\"\n"
            "    }%s\n",
            implant_category_str(f->category),
            risk_str(f->severity),
            f->title,
            (i < result->finding_count - 1) ? "," : "");
    }
    len += snprintf(buffer + len, size - len, "  ]\n}\n");

    return FG_SUCCESS;
}
