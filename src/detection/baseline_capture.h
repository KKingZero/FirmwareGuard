#ifndef FG_BASELINE_CAPTURE_H
#define FG_BASELINE_CAPTURE_H

#include "../../include/firmwareguard.h"
#include "smm_detect.h"
#include "bootguard_detect.h"
#include "txt_sgx_detect.h"
#include "uefi_extract.h"
#include <time.h>

/* Maximum limits */
#define MAX_PCI_DEVICES 256
#define MAX_USB_DEVICES 128
#define MAX_ACPI_TABLES 64
#define MAX_DRIVERS 256
#define MAX_BOOT_ENTRIES 32
#define MAX_UEFI_VARS 512

/* PCI device snapshot */
typedef struct {
    char bdf[16];              /* Bus:Device.Function */
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsystem_vendor;
    uint16_t subsystem_device;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t prog_if;
    char driver[64];
    char vendor_name[128];
    char device_name[128];
} pci_device_snapshot_t;

/* USB device snapshot */
typedef struct {
    char bus_port[32];
    uint16_t vendor_id;
    uint16_t product_id;
    char manufacturer[128];
    char product[128];
    char serial[64];
    uint8_t device_class;
    char driver[64];
} usb_device_snapshot_t;

/* ACPI table snapshot */
typedef struct {
    char signature[5];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[7];
    char oem_table_id[9];
    uint32_t oem_revision;
    uint8_t hash[32];
    char hash_hex[65];
} acpi_table_snapshot_t;

/* Kernel module snapshot */
typedef struct {
    char name[64];
    size_t size;
    int num_instances;
    char dependencies[256];
    bool tainted;
} kernel_module_snapshot_t;

/* Boot entry snapshot */
typedef struct {
    int entry_num;
    char label[128];
    char path[256];
    bool is_current;
    bool is_active;
} boot_entry_snapshot_t;

/* Memory map region */
typedef struct {
    uint64_t start;
    uint64_t end;
    char type[32];
    char description[128];
} memory_region_t;

/* CPU information snapshot */
typedef struct {
    char vendor[16];
    char model_name[128];
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    char microcode[32];
    int cores;
    int threads;
    uint64_t features;       /* CPUID feature flags */
    bool vmx_enabled;
    bool smx_enabled;
    bool sgx_enabled;
    bool sev_enabled;        /* AMD SEV */
} cpu_snapshot_t;

/* DMI/SMBIOS snapshot */
typedef struct {
    char bios_vendor[64];
    char bios_version[64];
    char bios_date[32];
    char system_manufacturer[64];
    char system_product[128];
    char system_version[64];
    char system_serial[64];
    char system_uuid[48];
    char board_manufacturer[64];
    char board_product[128];
    char board_version[64];
    char board_serial[64];
    char chassis_type[32];
    char chassis_manufacturer[64];
} dmi_snapshot_t;

/* Full baseline snapshot */
typedef struct {
    /* Metadata */
    char baseline_id[64];
    char hostname[64];
    time_t capture_time;
    char capture_time_str[32];
    uint32_t version;

    /* CPU information */
    cpu_snapshot_t cpu;

    /* DMI/SMBIOS */
    dmi_snapshot_t dmi;

    /* PCI devices */
    int pci_device_count;
    pci_device_snapshot_t pci_devices[MAX_PCI_DEVICES];

    /* USB devices */
    int usb_device_count;
    usb_device_snapshot_t usb_devices[MAX_USB_DEVICES];

    /* ACPI tables */
    int acpi_table_count;
    acpi_table_snapshot_t acpi_tables[MAX_ACPI_TABLES];

    /* Kernel modules */
    int module_count;
    kernel_module_snapshot_t modules[MAX_DRIVERS];

    /* Boot configuration */
    int boot_entry_count;
    boot_entry_snapshot_t boot_entries[MAX_BOOT_ENTRIES];
    char bootloader_type[32];
    char kernel_cmdline[1024];

    /* UEFI variables (key security vars) */
    bool uefi_available;
    bool secure_boot_enabled;
    bool setup_mode;
    int uefi_var_count;

    /* Security features */
    smm_scan_result_t smm;
    bootguard_status_t bootguard;
    txt_config_t txt;
    sgx_config_t sgx;
    tpm_measurement_t tpm;

    bool smm_captured;
    bool bootguard_captured;
    bool txt_captured;
    bool sgx_captured;
    bool tpm_captured;

    /* Memory map */
    int memory_region_count;
    memory_region_t memory_regions[64];
    uint64_t total_memory;

    /* Firmware hashes */
    bool spi_flash_captured;
    char spi_flash_hash[65];
    uint64_t spi_flash_size;

    /* Integrity */
    char baseline_hash[65];  /* Hash of entire baseline */

    /* Summary */
    char summary[2048];
} baseline_snapshot_t;

/* Comparison result */
typedef struct {
    char change_type[32];
    char category[64];
    char description[512];
    char old_value[256];
    char new_value[256];
    risk_level_t severity;
} baseline_change_t;

/* Baseline comparison result */
typedef struct {
    baseline_snapshot_t *baseline;
    baseline_snapshot_t *current;

    int change_count;
    baseline_change_t changes[256];

    int pci_added;
    int pci_removed;
    int usb_added;
    int usb_removed;
    int modules_added;
    int modules_removed;

    bool security_config_changed;
    bool firmware_hash_changed;
    bool boot_config_changed;

    risk_level_t overall_risk;
    char risk_reason[512];
    char summary[2048];
} baseline_comparison_t;

/* Initialize baseline capture subsystem */
int baseline_init(void);
void baseline_cleanup(void);

/* Capture current system state */
int baseline_capture(baseline_snapshot_t *snapshot);

/* Save/load baseline to/from file */
int baseline_save(const baseline_snapshot_t *snapshot, const char *filepath);
int baseline_load(const char *filepath, baseline_snapshot_t *snapshot);

/* Compare baselines */
int baseline_compare(const baseline_snapshot_t *baseline,
                     const baseline_snapshot_t *current,
                     baseline_comparison_t *result);

/* Compare against saved baseline file */
int baseline_compare_file(const char *baseline_path,
                          baseline_comparison_t *result);

/* Individual capture functions */
int baseline_capture_cpu(cpu_snapshot_t *cpu);
int baseline_capture_dmi(dmi_snapshot_t *dmi);
int baseline_capture_pci(baseline_snapshot_t *snapshot);
int baseline_capture_usb(baseline_snapshot_t *snapshot);
int baseline_capture_acpi(baseline_snapshot_t *snapshot);
int baseline_capture_modules(baseline_snapshot_t *snapshot);
int baseline_capture_boot(baseline_snapshot_t *snapshot);
int baseline_capture_memory(baseline_snapshot_t *snapshot);
int baseline_capture_security(baseline_snapshot_t *snapshot);

/* Compute baseline integrity hash */
int baseline_compute_hash(baseline_snapshot_t *snapshot);

/* Output functions */
void baseline_print_snapshot(const baseline_snapshot_t *snapshot, bool verbose);
void baseline_print_comparison(const baseline_comparison_t *result, bool verbose);

/* JSON export */
int baseline_to_json(const baseline_snapshot_t *snapshot, char *buffer, size_t size);
int baseline_comparison_to_json(const baseline_comparison_t *result, char *buffer, size_t size);

/* Utility */
const char* baseline_change_type_str(const char *type);

#endif /* FG_BASELINE_CAPTURE_H */
