#ifndef FG_IMPLANT_DETECT_H
#define FG_IMPLANT_DETECT_H

#include "../../include/firmwareguard.h"
#include "baseline_capture.h"

/* Detection categories */
typedef enum {
    IMPLANT_CAT_PCI,
    IMPLANT_CAT_USB,
    IMPLANT_CAT_FIRMWARE,
    IMPLANT_CAT_ACPI,
    IMPLANT_CAT_MEMORY,
    IMPLANT_CAT_DMA,
    IMPLANT_CAT_NETWORK,
    IMPLANT_CAT_UNKNOWN
} implant_category_t;

/* Known suspicious PCI vendor IDs */
typedef struct {
    uint16_t vendor_id;
    uint16_t device_id;   /* 0xFFFF = any device */
    const char *description;
    risk_level_t risk;
} suspicious_pci_t;

/* Known suspicious USB vendor IDs */
typedef struct {
    uint16_t vendor_id;
    uint16_t product_id;  /* 0xFFFF = any product */
    const char *description;
    risk_level_t risk;
} suspicious_usb_t;

/* Individual finding */
typedef struct {
    implant_category_t category;
    risk_level_t severity;
    char title[128];
    char description[512];
    char technical_details[1024];
    char remediation[512];
    char evidence[256];
    bool confirmed;  /* vs potential */
} implant_finding_t;

/* DMA capable device */
typedef struct {
    char name[64];
    char bdf[16];
    uint16_t vendor_id;
    uint16_t device_id;
    bool iommu_protected;
    bool dma_capable;
} dma_device_t;

/* IOMMU status */
typedef struct {
    bool iommu_present;
    bool iommu_enabled;
    char iommu_type[32];  /* intel_iommu, amd_iommu */
    int dma_device_count;
    dma_device_t dma_devices[64];
    int unprotected_count;
} iommu_status_t;

/* Memory anomaly */
typedef struct {
    uint64_t address;
    uint64_t size;
    char type[32];
    char description[256];
    bool suspicious;
} memory_anomaly_t;

/* Full scan result */
typedef struct {
    /* Scan metadata */
    time_t scan_time;
    char scan_time_str[32];
    char hostname[64];
    bool scan_complete;

    /* IOMMU/DMA status */
    iommu_status_t iommu;

    /* Suspicious PCI devices */
    int suspicious_pci_count;
    struct {
        pci_device_snapshot_t device;
        char reason[256];
        risk_level_t risk;
    } suspicious_pci[32];

    /* Suspicious USB devices */
    int suspicious_usb_count;
    struct {
        usb_device_snapshot_t device;
        char reason[256];
        risk_level_t risk;
    } suspicious_usb[32];

    /* Memory anomalies */
    int memory_anomaly_count;
    memory_anomaly_t memory_anomalies[32];

    /* Firmware anomalies */
    int firmware_anomaly_count;
    struct {
        char type[64];
        char description[256];
        risk_level_t risk;
    } firmware_anomalies[32];

    /* All findings */
    int finding_count;
    implant_finding_t findings[128];

    /* Risk assessment */
    risk_level_t overall_risk;
    char risk_reason[512];

    /* Summary */
    char summary[2048];
} implant_scan_result_t;

/* Initialize implant detection */
int implant_detect_init(void);
void implant_detect_cleanup(void);

/* Full hardware implant scan */
int implant_full_scan(implant_scan_result_t *result);

/* Individual scans */
int implant_scan_pci(implant_scan_result_t *result);
int implant_scan_usb(implant_scan_result_t *result);
int implant_scan_dma(implant_scan_result_t *result);
int implant_scan_memory(implant_scan_result_t *result);
int implant_scan_firmware(implant_scan_result_t *result);

/* Check against baseline */
int implant_check_baseline(const baseline_snapshot_t *baseline,
                           implant_scan_result_t *result);

/* Output functions */
void implant_print_result(const implant_scan_result_t *result, bool verbose);
int implant_to_json(const implant_scan_result_t *result, char *buffer, size_t size);

/* Helpers */
const char* implant_category_str(implant_category_t cat);
bool is_suspicious_pci(uint16_t vendor, uint16_t device, const char **reason);
bool is_suspicious_usb(uint16_t vendor, uint16_t product, const char **reason);

#endif /* FG_IMPLANT_DETECT_H */
