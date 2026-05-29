#ifndef FG_TXT_SGX_DETECT_H
#define FG_TXT_SGX_DETECT_H

#include "../../include/firmwareguard.h"
#include "msr.h"

/* TXT-related MSR addresses */
#define MSR_IA32_FEATURE_CONTROL    0x0000003A
#define MSR_IA32_SMM_MONITOR_CTL    0x0000009B

/* Feature Control bits */
#define FC_LOCK_BIT                 (1ULL << 0)
#define FC_VMX_IN_SMX               (1ULL << 1)
#define FC_VMX_OUTSIDE_SMX          (1ULL << 2)
#define FC_SENTER_LOCAL_ENABLE      (0x7FULL << 8)
#define FC_SENTER_GLOBAL_ENABLE     (1ULL << 15)
#define FC_SGX_LAUNCH_CONTROL       (1ULL << 17)
#define FC_SGX_GLOBAL_ENABLE        (1ULL << 18)
#define FC_LMCE                     (1ULL << 20)

/* SGX CPUID leaf */
#define SGX_CPUID_LEAF              0x12

/* TXT public space (memory-mapped) */
#define TXT_PUB_CONFIG_SPACE        0xFED30000ULL
#define TXT_PRIV_CONFIG_SPACE       0xFED20000ULL

/* TXT register offsets */
#define TXT_STS                     0x0000
#define TXT_ESTS                    0x0008
#define TXT_ERRORCODE               0x0030
#define TXT_CMD_RESET               0x0038
#define TXT_VER_FSBIF               0x0100
#define TXT_DIDVID                  0x0110
#define TXT_VER_QPIIF               0x0200
#define TXT_SINIT_BASE              0x0270
#define TXT_SINIT_SIZE              0x0278
#define TXT_MLE_JOIN                0x0290
#define TXT_HEAP_BASE               0x0300
#define TXT_HEAP_SIZE               0x0308
#define TXT_DPR                     0x0330
#define TXT_PUBLIC_KEY              0x0400

/* TXT status bits */
#define TXT_STS_SENTER_DONE         (1ULL << 0)
#define TXT_STS_SEXIT_DONE          (1ULL << 1)
#define TXT_STS_MEM_CONFIG_OK       (1ULL << 4)
#define TXT_STS_PRIVATE_OPEN        (1ULL << 5)
#define TXT_STS_LOCALITY_1          (1ULL << 15)
#define TXT_STS_LOCALITY_2          (1ULL << 16)

/* TXT configuration result */
typedef struct {
    /* CPU support */
    bool txt_supported;
    bool smx_supported;
    bool vmx_supported;

    /* Enable status */
    bool txt_enabled;
    bool senter_enabled;
    bool feature_control_locked;

    /* TXT hardware status */
    bool txt_hardware_present;
    uint64_t txt_status;
    uint64_t txt_error;
    uint32_t txt_didvid;

    /* SINIT ACM */
    uint64_t sinit_base;
    uint64_t sinit_size;
    bool sinit_present;
    char sinit_version[32];

    /* DPR (DMA Protected Range) */
    uint64_t dpr_base;
    uint64_t dpr_size;
    bool dpr_locked;

    /* TXT Heap */
    uint64_t heap_base;
    uint64_t heap_size;

    /* Raw values */
    uint64_t feature_control_raw;

    /* Risk assessment */
    risk_level_t risk_level;
    char risk_reason[256];

    /* Findings */
    int finding_count;
    char findings[16][256];

    /* Summary */
    char summary[512];
} txt_config_t;

/* SGX EPC (Enclave Page Cache) section */
typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t type;
    bool valid;
} sgx_epc_section_t;

/* SGX configuration result */
typedef struct {
    /* CPU support */
    bool sgx_supported;
    bool sgx1_supported;
    bool sgx2_supported;
    bool sgx_enabled;
    bool sgx_launch_control;

    /* EPC configuration */
    int epc_section_count;
    sgx_epc_section_t epc_sections[8];
    uint64_t total_epc_size;

    /* Enclave info */
    uint32_t max_enclave_size_32;
    uint32_t max_enclave_size_64;
    uint32_t miscselect;

    /* Security attributes */
    bool flexible_launch_control;
    bool kss_supported;  /* Key Separation and Sharing */

    /* SGX device presence */
    bool sgx_device_present;
    bool sgx_enclave_device;
    bool sgx_provision_device;

    /* Risk assessment */
    risk_level_t risk_level;
    char risk_reason[256];

    /* Findings */
    int finding_count;
    char findings[16][256];

    /* Summary */
    char summary[512];
} sgx_config_t;

/* TPM PCR value */
typedef struct {
    int pcr_index;
    uint8_t sha1[20];
    uint8_t sha256[32];
    char sha256_hex[65];
    bool valid;
} tpm_pcr_t;

/* TPM measurement result */
typedef struct {
    /* TPM presence */
    bool tpm_present;
    bool tpm_2_0;
    char tpm_version[32];
    char tpm_manufacturer[64];

    /* PCR values */
    int pcr_count;
    tpm_pcr_t pcrs[24];

    /* Event log */
    bool event_log_present;
    char event_log_path[256];
    size_t event_log_size;

    /* SRTM (Static Root of Trust) measurements */
    bool srtm_valid;
    bool drtm_valid;  /* Dynamic Root of Trust */

    /* Risk assessment */
    risk_level_t risk_level;
    char risk_reason[256];

    /* Findings */
    int finding_count;
    char findings[16][256];

    /* Summary */
    char summary[512];
} tpm_measurement_t;

/* Full trusted boot analysis */
typedef struct {
    txt_config_t txt;
    sgx_config_t sgx;
    tpm_measurement_t tpm;

    bool txt_scan_done;
    bool sgx_scan_done;
    bool tpm_scan_done;

    /* Overall assessment */
    risk_level_t overall_risk;
    char risk_reason[256];

    /* Combined findings */
    int finding_count;
    char findings[32][256];

    /* Summary */
    char summary[1024];
} trusted_boot_result_t;

/* Initialize TXT/SGX detection */
int txt_sgx_init(void);
void txt_sgx_cleanup(void);

/* TXT configuration audit */
int txt_scan_config(txt_config_t *result);
void txt_print_result(const txt_config_t *result, bool verbose);
int txt_to_json(const txt_config_t *result, char *buffer, size_t size);

/* SGX enumeration */
int sgx_scan_config(sgx_config_t *result);
void sgx_print_result(const sgx_config_t *result, bool verbose);
int sgx_to_json(const sgx_config_t *result, char *buffer, size_t size);

/* TPM measurement analysis */
int tpm_scan_measurements(tpm_measurement_t *result);
void tpm_print_result(const tpm_measurement_t *result, bool verbose);
int tpm_to_json(const tpm_measurement_t *result, char *buffer, size_t size);

/* Full trusted boot audit */
int trusted_boot_full_scan(trusted_boot_result_t *result);
void trusted_boot_print_result(const trusted_boot_result_t *result, bool verbose);
int trusted_boot_to_json(const trusted_boot_result_t *result, char *buffer, size_t size);

/* Helper functions */
risk_level_t txt_assess_risk(const txt_config_t *config);
risk_level_t sgx_assess_risk(const sgx_config_t *config);

#endif /* FG_TXT_SGX_DETECT_H */
