/*
 * FirmwareGuard - Live Firmware Memory Dump
 * Safe extraction of ME, SMRAM, and Option ROM contents
 * OFFLINE-ONLY: No network connectivity
 */

#include "live_dump.h"
#include "../../include/firmwareguard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>
#include <openssl/sha.h>

/* Paths */
#define ACPI_TABLES_PATH "/sys/firmware/acpi/tables"
#define PCI_DEVICES_PATH "/sys/bus/pci/devices"
#define FWGUARD_KM_PATH  "/dev/fwguard"
#define HECI_DEVICE      "/dev/mei0"

/* State */
static bool g_initialized = false;
static uint32_t g_capabilities = 0;

/* Forward declarations */
static void compute_file_sha256(const char *path, char *hash_out);
static int copy_file(const char *src, const char *dst);
static int run_flashrom(const char *output, const char *region);

/*
 * Initialize
 */
int dump_init(void)
{
    if (g_initialized) {
        return FG_SUCCESS;
    }

    g_capabilities = 0;

    /* Check what's available */

    /* ACPI tables - always available */
    if (access(ACPI_TABLES_PATH, R_OK) == 0) {
        g_capabilities |= (1 << DUMP_REGION_ACPI);
    }

    /* PCI Option ROMs - need root */
    if (geteuid() == 0 && access(PCI_DEVICES_PATH, R_OK) == 0) {
        g_capabilities |= (1 << DUMP_REGION_OPTIONROM);
    }

    /* HECI/MEI for ME access */
    if (access(HECI_DEVICE, R_OK) == 0) {
        g_capabilities |= (1 << DUMP_REGION_ME);
    }

    /* FirmwareGuard kernel module for SMRAM */
    if (access(FWGUARD_KM_PATH, R_OK) == 0) {
        g_capabilities |= (1 << DUMP_REGION_SMRAM);
    }

    /* flashrom for SPI */
    if (system("which flashrom > /dev/null 2>&1") == 0) {
        g_capabilities |= (1 << DUMP_REGION_SPI_FLASH);
    }

    g_initialized = true;
    return FG_SUCCESS;
}

/*
 * Check capabilities
 */
int dump_check_capabilities(uint32_t *capabilities)
{
    if (!g_initialized) {
        dump_init();
    }
    *capabilities = g_capabilities;
    return FG_SUCCESS;
}

/*
 * Region name
 */
const char *dump_region_name(dump_region_t region)
{
    switch (region) {
        case DUMP_REGION_ME: return "Intel ME";
        case DUMP_REGION_PSP: return "AMD PSP";
        case DUMP_REGION_SMRAM: return "SMRAM";
        case DUMP_REGION_OPTIONROM: return "Option ROM";
        case DUMP_REGION_UEFI_RT: return "UEFI Runtime";
        case DUMP_REGION_ACPI: return "ACPI Tables";
        case DUMP_REGION_SPI_FLASH: return "SPI Flash";
        default: return "Unknown";
    }
}

/*
 * Check region availability
 */
bool dump_region_available(dump_region_t region)
{
    if (!g_initialized) {
        dump_init();
    }
    return (g_capabilities & (1 << region)) != 0;
}

/*
 * Get risk level
 */
int dump_region_risk_level(dump_region_t region)
{
    switch (region) {
        case DUMP_REGION_ACPI: return 0;       /* Safe */
        case DUMP_REGION_OPTIONROM: return 1;  /* Low risk */
        case DUMP_REGION_ME: return 3;         /* Some risk */
        case DUMP_REGION_PSP: return 3;
        case DUMP_REGION_SPI_FLASH: return 5;  /* Medium */
        case DUMP_REGION_UEFI_RT: return 7;    /* High */
        case DUMP_REGION_SMRAM: return 9;      /* Very high */
        default: return 10;
    }
}

/*
 * Compute SHA-256
 */
static void compute_file_sha256(const char *path, char *hash_out)
{
    hash_out[0] = '\0';

    FILE *fp = fopen(path, "rb");
    if (!fp) return;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buffer[8192];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        SHA256_Update(&ctx, buffer, bytes);
    }

    fclose(fp);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_out + (i * 2), "%02x", hash[i]);
    }
}

/*
 * Copy file
 */
static int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in) return -1;

    FILE *out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }

    char buffer[8192];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        fwrite(buffer, 1, bytes, out);
    }

    fclose(in);
    fclose(out);

    return 0;
}

/*
 * Run flashrom
 */
static int run_flashrom(const char *output, const char *region)
{
    char cmd[1024];

    if (region && strcmp(region, "all") != 0) {
        snprintf(cmd, sizeof(cmd),
                "flashrom -p internal --ifd -i %s -r %s 2>&1",
                region, output);
    } else {
        snprintf(cmd, sizeof(cmd),
                "flashrom -p internal -r %s 2>&1",
                output);
    }

    return system(cmd);
}

/*
 * Dump ACPI tables
 */
int dump_acpi_tables(const char *output_dir, region_dump_t *result)
{
    memset(result, 0, sizeof(region_dump_t));
    result->region = DUMP_REGION_ACPI;
    result->dump_time = time(NULL);

    if (access(ACPI_TABLES_PATH, R_OK) != 0) {
        result->status = DUMP_STATUS_NOT_SUPPORTED;
        strncpy(result->error, "ACPI tables not accessible", sizeof(result->error));
        return FG_ERROR;
    }

    /* Create output directory */
    char acpi_dir[600];
    snprintf(acpi_dir, sizeof(acpi_dir), "%s/acpi", output_dir);
    mkdir(acpi_dir, 0755);

    DIR *dir = opendir(ACPI_TABLES_PATH);
    if (!dir) {
        result->status = DUMP_STATUS_FAILED;
        strncpy(result->error, "Cannot open ACPI tables directory", sizeof(result->error));
        return FG_ERROR;
    }

    struct dirent *entry;
    int count = 0;
    uint64_t total_size = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char src_path[768];
        char dst_path[768];
        snprintf(src_path, sizeof(src_path), "%s/%s", ACPI_TABLES_PATH, entry->d_name);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", acpi_dir, entry->d_name);

        struct stat st;
        if (stat(src_path, &st) == 0 && S_ISREG(st.st_mode)) {
            if (copy_file(src_path, dst_path) == 0) {
                count++;
                total_size += st.st_size;
            }
        }
    }

    closedir(dir);

    strncpy(result->output_path, acpi_dir, sizeof(result->output_path));
    result->size = total_size;
    strncpy(result->method_used, "sysfs copy", sizeof(result->method_used));

    if (count > 0) {
        result->status = DUMP_STATUS_SUCCESS;
        FG_INFO("Dumped %d ACPI tables (%lu bytes)", count, (unsigned long)total_size);
    } else {
        result->status = DUMP_STATUS_FAILED;
        strncpy(result->error, "No ACPI tables found", sizeof(result->error));
    }

    return count > 0 ? FG_SUCCESS : FG_ERROR;
}

/*
 * Dump Option ROMs
 */
int dump_option_roms(const char *output_dir, region_dump_t **results, int *count)
{
    *results = NULL;
    *count = 0;

    if (geteuid() != 0) {
        FG_LOG_ERROR("Option ROM dump requires root");
        return FG_NO_PERMISSION;
    }

    char rom_dir[600];
    snprintf(rom_dir, sizeof(rom_dir), "%s/optionrom", output_dir);
    mkdir(rom_dir, 0755);

    DIR *dir = opendir(PCI_DEVICES_PATH);
    if (!dir) {
        return FG_ERROR;
    }

    /* Count potential ROMs first */
    int max_roms = 32;
    *results = calloc(max_roms, sizeof(region_dump_t));
    if (!*results) {
        closedir(dir);
        return FG_ERROR;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL && *count < max_roms) {
        if (entry->d_name[0] == '.') continue;

        char rom_path[768];
        snprintf(rom_path, sizeof(rom_path), "%s/%s/rom",
                PCI_DEVICES_PATH, entry->d_name);

        struct stat st;
        if (stat(rom_path, &st) != 0 || st.st_size == 0) {
            continue;
        }

        /* Enable ROM reading */
        FILE *fp = fopen(rom_path, "w");
        if (fp) {
            fprintf(fp, "1");
            fclose(fp);
        }

        /* Read ROM */
        fp = fopen(rom_path, "rb");
        if (!fp) continue;

        char output_path[768];
        snprintf(output_path, sizeof(output_path), "%s/%s.rom",
                rom_dir, entry->d_name);

        FILE *out = fopen(output_path, "wb");
        if (!out) {
            fclose(fp);  /* Close fp before continuing to avoid leak */
            /* Disable ROM reading before continuing */
            fp = fopen(rom_path, "w");
            if (fp) {
                fprintf(fp, "0");
                fclose(fp);
            }
            continue;
        }

        char buffer[4096];
        size_t bytes;
        uint64_t total = 0;

        while ((bytes = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
            fwrite(buffer, 1, bytes, out);
            total += bytes;
        }

        fclose(out);
        fclose(fp);

        region_dump_t *result = &(*results)[*count];
        result->region = DUMP_REGION_OPTIONROM;
        result->status = DUMP_STATUS_SUCCESS;
        strncpy(result->output_path, output_path, sizeof(result->output_path));
        result->size = total;
        result->dump_time = time(NULL);
        strncpy(result->method_used, "sysfs rom", sizeof(result->method_used));
        compute_file_sha256(output_path, result->sha256);

        (*count)++;

        /* Disable ROM reading */
        fp = fopen(rom_path, "w");
        if (fp) {
            fprintf(fp, "0");
            fclose(fp);
        }
    }

    closedir(dir);

    FG_INFO("Dumped %d Option ROMs", *count);
    return FG_SUCCESS;
}

/*
 * Dump ME memory
 */
int dump_me_memory(const char *output_path, region_dump_t *result)
{
    memset(result, 0, sizeof(region_dump_t));
    result->region = DUMP_REGION_ME;
    result->dump_time = time(NULL);

    if (geteuid() != 0) {
        result->status = DUMP_STATUS_NO_PERMISSION;
        strncpy(result->error, "Requires root", sizeof(result->error));
        return FG_NO_PERMISSION;
    }

    /* Check for HECI device */
    if (access(HECI_DEVICE, R_OK) != 0) {
        result->status = DUMP_STATUS_NOT_SUPPORTED;
        strncpy(result->error, "HECI device not available", sizeof(result->error));
        return FG_NOT_SUPPORTED;
    }

    /* ME memory access is limited - we can get status but not full dump */
    /* For full ME region, use SPI flash dump */

    result->status = DUMP_STATUS_PARTIAL;
    strncpy(result->method_used, "HECI query", sizeof(result->method_used));
    strncpy(result->error, "Full ME dump requires SPI flash access", sizeof(result->error));

    FG_WARN("ME memory direct dump not fully implemented - use SPI dump");
    return FG_NOT_SUPPORTED;
}

/*
 * Dump SMRAM
 */
int dump_smram(const char *output_path, dump_safety_t safety, region_dump_t *result)
{
    memset(result, 0, sizeof(region_dump_t));
    result->region = DUMP_REGION_SMRAM;
    result->dump_time = time(NULL);

    if (geteuid() != 0) {
        result->status = DUMP_STATUS_NO_PERMISSION;
        strncpy(result->error, "Requires root", sizeof(result->error));
        return FG_NO_PERMISSION;
    }

    /* Check safety level */
    if (safety == DUMP_SAFE_ONLY) {
        result->status = DUMP_STATUS_UNSAFE_ABORT;
        strncpy(result->error, "SMRAM dump is risky - aborted due to safety setting",
               sizeof(result->error));
        return FG_ERROR;
    }

    /* Check for kernel module */
    if (access(FWGUARD_KM_PATH, R_OK) != 0) {
        result->status = DUMP_STATUS_NOT_SUPPORTED;
        strncpy(result->error, "FirmwareGuard kernel module not loaded",
               sizeof(result->error));
        return FG_NOT_SUPPORTED;
    }

    FG_WARN("SMRAM dump is a high-risk operation!");

    if (safety == DUMP_SAFE_WITH_FALLBACK) {
        FG_WARN("Proceeding with SMRAM dump due to SAFE_WITH_FALLBACK setting");
    }

    /* Open kernel module device */
    int fd = open(FWGUARD_KM_PATH, O_RDONLY);
    if (fd < 0) {
        result->status = DUMP_STATUS_FAILED;
        snprintf(result->error, sizeof(result->error),
                "Cannot open kernel module: %s", strerror(errno));
        return FG_ERROR;
    }

    /* SMRAM dump would use ioctl to kernel module */
    /* This is a placeholder - actual implementation requires kernel module support */

    close(fd);

    result->status = DUMP_STATUS_NOT_SUPPORTED;
    strncpy(result->error, "SMRAM dump not yet implemented in kernel module",
           sizeof(result->error));
    strncpy(result->method_used, "kernel_module", sizeof(result->method_used));

    return FG_NOT_SUPPORTED;
}

/*
 * Dump SPI flash
 */
int dump_spi_flash(const char *output_path, const char *region, region_dump_t *result)
{
    memset(result, 0, sizeof(region_dump_t));
    result->region = DUMP_REGION_SPI_FLASH;
    result->dump_time = time(NULL);

    if (geteuid() != 0) {
        result->status = DUMP_STATUS_NO_PERMISSION;
        strncpy(result->error, "Requires root", sizeof(result->error));
        return FG_NO_PERMISSION;
    }

    /* Check flashrom */
    if (system("which flashrom > /dev/null 2>&1") != 0) {
        result->status = DUMP_STATUS_NOT_SUPPORTED;
        strncpy(result->error, "flashrom not installed", sizeof(result->error));
        return FG_NOT_SUPPORTED;
    }

    FG_INFO("Starting SPI flash dump via flashrom...");
    strncpy(result->method_used, "flashrom", sizeof(result->method_used));

    int ret = run_flashrom(output_path, region);

    if (ret == 0) {
        result->status = DUMP_STATUS_SUCCESS;
        strncpy(result->output_path, output_path, sizeof(result->output_path));

        struct stat st;
        if (stat(output_path, &st) == 0) {
            result->size = st.st_size;
        }

        compute_file_sha256(output_path, result->sha256);
        FG_INFO("SPI flash dump complete: %s (%lu bytes)",
               output_path, (unsigned long)result->size);
    } else {
        result->status = DUMP_STATUS_FAILED;
        strncpy(result->error, "flashrom failed - check permissions and hardware support",
               sizeof(result->error));
    }

    return ret == 0 ? FG_SUCCESS : FG_ERROR;
}

/*
 * Run dump session
 */
int dump_session(const dump_options_t *opts, dump_session_t *session)
{
    if (!g_initialized) {
        dump_init();
    }

    dump_options_t default_opts = DUMP_OPTS_DEFAULT;
    if (!opts) {
        opts = &default_opts;
    }

    memset(session, 0, sizeof(dump_session_t));
    session->session_start = time(NULL);
    strncpy(session->output_dir, opts->output_dir, sizeof(session->output_dir));

    /* Create output directory */
    mkdir(opts->output_dir, 0755);

    if (opts->dry_run) {
        FG_INFO("Dry run - checking capabilities only");
        uint32_t caps;
        dump_check_capabilities(&caps);

        for (int r = 0; r < DUMP_REGION_MAX; r++) {
            if (caps & (1 << r)) {
                FG_INFO("  Available: %s (risk level: %d/10)",
                       dump_region_name(r), dump_region_risk_level(r));
            }
        }

        session->session_end = time(NULL);
        return FG_SUCCESS;
    }

    /* Dump each requested region */
    if (opts->dump_acpi) {
        region_dump_t *result = &session->regions[session->num_regions++];
        dump_acpi_tables(opts->output_dir, result);
    }

    if (opts->dump_optionrom) {
        region_dump_t *roms = NULL;
        int rom_count = 0;
        dump_option_roms(opts->output_dir, &roms, &rom_count);

        if (rom_count > 0 && roms) {
            /* Just record first one in session, count shows total */
            memcpy(&session->regions[session->num_regions++], &roms[0], sizeof(region_dump_t));
            free(roms);
        }
    }

    if (opts->dump_me) {
        char path[768];
        snprintf(path, sizeof(path), "%s/me_dump.bin", opts->output_dir);
        region_dump_t *result = &session->regions[session->num_regions++];
        dump_me_memory(path, result);
    }

    if (opts->dump_smram) {
        char path[768];
        snprintf(path, sizeof(path), "%s/smram_dump.bin", opts->output_dir);
        region_dump_t *result = &session->regions[session->num_regions++];
        dump_smram(path, opts->safety_level, result);
    }

    if (opts->dump_spi) {
        char path[768];
        snprintf(path, sizeof(path), "%s/spi_flash.bin", opts->output_dir);
        region_dump_t *result = &session->regions[session->num_regions++];
        dump_spi_flash(path, "all", result);
    }

    session->session_end = time(NULL);

    return FG_SUCCESS;
}

/*
 * Print session
 */
void dump_print_session(const dump_session_t *session)
{
    printf("\n=== Dump Session Results ===\n");
    printf("Output: %s\n", session->output_dir);
    printf("Duration: %ld seconds\n",
           (long)(session->session_end - session->session_start));
    printf("\n");

    for (int i = 0; i < session->num_regions; i++) {
        const region_dump_t *r = &session->regions[i];
        printf("[%s] %s\n",
               dump_status_string(r->status),
               dump_region_name(r->region));

        if (r->status == DUMP_STATUS_SUCCESS || r->status == DUMP_STATUS_PARTIAL) {
            printf("  Path: %s\n", r->output_path);
            printf("  Size: %lu bytes\n", (unsigned long)r->size);
            if (r->sha256[0]) {
                printf("  SHA-256: %s\n", r->sha256);
            }
            printf("  Method: %s\n", r->method_used);
        }

        if (r->error[0]) {
            printf("  Error: %s\n", r->error);
        }

        printf("\n");
    }

    if (session->warnings[0]) {
        printf("Warnings: %s\n", session->warnings);
    }
}

/*
 * Status string
 */
const char *dump_status_string(dump_status_t status)
{
    switch (status) {
        case DUMP_STATUS_SUCCESS: return "SUCCESS";
        case DUMP_STATUS_PARTIAL: return "PARTIAL";
        case DUMP_STATUS_FAILED: return "FAILED";
        case DUMP_STATUS_NO_PERMISSION: return "NO_PERMISSION";
        case DUMP_STATUS_NOT_SUPPORTED: return "NOT_SUPPORTED";
        case DUMP_STATUS_UNSAFE_ABORT: return "UNSAFE_ABORT";
        default: return "UNKNOWN";
    }
}

/*
 * Cleanup
 */
void dump_cleanup(void)
{
    g_initialized = false;
    g_capabilities = 0;
}
