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
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>

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
static bool resolve_trusted_command(const char *name, char *out, size_t out_size);
static bool valid_flashrom_region(const char *region);

static bool resolve_trusted_command(const char *name, char *out, size_t out_size)
{
    static const char *trusted_dirs[] = {
        "/usr/sbin", "/usr/bin", "/usr/local/sbin", "/usr/local/bin", "/sbin", "/bin", NULL
    };

    if (!name || strchr(name, '/')) {
        return false;
    }

    for (int i = 0; trusted_dirs[i]; i++) {
        char candidate[512];
        if (snprintf(candidate, sizeof(candidate), "%s/%s", trusted_dirs[i], name) >=
            (int)sizeof(candidate)) {
            continue;
        }
        if (access(candidate, X_OK) == 0) {
            if (strlen(candidate) >= out_size) {
                return false;
            }
            memcpy(out, candidate, strlen(candidate) + 1);
            return true;
        }
    }

    return false;
}

static bool valid_flashrom_region(const char *region)
{
    static const char *allowed[] = { "all", "bios", "me", "gbe", "pd", "ec", NULL };

    if (!region || strcmp(region, "all") == 0) {
        return true;
    }

    for (int i = 0; allowed[i]; i++) {
        if (strcmp(region, allowed[i]) == 0) {
            return true;
        }
    }

    return false;
}

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
    char flashrom_path[512];
    if (resolve_trusted_command("flashrom", flashrom_path, sizeof(flashrom_path))) {
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

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(fp);
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return;
    }

    unsigned char buffer[8192];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        EVP_DigestUpdate(ctx, buffer, bytes);
    }

    fclose(fp);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1 || hash_len < 32) {
        EVP_MD_CTX_free(ctx);
        return;
    }
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < 32; i++) {
        snprintf(hash_out + (i * 2), 3, "%02x", hash[i]);
    }
    hash_out[64] = '\0';
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
    if (!output || !valid_flashrom_region(region)) {
        return -1;
    }

    char output_arg[512];
    if (strlen(output) >= sizeof(output_arg)) {
        return -1;
    }
    memcpy(output_arg, output, strlen(output) + 1);

    char flashrom_path[512];
    if (!resolve_trusted_command("flashrom", flashrom_path, sizeof(flashrom_path))) {
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        if (region && strcmp(region, "all") != 0) {
            char include_arg[64];
            snprintf(include_arg, sizeof(include_arg), "%s", region);
            execv(flashrom_path, (char *const[]) {
                flashrom_path, "-p", "internal", "--ifd", "-i", include_arg,
                "-r", output_arg, NULL
            });
        } else {
            execv(flashrom_path, (char *const[]) {
                flashrom_path, "-p", "internal", "-r", output_arg, NULL
            });
        }
        _exit(127);
    }

    if (pid < 0) {
        return -1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
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
    if (snprintf(acpi_dir, sizeof(acpi_dir), "%s/acpi", output_dir) >=
        (int)sizeof(result->output_path)) {
        result->status = DUMP_STATUS_FAILED;
        strncpy(result->error, "Output path too long", sizeof(result->error) - 1);
        return FG_ERROR;
    }
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
        if (snprintf(src_path, sizeof(src_path), "%s/%s", ACPI_TABLES_PATH, entry->d_name) >=
            (int)sizeof(src_path) ||
            snprintf(dst_path, sizeof(dst_path), "%s/%s", acpi_dir, entry->d_name) >=
            (int)sizeof(dst_path)) {
            FG_WARN("Skipping ACPI table with overlong path: %s", entry->d_name);
            continue;
        }

        struct stat st;
        if (stat(src_path, &st) == 0 && S_ISREG(st.st_mode)) {
            if (copy_file(src_path, dst_path) == 0) {
                count++;
                total_size += st.st_size;
            }
        }
    }

    closedir(dir);

    size_t acpi_len = strlen(acpi_dir);
    memcpy(result->output_path, acpi_dir, acpi_len + 1);
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
        if (snprintf(output_path, sizeof(output_path), "%s/%s.rom",
                     rom_dir, entry->d_name) >= (int)sizeof((*results)[0].output_path)) {
            FG_WARN("Skipping Option ROM with overlong path: %s", entry->d_name);
            fclose(fp);
            fp = fopen(rom_path, "w");
            if (fp) {
                fprintf(fp, "0");
                fclose(fp);
            }
            continue;
        }

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
        size_t output_len = strlen(output_path);
        memcpy(result->output_path, output_path, output_len + 1);
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
    (void)output_path;
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
    (void)output_path;
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
    char flashrom_path[512];
    if (!resolve_trusted_command("flashrom", flashrom_path, sizeof(flashrom_path))) {
        result->status = DUMP_STATUS_NOT_SUPPORTED;
        strncpy(result->error, "flashrom not installed", sizeof(result->error));
        return FG_NOT_SUPPORTED;
    }

    FG_INFO("Starting SPI flash dump via flashrom...");
    strncpy(result->method_used, "flashrom", sizeof(result->method_used));

    int ret = run_flashrom(output_path, region);

    if (ret == 0) {
        result->status = DUMP_STATUS_SUCCESS;
        snprintf(result->output_path, sizeof(result->output_path), "%s", output_path);

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

int dump_psp_memory(const char *output_path, region_dump_t *result)
{
    (void)output_path;
    memset(result, 0, sizeof(region_dump_t));
    result->region = DUMP_REGION_PSP;
    result->dump_time = time(NULL);
    result->status = DUMP_STATUS_NOT_SUPPORTED;
    strncpy(result->error, "AMD PSP memory dump is not supported from userspace",
            sizeof(result->error) - 1);
    return FG_NOT_SUPPORTED;
}

int dump_uefi_runtime(const char *output_path, region_dump_t *result)
{
    (void)output_path;
    memset(result, 0, sizeof(region_dump_t));
    result->region = DUMP_REGION_UEFI_RT;
    result->dump_time = time(NULL);
    result->status = DUMP_STATUS_NOT_SUPPORTED;
    strncpy(result->error, "UEFI runtime memory dump requires kernel cooperation and is not wired",
            sizeof(result->error) - 1);
    return FG_NOT_SUPPORTED;
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
    snprintf(session->output_dir, sizeof(session->output_dir), "%s", opts->output_dir);

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

    int overall = FG_SUCCESS;

    /* Dump each requested region */
    if (opts->dump_acpi) {
        region_dump_t *result = &session->regions[session->num_regions++];
        int ret = dump_acpi_tables(opts->output_dir, result);
        if (ret != FG_SUCCESS && result->status != DUMP_STATUS_NOT_SUPPORTED) {
            overall = FG_ERROR;
        }
    }

    if (opts->dump_optionrom) {
        region_dump_t *roms = NULL;
        int rom_count = 0;
        int ret = dump_option_roms(opts->output_dir, &roms, &rom_count);

        if (rom_count > 0 && roms) {
            /* Just record first one in session, count shows total */
            memcpy(&session->regions[session->num_regions++], &roms[0], sizeof(region_dump_t));
        } else if (ret != FG_SUCCESS && session->num_regions < DUMP_REGION_MAX) {
            region_dump_t *result = &session->regions[session->num_regions++];
            memset(result, 0, sizeof(*result));
            result->region = DUMP_REGION_OPTIONROM;
            result->dump_time = time(NULL);
            result->status = (ret == FG_NO_PERMISSION) ?
                             DUMP_STATUS_NO_PERMISSION : DUMP_STATUS_FAILED;
            snprintf(result->error, sizeof(result->error),
                     "%s", ret == FG_NO_PERMISSION ? "Requires root" : "Option ROM dump failed");
            overall = FG_ERROR;
        }
        free(roms);
    }

    if (opts->dump_me) {
        char path[768];
        snprintf(path, sizeof(path), "%s/me_dump.bin", opts->output_dir);
        region_dump_t *result = &session->regions[session->num_regions++];
        int ret = dump_me_memory(path, result);
        if (ret != FG_SUCCESS && result->status != DUMP_STATUS_NOT_SUPPORTED) {
            overall = FG_ERROR;
        }
    }

    if (opts->dump_smram) {
        char path[768];
        snprintf(path, sizeof(path), "%s/smram_dump.bin", opts->output_dir);
        region_dump_t *result = &session->regions[session->num_regions++];
        int ret = dump_smram(path, opts->safety_level, result);
        if (ret != FG_SUCCESS && result->status != DUMP_STATUS_NOT_SUPPORTED) {
            overall = FG_ERROR;
        }
    }

    if (opts->dump_spi) {
        char path[768];
        snprintf(path, sizeof(path), "%s/spi_flash.bin", opts->output_dir);
        region_dump_t *result = &session->regions[session->num_regions++];
        int ret = dump_spi_flash(path, "all", result);
        if (ret != FG_SUCCESS && result->status != DUMP_STATUS_NOT_SUPPORTED) {
            overall = FG_ERROR;
        }
    }

    session->session_end = time(NULL);

    return overall;
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

int dump_verify(const char *dump_path, const char *expected_sha256, char *computed_sha256)
{
    char hash[65];

    if (!dump_path) {
        return FG_ERROR;
    }

    compute_file_sha256(dump_path, hash);
    if (hash[0] == '\0') {
        return FG_ERROR;
    }

    if (computed_sha256) {
        memcpy(computed_sha256, hash, sizeof(hash));
    }

    if (expected_sha256 && *expected_sha256) {
        return strcmp(hash, expected_sha256) == 0 ? FG_SUCCESS : 1;
    }

    return FG_SUCCESS;
}

/*
 * Cleanup
 */
void dump_cleanup(void)
{
    g_initialized = false;
    g_capabilities = 0;
}
