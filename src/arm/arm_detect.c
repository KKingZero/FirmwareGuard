#include "arm_detect.h"
#include "cJSON.h"
#include <dirent.h>
#include <sys/utsname.h>

#define EFIVARS_PATH        "/sys/firmware/efi/efivars"
#define ACPI_TABLES_PATH    "/sys/firmware/acpi/tables"
#define DT_PROC_PATH        "/proc/device-tree"
#define DT_SYS_PATH         "/sys/firmware/devicetree"
#define DT_MODEL_PATH       "/sys/firmware/devicetree/base/model"
#define DT_FIRMWARE_OPTEE   "/sys/firmware/devicetree/base/firmware/optee"
#define DT_FIRMWARE_PSCI    "/sys/firmware/devicetree/base/psci"
#define TEE_DEV0            "/dev/tee0"
#define TEE_PRIV_DEV0       "/dev/teepriv0"
#define OPTEE_BUS_PATH      "/sys/bus/tee/devices"
#define NET_CLASS_PATH      "/sys/class/net"

static bool path_exists(const char *p) {
    return access(p, F_OK) == 0;
}

static bool optee_device_present(void) {
    DIR *d = opendir(OPTEE_BUS_PATH);
    if (!d) return false;
    struct dirent *e;
    bool found = false;
    /* Prefix match: kernel exposes "optee", "optee-clnt0", etc. */
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "optee", 5) == 0) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

static bool nic_firmware_visible(void) {
    DIR *d = opendir(NET_CLASS_PATH);
    if (!d) return false;
    struct dirent *e;
    bool found = false;
    char path[512];
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        int n = snprintf(path, sizeof(path), "%s/%s/device/firmware_node",
                         NET_CLASS_PATH, e->d_name);
        if (n > 0 && n < (int)sizeof(path) && path_exists(path)) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

static void read_dt_model(char *out, size_t n) {
    if (!out || n == 0) return;
    out[0] = '\0';
    int fd = open(DT_MODEL_PATH, O_RDONLY);
    if (fd < 0) return;
    ssize_t r = read(fd, out, n - 1);
    close(fd);
    if (r <= 0) { out[0] = '\0'; return; }
    /* devicetree model is NUL-terminated binary; trim trailing NULs/spaces */
    out[r] = '\0';
    for (ssize_t i = r - 1; i >= 0; --i) {
        if (out[i] == '\0' || out[i] == '\n' || out[i] == ' ') {
            out[i] = '\0';
        } else {
            break;
        }
    }
}

int arm_detect_run(arm_detect_result_t *out) {
    if (!out) return FG_ERROR;
    memset(out, 0, sizeof(*out));

    out->efivars_present     = path_exists(EFIVARS_PATH);
    out->acpi_tables_present = path_exists(ACPI_TABLES_PATH);
    out->devicetree_present  = path_exists(DT_PROC_PATH) || path_exists(DT_SYS_PATH);
    out->tee_present         = path_exists(TEE_DEV0) || path_exists(TEE_PRIV_DEV0);
    out->optee_present       = optee_device_present();
    out->secure_monitor_hint = path_exists(DT_FIRMWARE_OPTEE) ||
                               path_exists(DT_FIRMWARE_PSCI);
    out->nic_firmware_paths  = nic_firmware_visible();

    struct utsname u;
    if (uname(&u) == 0) {
        snprintf(out->kernel_release, sizeof(out->kernel_release), "%s", u.release);
    } else {
        snprintf(out->kernel_release, sizeof(out->kernel_release), "unknown");
    }

    read_dt_model(out->machine_model, sizeof(out->machine_model));

    return FG_SUCCESS;
}

static const char *bool_str(bool b) { return b ? "yes" : "no"; }

void arm_detect_print(const arm_detect_result_t *r, bool verbose) {
    if (!r) return;
    printf("ARM firmware surface detection\n");
    printf("  kernel:              %s\n", r->kernel_release);
    printf("  machine model:       %s\n",
           r->machine_model[0] ? r->machine_model : "(none)");
    printf("  efivars present:     %s\n", bool_str(r->efivars_present));
    printf("  acpi tables present: %s\n", bool_str(r->acpi_tables_present));
    printf("  device-tree present: %s\n", bool_str(r->devicetree_present));
    printf("  /dev/tee present:    %s\n", bool_str(r->tee_present));
    printf("  op-tee device:       %s\n", bool_str(r->optee_present));
    printf("  secure monitor hint: %s\n", bool_str(r->secure_monitor_hint));
    printf("  nic firmware nodes:  %s\n", bool_str(r->nic_firmware_paths));
    if (verbose) {
        printf("  (paths probed: %s, %s, %s, %s, %s, %s)\n",
               EFIVARS_PATH, ACPI_TABLES_PATH, DT_PROC_PATH, DT_SYS_PATH,
               TEE_DEV0, OPTEE_BUS_PATH);
    }
}

int arm_detect_to_json(const arm_detect_result_t *r, char *buf, size_t n) {
    if (!r || !buf || n == 0) return FG_ERROR;

    cJSON *o = cJSON_CreateObject();
    if (!o) return FG_ERROR;

    if (!cJSON_AddStringToObject(o, "kernel_release", r->kernel_release) ||
        !cJSON_AddStringToObject(o, "machine_model",  r->machine_model)  ||
        !cJSON_AddBoolToObject(o, "efivars_present",     r->efivars_present)     ||
        !cJSON_AddBoolToObject(o, "acpi_tables_present", r->acpi_tables_present) ||
        !cJSON_AddBoolToObject(o, "devicetree_present",  r->devicetree_present)  ||
        !cJSON_AddBoolToObject(o, "tee_present",         r->tee_present)         ||
        !cJSON_AddBoolToObject(o, "optee_present",       r->optee_present)       ||
        !cJSON_AddBoolToObject(o, "secure_monitor_hint", r->secure_monitor_hint) ||
        !cJSON_AddBoolToObject(o, "nic_firmware_paths",  r->nic_firmware_paths)) {
        cJSON_Delete(o);
        return FG_ERROR;
    }

    char *s = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!s) return FG_ERROR;

    int w = snprintf(buf, n, "%s", s);
    free(s);
    if (w < 0 || (size_t)w >= n) return FG_ERROR;
    return FG_SUCCESS;
}
