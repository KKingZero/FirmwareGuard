#include "arm_probe.h"
#include "arm_detect.h"

static void add_component(audit_result_t *out,
                          component_type_t type,
                          const char *name,
                          bool detected,
                          const char *details) {
    if (out->num_components >= (int)(sizeof(out->components) / sizeof(out->components[0]))) {
        return;
    }
    component_status_t *c = &out->components[out->num_components++];
    memset(c, 0, sizeof(*c));
    c->type = type;
    snprintf(c->name, sizeof(c->name), "%s", name);
    c->detected = detected;
    c->active = detected;
    c->blockable = false;
    c->blocked = false;
    c->risk = RISK_NONE;
    snprintf(c->details, sizeof(c->details), "%s", details ? details : "");
}

int arm_probe_scan(audit_result_t *out) {
    if (!out) return FG_ERROR;
    memset(out, 0, sizeof(*out));

    arm_detect_result_t r;
    int rc = arm_detect_run(&r);
    if (rc != FG_SUCCESS) return rc;

    add_component(out, COMPONENT_UEFI_NVRAM, "UEFI efivars",
                  r.efivars_present,
                  r.efivars_present ? "/sys/firmware/efi/efivars" : "not present");

    add_component(out, COMPONENT_ACPI_TABLE, "ACPI tables",
                  r.acpi_tables_present,
                  r.acpi_tables_present ? "/sys/firmware/acpi/tables" : "not present");

    add_component(out, COMPONENT_ARM_FIRMWARE, "Device Tree",
                  r.devicetree_present,
                  r.devicetree_present ? "/proc/device-tree or /sys/firmware/devicetree" : "not present");

    add_component(out, COMPONENT_ARM_FIRMWARE, "TEE device",
                  r.tee_present,
                  r.tee_present ? "/dev/tee0 or /dev/teepriv0" : "not present");

    add_component(out, COMPONENT_ARM_FIRMWARE, "OP-TEE",
                  r.optee_present,
                  r.optee_present ? "/sys/bus/tee/devices/optee*" : "not present");

    add_component(out, COMPONENT_ARM_FIRMWARE, "Secure monitor (PSCI/OP-TEE node)",
                  r.secure_monitor_hint,
                  r.secure_monitor_hint ? "/sys/firmware/devicetree/base/firmware" : "not present");

    add_component(out, COMPONENT_NIC_TELEMETRY, "NIC firmware nodes",
                  r.nic_firmware_paths,
                  r.nic_firmware_paths ? "/sys/class/net/*/device/firmware_node" : "not present");

    out->overall_risk = RISK_NONE;
    snprintf(out->summary, sizeof(out->summary),
             "ARM v1 detection: %d surfaces inspected (read-only)",
             out->num_components);
    return FG_SUCCESS;
}
