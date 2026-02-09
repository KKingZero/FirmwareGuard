# FirmwareGuard Known Limitations

This document outlines known limitations identified during Phase 2 implementation. These issues should be addressed in future development cycles.

## 1. ~~Secure Boot Compatibility~~ (RESOLVED)

-   **Status**: Resolved. The `uefi_delete_variable()` path now checks `uefi_can_modify_vars_with_secureboot()` before proceeding, matching the existing check in `uefi_write_variable()`. The `uefi_set_me_hap_bit()` function now performs an early Secure Boot rejection before the user confirmation dialog, preventing users from going through the scary confirmation only to fail at the write step. `uefi_is_secure_boot_enabled()` now has debug logging to distinguish "disabled" from "not found".

## 2. Kernel Module Symbol Conflicts

-   **Impact**: The FirmwareGuard kernel module (`fwguard_km`) may experience symbol conflicts with other security modules or existing kernel components, leading to module load failures or system instability.
-   **Mitigation**: Ensure all symbols in `fwguard_km` are prefixed (e.g., `fwguard_`). Implement robust conflict detection mechanisms during module loading. Document known conflicts and potential workarounds.

## 3. ~~HAP Platform Support~~ (RESOLVED)

-   **Status**: Resolved. `uefi_check_hap_platform_support()` now reads `/proc/cpuinfo` and validates the CPU is Intel Family 6, Model >= 0x4E (Skylake or newer) before allowing HAP bit modification. This check is integrated into both `uefi_set_me_hap_bit()` and `uefi_is_me_hap_available()` to prevent bricking on unsupported hardware.

## 4. GRUB Complexity

-   **Impact**: FirmwareGuard's GRUB configuration management may not fully support or might break highly customized GRUB setups (e.g., encrypted `/boot` partitions, complex multi-boot configurations).
-   **Mitigation**: Emphasize the dry-run mode for GRUB modifications. Strongly recommend users to back up their GRUB configuration before applying changes. Document known incompatibilities and provide guidance for manual configuration for advanced users.

## 5. ~~Race Conditions in Backup Registry~~ (RESOLVED)

-   **Status**: Resolved. `safety_save_registry()` uses `flock(LOCK_EX)` and `safety_load_registry()` uses `flock(LOCK_SH)` to prevent concurrent access to the backup registry file.

---

**Last Updated:** 2026-02-08
