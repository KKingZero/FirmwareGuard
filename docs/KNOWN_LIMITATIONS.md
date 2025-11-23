# FirmwareGuard Known Limitations

This document outlines known limitations identified during Phase 2 implementation. These issues should be addressed in future development cycles.

## 1. Secure Boot Compatibility

-   **Impact**: UEFI variable modification (e.g., for HAP bit) may fail silently or explicitly with Secure Boot enabled. This can lead to operations not being applied or the user being unaware of the failure.
-   **Mitigation**: Document this limitation clearly to users. Implement detection for Secure Boot status and provide clearer error messages or warnings if an operation is attempted with Secure Boot enabled. Investigate methods for safe UEFI variable modification under Secure Boot (if feasible).

## 2. Kernel Module Symbol Conflicts

-   **Impact**: The FirmwareGuard kernel module (`fwguard_km`) may experience symbol conflicts with other security modules or existing kernel components, leading to module load failures or system instability.
-   **Mitigation**: Ensure all symbols in `fwguard_km` are prefixed (e.g., `fwguard_`). Implement robust conflict detection mechanisms during module loading. Document known conflicts and potential workarounds.

## 3. HAP Platform Support

-   **Impact**: Not all Intel platforms support the HAP (High Assurance Platform) bit for ME disablement. Operations attempting to set the HAP bit on unsupported hardware will fail.
-   **Mitigation**: Implement a pre-check to determine HAP bit availability on the specific hardware before attempting modification. Provide clear, user-friendly error messages if the feature is not supported.

## 4. GRUB Complexity

-   **Impact**: FirmwareGuard's GRUB configuration management may not fully support or might break highly customized GRUB setups (e.g., encrypted `/boot` partitions, complex multi-boot configurations).
-   **Mitigation**: Emphasize the dry-run mode for GRUB modifications. Strongly recommend users to back up their GRUB configuration before applying changes. Document known incompatibilities and provide guidance for manual configuration for advanced users.

## 5. Race Conditions in Backup Registry

-   **Impact**: The backup registry is not fully protected against concurrent access. While FirmwareGuard is primarily a single-user tool, a rapid sequence of operations or unusual system events could theoretically lead to backup corruption.
-   **Mitigation**: Implement file locking (e.g., `flock()`) on the backup registry files to ensure atomicity and prevent race conditions, especially before writing or modifying backup metadata.

---

**Last Updated:** 2025-11-22
