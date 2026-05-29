# FirmwareGuard ARM Support Plan

## Summary

Add ARM/aarch64 support in the main FirmwareGuard codebase, developed on a short-lived feature branch such as `feature/arm-support`. Do not create a separate long-lived ARM version. The existing architecture already treats ARM and RISC-V as future portability targets, so ARM should be a platform expansion rather than a fork.

The first ARM release should focus on safe detection and reporting. Existing x86 behavior must remain unchanged, while ARM systems should build successfully and report unsupported x86-only checks cleanly.

## Branch Strategy

- Create a normal feature branch: `feature/arm-support`.
- Keep all ARM work in the same repository and merge back to `main` after validation.
- Avoid a permanent ARM branch or separate ARM version, because security fixes, report formats, docs, and packaging would drift.
- Release ARM support as part of the normal FirmwareGuard version stream once the build and scan behavior are verified.

## Key Implementation Changes

- Add platform detection for `x86`, `x86_64`, `arm`, `aarch64`, and `unknown`.
- Add capability gates so x86-only modules return `FG_NOT_SUPPORTED` on ARM instead of failing or assuming Intel/AMD firmware features exist.
- Preserve one CLI and one report schema across architectures.
- Add architecture and capability information to reports so users can distinguish:
  - supported checks
  - unsupported checks
  - not-applicable x86-only checks
  - failed checks
- Keep blocking and firmware modification disabled for ARM in the first pass unless a specific safe mitigation path is proven.

## ARM v1 Detection Scope

Initial ARM support should include generic, low-risk Linux firmware surfaces:

- UEFI variable availability when `/sys/firmware/efi/efivars` exists.
- ACPI table availability when `/sys/firmware/acpi/tables` exists.
- Device tree presence through `/proc/device-tree` or `/sys/firmware/devicetree`.
- TEE or OP-TEE device presence where Linux exposes it.
- Secure monitor or trusted firmware indicators where they are available through safe read-only system files.
- Generic NIC firmware and report generation paths where they are not x86-specific.

ARM v1 should mark these x86-specific areas as not applicable:

- Intel ME
- AMD PSP
- Intel Boot Guard
- Intel TXT
- Intel SGX
- HECI/MEI monitoring
- x86 MSR-based checks

## Build and Packaging

- First make the current build state explicit, because the Makefile references several `src/core` files and headers that are not present in the checked-out tree.
- Ensure x86-only source files are excluded or internally gated when building for ARM.
- Keep Debian `Architecture: amd64` until ARM builds are verified.
- After validation, update packaging to support the confirmed ARM architecture targets.
- Document ARM support as initial audit/detection support, not full parity with x86 blocking and hardening.

## Test Plan

- Build on x86_64 and verify existing commands still compile.
- Verify x86-only checks behave as before on x86_64.
- Cross-build or native-build on aarch64.
- Run scan on ARM and confirm x86-only checks are reported as not applicable or unsupported, not hard failures.
- Add unit tests for architecture detection.
- Add tests for `FG_NOT_SUPPORTED` behavior in x86-only modules.
- Add at least one CI job or documented manual test path for aarch64 once dependencies are known.

## Acceptance Criteria

- FirmwareGuard builds on x86_64 with no regression in existing behavior.
- FirmwareGuard builds on aarch64.
- ARM scan output is useful, honest, and does not imply x86-only protections exist.
- ARM systems do not attempt unsafe firmware writes or x86-specific hardware access.
- Documentation clearly states the ARM support level and limitations.

## Assumptions

- ARM support initially means Linux ARM/aarch64 detection and reporting.
- ARM firmware modification is out of scope for the first pass.
- Existing x86 functionality remains the primary supported path during the first ARM implementation.
- ARM support should be merged into `main` and released through the normal FirmwareGuard release process.
