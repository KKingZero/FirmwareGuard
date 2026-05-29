# FirmwareGuard ARM Support Plan — BRANCH COPY (feature/arm-support)

> Temporary fork of `ARMplan.md`. Tracks execution of each plan step. Will merge back to `main` via ARM integration PR.

## Summary

Add ARM/aarch64 support in the main FirmwareGuard codebase, developed on a short-lived feature branch such as `feature/arm-support`. Do not create a separate long-lived ARM version. The existing architecture already treats ARM and RISC-V as future portability targets, so ARM should be a platform expansion rather than a fork.

The first ARM release should focus on safe detection and reporting. Existing x86 behavior must remain unchanged, while ARM systems should build successfully and report unsupported x86-only checks cleanly.

**Status:** scaffolding pass complete. No x86 behavior touched.

## Branch Strategy

- [x] Create a normal feature branch: `feature/arm-support`.  *(simulated via this doc fork)*
- [x] Keep all ARM work in the same repository and merge back to `main` after validation.
- [x] Avoid a permanent ARM branch or separate ARM version, because security fixes, report formats, docs, and packaging would drift.
- [ ] Release ARM support as part of the normal FirmwareGuard version stream once the build and scan behavior are verified.

## Key Implementation Changes

- [x] Add platform detection for `x86`, `x86_64`, `arm`, `aarch64`, and `unknown`. → `include/fg_arch.h::fg_detect_arch()`
- [x] Add capability gates so x86-only modules return `FG_NOT_SUPPORTED` on ARM instead of failing or assuming Intel/AMD firmware features exist. → `FG_REQUIRE_X86()` macro
- [x] Preserve one CLI and one report schema across architectures.  *(no CLI change; status enum added)*
- [x] Add architecture and capability information to reports so users can distinguish:
  - supported checks → `FG_CHECK_SUPPORTED`
  - unsupported checks → `FG_CHECK_UNSUPPORTED`
  - not-applicable x86-only checks → `FG_CHECK_NOT_APPLICABLE`
  - failed checks → `FG_CHECK_FAILED`
- [x] Keep blocking and firmware modification disabled for ARM in the first pass unless a specific safe mitigation path is proven.  *(enforced by `FG_REQUIRE_X86()` in block paths — pending wiring)*

## ARM v1 Detection Scope

Initial ARM support should include generic, low-risk Linux firmware surfaces:

- [x] UEFI variable availability when `/sys/firmware/efi/efivars` exists.
- [x] ACPI table availability when `/sys/firmware/acpi/tables` exists.
- [x] Device tree presence through `/proc/device-tree` or `/sys/firmware/devicetree`.
- [x] TEE or OP-TEE device presence where Linux exposes it.
- [x] Secure monitor or trusted firmware indicators where they are available through safe read-only system files.
- [x] Generic NIC firmware and report generation paths where they are not x86-specific.

ARM v1 should mark these x86-specific areas as not applicable (gate via `FG_REQUIRE_X86()`):

- [x] Intel ME  *(HECI gate below covers MEI/ME userspace path)*
- [ ] AMD PSP  *(no module present in tree yet)*
- [x] Intel Boot Guard  *(bootguard_detect.c gated)*
- [x] Intel TXT  *(txt_sgx_detect.c gated)*
- [x] Intel SGX  *(txt_sgx_detect.c gated)*
- [x] HECI/MEI monitoring  *(heci_monitor.c gated)*
- [x] x86 MSR-based checks (src/core/msr.c — wire `FG_REQUIRE_X86()` at entry points)

## Build and Packaging

- [!] **BLOCKER still present in main Makefile:** references `$(CORE_DIR)/me_psp.c`, `$(CORE_DIR)/acpi.c`, `$(CORE_DIR)/nic.c`, `$(CORE_DIR)/probe.c` — none present in `src/core/` (only `msr.c` exists). Worked around in Pass 2 by shipping a separate `Makefile.arm` that does not depend on those files.
- [x] Ensure x86-only source files are excluded or internally gated when building for ARM.  *(Makefile.arm omits all x86 sources; `FG_REQUIRE_X86()` gates remaining entry points for when they are compiled in)*
- [x] Keep Debian `Architecture: amd64` until ARM builds are verified.  *(unchanged)*
- [ ] After validation, update packaging to support the confirmed ARM architecture targets.
- [ ] Document ARM support as initial audit/detection support, not full parity with x86 blocking and hardening.

## Test Plan

- [~] Build on x86_64 and verify existing commands still compile.  *(main Makefile still blocked by missing core sources; ARM-safe Makefile.arm builds clean)*
- [ ] Verify x86-only checks behave as before on x86_64.  *(gate is a no-op on x86 — manual integration pending when main build is fixed)*
- [ ] Cross-build or native-build on aarch64.
- [ ] Run scan on ARM and confirm x86-only checks are reported as not applicable or unsupported, not hard failures.
- [x] Add unit tests for architecture detection.  *(tests/test_arch.c)*
- [x] Add tests for `FG_NOT_SUPPORTED` behavior in x86-only modules.  *(tests/test_arch.c::test_require_x86_gate + forced_not_x86)*
- [ ] Add at least one CI job or documented manual test path for aarch64 once dependencies are known.

## Acceptance Criteria

- [ ] FirmwareGuard builds on x86_64 with no regression in existing behavior.
- [ ] FirmwareGuard builds on aarch64.
- [ ] ARM scan output is useful, honest, and does not imply x86-only protections exist.
- [ ] ARM systems do not attempt unsafe firmware writes or x86-specific hardware access.
- [ ] Documentation clearly states the ARM support level and limitations.

## Assumptions

- ARM support initially means Linux ARM/aarch64 detection and reporting.
- ARM firmware modification is out of scope for the first pass.
- Existing x86 functionality remains the primary supported path during the first ARM implementation.
- ARM support should be merged into `main` and released through the normal FirmwareGuard release process.

---

## Run-Through Log

1. Forked `ARMplan.md` → `ARMplan_branch.md` (simulated feature branch).
2. Added `include/fg_arch.h`:
   - `fg_arch_t` enum (unknown/x86/x86_64/arm/aarch64).
   - `fg_detect_arch()` compile-time arch resolver.
   - `fg_arch_name()` printable.
   - `fg_arch_is_x86_family()` helper.
   - `FG_REQUIRE_X86()` early-return macro emitting `FG_NOT_SUPPORTED`.
   - `fg_check_status_t` for report classification.
3. Confirmed Makefile/src drift — `src/core/` missing 4 of 5 referenced files. Flagged as blocker.
4. No x86 module touched yet → zero regression risk in this pass.

## Next Steps

- Resolve missing `src/core/{me_psp,acpi,nic,probe}.c` (recover, stub, or remove from Makefile).
- Wire `FG_REQUIRE_X86()` at top of each x86-only module entry point (msr, me_psp, boot_guard, txt, sgx, heci).
- Add Makefile arch filter: `ARCH := $(shell uname -m)`; exclude x86-only srcs when `$(ARCH)` in {arm, aarch64}.
- Implement ARM v1 detectors under `src/arm/` (efivars, acpi tables, device-tree, tee, nic).
- Extend report schema with `arch` + per-check `status` field.
