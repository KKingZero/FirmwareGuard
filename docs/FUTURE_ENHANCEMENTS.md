# FirmwareGuard Future Enhancements

This document outlines recommended enhancements for future development, as identified in the Phase 2 Implementation Report.

## 1. ~~Cryptographic Checksums for Backups~~ (IMPLEMENTED)

-   **Status**: Implemented. `safety_calculate_checksum()` (weak CRC32-like hash) has been replaced with `safety_calculate_hash()` using OpenSSL SHA-256. The `backup_entry_t.checksum` field is now `uint8_t[32]` with a `checksum_version` field. All backup creation, restoration, verification, and listing functions have been updated. Old registry files will be detected as corrupted and re-initialized (acceptable — re-verifying with SHA-256 is better than trusting old weak checksums).

## 2. ~~File Locking for Backup Registry~~ (ALREADY IMPLEMENTED)

-   **Status**: Already implemented. `safety_save_registry()` acquires `LOCK_EX` and `safety_load_registry()` acquires `LOCK_SH` via `flock()` on the registry file descriptor, with proper error handling and unlock-on-close.

---

**Last Updated:** 2026-02-08
