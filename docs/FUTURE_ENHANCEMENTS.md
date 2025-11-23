# FirmwareGuard Future Enhancements

This document outlines recommended enhancements for future development, as identified in the Phase 2 Implementation Report.

## 1. Cryptographic Checksums for Backups

-   **Description**: Replace the current CRC32 checksums used for backups with a cryptographically stronger hashing algorithm like SHA-256.
-   **Rationale**: SHA-256 provides a much higher level of collision resistance and cryptographic security, making backups more robust against accidental corruption and malicious tampering.
-   **Implementation Notes**:
    -   Update the `src/safety/safety.c` and `src/safety/safety.h` files.
    -   Integrate a SHA-256 library (e.g., from OpenSSL or a lightweight standalone implementation).
    -   Ensure backward compatibility with existing CRC32 backups (if deemed necessary) or provide a migration path.

## 2. File Locking for Backup Registry

-   **Description**: Add file locking mechanisms to the backup registry to prevent race conditions during concurrent access.
-   **Rationale**: While FirmwareGuard is primarily a single-user tool, adding file locking (e.g., using `flock()`) will enhance the robustness of the backup system, particularly in scenarios where multiple processes or rapid sequential operations might attempt to interact with the backup registry.
-   **Implementation Notes**:
    -   Update the `src/safety/safety.c` functions that access or modify the backup registry files.
    -   Implement `flock(fd, LOCK_EX)` before critical sections and `flock(fd, LOCK_UN)` afterwards.
    -   Handle potential deadlocks and error conditions gracefully.

---

**Last Updated:** 2025-11-22
