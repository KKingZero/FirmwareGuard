# FirmwareGuard Security Audit Report
**Date:** 2025-11-26
**Auditor:** Claude Code
**Version Tested:** v0.1.0-MVP (Build from source)
**Codebase Size:** ~5,169 lines of C code

---

## Executive Summary

FirmwareGuard is a security-focused firmware telemetry detection tool written in C. The codebase demonstrates **good security practices** overall, but several **critical vulnerabilities** and weaknesses were identified that require immediate attention.

**Overall Security Rating:** ⚠️ **MODERATE** (6/10)

### Key Findings
- ✅ **Strengths:** Security-hardened compilation, proper privilege checking, safe string functions
- ⚠️ **Critical Issues:** 1 command injection vulnerability, 1 TOCTOU race condition
- ⚠️ **Logic Bugs:** Blocking logic doesn't handle inactive-but-blockable components
- ⚠️ **Moderate Issues:** Missing input validation, ignored system() return values

---

## 1. Critical Vulnerabilities (IMMEDIATE FIX REQUIRED)

### 🔴 CRITICAL: Command Injection in blocker.c

**Location:** `src/block/blocker.c:93-94`

```c
snprintf(cmd, sizeof(cmd), "ethtool -s %s wol d 2>/dev/null", interface);
ret = system(cmd);
```

**Vulnerability:** The `interface` parameter is directly interpolated into a shell command without validation.

**Exploitation Scenario:**
```c
// Malicious interface name from audit data
interface = "eth0; rm -rf / #"
// Resulting command: ethtool -s eth0; rm -rf / # wol d 2>/dev/null
```

**Impact:** **CRITICAL** - Arbitrary command execution as root (since FirmwareGuard runs with sudo)

**Recommended Fix:**
```c
// Whitelist validation
if (!is_valid_interface_name(interface)) {
    FG_LOG_ERROR("Invalid interface name: %s", interface);
    return FG_ERROR;
}

// Use secure_execute() instead of system()
char *args[] = {"ethtool", "-s", interface, "wol", "d", NULL};
secure_execute("/usr/sbin/ethtool", args);
```

**Status:** ❌ **UNPATCHED**

---

### 🔴 HIGH: Predictable Temporary File Creation (TOCTOU)

**Location:** `src/grub/grub_config.c:305-313`

```c
snprintf(temp_file, sizeof(temp_file), "%s.tmp", config->grub_file);
// ... time passes (TOCTOU window) ...
fp_out = fopen(temp_file, "w");
```

**Vulnerability:** Predictable temp file name allows symlink attack.

**Exploitation Scenario:**
1. Attacker predicts temp file path: `/etc/default/grub.tmp`
2. Attacker creates symlink: `ln -s /etc/shadow /etc/default/grub.tmp`
3. FirmwareGuard writes GRUB config to `/etc/shadow` → system compromise

**Impact:** **HIGH** - File overwrite vulnerability, potential privilege escalation

**Recommended Fix:**
```c
// Use mkstemp() for secure temp file creation
char temp_file[] = "/tmp/fwguard-grub-XXXXXX";
int fd = mkstemp(temp_file);
if (fd == -1) {
    FG_LOG_ERROR("Failed to create secure temp file");
    return FG_ERROR;
}
fp_out = fdopen(fd, "w");
```

**Status:** ❌ **UNPATCHED**

---

## 2. High Priority Issues

### 🟠 Command Injection in grub_config.c

**Location:** `src/grub/grub_config.c:126-128`

```c
snprintf(cp_cmd, sizeof(cp_cmd), "cp -a %s %s", GRUB_DEFAULT_FILE, timestamp_backup);
if (system(cp_cmd) == 0) {
```

**Issue:** Uses `system()` which invokes a shell. While `GRUB_DEFAULT_FILE` is a constant, `timestamp_backup` is constructed from `strftime()` which *should* be safe, but best practice is to avoid `system()` entirely.

**Note:** Partial mitigation exists - a `secure_execute()` function is implemented starting at line 357 but **not used here**.

**Recommended Fix:** Replace with `secure_execute()` or direct `execve()` call.

**Status:** ⚠️ **PARTIAL** (safe input but dangerous pattern)

---

### 🟠 Ignored system() Return Value

**Location:** `src/core/msr.c:38`

```c
system("modprobe msr 2>/dev/null");  // Return value ignored
```

**Issue:** Compiler warning: "ignoring return value of 'system' declared with attribute 'warn_unused_result'"

**Impact:** **MEDIUM** - Tool may proceed without required MSR module loaded, leading to silent failures.

**Recommended Fix:**
```c
int ret = system("modprobe msr 2>/dev/null");
if (ret != 0) {
    FG_WARN("Failed to load MSR module (error: %d), some features may not work", ret);
}
```

**Status:** ❌ **UNPATCHED**

---

## 3. Logic Bugs

### 🟡 Inactive Components Not Blocked

**Location:** `src/block/blocker.c:134-139`

```c
for (int i = 0; i < audit->num_components; i++) {
    const component_status_t *comp = &audit->components[i];

    if (!comp->detected || !comp->active) {
        continue;  // BUG: Skips inactive but blockable components
    }
```

**Bug:** Intel ME shows as "Inactive" and "Blockable: Yes" but generates **0 blocking actions**.

**Test Results:**
```
[1] Intel Management Engine
    Status:    Inactive
    Blockable: Yes

[INFO] 0 blocking actions generated: 0 successful, 0 failed/recommendations
```

**Expected Behavior:** Should offer to block inactive ME to prevent re-enablement.

**Impact:** **MEDIUM** - Reduced functionality, users can't proactively block dormant telemetry.

**Recommended Fix:**
```c
// Option 1: Remove the active check for blockable components
if (!comp->detected) {
    continue;
}

// Option 2: Add logic to handle inactive-but-blockable components
if (!comp->active && comp->blockable) {
    // Generate preventative blocking action
}
```

**Status:** ❌ **BUG CONFIRMED**

---

## 4. Code Quality Issues

### Compilation Warnings Summary

**Total Warnings:** 15 (non-critical but should be addressed)

| Warning Type | Count | Severity |
|--------------|-------|----------|
| Sign comparison | 2 | Low |
| Unused variables | 4 | Low |
| String truncation | 5 | Info (expected with strncpy) |
| Unused parameters | 4 | Low |
| Missing include (isalnum) | 1 | Medium |

**Priority Fixes:**

1. **Missing `<ctype.h>` include** (`src/safety/safety.c:168`)
   ```c
   // Current: Implicit declaration of isalnum
   // Fix: Add #include <ctype.h>
   ```

2. **Sign comparison warnings** (`src/core/msr.c:66, 110`)
   ```c
   // Current: if (cpu >= cpu_count)  // uint32_t vs int
   // Fix: Make cpu_count unsigned or cast properly
   ```

---

## 5. Input Validation Assessment

### ✅ Good Practices Found

1. **Kernel parameter validation** (`src/grub/grub_config.c:199-204`)
   ```c
   if (strchr(param, ';') || strchr(param, '&') || strchr(param, '|') ||
       strchr(param, '`') || strchr(param, '$') || strchr(param, '\n')) {
       FG_LOG_ERROR("Invalid kernel parameter (contains dangerous characters)");
       return FG_ERROR;
   }
   ```

2. **Backup name whitelist** (`src/safety/safety.c:167-172`)
   ```c
   for (const char *p = name; *p; p++) {
       if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') {
           FG_LOG_ERROR("Invalid backup name character '%c'", *p);
           return FG_ERROR;
       }
   }
   ```

### ❌ Missing Validation

1. **Network interface names** (`src/block/blocker.c:78-93`)
   - ❌ No validation before passing to `system()`
   - **FIX:** Add `is_valid_interface_name()` function

2. **File path validation** (multiple locations)
   - ⚠️ Relies on snprintf() bounds checking but doesn't validate for path traversal
   - **RECOMMENDATION:** Add path canonicalization checks

---

## 6. Memory Safety Analysis

### ✅ Strengths

1. **Proper cleanup:** All allocated memory has corresponding `free()` calls
2. **Bounds checking:** Consistent use of `sizeof()` and buffer size validation
3. **Safe string functions:** Uses `strncpy()`, `snprintf()` throughout

### ⚠️ Potential Issues

1. **Buffer allocation** (`src/grub/grub_config.c:153-156`)
   ```c
   size = (size_t)st.st_size;
   data = malloc(size);
   if (!data) {
       return FG_ERROR;  // ✅ Good: Checks for NULL
   }
   ```
   ✅ Properly validates size limits (line 148: max 1MB for GRUB config)

2. **No memory leaks detected** in primary code paths (based on static analysis)

---

## 7. Privilege Handling

### ✅ Proper Implementation

```c
// include/firmwareguard.h:75-81
static inline int fg_require_root(void) {
    if (geteuid() != 0) {
        FG_LOG_ERROR("This operation requires root privileges");
        return FG_NO_PERMISSION;
    }
    return FG_SUCCESS;
}
```

**Analysis:**
- ✅ Uses `geteuid()` (effective UID) instead of `getuid()` - **CORRECT**
- ✅ Checks before privileged operations
- ✅ Clear error messages

**No privilege escalation vulnerabilities found.**

---

## 8. Build & Compilation Security

### ✅ Excellent Security Hardening

**Makefile Security Flags:**
```makefile
SECURITY_FLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
                 -Wformat -Wformat-security -fPIE \
                 -Wshadow -Wpointer-arith -Wcast-qual
LDFLAGS = -lm -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
```

**Analysis:**
- ✅ Stack canaries: `-fstack-protector-strong`
- ✅ Buffer overflow detection: `-D_FORTIFY_SOURCE=2`
- ✅ Position Independent Executable: `-fPIE -pie`
- ✅ Full RELRO: `-Wl,-z,relro,-z,now`
- ✅ Non-executable stack: `-Wl,-z,noexecstack`

**Verification:**
```bash
$ make
✅ Offline-only verification passed
✅ Binary: ./firmwareguard
```

**Rating:** ⭐⭐⭐⭐⭐ Excellent build security

---

## 9. Functional Testing Results

### Test Environment
- **System:** Linux 6.14.0-36-generic
- **CPU:** Intel (16 cores)
- **Privilege:** sudo (with password)

### Scan Test Results

```bash
$ sudo ./firmwareguard scan

✅ SUCCESS: Scan completed
✅ Detected: Intel ME (Inactive), TPM2, DMAR, FPDT, 5 NICs
✅ Risk Assessment: MEDIUM
✅ Output Format: Human-readable text (proper formatting)
```

### JSON Output Test

```bash
$ sudo ./firmwareguard scan --json

✅ SUCCESS: Valid JSON output
✅ Schema: Proper structure with components array
⚠️ WARNING: -o flag doesn't work (file not created)
```

**BUG FOUND:** JSON output flag `-o` fails silently (no file created at specified path)

### Blocking Test

```bash
$ sudo ./firmwareguard block

✅ No crashes
❌ BUG: Generates 0 blocking actions despite ME being blockable
🐛 Root cause: Inactive components skipped by blocker logic
```

---

## 10. Offline-Only Architecture Verification

### ✅ VERIFIED: No Network Code

**Audit Command:**
```bash
$ grep -r "socket\|connect\|listen\|bind\|http\|curl" src/
# Result: Only found in comments and nic.c for ioctl() hardware probing
```

**Network Usage Analysis:**
- ✅ No `socket()` calls for network communication
- ✅ `socket()` in `nic.c` is for `ioctl()` only (hardware info retrieval)
- ✅ No HTTP/TCP/UDP protocols
- ✅ No external dependencies on network libraries

**Makefile Verification:**
```bash
✅ Offline-only verification passed
   Note: socket() usage in nic.c is for local ioctl hardware probing only
```

**Rating:** ⭐⭐⭐⭐⭐ True offline-only design verified

---

## 11. Recommendations by Priority

### 🔴 CRITICAL (Fix Immediately)

1. **Fix command injection in blocker.c:93**
   - Replace `system()` with `secure_execute()` or direct exec
   - Add interface name validation
   - **Estimated time:** 30 minutes

2. **Fix TOCTOU in grub_config.c:305**
   - Use `mkstemp()` for secure temp files
   - **Estimated time:** 20 minutes

### 🟠 HIGH (Fix Soon)

3. **Replace all `system()` calls**
   - Use existing `secure_execute()` function (line 357)
   - **Estimated time:** 1 hour

4. **Fix blocking logic bug**
   - Handle inactive-but-blockable components
   - **Estimated time:** 30 minutes

5. **Fix JSON -o flag**
   - Debug file creation issue
   - **Estimated time:** 15 minutes

### 🟡 MEDIUM (Address in Next Release)

6. **Add missing `#include <ctype.h>`** in safety.c
7. **Fix sign comparison warnings** in msr.c
8. **Handle system() return values** properly

### 🟢 LOW (Code Quality Improvements)

9. **Remove unused variables and parameters**
10. **Add network interface name validation**
11. **Improve error messages** for better debugging

---

## 12. Security Best Practices Already Implemented

✅ **Excellent practices found:**

1. Security-hardened compilation flags
2. Proper use of `strncpy()` and `snprintf()`
3. Bounds checking before buffer operations
4. Privilege checking with `geteuid()`
5. Dry-run mode for safe testing
6. Automatic backups before modifications
7. Input validation in critical paths (kernel params, backup names)
8. No hardcoded secrets or credentials
9. Clear separation of user/kernel space
10. Comprehensive logging

---

## 13. Conclusion

FirmwareGuard demonstrates **strong security awareness** in its design, with excellent compilation hardening and a true offline-only architecture. However, **critical vulnerabilities exist** that must be addressed before production use:

### Summary

| Category | Rating | Notes |
|----------|--------|-------|
| **Architecture** | ⭐⭐⭐⭐⭐ | Excellent offline-only design |
| **Build Security** | ⭐⭐⭐⭐⭐ | Full hardening flags |
| **Input Validation** | ⭐⭐⭐☆☆ | Good but inconsistent |
| **Memory Safety** | ⭐⭐⭐⭐☆ | Solid, no leaks found |
| **Privilege Handling** | ⭐⭐⭐⭐⭐ | Correct implementation |
| **Command Injection** | ⭐☆☆☆☆ | **CRITICAL VULNERABILITY** |
| **Overall** | ⭐⭐⭐☆☆ | **6/10 - MODERATE** |

### Final Verdict

**Not recommended for production use** until critical vulnerabilities are patched.

**Estimated fix time:** ~3 hours for all critical issues.

---

## Appendix A: Detailed Vulnerability Catalog

| ID | Severity | Location | Type | Status |
|----|----------|----------|------|--------|
| FG-2025-001 | CRITICAL | blocker.c:93 | Command Injection | Open |
| FG-2025-002 | HIGH | grub_config.c:305 | TOCTOU Race | Open |
| FG-2025-003 | HIGH | grub_config.c:128 | Unsafe system() | Open |
| FG-2025-004 | MEDIUM | msr.c:38 | Ignored Return | Open |
| FG-2025-005 | MEDIUM | blocker.c:137 | Logic Bug | Open |
| FG-2025-006 | MEDIUM | main.c (JSON -o) | Feature Bug | Open |
| FG-2025-007 | LOW | safety.c:168 | Missing Include | Open |

---

**Report Generated:** 2025-11-26
**Next Audit Recommended:** After critical fixes are applied
