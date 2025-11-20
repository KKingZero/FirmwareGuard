# Contributing to FirmwareGuard

Thank you for your interest in contributing to FirmwareGuard!

## How to Contribute

### Reporting Issues

**Before submitting:**
- Check existing issues for duplicates
- Gather system information
- Include full error output

**Issue template:**
```
**System Information:**
- OS: [e.g., Ubuntu 22.04]
- Kernel: [uname -r]
- CPU: [Intel/AMD, model]
- FirmwareGuard version: [e.g., 0.1.0-MVP]

**Problem Description:**
[Clear description of the issue]

**Steps to Reproduce:**
1. Run command X
2. Observe error Y

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happened]

**Output:**
```
[paste full output here]
```
```

### Adding New Hardware Probes

**Example: Add IPMI Detection**

1. **Create module files:**
```bash
touch src/core/ipmi.h
touch src/core/ipmi.c
```

2. **Define interface (ipmi.h):**
```c
#ifndef FG_IPMI_H
#define FG_IPMI_H

#include "../../include/firmwareguard.h"

typedef struct {
    bool present;
    bool enabled;
    char version[64];
} ipmi_info_t;

int probe_ipmi(ipmi_info_t *info);

#endif
```

3. **Implement detection (ipmi.c):**
```c
#include "ipmi.h"

int probe_ipmi(ipmi_info_t *info) {
    // Check /dev/ipmi0
    // Parse DMI tables
    // Detect IPMI interfaces
    return FG_SUCCESS;
}
```

4. **Integrate into probe.c:**
```c
#include "core/ipmi.h"

int probe_scan_hardware(probe_result_t *result) {
    // ... existing code ...

    ipmi_info_t ipmi;
    if (probe_ipmi(&ipmi) == FG_SUCCESS) {
        result->ipmi_present = true;
        // Add to components
    }
}
```

5. **Update Makefile:**
```makefile
CORE_SRCS = ... \
            $(CORE_DIR)/ipmi.c
```

6. **Update risk scoring:**
```c
risk_level_t probe_assess_risk(const probe_result_t *result) {
    // ...
    if (result->ipmi_present && result->ipmi.enabled) {
        risk_score += 2;  // MEDIUM risk
    }
}
```

7. **Document:**
- Update README.md
- Update ARCHITECTURE.md
- Add to QUICKSTART.md examples

### Code Style Guidelines

**Formatting:**
```c
// Function names: lowercase_with_underscores
int probe_intel_me(intel_me_info_t *info);

// Constants: UPPERCASE_WITH_UNDERSCORES
#define MSR_IA32_FEATURE_CONTROL 0x0000003A

// Structs: lowercase_with_underscores_t
typedef struct {
    bool active;
    char version[64];
} component_info_t;

// Indentation: 4 spaces (NO TABS)
if (condition) {
    do_something();
    if (nested_condition) {
        do_nested_thing();
    }
}
```

**Comments:**
```c
/* Multi-line comments for function documentation */
int important_function(void) {
    /* Explain complex logic */

    // Single-line comments for brief notes
    return value;
}
```

**Error handling:**
```c
int my_function(void) {
    if (error_condition) {
        FG_LOG_ERROR("Descriptive error message");
        return FG_ERROR;
    }

    if (not_found) {
        FG_DEBUG("Not critical, just informational");
        return FG_NOT_FOUND;
    }

    return FG_SUCCESS;
}
```

### Testing Contributions

**Manual testing:**
```bash
# Build with debug symbols
make debug

# Test on your hardware
sudo ./firmwareguard scan

# Test JSON output
sudo ./firmwareguard scan --json | jq .

# Verify blocking recommendations
sudo ./firmwareguard block
```

**Hardware diversity:**
- Test on Intel systems
- Test on AMD systems
- Test on VMs (if applicable)
- Document tested platforms in PR

### Pull Request Process

1. **Fork the repository**
2. **Create feature branch:**
   ```bash
   git checkout -b feature/ipmi-detection
   ```

3. **Make changes:**
   - Follow code style
   - Add documentation
   - Test thoroughly

4. **Commit with clear messages:**
   ```bash
   git commit -m "Add IPMI detection module

   - Detects IPMI via /dev/ipmi0
   - Parses DMI tables for BMC info
   - Adds MEDIUM risk for active IPMI
   - Tested on Dell PowerEdge R720"
   ```

5. **Push and create PR:**
   ```bash
   git push origin feature/ipmi-detection
   # Then create PR on GitHub
   ```

6. **PR description template:**
   ```markdown
   ## Description
   Adds IPMI detection capability to identify Baseboard Management Controllers.

   ## Motivation
   IPMI provides out-of-band access and can be a telemetry vector.

   ## Changes
   - Added src/core/ipmi.c and ipmi.h
   - Integrated into probe orchestrator
   - Updated risk scoring (+2 for active IPMI)

   ## Testing
   - Tested on: Dell PowerEdge R720 (IPMI 2.0)
   - Tested on: Desktop without IPMI (correctly reports not found)
   - Tested on: VM (no IPMI device)

   ## Documentation
   - Updated README.md
   - Updated ARCHITECTURE.md
   - Added QUICKSTART.md example
   ```

### Areas for Contribution

**High Priority:**
- [ ] Windows support (basic detection)
- [ ] ARM platform detection
- [ ] UEFI variable parsing
- [ ] SMM (System Management Mode) detection
- [ ] Boot Guard detection
- [ ] Unit tests framework

**Medium Priority:**
- [ ] Web dashboard for reports
- [ ] Kernel module for DMA restriction
- [ ] Persistent blocking configurations
- [ ] Fleet management tools

**Nice to Have:**
- [ ] MacOS support
- [ ] RISC-V platform support
- [ ] Automated firmware dumping
- [ ] Integration with vulnerability scanners

### Code Review Criteria

**We check for:**
- ✅ Code follows style guide
- ✅ No unnecessary privileges requested
- ✅ Error handling is robust
- ✅ Documentation is complete
- ✅ Backward compatibility maintained
- ✅ No hardcoded paths (use sysfs when possible)
- ✅ Memory leaks prevented (valgrind clean)

### License

By contributing, you agree that your contributions will be licensed under the MIT License.

### Questions?

- Open a discussion on GitHub
- Email: dev@firmwareguard.dev
- IRC: #firmwareguard on Libera.Chat

---

**Thank you for contributing to hardware security!**
