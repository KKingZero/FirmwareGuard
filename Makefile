# FirmwareGuard Makefile - Phase 2
# Low-level firmware telemetry detection and active blocking framework

CC = gcc
# Security hardening flags
SECURITY_FLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
                 -Wformat -Wformat-security -fPIE \
                 -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS = -Wall -Wextra -O2 -std=gnu11 -Iinclude -D_GNU_SOURCE $(SECURITY_FLAGS)
LDFLAGS = -lm -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
INSTALL = install
INSTALL_DIR = /usr/local/bin
SYSTEMD_DIR = /etc/systemd/system
CONFIG_DIR = /etc/firmwareguard

# Directories
SRC_DIR = src
BUILD_DIR = build
CORE_DIR = $(SRC_DIR)/core
BLOCK_DIR = $(SRC_DIR)/block
AUDIT_DIR = $(SRC_DIR)/audit
SAFETY_DIR = $(SRC_DIR)/safety
CONFIG_MGMT_DIR = $(SRC_DIR)/config
UEFI_DIR = $(SRC_DIR)/uefi
GRUB_DIR = $(SRC_DIR)/grub
KERNEL_DIR = kernel

# Target binary
TARGET = firmwareguard

# Phase 1 sources
CORE_SRCS = $(CORE_DIR)/msr.c \
            $(CORE_DIR)/me_psp.c \
            $(CORE_DIR)/acpi.c \
            $(CORE_DIR)/nic.c \
            $(CORE_DIR)/probe.c

BLOCK_SRCS = $(BLOCK_DIR)/blocker.c

AUDIT_SRCS = $(AUDIT_DIR)/reporter.c

# Phase 2 sources
SAFETY_SRCS = $(SAFETY_DIR)/safety.c

CONFIG_MGMT_SRCS = $(CONFIG_MGMT_DIR)/config.c

UEFI_SRCS = $(UEFI_DIR)/uefi_vars.c

GRUB_SRCS = $(GRUB_DIR)/grub_config.c

MAIN_SRC = $(SRC_DIR)/main.c

# All sources
ALL_SRCS = $(CORE_SRCS) $(BLOCK_SRCS) $(AUDIT_SRCS) $(SAFETY_SRCS) \
           $(CONFIG_MGMT_SRCS) $(UEFI_SRCS) $(GRUB_SRCS) $(MAIN_SRC)

# Object files
CORE_OBJS = $(patsubst $(CORE_DIR)/%.c,$(BUILD_DIR)/core_%.o,$(CORE_SRCS))
BLOCK_OBJS = $(patsubst $(BLOCK_DIR)/%.c,$(BUILD_DIR)/block_%.o,$(BLOCK_SRCS))
AUDIT_OBJS = $(patsubst $(AUDIT_DIR)/%.c,$(BUILD_DIR)/audit_%.o,$(AUDIT_SRCS))
SAFETY_OBJS = $(patsubst $(SAFETY_DIR)/%.c,$(BUILD_DIR)/safety_%.o,$(SAFETY_SRCS))
CONFIG_MGMT_OBJS = $(patsubst $(CONFIG_MGMT_DIR)/%.c,$(BUILD_DIR)/config_%.o,$(CONFIG_MGMT_SRCS))
UEFI_OBJS = $(patsubst $(UEFI_DIR)/%.c,$(BUILD_DIR)/uefi_%.o,$(UEFI_SRCS))
GRUB_OBJS = $(patsubst $(GRUB_DIR)/%.c,$(BUILD_DIR)/grub_%.o,$(GRUB_SRCS))
MAIN_OBJ = $(BUILD_DIR)/main.o

ALL_OBJS = $(CORE_OBJS) $(BLOCK_OBJS) $(AUDIT_OBJS) $(SAFETY_OBJS) \
           $(CONFIG_MGMT_OBJS) $(UEFI_OBJS) $(GRUB_OBJS) $(MAIN_OBJ)

# Default target
.PHONY: all
all: $(BUILD_DIR) $(TARGET)
	@echo ""
	@echo "========================================="
	@echo "  FirmwareGuard Phase 2 Build Complete"
	@echo "========================================="
	@echo "Binary: ./$(TARGET)"
	@echo ""
	@echo "To install system-wide: sudo make install"
	@echo "To build kernel module: make kernel"
	@echo ""

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Link final binary
$(TARGET): $(ALL_OBJS)
	@echo "Linking $@..."
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile rules for different directories
$(BUILD_DIR)/core_%.o: $(CORE_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/block_%.o: $(BLOCK_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/audit_%.o: $(AUDIT_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/safety_%.o: $(SAFETY_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/config_%.o: $(CONFIG_MGMT_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/uefi_%.o: $(UEFI_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/grub_%.o: $(GRUB_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/main.o: $(MAIN_SRC)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Build kernel module
.PHONY: kernel
kernel:
	@echo "Building FirmwareGuard kernel module..."
	@$(MAKE) -C $(KERNEL_DIR)
	@echo "Kernel module built: $(KERNEL_DIR)/fwguard_km.ko"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(TARGET)
	@$(MAKE) -C $(KERNEL_DIR) clean
	@echo "Clean complete"

# Install (requires root)
.PHONY: install
install: $(TARGET)
	@echo "Installing FirmwareGuard Phase 2..."
	@echo "  Installing binary to $(INSTALL_DIR)..."
	@$(INSTALL) -m 755 $(TARGET) $(INSTALL_DIR)/
	@echo "  Creating configuration directory..."
	@$(INSTALL) -d -m 755 $(CONFIG_DIR)
	@echo "  Creating state directory..."
	@$(INSTALL) -d -m 700 /var/lib/firmwareguard
	@$(INSTALL) -d -m 700 /var/lib/firmwareguard/backups
	@echo "  Installing systemd service..."
	@$(INSTALL) -m 644 systemd/firmwareguard.service $(SYSTEMD_DIR)/
	@systemctl daemon-reload
	@echo ""
	@echo "Installation complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit configuration: $(CONFIG_DIR)/config.conf"
	@echo "  2. Enable service: systemctl enable firmwareguard"
	@echo "  3. Start service: systemctl start firmwareguard"
	@echo ""
	@echo "To install kernel module:"
	@echo "  make kernel-install"
	@echo ""

# Install kernel module (requires root)
.PHONY: kernel-install
kernel-install: kernel
	@echo "Installing FirmwareGuard kernel module..."
	@$(MAKE) -C $(KERNEL_DIR) install
	@echo "Kernel module installed"

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Uninstalling FirmwareGuard..."
	@systemctl stop firmwareguard 2>/dev/null || true
	@systemctl disable firmwareguard 2>/dev/null || true
	@rm -f $(SYSTEMD_DIR)/firmwareguard.service
	@rm -f $(INSTALL_DIR)/$(TARGET)
	@systemctl daemon-reload
	@echo "Uninstall complete"
	@echo ""
	@echo "Configuration and backups preserved in:"
	@echo "  $(CONFIG_DIR)"
	@echo "  /var/lib/firmwareguard"
	@echo ""
	@echo "To remove configuration and backups:"
	@echo "  sudo rm -rf $(CONFIG_DIR) /var/lib/firmwareguard"

# Run tests (basic functionality check)
.PHONY: test
test: $(TARGET)
	@echo "Running Phase 2 functionality tests..."
	@./$(TARGET) --help
	@echo ""
	@echo "Test passed!"

# Debug build
.PHONY: debug
debug: CFLAGS += -g -DDEBUG -O0
debug: clean all

# Check code style and potential issues
.PHONY: check
check:
	@echo "Running static analysis..."
	@which cppcheck >/dev/null 2>&1 && cppcheck --enable=all --suppress=missingIncludeSystem $(SRC_DIR) || echo "cppcheck not installed"
	@echo ""

# Count lines of code
.PHONY: stats
stats:
	@echo "FirmwareGuard Code Statistics:"
	@echo "==============================="
	@echo ""
	@echo "C source files:"
	@find $(SRC_DIR) -name "*.c" | wc -l
	@echo ""
	@echo "Lines of code:"
	@find $(SRC_DIR) -name "*.c" -o -name "*.h" | xargs wc -l | tail -1
	@echo ""
	@echo "Binary size:"
	@ls -lh $(TARGET) 2>/dev/null || echo "Not built"
	@echo ""

# Help
.PHONY: help
help:
	@echo "FirmwareGuard Phase 2 Build System"
	@echo "==================================="
	@echo ""
	@echo "Targets:"
	@echo "  all            - Build userspace binary (default)"
	@echo "  kernel         - Build kernel module"
	@echo "  clean          - Remove build artifacts"
	@echo "  install        - Install to system (requires root)"
	@echo "  kernel-install - Install kernel module (requires root)"
	@echo "  uninstall      - Remove from system"
	@echo "  test           - Run basic functionality tests"
	@echo "  debug          - Build with debug symbols"
	@echo "  check          - Run static analysis"
	@echo "  stats          - Show code statistics"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make                  # Build userspace"
	@echo "  make kernel           # Build kernel module"
	@echo "  sudo make install     # Install system-wide"
	@echo "  make clean            # Clean build files"
	@echo ""
	@echo "Phase 2 Features:"
	@echo "  - Safety framework (backup, dry-run, rollback)"
	@echo "  - Configuration management"
	@echo "  - UEFI variable manipulation (Intel ME HAP bit)"
	@echo "  - GRUB configuration management (AMD PSP mitigation)"
	@echo "  - Kernel module for MMIO/DMA protection"
	@echo "  - Systemd service for boot-time enforcement"
	@echo ""

.PHONY: all clean install uninstall test debug kernel kernel-install check stats help
