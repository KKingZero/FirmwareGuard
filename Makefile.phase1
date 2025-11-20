# FirmwareGuard Makefile
# Low-level firmware telemetry detection and blocking framework

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=gnu11 -Iinclude
LDFLAGS = -lm

# Directories
SRC_DIR = src
BUILD_DIR = build
CORE_DIR = $(SRC_DIR)/core
BLOCK_DIR = $(SRC_DIR)/block
AUDIT_DIR = $(SRC_DIR)/audit

# Target binary
TARGET = firmwareguard

# Source files
CORE_SRCS = $(CORE_DIR)/msr.c \
            $(CORE_DIR)/me_psp.c \
            $(CORE_DIR)/acpi.c \
            $(CORE_DIR)/nic.c \
            $(CORE_DIR)/probe.c

BLOCK_SRCS = $(BLOCK_DIR)/blocker.c

AUDIT_SRCS = $(AUDIT_DIR)/reporter.c

MAIN_SRC = $(SRC_DIR)/main.c

# Object files
CORE_OBJS = $(patsubst $(CORE_DIR)/%.c,$(BUILD_DIR)/core_%.o,$(CORE_SRCS))
BLOCK_OBJS = $(patsubst $(BLOCK_DIR)/%.c,$(BUILD_DIR)/block_%.o,$(BLOCK_SRCS))
AUDIT_OBJS = $(patsubst $(AUDIT_DIR)/%.c,$(BUILD_DIR)/audit_%.o,$(AUDIT_SRCS))
MAIN_OBJ = $(BUILD_DIR)/main.o

ALL_OBJS = $(CORE_OBJS) $(BLOCK_OBJS) $(AUDIT_OBJS) $(MAIN_OBJ)

# Default target
.PHONY: all
all: $(BUILD_DIR) $(TARGET)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Link final binary
$(TARGET): $(ALL_OBJS)
	@echo "Linking $@..."
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete: $@"

# Compile core modules
$(BUILD_DIR)/core_%.o: $(CORE_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Compile block modules
$(BUILD_DIR)/block_%.o: $(BLOCK_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Compile audit modules
$(BUILD_DIR)/audit_%.o: $(AUDIT_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Compile main
$(BUILD_DIR)/main.o: $(MAIN_SRC)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(TARGET)
	@echo "Clean complete"

# Install (requires root)
.PHONY: install
install: $(TARGET)
	@echo "Installing $(TARGET) to /usr/local/bin..."
	@install -m 755 $(TARGET) /usr/local/bin/
	@echo "Installation complete"

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Removing $(TARGET) from /usr/local/bin..."
	@rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstall complete"

# Run tests (basic functionality check)
.PHONY: test
test: $(TARGET)
	@echo "Running basic functionality tests..."
	@./$(TARGET) --help
	@echo "Test complete"

# Debug build
.PHONY: debug
debug: CFLAGS += -g -DDEBUG
debug: clean all

# Help
.PHONY: help
help:
	@echo "FirmwareGuard Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the project (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to /usr/local/bin (requires root)"
	@echo "  uninstall - Remove from /usr/local/bin"
	@echo "  test      - Run basic functionality tests"
	@echo "  debug     - Build with debug symbols"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build the project"
	@echo "  make clean        # Clean build files"
	@echo "  sudo make install # Install system-wide"
