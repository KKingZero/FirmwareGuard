# FirmwareGuard Kernel Module Makefile

obj-m += fwguard_km.o

# Kernel build directory
KDIR ?= /lib/modules/$(shell uname -r)/build

# Module source
PWD := $(shell pwd)

# Default target
all:
	@echo "Building FirmwareGuard kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean
clean:
	@echo "Cleaning kernel module build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Install module (requires root)
install:
	@echo "Installing FirmwareGuard kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

# Load module
load:
	@echo "Loading FirmwareGuard kernel module..."
	insmod fwguard_km.ko

# Unload module
unload:
	@echo "Unloading FirmwareGuard kernel module..."
	rmmod fwguard_km

# Help
help:
	@echo "FirmwareGuard Kernel Module Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the kernel module (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install module to system (requires root)"
	@echo "  load     - Load module into running kernel (requires root)"
	@echo "  unload   - Unload module from kernel (requires root)"
	@echo "  help     - Show this help message"

.PHONY: all clean install load unload help
