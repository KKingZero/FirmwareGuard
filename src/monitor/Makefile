# Makefile for HECI Monitor Module
#
# Build standalone test program and module object file

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O2 -std=c11 -pthread
CFLAGS += -I../../include
LDFLAGS = -pthread

# Source files
MONITOR_SRC = heci_monitor.c
MONITOR_OBJ = heci_monitor.o
TEST_SRC = heci_test.c
TEST_BIN = heci_test

# Targets
.PHONY: all clean test install

all: $(MONITOR_OBJ) $(TEST_BIN)

# Compile monitor module
$(MONITOR_OBJ): $(MONITOR_SRC) heci_monitor.h ../../include/firmwareguard.h
	$(CC) $(CFLAGS) -c $(MONITOR_SRC) -o $(MONITOR_OBJ)

# Build standalone test program
$(TEST_BIN): $(TEST_SRC) $(MONITOR_OBJ) heci_monitor.h ../../include/firmwareguard.h
	$(CC) $(CFLAGS) $(TEST_SRC) $(MONITOR_OBJ) $(LDFLAGS) -o $(TEST_BIN)

# Run test (requires root)
test: $(TEST_BIN)
	@echo "Running HECI monitor test (requires root)..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: Test requires root privileges"; \
		echo "Try: sudo make test"; \
		exit 1; \
	fi
	./$(TEST_BIN) 10

# Clean build artifacts
clean:
	rm -f $(MONITOR_OBJ) $(TEST_BIN)
	rm -f /tmp/heci_traffic.json

# Install (copy to system library location)
install: $(MONITOR_OBJ)
	@echo "Installing HECI monitor module..."
	install -m 644 heci_monitor.h /usr/local/include/
	install -m 644 $(MONITOR_OBJ) /usr/local/lib/

# Help
help:
	@echo "HECI Monitor Module - Build Targets"
	@echo ""
	@echo "  make              - Build module object and test program"
	@echo "  make test         - Run test program (requires root)"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make install      - Install module to system (requires root)"
	@echo "  make help         - Show this help"
	@echo ""
	@echo "Manual test usage:"
	@echo "  sudo ./heci_test [duration_seconds]"
	@echo ""
