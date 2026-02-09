#!/bin/bash
#
# FirmwareGuard - Test Runner
#
# Compiles and runs the safety hash and UEFI safety tests.
# Designed to run on any Linux distro (Fedora, Debian, Arch, etc.)
# either directly or inside a podman/docker container.
#
# Usage:
#   ./tools/run-tests.sh              # Run from project root
#   podman build -t fg-test -f tools/Containerfile.test . && podman run --rm fg-test
#

set -e

# Detect project root (script may be run from project root or tools/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/../include/firmwareguard.h" ]; then
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [ -f "include/firmwareguard.h" ]; then
    PROJECT_ROOT="$(pwd)"
else
    echo "ERROR: Cannot find project root. Run from FirmwareGuard/ directory."
    exit 1
fi

cd "$PROJECT_ROOT"

# Compiler flags (match Makefile)
CC="${CC:-gcc}"
CFLAGS="-Wall -Wextra -O2 -std=gnu11 -Iinclude -D_GNU_SOURCE"
CFLAGS="$CFLAGS -fstack-protector-strong -D_FORTIFY_SOURCE=2"

# Check for OpenSSL
if ! pkg-config --exists openssl 2>/dev/null; then
    echo "WARNING: pkg-config cannot find openssl."
    echo "  Fedora/RHEL: dnf install openssl-devel"
    echo "  Debian/Ubuntu: apt-get install libssl-dev"
    echo "  Arch: pacman -S openssl"
    echo "Attempting to compile anyway..."
fi

LDFLAGS="-lcrypto -lm"
BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

TOTAL_PASS=0
TOTAL_FAIL=0

echo ""
echo "============================================"
echo "  FirmwareGuard Test Runner"
echo "  $(date)"
echo "  $(uname -srm)"
echo "============================================"
echo ""

# --- Test 1: Safety Hash Tests ---
echo "--- Compiling test-safety-hash ---"
if $CC $CFLAGS \
    -o "$BUILD_DIR/test-safety-hash" \
    tools/test-safety-hash.c src/safety/safety.c \
    $LDFLAGS 2>&1; then
    echo "  Compiled OK"
else
    echo "  COMPILATION FAILED"
    exit 1
fi

echo ""
echo "--- Running test-safety-hash ---"
if "$BUILD_DIR/test-safety-hash"; then
    TOTAL_PASS=$((TOTAL_PASS + 1))
else
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

# --- Test 2: UEFI Safety Tests ---
echo ""
echo "--- Compiling test-uefi-safety ---"
if $CC $CFLAGS \
    -o "$BUILD_DIR/test-uefi-safety" \
    tools/test-uefi-safety.c src/uefi/uefi_vars.c src/safety/safety.c \
    $LDFLAGS 2>&1; then
    echo "  Compiled OK"
else
    echo "  COMPILATION FAILED"
    exit 1
fi

echo ""
echo "--- Running test-uefi-safety ---"
if "$BUILD_DIR/test-uefi-safety"; then
    TOTAL_PASS=$((TOTAL_PASS + 1))
else
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

# --- Summary ---
echo ""
echo "============================================"
echo "  Overall Test Results"
echo "============================================"
echo "  Test suites passed: $TOTAL_PASS"
echo "  Test suites failed: $TOTAL_FAIL"
echo "============================================"
echo ""

if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
