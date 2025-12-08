#!/bin/bash
# FirmwareGuard Package Build Script
# Builds .deb packages for Debian and Ubuntu distributions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Package information
PACKAGE_NAME="firmwareguard"
VERSION="1.0.0"
REVISION="1"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  FirmwareGuard Package Builder${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if we're in the right directory
if [ ! -f "Makefile" ] || [ ! -d "debian" ]; then
    echo -e "${RED}Error: Must run from FirmwareGuard root directory${NC}"
    exit 1
fi

# Check for required tools
echo "[1] Checking build dependencies..."
MISSING_DEPS=""

for tool in dpkg-deb fakeroot debhelper; do
    if ! command -v $tool &> /dev/null; then
        MISSING_DEPS="$MISSING_DEPS $tool"
    fi
done

if [ -n "$MISSING_DEPS" ]; then
    echo -e "${YELLOW}Missing dependencies:$MISSING_DEPS${NC}"
    echo "Install with: sudo apt-get install build-essential devscripts debhelper fakeroot"
    read -p "Install now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt-get update
        sudo apt-get install -y build-essential devscripts debhelper fakeroot
    else
        exit 1
    fi
fi

echo -e "${GREEN}✓${NC} All dependencies satisfied"
echo ""

# Clean previous builds
echo "[2] Cleaning previous builds..."
make clean
rm -rf debian/firmwareguard
rm -f ../${PACKAGE_NAME}_${VERSION}-${REVISION}_*.deb
rm -f ../${PACKAGE_NAME}_${VERSION}-${REVISION}_*.changes
rm -f ../${PACKAGE_NAME}_${VERSION}-${REVISION}_*.buildinfo
echo -e "${GREEN}✓${NC} Clean complete"
echo ""

# Build the package
echo "[3] Building Debian package..."
echo "Package: ${PACKAGE_NAME} ${VERSION}-${REVISION}"
echo ""

# Use dpkg-buildpackage for proper Debian package build
if dpkg-buildpackage -us -uc -b; then
    echo ""
    echo -e "${GREEN}✓${NC} Package built successfully"
    echo ""
else
    echo -e "${RED}✗${NC} Package build failed"
    exit 1
fi

# List built packages
echo "[4] Built packages:"
ls -lh ../${PACKAGE_NAME}_${VERSION}-${REVISION}_*.deb 2>/dev/null || echo "No .deb files found"
echo ""

# Package information
if [ -f "../${PACKAGE_NAME}_${VERSION}-${REVISION}_amd64.deb" ]; then
    echo "[5] Package information:"
    dpkg-deb -I "../${PACKAGE_NAME}_${VERSION}-${REVISION}_amd64.deb"
    echo ""

    echo "[6] Package contents:"
    dpkg-deb -c "../${PACKAGE_NAME}_${VERSION}-${REVISION}_amd64.deb" | head -20
    echo ""

    # Lintian check (if available)
    if command -v lintian &> /dev/null; then
        echo "[7] Running lintian checks..."
        lintian "../${PACKAGE_NAME}_${VERSION}-${REVISION}_amd64.deb" || true
        echo ""
    fi
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Package location: ../${PACKAGE_NAME}_${VERSION}-${REVISION}_amd64.deb"
echo ""
echo "To install:"
echo "  sudo dpkg -i ../${PACKAGE_NAME}_${VERSION}-${REVISION}_amd64.deb"
echo "  sudo apt-get install -f  # Fix dependencies if needed"
echo ""
echo "To test:"
echo "  sudo firmwareguard scan"
echo ""
