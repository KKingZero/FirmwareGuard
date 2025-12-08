# FirmwareGuard Packaging Guide

## Debian/Ubuntu Packages

### Quick Build

```bash
./build-packages.sh
```

### Manual Build

```bash
# Install build dependencies
sudo apt-get install build-essential devscripts debhelper fakeroot

# Build package
dpkg-buildpackage -us -uc -b

# Package will be in parent directory
ls ../*.deb
```

### Installation

```bash
# Install package
sudo dpkg -i ../firmwareguard_1.0.0-1_amd64.deb

# Fix dependencies if needed
sudo apt-get install -f
```

### Testing Installation

```bash
# Verify installation
dpkg -l | grep firmwareguard
which firmwareguard
firmwareguard --help

# Run scan
sudo firmwareguard scan
```

### Removal

```bash
# Remove package (keep configuration)
sudo apt-get remove firmwareguard

# Purge package (remove everything)
sudo apt-get purge firmwareguard
```

## Supported Distributions

### Tested On
- Debian 11 (Bullseye)
- Debian 12 (Bookworm)
- Ubuntu 22.04 LTS (Jammy)
- Ubuntu 24.04 LTS (Noble)

### Package Contents

```
/usr/bin/firmwareguard                           # Main binary
/usr/share/firmwareguard/patterns/               # Pattern database
/lib/systemd/system/firmwareguard.service       # Systemd service
/etc/firmwareguard/                              # Configuration directory
/usr/share/doc/firmwareguard/                    # Documentation
```

## Building for Specific Distributions

### Debian 11 (Bullseye)

```bash
# In Debian 11 environment
./build-packages.sh
```

### Debian 12 (Bookworm)

```bash
# In Debian 12 environment
./build-packages.sh
```

### Ubuntu 22.04 LTS

```bash
# In Ubuntu 22.04 environment
./build-packages.sh
```

### Ubuntu 24.04 LTS

```bash
# In Ubuntu 24.04 environment
./build-packages.sh
```

## Using Docker for Multi-Distribution Builds

### Build for Debian 12

```bash
docker run --rm -v $(pwd):/workspace -w /workspace \
  debian:12 bash -c "
    apt-get update && \
    apt-get install -y build-essential devscripts debhelper fakeroot && \
    ./build-packages.sh
  "
```

### Build for Ubuntu 24.04

```bash
docker run --rm -v $(pwd):/workspace -w /workspace \
  ubuntu:24.04 bash -c "
    apt-get update && \
    apt-get install -y build-essential devscripts debhelper fakeroot && \
    ./build-packages.sh
  "
```

## Package Validation

### Lintian Checks

```bash
lintian ../firmwareguard_1.0.0-1_amd64.deb
```

### Package Information

```bash
# Show package info
dpkg-deb -I ../firmwareguard_1.0.0-1_amd64.deb

# List package contents
dpkg-deb -c ../firmwareguard_1.0.0-1_amd64.deb

# Show package dependencies
dpkg-deb -f ../firmwareguard_1.0.0-1_amd64.deb Depends
```

## Troubleshooting

### Build Fails with Missing Dependencies

```bash
sudo apt-get install build-essential devscripts debhelper fakeroot
```

### dpkg-buildpackage Not Found

```bash
sudo apt-get install dpkg-dev
```

### Lintian Warnings

Most lintian warnings are informational. Critical issues:
- `binary-without-manpage` - TODO: Add man page
- `no-copyright-file` - Should be present in debian/copyright

### Installation Issues

```bash
# Check dependencies
sudo apt-get install -f

# Force reinstall
sudo dpkg -i --force-all ../firmwareguard_1.0.0-1_amd64.deb
```

## Repository Publishing

### Local APT Repository

```bash
# Create repository structure
mkdir -p /var/www/apt/pool/main
cp ../firmwareguard_*.deb /var/www/apt/pool/main/

# Generate Packages file
cd /var/www/apt
dpkg-scanpackages pool/main /dev/null | gzip -9c > pool/main/Packages.gz

# Add to sources.list
echo "deb [trusted=yes] file:///var/www/apt pool/main" | \
  sudo tee /etc/apt/sources.list.d/firmwareguard.list

# Update and install
sudo apt-get update
sudo apt-get install firmwareguard
```

### GitHub Releases

```bash
# Create release with package
gh release create v1.0.0 \
  ../firmwareguard_1.0.0-1_amd64.deb \
  --title "FirmwareGuard v1.0.0" \
  --notes "Initial release"
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Build Packages

on: [push, pull_request]

jobs:
  build-deb:
    runs-on: ubuntu-latest
    container: debian:12
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: |
          apt-get update
          apt-get install -y build-essential devscripts debhelper fakeroot
      - name: Build package
        run: ./build-packages.sh
      - name: Upload package
        uses: actions/upload-artifact@v3
        with:
          name: debian-package
          path: ../*.deb
```

## Version Bumping

To create a new release:

1. Update `debian/changelog`:
   ```bash
   dch -v 1.1.0-1 "New release"
   ```

2. Update version in `build-packages.sh`

3. Rebuild:
   ```bash
   ./build-packages.sh
   ```

---

**Last Updated:** 2025-11-29
