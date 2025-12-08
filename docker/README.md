# FirmwareGuard Docker Usage

## Quick Start

### Build the Container

```bash
docker build -t firmwareguard:dev .
```

### Run a Hardware Scan

```bash
docker run --rm --privileged \
  -v /sys:/sys:ro \
  -v /dev:/dev:ro \
  -v $(pwd)/reports:/firmwareguard/reports \
  firmwareguard:dev scan --json -o /firmwareguard/reports/scan.json
```

### Interactive Development

```bash
docker run --rm -it --privileged \
  -v /sys:/sys:ro \
  -v /dev:/dev:ro \
  -v $(pwd):/firmwareguard \
  firmwareguard:dev /bin/bash
```

## Docker Compose

### Development Environment

```bash
docker-compose up -d firmwareguard-dev
docker-compose exec firmwareguard-dev /bin/bash
```

### CI/CD Validation

```bash
docker-compose run firmwareguard-ci
```

## Volume Mounts Explained

### Required Mounts (Read-Only)
- `/sys:/sys:ro` - Sysfs access for ACPI tables, PCI devices, etc.
- `/dev:/dev:ro` - Device access for MSR, memory-mapped I/O

### Optional Mounts
- `./reports:/firmwareguard/reports` - Output directory for scan reports
- `./patterns:/firmwareguard/patterns:ro` - Custom pattern database

## Privileged Mode

**Why `--privileged` is required:**
- Access to `/dev/mem` for MMIO reads
- Access to `/dev/cpu/*/msr` for MSR reads
- PCI device enumeration
- ACPI table access

**Security Note:** Only run FirmwareGuard container on trusted systems. The privileged flag grants extensive hardware access.

## Build Variants

### Minimal Runtime Container

```dockerfile
FROM debian:12-slim
# ... copy only compiled binary and patterns ...
```

### Full Development Container

Use the provided `Dockerfile` (includes build tools, debuggers, etc.)

## Environment Variables

- `FG_PATTERNS_DIR` - Pattern database directory (default: `/firmwareguard/patterns`)

## Examples

### Scan and Save JSON Report

```bash
docker run --rm --privileged \
  -v /sys:/sys:ro \
  -v /dev:/dev:ro \
  -v $(pwd)/reports:/firmwareguard/reports \
  firmwareguard:dev scan --json -o /firmwareguard/reports/$(hostname)-$(date +%Y%m%d).json
```

### Test Pattern Database

```bash
docker run --rm --privileged \
  -v /sys:/sys:ro \
  -v /dev:/dev:ro \
  firmwareguard:dev /firmwareguard/tools/test-patterns
```

### Build and Run Kernel Module

```bash
docker run --rm -it --privileged \
  -v /sys:/sys:ro \
  -v /dev:/dev:ro \
  -v /lib/modules:/lib/modules:ro \
  firmwareguard:dev /bin/bash

# Inside container:
make kernel
insmod kernel/fwguard_km.ko
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run FirmwareGuard Scan
  run: |
    docker build -t firmwareguard:ci .
    docker run --rm --privileged \
      -v /sys:/sys:ro \
      -v /dev:/dev:ro \
      -v ${{ github.workspace }}/reports:/firmwareguard/reports \
      firmwareguard:ci scan --json -o /firmwareguard/reports/scan.json
```

### GitLab CI

```yaml
firmware_scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t firmwareguard:ci .
    - docker run --privileged -v /sys:/sys:ro -v /dev:/dev:ro firmwareguard:ci scan
```

## Troubleshooting

### Permission Denied Errors

Ensure container runs with `--privileged` flag.

### Pattern Database Not Found

Mount patterns directory: `-v $(pwd)/patterns:/firmwareguard/patterns:ro`

### Kernel Module Build Fails

Mount kernel headers: `-v /lib/modules:/lib/modules:ro`

---

**Last Updated:** 2025-11-29
