# FirmwareGuard Development & Testing Container
# Base: Debian 12 (Bookworm) for broad compatibility

FROM debian:12-slim

LABEL maintainer="FirmwareGuard Team"
LABEL description="FirmwareGuard development and testing environment"
LABEL version="1.0.0"

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies and runtime requirements
RUN apt-get update && apt-get install -y \
    # Build essentials
    build-essential \
    gcc \
    make \
    git \
    # Kernel headers for module building
    linux-headers-generic \
    # Development libraries
    libssl-dev \
    # System utilities
    pciutils \
    usbutils \
    dmidecode \
    lshw \
    ethtool \
    util-linux \
    # Debugging tools
    gdb \
    strace \
    ltrace \
    # Pattern validation tools
    python3 \
    python3-pip \
    python3-jsonschema \
    # Documentation tools
    curl \
    wget \
    vim \
    nano \
    less \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages for pattern validation
RUN pip3 install --no-cache-dir \
    jsonschema \
    pyyaml

# Create directories
RUN mkdir -p /firmwareguard \
    /firmwareguard/build \
    /firmwareguard/patterns \
    /firmwareguard/reports \
    /etc/firmwareguard

# Set working directory
WORKDIR /firmwareguard

# Copy source code
COPY . /firmwareguard/

# Build FirmwareGuard
RUN make clean && make

# Create volume mount points
VOLUME ["/firmwareguard/reports", "/firmwareguard/patterns"]

# Environment variables
ENV PATH="/firmwareguard:${PATH}"
ENV FG_PATTERNS_DIR="/firmwareguard/patterns"

# Default command: show help
CMD ["./firmwareguard"]

# Usage instructions in labels
LABEL usage.build="docker build -t firmwareguard:dev ."
LABEL usage.run="docker run --rm --privileged -v /sys:/sys:ro -v /dev:/dev:ro firmwareguard:dev scan"
LABEL usage.interactive="docker run --rm -it --privileged -v /sys:/sys:ro -v /dev:/dev:ro firmwareguard:dev /bin/bash"

# Note: --privileged flag is required for hardware access
# - /sys:/sys:ro for sysfs access (ACPI tables, PCI devices)
# - /dev:/dev:ro for device access (MSR, memory)
