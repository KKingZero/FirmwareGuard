#!/bin/bash
# FirmwareGuard Ghidra Analysis Runner
# Wrapper script for headless Ghidra analysis
# OFFLINE-ONLY: No network connectivity required

set -e

VERSION="1.0.0"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
OUTPUT_DIR="/var/lib/firmwareguard/ghidra_analysis"
PROJECT_DIR="/var/lib/firmwareguard/ghidra_projects"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Print usage
usage() {
    cat << EOF
FirmwareGuard Ghidra Analysis Runner v${VERSION}

Usage: $(basename "$0") [OPTIONS] <firmware_file>

Options:
    -h, --help          Show this help message
    -t, --type TYPE     Analysis type: uefi, me, all (default: all)
    -o, --output DIR    Output directory (default: ${OUTPUT_DIR})
    -p, --project NAME  Ghidra project name (default: auto-generated)
    -g, --ghidra PATH   Path to Ghidra installation
    -s, --script SCRIPT Specific analysis script to run
    -v, --verbose       Verbose output
    --keep-project      Keep Ghidra project after analysis

Analysis Types:
    uefi    - UEFI driver analysis only
    me      - Intel ME firmware analysis only
    all     - Full firmware analysis (default)

Examples:
    $(basename "$0") firmware.bin
    $(basename "$0") -t uefi driver.efi
    $(basename "$0") -t me me_region.bin -o ./results/
    $(basename "$0") --ghidra /opt/ghidra firmware.rom

EOF
    exit 0
}

# Find Ghidra installation
find_ghidra() {
    local ghidra_paths=(
        "/opt/ghidra"
        "/usr/share/ghidra"
        "/usr/local/ghidra"
        "$HOME/ghidra"
        "$HOME/tools/ghidra"
    )

    # Check for explicit path
    if [ -n "$GHIDRA_HOME" ]; then
        if [ -f "$GHIDRA_HOME/support/analyzeHeadless" ]; then
            echo "$GHIDRA_HOME"
            return 0
        fi
    fi

    # Search common locations
    for path in "${ghidra_paths[@]}"; do
        # Check for versioned directories
        for dir in "$path"* "$path"_* "$path"-*; do
            if [ -f "$dir/support/analyzeHeadless" ]; then
                echo "$dir"
                return 0
            fi
        done

        if [ -f "$path/support/analyzeHeadless" ]; then
            echo "$path"
            return 0
        fi
    done

    return 1
}

# Detect firmware type
detect_firmware_type() {
    local file="$1"
    local magic

    # Read first few bytes
    magic=$(xxd -l 8 -p "$file" 2>/dev/null | tr '[:lower:]' '[:upper:]')

    case "$magic" in
        4D5A*)
            # MZ header - PE executable (likely UEFI driver)
            echo "uefi"
            ;;
        24465054*)
            # $FPT - Flash Partition Table (Intel ME)
            echo "me"
            ;;
        244D4E32*)
            # $MN2 - ME Manifest
            echo "me"
            ;;
        5A4D*)
            # ZM (reversed MZ) - some firmware formats
            echo "firmware"
            ;;
        *)
            # Check for common firmware signatures deeper in file
            if grep -q '$FPT' "$file" 2>/dev/null; then
                echo "me"
            elif grep -q 'UEFI' "$file" 2>/dev/null; then
                echo "uefi"
            else
                echo "unknown"
            fi
            ;;
    esac
}

# Run Ghidra analysis
run_analysis() {
    local firmware_file="$1"
    local analysis_type="$2"
    local ghidra_home="$3"
    local output_dir="$4"
    local project_name="$5"
    local script="$6"

    local analyze_headless="$ghidra_home/support/analyzeHeadless"

    # Create directories
    mkdir -p "$output_dir"
    mkdir -p "$PROJECT_DIR"

    # Determine script to run
    case "$analysis_type" in
        uefi)
            script="${script:-$SCRIPT_DIR/uefi_driver_analysis.py}"
            ;;
        me)
            script="${script:-$SCRIPT_DIR/me_firmware_analysis.py}"
            ;;
        *)
            script="${script:-$SCRIPT_DIR/fw_analyze.py}"
            ;;
    esac

    if [ ! -f "$script" ]; then
        log_error "Analysis script not found: $script"
        exit 1
    fi

    log_info "Running Ghidra headless analysis..."
    log_info "  Firmware: $firmware_file"
    log_info "  Type: $analysis_type"
    log_info "  Script: $(basename "$script")"
    log_info "  Output: $output_dir"

    # Run analyzeHeadless
    "$analyze_headless" "$PROJECT_DIR" "$project_name" \
        -import "$firmware_file" \
        -postScript "$script" \
        -scriptPath "$SCRIPT_DIR" \
        -overwrite \
        -deleteProject \
        2>&1 | while read -r line; do
            if [ -n "$VERBOSE" ]; then
                echo "    $line"
            elif echo "$line" | grep -q -E '\[[\+\*\!-]\]'; then
                echo "    $line"
            fi
        done

    local exit_code=${PIPESTATUS[0]}

    if [ $exit_code -ne 0 ]; then
        log_error "Ghidra analysis failed with exit code: $exit_code"
        return 1
    fi

    log_success "Ghidra analysis complete!"

    # Find and display results
    local latest_result
    latest_result=$(find "$output_dir" -name "*.json" -mmin -5 2>/dev/null | sort | tail -1)

    if [ -n "$latest_result" ]; then
        log_success "Results saved to: $latest_result"

        # Display summary if jq is available
        if command -v jq &>/dev/null; then
            echo ""
            log_info "Analysis Summary:"
            jq -r '
                "  Risk Level: \(.risk_level // "unknown" | ascii_upcase)",
                "  Risk Score: \(.risk_score // 0)/100",
                "  Suspicious Indicators: \(.suspicious_indicators | length // 0)",
                "  Security Issues: \(.security_issues | length // 0)"
            ' "$latest_result" 2>/dev/null || true
        fi
    fi

    return 0
}

# Main
main() {
    local firmware_file=""
    local analysis_type="all"
    local output_dir="$OUTPUT_DIR"
    local project_name=""
    local ghidra_path=""
    local custom_script=""
    local keep_project=false
    VERBOSE=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            -t|--type)
                analysis_type="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -p|--project)
                project_name="$2"
                shift 2
                ;;
            -g|--ghidra)
                ghidra_path="$2"
                shift 2
                ;;
            -s|--script)
                custom_script="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            --keep-project)
                keep_project=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                ;;
            *)
                firmware_file="$1"
                shift
                ;;
        esac
    done

    # Validate firmware file
    if [ -z "$firmware_file" ]; then
        log_error "No firmware file specified"
        usage
    fi

    if [ ! -f "$firmware_file" ]; then
        log_error "Firmware file not found: $firmware_file"
        exit 1
    fi

    # Find Ghidra
    if [ -n "$ghidra_path" ]; then
        GHIDRA_HOME="$ghidra_path"
    fi

    ghidra_home=$(find_ghidra)
    if [ -z "$ghidra_home" ]; then
        log_error "Ghidra installation not found"
        log_info "Set GHIDRA_HOME environment variable or use --ghidra option"
        exit 1
    fi

    log_info "Using Ghidra: $ghidra_home"

    # Auto-detect firmware type if needed
    if [ "$analysis_type" = "all" ] || [ "$analysis_type" = "auto" ]; then
        detected_type=$(detect_firmware_type "$firmware_file")
        log_info "Detected firmware type: $detected_type"

        if [ "$detected_type" != "unknown" ]; then
            analysis_type="$detected_type"
        fi
    fi

    # Generate project name if not specified
    if [ -z "$project_name" ]; then
        project_name="FWGuard_$(basename "$firmware_file" | tr ' .' '_')_$(date +%Y%m%d%H%M%S)"
    fi

    # Run analysis
    run_analysis "$firmware_file" "$analysis_type" "$ghidra_home" "$output_dir" "$project_name" "$custom_script"
}

main "$@"
