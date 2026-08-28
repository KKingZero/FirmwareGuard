#!/bin/bash
#
# Smoke tests for graduated CLI commands. Designed to run in a sandbox/container.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$PROJECT_ROOT/firmwareguard"

if [ ! -x "$BIN" ]; then
    echo "ERROR: $BIN is missing; run make first."
    exit 1
fi

TMPDIR="${TMPDIR:-/tmp}"
FIXTURE="$(mktemp "$TMPDIR/fg-fw.XXXXXX.bin")"
mkdir -p "$PROJECT_ROOT/build"
FAKE_GHIDRA="$(mktemp -d "$PROJECT_ROOT/build/fg-ghidra.XXXXXX")"
FAKE_SCRIPTS="$(mktemp -d "$PROJECT_ROOT/build/fg-ghidra-scripts.XXXXXX")"
FAKE_OUT="$(mktemp -d "$PROJECT_ROOT/build/fg-ghidra-out.XXXXXX")"
MISSING_OUT="$TMPDIR/fg-ghidra-missing-$$"
trap 'rm -f "$FIXTURE"; rm -rf "$FAKE_GHIDRA" "$FAKE_SCRIPTS" "$FAKE_OUT" "$MISSING_OUT"' EXIT
printf 'firmwareguard test fixture\n' > "$FIXTURE"
mkdir -p "$FAKE_GHIDRA/support"
cat > "$FAKE_GHIDRA/support/analyzeHeadless" <<'SCRIPT'
#!/bin/sh
exit 0
SCRIPT
chmod +x "$FAKE_GHIDRA/support/analyzeHeadless"
cat > "$FAKE_SCRIPTS/ghidra_runner.sh" <<'SCRIPT'
#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            out="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done
mkdir -p "$out"
cat > "$out/fake-result.json" <<'JSON'
{
  "filename": "fixture.bin",
  "file_hash": "abc123",
  "file_size": 24,
  "firmware_type": "test",
  "risk_score": 7,
  "risk_level": "low",
  "suspicious_indicators": []
}
JSON
exit 0
SCRIPT
chmod +x "$FAKE_SCRIPTS/ghidra_runner.sh"

assert_ok() {
    if ! "$@"; then
        echo "FAIL: expected success: $*"
        exit 1
    fi
}

assert_fail() {
    if "$@"; then
        echo "FAIL: expected failure: $*"
        exit 1
    fi
}

assert_contains() {
    local needle="$1"
    shift
    if ! "$@" 2>&1 | grep -q "$needle"; then
        echo "FAIL: output did not contain '$needle': $*"
        exit 1
    fi
}

assert_contains "uefi-integrity" "$BIN" --help
assert_contains "coreboot-check" "$BIN" --help
assert_contains "ghidra-analyze" "$BIN" --help
assert_contains "live-dump" "$BIN" --help

assert_contains '"dry_run": true' "$BIN" live-dump --json
assert_fail "$BIN" live-dump --spi --json
assert_fail "$BIN" ghidra-analyze /no/such.bin --json
assert_ok "$BIN" uefi-integrity --brief --json
if "$BIN" uefi-integrity --json 2>&1 | grep -q "requires root"; then
    echo "FAIL: read-only uefi-integrity scan required root"
    exit 1
fi
assert_ok "$BIN" coreboot-check --json
assert_contains '"warnings": \[' "$BIN" coreboot-check --json

assert_ok env GHIDRA_HOME=/no/such/ghidra \
    "$BIN" ghidra-analyze "$FIXTURE" --json -o "$MISSING_OUT"
if [ -e "$MISSING_OUT" ]; then
    echo "FAIL: missing Ghidra path created output directory"
    exit 1
fi

assert_contains '"available": true' env GHIDRA_HOME="$FAKE_GHIDRA" \
    FG_GHIDRA_SCRIPTS_DIR="$FAKE_SCRIPTS" \
    "$BIN" ghidra-analyze "$FIXTURE" --json -o "$FAKE_OUT"
test -f "$FAKE_OUT/fake-result.json"

echo "graduated CLI smoke tests passed"
