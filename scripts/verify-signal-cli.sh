#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# verify-signal-cli.sh — Signal CLI Binary Integrity Verification
# =============================================================================
# Verifies the SHA256 hash of the signal-cli binary against a known-good value.
# This prevents running a tampered or corrupted binary.
#
# Usage:
#   ./scripts/verify-signal-cli.sh /path/to/signal-cli
#   ./scripts/verify-signal-cli.sh                        # defaults to /opt/signal-cli/bin/signal-cli
#
# The known-good hash can be set via:
#   1. Environment variable: SIGNAL_CLI_SHA256
#   2. Hash file:            /opt/signal-cli/bin/signal-cli.sha256
#   3. Command-line:         --hash <sha256hex>
#
# Exit codes:
#   0 — Hash matches (binary is authentic)
#   1 — Hash mismatch or error (binary may be tampered)
# =============================================================================

readonly DEFAULT_BINARY="/opt/signal-cli/bin/signal-cli"
readonly DEFAULT_HASH_FILE_SUFFIX=".sha256"

# --- Color output helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
ok()      { echo -e "${GREEN}[PASS]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*" >&2; }

usage() {
    echo "Usage: $(basename "$0") [OPTIONS] [BINARY_PATH]"
    echo ""
    echo "Verify signal-cli binary SHA256 hash against a known-good value."
    echo ""
    echo "Arguments:"
    echo "  BINARY_PATH           Path to signal-cli binary (default: ${DEFAULT_BINARY})"
    echo ""
    echo "Options:"
    echo "  --hash <sha256>       Expected SHA256 hash (hex string)"
    echo "  --hash-file <path>    File containing the expected SHA256 hash"
    echo "  --generate            Print the SHA256 hash of the binary and exit"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Hash resolution order:"
    echo "  1. --hash flag"
    echo "  2. --hash-file flag"
    echo "  3. SIGNAL_CLI_SHA256 environment variable"
    echo "  4. <binary_path>.sha256 sidecar file"
}

# =============================================================================
# Parse arguments
# =============================================================================
BINARY_PATH=""
EXPECTED_HASH=""
HASH_FILE=""
GENERATE_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hash)
            EXPECTED_HASH="${2:-}"
            if [[ -z "${EXPECTED_HASH}" ]]; then
                fail "--hash requires a SHA256 hex string argument."
                exit 1
            fi
            shift 2
            ;;
        --hash-file)
            HASH_FILE="${2:-}"
            if [[ -z "${HASH_FILE}" ]]; then
                fail "--hash-file requires a file path argument."
                exit 1
            fi
            shift 2
            ;;
        --generate)
            GENERATE_MODE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            fail "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            BINARY_PATH="$1"
            shift
            ;;
    esac
done

# Default binary path
BINARY_PATH="${BINARY_PATH:-${DEFAULT_BINARY}}"

# =============================================================================
# Validate binary exists
# =============================================================================
if [[ ! -f "${BINARY_PATH}" ]]; then
    fail "Binary not found: ${BINARY_PATH}"
    info "Install signal-cli first, or provide the correct path."
    exit 1
fi

if [[ ! -r "${BINARY_PATH}" ]]; then
    fail "Binary is not readable: ${BINARY_PATH}"
    info "Check file permissions."
    exit 1
fi

# =============================================================================
# Compute SHA256 hash of the binary
# =============================================================================
compute_sha256() {
    local file="$1"

    if command -v sha256sum &>/dev/null; then
        # Linux (coreutils)
        sha256sum "${file}" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        # macOS
        shasum -a 256 "${file}" | awk '{print $1}'
    elif command -v openssl &>/dev/null; then
        # Fallback: openssl
        openssl dgst -sha256 "${file}" | awk '{print $NF}'
    else
        fail "No SHA256 tool found. Install coreutils, shasum, or openssl."
        exit 1
    fi
}

info "Computing SHA256 hash of: ${BINARY_PATH}"
ACTUAL_HASH=$(compute_sha256 "${BINARY_PATH}")
info "SHA256: ${ACTUAL_HASH}"

# =============================================================================
# Generate mode: just print the hash and exit
# =============================================================================
if ${GENERATE_MODE}; then
    echo ""
    echo "# signal-cli binary SHA256 hash"
    echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "# Binary:    ${BINARY_PATH}"
    echo "# Size:      $(wc -c < "${BINARY_PATH}" | tr -d ' ') bytes"
    echo "${ACTUAL_HASH}"
    echo ""
    info "To save as a sidecar file:"
    echo "  echo '${ACTUAL_HASH}' > ${BINARY_PATH}${DEFAULT_HASH_FILE_SUFFIX}"
    echo ""
    info "To set as environment variable:"
    echo "  export SIGNAL_CLI_SHA256='${ACTUAL_HASH}'"
    exit 0
fi

# =============================================================================
# Resolve expected hash (priority order)
# =============================================================================

# Priority 1: --hash flag (already set above if provided)

# Priority 2: --hash-file flag
if [[ -z "${EXPECTED_HASH}" && -n "${HASH_FILE}" ]]; then
    if [[ -f "${HASH_FILE}" ]]; then
        # Read first non-comment, non-empty line from hash file
        EXPECTED_HASH=$(grep -v '^#' "${HASH_FILE}" | grep -v '^\s*$' | head -1 | awk '{print $1}')
        info "Loaded expected hash from: ${HASH_FILE}"
    else
        fail "Hash file not found: ${HASH_FILE}"
        exit 1
    fi
fi

# Priority 3: SIGNAL_CLI_SHA256 environment variable
if [[ -z "${EXPECTED_HASH}" && -n "${SIGNAL_CLI_SHA256:-}" ]]; then
    EXPECTED_HASH="${SIGNAL_CLI_SHA256}"
    info "Using expected hash from SIGNAL_CLI_SHA256 environment variable."
fi

# Priority 4: Sidecar .sha256 file next to the binary
if [[ -z "${EXPECTED_HASH}" ]]; then
    local_hash_file="${BINARY_PATH}${DEFAULT_HASH_FILE_SUFFIX}"
    if [[ -f "${local_hash_file}" ]]; then
        EXPECTED_HASH=$(grep -v '^#' "${local_hash_file}" | grep -v '^\s*$' | head -1 | awk '{print $1}')
        info "Loaded expected hash from sidecar: ${local_hash_file}"
    fi
fi

# If we still have no expected hash, we cannot verify
if [[ -z "${EXPECTED_HASH}" ]]; then
    fail "No expected hash provided. Cannot verify binary integrity."
    echo ""
    info "Provide the expected hash via one of:"
    echo "  1. --hash <sha256hex>"
    echo "  2. --hash-file <path>"
    echo "  3. export SIGNAL_CLI_SHA256=<sha256hex>"
    echo "  4. Create ${BINARY_PATH}${DEFAULT_HASH_FILE_SUFFIX}"
    echo ""
    info "To generate the hash of the current binary:"
    echo "  $(basename "$0") --generate ${BINARY_PATH}"
    exit 1
fi

# Normalize hashes to lowercase for comparison
ACTUAL_HASH=$(echo "${ACTUAL_HASH}" | tr '[:upper:]' '[:lower:]')
EXPECTED_HASH=$(echo "${EXPECTED_HASH}" | tr '[:upper:]' '[:lower:]')

# =============================================================================
# Compare hashes
# =============================================================================
echo ""
echo "  Expected: ${EXPECTED_HASH}"
echo "  Actual:   ${ACTUAL_HASH}"
echo ""

if [[ "${ACTUAL_HASH}" == "${EXPECTED_HASH}" ]]; then
    ok "SHA256 hash MATCHES. Binary integrity verified."
    ok "Binary: ${BINARY_PATH}"
    exit 0
else
    fail "SHA256 hash MISMATCH! Binary may be tampered or corrupted."
    fail "Binary: ${BINARY_PATH}"
    echo ""
    warn "DO NOT run this binary. Re-download from the official source:"
    info "  https://github.com/AsamK/signal-cli/releases"
    exit 1
fi
