#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# verify-firewall.sh — Firewall Verification Test
# =============================================================================
# Tests that ports 18789 (OpenClaw API) and 8080 (signal-cli) are NOT
# accessible from external (non-loopback) IP addresses.
#
# Strategy:
#   1. Determine the machine's non-loopback IP address(es)
#   2. Attempt connections from those IPs to the protected ports
#   3. Verify that connections are REFUSED or TIMED OUT
#   4. Verify that loopback connections still work (if services are running)
#
# Exit codes:
#   0 — Firewall is correctly blocking external access (SECURE)
#   1 — External access detected or test error (INSECURE)
#
# Usage:
#   ./scripts/verify-firewall.sh
#   ./scripts/verify-firewall.sh --verbose
# =============================================================================

readonly OPENCLAW_PORT=18789
readonly SIGNAL_PORT=8080
readonly CONNECT_TIMEOUT=3

# --- Parse flags ---
VERBOSE=false
if [[ "${1:-}" == "--verbose" || "${1:-}" == "-v" ]]; then
    VERBOSE=true
fi

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
debug()   { ${VERBOSE} && echo -e "${CYAN}[DBG ]${NC}  $*" || true; }

# Track overall result
SECURE=true
TESTS_RUN=0
TESTS_PASSED=0

mark_insecure() {
    SECURE=false
}

# =============================================================================
# Detect non-loopback IP addresses
# =============================================================================
get_external_ips() {
    local ips=()

    case "$(uname -s)" in
        Darwin)
            # macOS: get IPs from active network interfaces (excluding lo0)
            while IFS= read -r line; do
                ips+=("${line}")
            done < <(ifconfig 2>/dev/null \
                | grep "inet " \
                | grep -v "127.0.0.1" \
                | awk '{print $2}' \
                | sort -u)
            ;;
        Linux)
            # Linux: use ip command
            if command -v ip &>/dev/null; then
                while IFS= read -r line; do
                    ips+=("${line}")
                done < <(ip -4 addr show 2>/dev/null \
                    | grep "inet " \
                    | grep -v "127.0.0.1" \
                    | awk '{print $2}' \
                    | cut -d/ -f1 \
                    | sort -u)
            else
                while IFS= read -r line; do
                    ips+=("${line}")
                done < <(ifconfig 2>/dev/null \
                    | grep "inet " \
                    | grep -v "127.0.0.1" \
                    | awk '{print $2}' \
                    | sed 's/addr://' \
                    | sort -u)
            fi
            ;;
    esac

    # Also try hostname-based resolution as a fallback
    if command -v hostname &>/dev/null; then
        local hostname_ip
        hostname_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
        if [[ -n "${hostname_ip}" && "${hostname_ip}" != "127.0.0.1" ]]; then
            ips+=("${hostname_ip}")
        fi
    fi

    # Deduplicate
    printf '%s\n' "${ips[@]}" | sort -u
}

# =============================================================================
# Test connectivity to a port
# Returns 0 if connection SUCCEEDS (bad — port is accessible)
# Returns 1 if connection FAILS (good — port is blocked)
# =============================================================================
test_connection() {
    local host="$1"
    local port="$2"

    debug "Testing connection to ${host}:${port}..."

    # Try nc (netcat) first
    if command -v nc &>/dev/null; then
        if nc -z -w "${CONNECT_TIMEOUT}" "${host}" "${port}" 2>/dev/null; then
            return 0  # Connection succeeded (port accessible)
        else
            return 1  # Connection failed (port blocked)
        fi
    fi

    # Fall back to curl
    if command -v curl &>/dev/null; then
        if curl -s --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${CONNECT_TIMEOUT}" \
            "http://${host}:${port}/" &>/dev/null; then
            return 0  # Connection succeeded
        else
            return 1  # Connection failed
        fi
    fi

    # Fall back to bash /dev/tcp (if available)
    if (echo >/dev/tcp/"${host}"/"${port}") 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# =============================================================================
# Test: External IP should NOT connect to a port
# =============================================================================
test_external_blocked() {
    local ip="$1"
    local port="$2"
    local label="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    info "Testing external access: ${ip}:${port} (${label})..."

    if test_connection "${ip}" "${port}"; then
        fail "SECURITY ISSUE: ${ip}:${port} is ACCESSIBLE from external IP!"
        fail "Port ${port} (${label}) must be blocked for non-loopback addresses."
        mark_insecure
    else
        ok "External access blocked: ${ip}:${port} (${label}) -- connection refused/timed out."
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

# =============================================================================
# Test: Loopback should still be able to connect (if service is running)
# =============================================================================
test_loopback_allowed() {
    local port="$1"
    local label="$2"

    TESTS_RUN=$((TESTS_RUN + 1))

    info "Testing loopback access: 127.0.0.1:${port} (${label})..."

    if test_connection "127.0.0.1" "${port}"; then
        ok "Loopback access works: 127.0.0.1:${port} (${label}) -- service is responding."
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        warn "Loopback connection failed: 127.0.0.1:${port} (${label})"
        warn "This may be OK if the service is not currently running."
        # Don't mark as insecure — service might just not be running
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

# =============================================================================
# Test: Check for wildcard binding (0.0.0.0)
# =============================================================================
test_no_wildcard_binding() {
    local port="$1"
    local label="$2"

    TESTS_RUN=$((TESTS_RUN + 1))

    info "Checking for wildcard binding on port ${port} (${label})..."

    local listeners=""

    if command -v ss &>/dev/null; then
        listeners=$(ss -tlnp 2>/dev/null | grep ":${port}" || true)
    elif command -v lsof &>/dev/null; then
        listeners=$(lsof -iTCP:${port} -sTCP:LISTEN -nP 2>/dev/null || true)
    elif command -v netstat &>/dev/null; then
        listeners=$(netstat -an 2>/dev/null | grep "LISTEN" | grep ":${port}" || true)
    else
        warn "No socket inspection tool found. Skipping wildcard binding check."
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return
    fi

    if [[ -z "${listeners}" ]]; then
        debug "Nothing listening on port ${port}. Binding check not applicable."
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return
    fi

    if echo "${listeners}" | grep -qE '(\*:|0\.0\.0\.0:)'"${port}"; then
        fail "SECURITY ISSUE: Port ${port} (${label}) is bound to 0.0.0.0 (all interfaces)!"
        fail "Services must bind to 127.0.0.1 only."
        ${VERBOSE} && echo "${listeners}"
        mark_insecure
    else
        ok "Port ${port} (${label}) is NOT bound to wildcard address."
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo "============================================="
    echo "  OpenClaw Fortress — Firewall Verification"
    echo "============================================="
    echo ""

    # Discover external IPs
    info "Detecting non-loopback IP addresses..."
    local external_ips
    external_ips=$(get_external_ips)

    if [[ -z "${external_ips}" ]]; then
        warn "No non-loopback IP addresses detected."
        warn "This machine may not have an active network interface."
        warn "Skipping external connectivity tests."
        echo ""
    else
        info "Found external IPs:"
        while IFS= read -r ip; do
            echo "    ${ip}"
        done <<< "${external_ips}"
        echo ""
    fi

    # --- Test 1: Wildcard binding checks ---
    echo "--- Wildcard Binding Checks ---"
    test_no_wildcard_binding "${OPENCLAW_PORT}" "OpenClaw API"
    test_no_wildcard_binding "${SIGNAL_PORT}" "signal-cli daemon"
    echo ""

    # --- Test 2: External access should be blocked ---
    if [[ -n "${external_ips}" ]]; then
        echo "--- External Access Tests ---"
        while IFS= read -r ip; do
            test_external_blocked "${ip}" "${OPENCLAW_PORT}" "OpenClaw API"
            test_external_blocked "${ip}" "${SIGNAL_PORT}" "signal-cli daemon"
        done <<< "${external_ips}"
        echo ""
    fi

    # --- Test 3: Loopback should still work ---
    echo "--- Loopback Access Tests ---"
    test_loopback_allowed "${OPENCLAW_PORT}" "OpenClaw API"
    test_loopback_allowed "${SIGNAL_PORT}" "signal-cli daemon"
    echo ""

    # --- Summary ---
    echo "============================================="
    echo "  Results: ${TESTS_PASSED}/${TESTS_RUN} tests passed"
    echo "============================================="
    echo ""

    if ${SECURE}; then
        ok "FIREWALL VERIFICATION PASSED."
        ok "All tested ports are properly secured against external access."
        exit 0
    else
        fail "FIREWALL VERIFICATION FAILED."
        fail "One or more ports are accessible from external IPs."
        fail "Run scripts/firewall-setup.sh to configure firewall rules."
        exit 1
    fi
}

main "$@"
