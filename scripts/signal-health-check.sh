#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# signal-health-check.sh — Signal CLI Daemon Health Check
# =============================================================================
# Verifies that the signal-cli REST daemon is:
#   1. Running as a process
#   2. Bound to loopback (127.0.0.1:8080) only
#   3. Responding to HTTP requests at /v1/about
#
# Exit codes:
#   0 — All checks passed (healthy)
#   1 — One or more checks failed (unhealthy)
#
# Usage:
#   ./scripts/signal-health-check.sh
#   ./scripts/signal-health-check.sh --quiet    # Suppress output, exit code only
# =============================================================================

readonly SIGNAL_HOST="127.0.0.1"
readonly SIGNAL_PORT=8080
readonly HEALTH_ENDPOINT="http://${SIGNAL_HOST}:${SIGNAL_PORT}/v1/about"
readonly HTTP_TIMEOUT=5

# --- Parse flags ---
QUIET=false
if [[ "${1:-}" == "--quiet" || "${1:-}" == "-q" ]]; then
    QUIET=true
fi

# --- Color output helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { ${QUIET} || echo -e "${CYAN}[INFO]${NC}  $*"; }
warn()    { ${QUIET} || echo -e "${YELLOW}[WARN]${NC}  $*"; }
ok()      { ${QUIET} || echo -e "${GREEN}[PASS]${NC}  $*"; }
fail()    { ${QUIET} || echo -e "${RED}[FAIL]${NC}  $*" >&2; }

# Track overall health
HEALTHY=true

mark_unhealthy() {
    HEALTHY=false
}

# =============================================================================
# Check 1: Is signal-cli process running?
# =============================================================================
check_process() {
    info "Checking if signal-cli process is running..."

    if pgrep -f "signal-cli.*daemon" &>/dev/null; then
        local pid
        pid=$(pgrep -f "signal-cli.*daemon" | head -1)
        ok "signal-cli daemon is running (PID: ${pid})"
    else
        fail "signal-cli daemon process not found."
        info "Start it with: sudo systemctl start signal-cli"
        mark_unhealthy
    fi
}

# =============================================================================
# Check 2: Is it bound to loopback only?
# =============================================================================
check_loopback_binding() {
    info "Checking loopback binding on port ${SIGNAL_PORT}..."

    # Detect available tool for socket inspection
    local bound_addresses=""

    if command -v ss &>/dev/null; then
        # Linux: use ss
        bound_addresses=$(ss -tlnp 2>/dev/null | grep ":${SIGNAL_PORT}" || true)
    elif command -v lsof &>/dev/null; then
        # macOS/fallback: use lsof
        bound_addresses=$(lsof -iTCP:${SIGNAL_PORT} -sTCP:LISTEN -nP 2>/dev/null || true)
    elif command -v netstat &>/dev/null; then
        # Fallback: netstat
        bound_addresses=$(netstat -an 2>/dev/null | grep "LISTEN" | grep ":${SIGNAL_PORT}" || true)
    else
        warn "No socket inspection tool found (ss, lsof, netstat). Skipping binding check."
        return
    fi

    if [[ -z "${bound_addresses}" ]]; then
        fail "Nothing is listening on port ${SIGNAL_PORT}."
        mark_unhealthy
        return
    fi

    # Check that ONLY loopback is bound (no 0.0.0.0 or *)
    if echo "${bound_addresses}" | grep -qE '(0\.0\.0\.0|::|\*)'; then
        fail "Port ${SIGNAL_PORT} is bound to a non-loopback address!"
        fail "This is a SECURITY RISK. signal-cli must bind to 127.0.0.1 only."
        ${QUIET} || echo ""
        ${QUIET} || echo "${bound_addresses}"
        mark_unhealthy
    else
        ok "Port ${SIGNAL_PORT} is bound to loopback only."
        ${QUIET} || echo "    ${bound_addresses}" | head -3
    fi
}

# =============================================================================
# Check 3: Is the HTTP endpoint responding?
# =============================================================================
check_http_response() {
    info "Checking HTTP response from ${HEALTH_ENDPOINT}..."

    # Prefer curl, fall back to wget
    local http_code=""
    local response_body=""

    if command -v curl &>/dev/null; then
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout "${HTTP_TIMEOUT}" \
            --max-time "${HTTP_TIMEOUT}" \
            "${HEALTH_ENDPOINT}" 2>/dev/null || echo "000")
        response_body=$(curl -s \
            --connect-timeout "${HTTP_TIMEOUT}" \
            --max-time "${HTTP_TIMEOUT}" \
            "${HEALTH_ENDPOINT}" 2>/dev/null || echo "")
    elif command -v wget &>/dev/null; then
        local tmp_file
        tmp_file=$(mktemp)
        http_code=$(wget -q -O "${tmp_file}" \
            --timeout="${HTTP_TIMEOUT}" \
            --server-response \
            "${HEALTH_ENDPOINT}" 2>&1 | grep "HTTP/" | tail -1 | awk '{print $2}' || echo "000")
        response_body=$(cat "${tmp_file}" 2>/dev/null || echo "")
        rm -f "${tmp_file}"
    else
        fail "Neither curl nor wget found. Cannot check HTTP endpoint."
        mark_unhealthy
        return
    fi

    case "${http_code}" in
        200)
            ok "HTTP endpoint returned 200 OK."
            if [[ -n "${response_body}" ]]; then
                # Try to extract version info if jq is available
                if command -v jq &>/dev/null; then
                    local version
                    version=$(echo "${response_body}" | jq -r '.version // "unknown"' 2>/dev/null || echo "unknown")
                    info "signal-cli version: ${version}"
                else
                    info "Response: ${response_body:0:200}"
                fi
            fi
            ;;
        000)
            fail "Connection refused or timed out at ${HEALTH_ENDPOINT}."
            fail "signal-cli daemon may not be running or not bound to ${SIGNAL_HOST}:${SIGNAL_PORT}."
            mark_unhealthy
            ;;
        *)
            fail "HTTP endpoint returned unexpected status: ${http_code}"
            mark_unhealthy
            ;;
    esac
}

# =============================================================================
# Check 4: Systemd service status (Linux only)
# =============================================================================
check_systemd_status() {
    # Only run on Linux with systemd
    if [[ "$(uname -s)" != "Linux" ]] || ! command -v systemctl &>/dev/null; then
        return
    fi

    info "Checking systemd service status..."

    if systemctl is-active --quiet signal-cli 2>/dev/null; then
        ok "systemd service 'signal-cli' is active."
    else
        local status
        status=$(systemctl is-active signal-cli 2>/dev/null || echo "unknown")
        fail "systemd service 'signal-cli' status: ${status}"
        info "Check logs with: journalctl -u signal-cli --no-pager -n 50"
        mark_unhealthy
    fi

    if systemctl is-enabled --quiet signal-cli 2>/dev/null; then
        ok "systemd service 'signal-cli' is enabled (starts on boot)."
    else
        warn "systemd service 'signal-cli' is not enabled for boot."
    fi
}

# =============================================================================
# Main
# =============================================================================
main() {
    ${QUIET} || echo "============================================="
    ${QUIET} || echo "  OpenClaw Fortress — Signal Health Check"
    ${QUIET} || echo "============================================="
    ${QUIET} || echo ""

    check_process
    ${QUIET} || echo ""
    check_loopback_binding
    ${QUIET} || echo ""
    check_http_response
    ${QUIET} || echo ""
    check_systemd_status

    ${QUIET} || echo ""
    ${QUIET} || echo "---------------------------------------------"

    if ${HEALTHY}; then
        ok "All health checks passed. signal-cli daemon is healthy."
        exit 0
    else
        fail "One or more health checks failed. signal-cli daemon needs attention."
        exit 1
    fi
}

main "$@"
