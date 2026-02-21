#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# firewall-setup.sh — OpenClaw Fortress Firewall Configuration
# =============================================================================
# Detects OS and configures firewall rules:
#   - macOS:  Uses pf (pfctl) to restrict traffic to loopback only
#   - Linux:  Uses ufw + optional nftables to restrict traffic
#
# Allowed endpoints (loopback only):
#   - 127.0.0.1:18789  (OpenClaw API server)
#   - 127.0.0.1:8080   (signal-cli REST daemon)
#
# All other inbound traffic on these ports is blocked from external interfaces.
# Requires root/sudo to apply firewall rules.
# =============================================================================

readonly OPENCLAW_PORT=18789
readonly SIGNAL_PORT=8080
readonly PF_ANCHOR="com.openclaw.fortress"
readonly PF_RULES_FILE="/etc/pf.anchors/${PF_ANCHOR}"
readonly UFW_COMMENT="openclaw-fortress"

# --- Color output helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No color

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }
err()     { echo -e "${RED}[ERR ]${NC}  $*" >&2; }

# --- Pre-flight checks ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (sudo)."
        exit 1
    fi
}

# --- Confirmation prompt ---
confirm() {
    local msg="${1:-Proceed?}"
    echo ""
    warn "THIS WILL MODIFY YOUR SYSTEM FIREWALL RULES."
    echo -e "  Allowed: 127.0.0.1:${OPENCLAW_PORT} (OpenClaw API)"
    echo -e "  Allowed: 127.0.0.1:${SIGNAL_PORT}   (signal-cli daemon)"
    echo -e "  Blocked: All external access to these ports"
    echo ""
    read -rp "$(echo -e "${YELLOW}${msg} [y/N]:${NC} ")" answer
    case "${answer}" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) info "Aborted by user."; exit 0 ;;
    esac
}

# =============================================================================
# macOS — pf (Packet Filter) configuration
# =============================================================================
setup_macos_pf() {
    info "Detected macOS. Configuring pf (Packet Filter)..."

    # Backup existing pf.conf if no backup exists yet
    if [[ ! -f /etc/pf.conf.openclaw-backup ]]; then
        cp /etc/pf.conf /etc/pf.conf.openclaw-backup
        ok "Backed up /etc/pf.conf to /etc/pf.conf.openclaw-backup"
    else
        info "Backup already exists at /etc/pf.conf.openclaw-backup"
    fi

    # Create the anchor rules file
    mkdir -p /etc/pf.anchors
    cat > "${PF_RULES_FILE}" <<PFRULES
# =============================================================================
# OpenClaw Fortress — pf anchor rules
# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
# =============================================================================
# Block external access to OpenClaw API port
block in quick on ! lo0 proto tcp from any to any port ${OPENCLAW_PORT}
# Block external access to signal-cli REST port
block in quick on ! lo0 proto tcp from any to any port ${SIGNAL_PORT}
# Allow loopback traffic (implicit, but explicit for clarity)
pass in quick on lo0 proto tcp from 127.0.0.1 to 127.0.0.1 port ${OPENCLAW_PORT}
pass in quick on lo0 proto tcp from 127.0.0.1 to 127.0.0.1 port ${SIGNAL_PORT}
PFRULES

    ok "Wrote pf anchor rules to ${PF_RULES_FILE}"

    # Ensure the anchor is loaded in pf.conf
    if ! grep -q "${PF_ANCHOR}" /etc/pf.conf 2>/dev/null; then
        # Add anchor reference and load directive
        cat >> /etc/pf.conf <<PFCONF

# --- OpenClaw Fortress firewall rules ---
anchor "${PF_ANCHOR}"
load anchor "${PF_ANCHOR}" from "${PF_RULES_FILE}"
PFCONF
        ok "Added anchor reference to /etc/pf.conf"
    else
        info "Anchor reference already exists in /etc/pf.conf"
    fi

    # Validate and load the rules
    info "Validating pf configuration..."
    if pfctl -n -f /etc/pf.conf; then
        ok "pf configuration is valid."
    else
        err "pf configuration validation failed. Restoring backup."
        cp /etc/pf.conf.openclaw-backup /etc/pf.conf
        exit 1
    fi

    info "Loading pf rules..."
    pfctl -f /etc/pf.conf
    pfctl -e 2>/dev/null || true  # Enable pf (may already be enabled)

    ok "macOS pf firewall configured successfully."
    echo ""
    info "To verify:  sudo pfctl -sr"
    info "To disable: sudo pfctl -d"
    info "To restore: sudo cp /etc/pf.conf.openclaw-backup /etc/pf.conf && sudo pfctl -f /etc/pf.conf"
}

# =============================================================================
# Linux — UFW + nftables configuration
# =============================================================================
setup_linux_ufw() {
    info "Detected Linux. Configuring ufw firewall..."

    # Check that ufw is installed
    if ! command -v ufw &>/dev/null; then
        err "ufw is not installed. Install it with: sudo apt install ufw"
        exit 1
    fi

    # Enable ufw if not already active
    local ufw_status
    ufw_status=$(ufw status | head -1)
    if [[ "${ufw_status}" != *"active"* ]]; then
        info "Enabling ufw..."
        ufw --force enable
    fi

    # Default policies: deny incoming, allow outgoing
    ufw default deny incoming
    ufw default allow outgoing
    ok "Set default policies: deny incoming, allow outgoing"

    # Allow loopback traffic on the two ports
    # UFW doesn't natively filter by interface easily, so we use ufw route rules
    # and also insert deny rules for non-loopback access.

    # Allow from localhost only
    ufw allow from 127.0.0.1 to 127.0.0.1 port "${OPENCLAW_PORT}" proto tcp \
        comment "${UFW_COMMENT}-api"
    ufw allow from 127.0.0.1 to 127.0.0.1 port "${SIGNAL_PORT}" proto tcp \
        comment "${UFW_COMMENT}-signal"

    # Explicitly deny from any other source to these ports
    ufw deny from any to any port "${OPENCLAW_PORT}" proto tcp \
        comment "${UFW_COMMENT}-api-deny-external"
    ufw deny from any to any port "${SIGNAL_PORT}" proto tcp \
        comment "${UFW_COMMENT}-signal-deny-external"

    ok "UFW rules configured."

    # Optional: set up nftables rules for defense-in-depth
    if command -v nft &>/dev/null; then
        info "nftables detected. Adding supplementary rules..."
        nft add table inet openclaw_fortress 2>/dev/null || true
        nft flush table inet openclaw_fortress 2>/dev/null || true

        nft add chain inet openclaw_fortress input \
            '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true

        # Drop non-loopback traffic to our ports
        nft add rule inet openclaw_fortress input \
            iifname != "lo" tcp dport "${OPENCLAW_PORT}" drop 2>/dev/null || true
        nft add rule inet openclaw_fortress input \
            iifname != "lo" tcp dport "${SIGNAL_PORT}" drop 2>/dev/null || true

        ok "nftables supplementary rules applied."
    else
        info "nftables not found. Skipping supplementary rules (ufw is sufficient)."
    fi

    # Reload and show status
    ufw reload
    echo ""
    ufw status verbose
    ok "Linux firewall configured successfully."
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo "============================================="
    echo "  OpenClaw Fortress — Firewall Setup"
    echo "============================================="
    echo ""

    check_root
    confirm "Apply firewall rules?"

    case "$(uname -s)" in
        Darwin)
            setup_macos_pf
            ;;
        Linux)
            setup_linux_ufw
            ;;
        *)
            err "Unsupported operating system: $(uname -s)"
            err "This script supports macOS (pf) and Linux (ufw/nftables)."
            exit 1
            ;;
    esac

    echo ""
    ok "Firewall setup complete. Run scripts/verify-firewall.sh to validate."
}

main "$@"
