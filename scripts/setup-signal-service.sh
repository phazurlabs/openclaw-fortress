#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# setup-signal-service.sh — Signal CLI Service Setup (Linux Only)
# =============================================================================
# Creates the signal-svc system user and sets up the directory structure
# required for the signal-cli daemon at /opt/signal-cli.
#
# Directory layout:
#   /opt/signal-cli/
#   ├── bin/          — signal-cli binary
#   ├── config/       — signal-cli configuration and registration data
#   ├── data/         — runtime data (message store, attachments)
#   └── logs/         — daemon log files
#
# The signal-svc user:
#   - System account (no login shell, no home directory)
#   - Owns /opt/signal-cli recursively
#   - Used by the systemd unit to run signal-cli as non-root
#
# Requires root/sudo. Exits gracefully on non-Linux systems.
# =============================================================================

readonly SERVICE_USER="signal-svc"
readonly SERVICE_GROUP="signal-svc"
readonly INSTALL_DIR="/opt/signal-cli"
readonly LOG_DIR="${INSTALL_DIR}/logs"
readonly BIN_DIR="${INSTALL_DIR}/bin"
readonly CONFIG_DIR="${INSTALL_DIR}/config"
readonly DATA_DIR="${INSTALL_DIR}/data"

# --- Color output helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }
err()     { echo -e "${RED}[ERR ]${NC}  $*" >&2; }

# =============================================================================
# Pre-flight checks
# =============================================================================

# Exit immediately if not Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    warn "This script is Linux-only. Detected OS: $(uname -s)"
    warn "signal-cli systemd service setup is not applicable on this platform."
    exit 0
fi

# Must be root
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo)."
    exit 1
fi

echo "============================================="
echo "  OpenClaw Fortress — Signal Service Setup"
echo "============================================="
echo ""

# =============================================================================
# Step 1: Create the service group (if it does not exist)
# =============================================================================
if getent group "${SERVICE_GROUP}" &>/dev/null; then
    info "Group '${SERVICE_GROUP}' already exists."
else
    info "Creating system group '${SERVICE_GROUP}'..."
    groupadd --system "${SERVICE_GROUP}"
    ok "Group '${SERVICE_GROUP}' created."
fi

# =============================================================================
# Step 2: Create the service user (if it does not exist)
# =============================================================================
if id "${SERVICE_USER}" &>/dev/null; then
    info "User '${SERVICE_USER}' already exists."
else
    info "Creating system user '${SERVICE_USER}'..."
    useradd \
        --system \
        --gid "${SERVICE_GROUP}" \
        --no-create-home \
        --home-dir "${INSTALL_DIR}" \
        --shell /usr/sbin/nologin \
        --comment "OpenClaw signal-cli daemon service account" \
        "${SERVICE_USER}"
    ok "User '${SERVICE_USER}' created (no login shell, no home directory)."
fi

# =============================================================================
# Step 3: Create directory structure
# =============================================================================
info "Setting up directory structure at ${INSTALL_DIR}..."

declare -a DIRS=(
    "${INSTALL_DIR}"
    "${BIN_DIR}"
    "${CONFIG_DIR}"
    "${DATA_DIR}"
    "${LOG_DIR}"
)

for dir in "${DIRS[@]}"; do
    if [[ -d "${dir}" ]]; then
        info "  Directory exists: ${dir}"
    else
        mkdir -p "${dir}"
        ok "  Created: ${dir}"
    fi
done

# =============================================================================
# Step 4: Set ownership and permissions
# =============================================================================
info "Setting ownership and permissions..."

# Recursive ownership to signal-svc
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}"
ok "Ownership set to ${SERVICE_USER}:${SERVICE_GROUP} on ${INSTALL_DIR}"

# Directory permissions:
#   - bin:    755 (readable/executable by all, writable by owner)
#   - config: 750 (readable by group, no access for others — contains secrets)
#   - data:   750 (readable by group, no access for others)
#   - logs:   755 (readable by all for debugging)
chmod 755 "${INSTALL_DIR}"
chmod 755 "${BIN_DIR}"
chmod 750 "${CONFIG_DIR}"
chmod 750 "${DATA_DIR}"
chmod 755 "${LOG_DIR}"

ok "Permissions applied:"
echo "    ${INSTALL_DIR}   755"
echo "    ${BIN_DIR}       755"
echo "    ${CONFIG_DIR}    750 (restricted — contains secrets)"
echo "    ${DATA_DIR}      750 (restricted)"
echo "    ${LOG_DIR}       755"

# =============================================================================
# Step 5: Verify setup
# =============================================================================
echo ""
info "Verification:"
echo ""
echo "  User:  $(id "${SERVICE_USER}")"
echo ""
echo "  Directory tree:"
ls -la "${INSTALL_DIR}/"
echo ""

# Check if signal-cli binary is present
if [[ -f "${BIN_DIR}/signal-cli" ]]; then
    ok "signal-cli binary found at ${BIN_DIR}/signal-cli"
else
    warn "signal-cli binary not yet installed at ${BIN_DIR}/signal-cli"
    info "Download from: https://github.com/AsamK/signal-cli/releases"
    info "Place the binary at: ${BIN_DIR}/signal-cli"
fi

# =============================================================================
# Step 6: Install systemd unit file if present
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_FILE="${SCRIPT_DIR}/signal-cli.service"

if [[ -f "${UNIT_FILE}" ]]; then
    info "Installing systemd unit file..."
    cp "${UNIT_FILE}" /etc/systemd/system/signal-cli.service
    chmod 644 /etc/systemd/system/signal-cli.service
    systemctl daemon-reload
    ok "Installed signal-cli.service to /etc/systemd/system/"
    info "Enable with:  sudo systemctl enable signal-cli"
    info "Start with:   sudo systemctl start signal-cli"
else
    warn "Systemd unit file not found at ${UNIT_FILE}"
    info "Copy scripts/signal-cli.service to /etc/systemd/system/ manually."
fi

echo ""
ok "Signal service setup complete."
