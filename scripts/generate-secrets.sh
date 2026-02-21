#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# generate-secrets.sh — Environment Secret Generator
# =============================================================================
# Generates all required environment variables for OpenClaw Fortress using
# cryptographically secure random values from openssl.
#
# Output is in .env format, ready to copy to your .env file or pipe directly:
#
# Usage:
#   ./scripts/generate-secrets.sh               # Print to stdout
#   ./scripts/generate-secrets.sh > .env         # Write to .env file
#   ./scripts/generate-secrets.sh --append >> .env  # Append to existing .env
#   ./scripts/generate-secrets.sh --check        # Verify openssl is available
#
# All secrets are generated using: openssl rand -hex 32 (256-bit entropy)
# Shorter tokens use: openssl rand -hex 16 (128-bit entropy)
# =============================================================================

# --- Color output helpers (only when stderr is a terminal) ---
if [[ -t 2 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' NC=''
fi

info()    { echo -e "${CYAN}[INFO]${NC}  $*" >&2; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*" >&2; }
err()     { echo -e "${RED}[ERR ]${NC}  $*" >&2; }

# --- Parse arguments ---
CHECK_MODE=false
APPEND_MODE=false

for arg in "$@"; do
    case "${arg}" in
        --check)
            CHECK_MODE=true
            ;;
        --append)
            APPEND_MODE=true
            ;;
        -h|--help)
            echo "Usage: $(basename "$0") [OPTIONS]"
            echo ""
            echo "Generate cryptographically secure environment variables for OpenClaw Fortress."
            echo ""
            echo "Options:"
            echo "  --check    Verify openssl is available and exit"
            echo "  --append   Print without header (suitable for >> append)"
            echo "  -h, --help Show this help"
            echo ""
            echo "Examples:"
            echo "  $(basename "$0")              # Print to stdout"
            echo "  $(basename "$0") > .env       # Write new .env file"
            echo "  $(basename "$0") --append >> .env  # Append to existing"
            exit 0
            ;;
        *)
            err "Unknown argument: ${arg}"
            exit 1
            ;;
    esac
done

# =============================================================================
# Verify openssl is available
# =============================================================================
if ! command -v openssl &>/dev/null; then
    err "openssl is not installed or not in PATH."
    err "Install OpenSSL and try again."
    exit 1
fi

if ${CHECK_MODE}; then
    ok "openssl is available: $(openssl version)"
    ok "Random generation test: $(openssl rand -hex 4)"
    exit 0
fi

# =============================================================================
# Secret generation helpers
# =============================================================================

# Generate a 256-bit hex secret (64 hex characters)
secret_256() {
    openssl rand -hex 32
}

# Generate a 128-bit hex secret (32 hex characters)
secret_128() {
    openssl rand -hex 16
}

# Generate a base64 secret (suitable for JWT, etc.)
secret_b64() {
    openssl rand -base64 32 | tr -d '\n'
}

# Generate a URL-safe base64 secret
secret_urlsafe() {
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
}

# =============================================================================
# Generate and output all secrets
# =============================================================================

info "Generating cryptographically secure secrets..."
info "Using openssl rand with 256-bit entropy for keys, 128-bit for tokens."
echo "" >&2

# --- Header ---
if ! ${APPEND_MODE}; then
    cat <<'HEADER'
# =============================================================================
# OpenClaw Fortress — Environment Configuration
# =============================================================================
# GENERATED SECRETS — DO NOT COMMIT TO VERSION CONTROL
#
# Add this file to .gitignore:
#   echo ".env" >> .gitignore
#
HEADER
    echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "# Host:      $(hostname)"
    echo ""
fi

# --- Core Application Secrets ---
cat <<EOF
# -----------------------------------------------------------------------------
# Core Application Secrets
# -----------------------------------------------------------------------------

# Master encryption key for credential vault (AES-256)
OPENCLAW_MASTER_KEY=$(secret_256)

# Session signing secret (HMAC-SHA256)
OPENCLAW_SESSION_SECRET=$(secret_256)

# JWT signing secret for API authentication
OPENCLAW_JWT_SECRET=$(secret_b64)

# CSRF protection token seed
OPENCLAW_CSRF_SECRET=$(secret_128)

# -----------------------------------------------------------------------------
# API Keys & Service Credentials
# -----------------------------------------------------------------------------

# Anthropic API key (replace with your actual key)
OPENCLAW_ANTHROPIC_API_KEY=sk-ant-REPLACE_WITH_YOUR_KEY

# Internal API authentication token
OPENCLAW_API_TOKEN=$(secret_256)

# Webhook signing secret (for verifying inbound webhooks)
OPENCLAW_WEBHOOK_SECRET=$(secret_256)

# -----------------------------------------------------------------------------
# Signal CLI Configuration
# -----------------------------------------------------------------------------

# Signal service authentication token
OPENCLAW_SIGNAL_AUTH_TOKEN=$(secret_128)

# Signal CLI REST API host and port
OPENCLAW_SIGNAL_HOST=127.0.0.1
OPENCLAW_SIGNAL_PORT=8080

# -----------------------------------------------------------------------------
# Discord Bot Configuration
# -----------------------------------------------------------------------------

# Discord bot token (replace with your actual token)
OPENCLAW_DISCORD_TOKEN=REPLACE_WITH_YOUR_DISCORD_BOT_TOKEN

# Discord application ID
OPENCLAW_DISCORD_APP_ID=REPLACE_WITH_YOUR_DISCORD_APP_ID

# -----------------------------------------------------------------------------
# Database & Storage
# -----------------------------------------------------------------------------

# Database encryption key (for at-rest encryption)
OPENCLAW_DB_ENCRYPTION_KEY=$(secret_256)

# Audit log HMAC key (for tamper detection)
OPENCLAW_AUDIT_HMAC_KEY=$(secret_256)

# -----------------------------------------------------------------------------
# Server Configuration
# -----------------------------------------------------------------------------

# OpenClaw API server binding
OPENCLAW_HOST=127.0.0.1
OPENCLAW_PORT=18789

# Environment (development | staging | production)
OPENCLAW_ENV=development

# Log level (debug | info | warn | error)
OPENCLAW_LOG_LEVEL=info

# -----------------------------------------------------------------------------
# Rate Limiting & Security
# -----------------------------------------------------------------------------

# Rate limiter seed (for consistent hashing)
OPENCLAW_RATE_LIMIT_SEED=$(secret_128)

# IP allowlist (comma-separated, empty = allow all local)
OPENCLAW_IP_ALLOWLIST=127.0.0.1

# Cookie encryption key
OPENCLAW_COOKIE_SECRET=$(secret_urlsafe)

EOF

# --- Summary ---
info "Secret generation complete."
info ""
info "IMPORTANT REMINDERS:"
warn "  1. Replace placeholder values (REPLACE_WITH_*) with your actual credentials."
warn "  2. Add .env to your .gitignore immediately."
warn "  3. Consider migrating to OS keychain: npx tsx scripts/migrate-credentials.ts"
warn "  4. Back up your .env securely (not in version control)."
echo "" >&2
ok "Done. Secrets are ready."
