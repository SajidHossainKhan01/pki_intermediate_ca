#!/usr/bin/env bash
# =============================================================================
# Script 01 — Build Root CA
# CSE PKI — University of Dhaka
#
# Creates the offline Root CA: directory structure, private key, self-signed cert.
# Run this ONCE on an air-gapped or highly restricted machine.
# After setup, the Root CA key should be taken OFFLINE.
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
ROOT_DIR="${PKI_ROOT_DIR:-./certs/root}"
CONFIG="./configs/root_ca.cnf"
KEY_BITS=4096
DAYS=7300          # 20 years
SUBJECT="/C=BD/O=University of Dhaka/OU=CSE PKI Root/CN=CSE Root CA"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Checks ────────────────────────────────────────────────────────────────────
command -v openssl >/dev/null 2>&1 || error "openssl is not installed."
[[ -f "$CONFIG" ]] || error "Config not found: $CONFIG"

echo ""
echo "============================================================"
echo "  CSE PKI — Building Root Certificate Authority"
echo "============================================================"
echo ""

# ── Directory Structure ───────────────────────────────────────────────────────
info "Creating Root CA directory structure..."
mkdir -p "$ROOT_DIR"/{certs,crl,newcerts,private}
chmod 700 "$ROOT_DIR/private"

# Initialize databases
[[ -f "$ROOT_DIR/index.txt" ]] || touch "$ROOT_DIR/index.txt"
[[ -f "$ROOT_DIR/serial"    ]] || echo "1000" > "$ROOT_DIR/serial"
[[ -f "$ROOT_DIR/crlnumber" ]] || echo "1000" > "$ROOT_DIR/crlnumber"
info "Directory structure ready."

# ── Generate Root CA Private Key ──────────────────────────────────────────────
KEY_FILE="$ROOT_DIR/private/ca.key.pem"

if [[ -f "$KEY_FILE" ]]; then
    warn "Root CA key already exists. Skipping key generation."
else
    info "Generating Root CA private key (RSA-${KEY_BITS})..."
    echo "You will be prompted for a passphrase. Use a strong passphrase and store it securely."
    openssl genrsa -aes256 -out "$KEY_FILE" $KEY_BITS
    chmod 400 "$KEY_FILE"
    info "Root CA key generated: $KEY_FILE"
fi

# ── Generate Self-Signed Root CA Certificate ──────────────────────────────────
CERT_FILE="$ROOT_DIR/certs/ca.cert.pem"

if [[ -f "$CERT_FILE" ]]; then
    warn "Root CA certificate already exists. Skipping."
else
    info "Generating self-signed Root CA certificate (${DAYS} days)..."
    openssl req -config "$CONFIG" \
        -key "$KEY_FILE" \
        -new -x509 \
        -days $DAYS \
        -sha256 \
        -extensions v3_ca \
        -out "$CERT_FILE" \
        -subj "$SUBJECT"
    chmod 444 "$CERT_FILE"
    info "Root CA certificate generated: $CERT_FILE"
fi

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
info "Verifying Root CA certificate..."
openssl x509 -in "$CERT_FILE" -noout -text | grep -E "Subject:|Issuer:|Not Before:|Not After:|CA:"
echo ""

echo "============================================================"
echo -e "  ${GREEN}Root CA setup complete!${NC}"
echo "============================================================"
echo ""
echo "  Key  : $KEY_FILE"
echo "  Cert : $CERT_FILE"
echo ""
echo -e "  ${YELLOW}SECURITY: The Root CA key should now be taken OFFLINE.${NC}"
echo "  Store the passphrase in a secure, offline location."
echo ""
