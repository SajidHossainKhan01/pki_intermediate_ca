#!/usr/bin/env bash
# =============================================================================
# Script 02 — Build Intermediate CA
# CSE PKI — University of Dhaka
#
# Generates the Intermediate CA key + CSR, then has the Root CA sign it.
# The Intermediate CA is the OPERATIONAL issuer (kept online).
# The Root CA key is used here and should go offline immediately after.
# =============================================================================

set -euo pipefail

ROOT_DIR="${PKI_ROOT_DIR:-./certs/root}"
INT_DIR="${PKI_INT_DIR:-./certs/intermediate}"
ROOT_CONFIG="./configs/root_ca.cnf"
INT_CONFIG="./configs/intermediate_ca.cnf"
KEY_BITS=4096
DAYS=1825    # 5 years
SUBJECT="/C=BD/O=University of Dhaka/OU=CSE PKI/CN=CSE Intermediate CA"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || error "openssl not installed."
[[ -f "$ROOT_DIR/private/ca.key.pem" ]]  || error "Root CA key not found. Run 01_build_root_ca.sh first."
[[ -f "$ROOT_DIR/certs/ca.cert.pem" ]]   || error "Root CA cert not found. Run 01_build_root_ca.sh first."

echo ""
echo "============================================================"
echo "  CSE PKI — Building Intermediate Certificate Authority"
echo "============================================================"
echo ""

# ── Directory Structure ───────────────────────────────────────────────────────
info "Creating Intermediate CA directory structure..."
mkdir -p "$INT_DIR"/{certs,crl,csr,newcerts,private}
chmod 700 "$INT_DIR/private"

[[ -f "$INT_DIR/index.txt" ]] || touch "$INT_DIR/index.txt"
[[ -f "$INT_DIR/serial"    ]] || echo "1000" > "$INT_DIR/serial"
[[ -f "$INT_DIR/crlnumber" ]] || echo "1000" > "$INT_DIR/crlnumber"
info "Directory structure ready."

# ── Generate Intermediate CA Private Key ──────────────────────────────────────
KEY_FILE="$INT_DIR/private/intermediate.key.pem"

if [[ -f "$KEY_FILE" ]]; then
    warn "Intermediate CA key already exists. Skipping."
else
    info "Generating Intermediate CA private key (RSA-${KEY_BITS})..."
    openssl genrsa -aes256 -out "$KEY_FILE" $KEY_BITS
    chmod 400 "$KEY_FILE"
    info "Intermediate CA key generated: $KEY_FILE"
fi

# ── Generate Intermediate CA CSR ─────────────────────────────────────────────
CSR_FILE="$INT_DIR/csr/intermediate.csr.pem"

if [[ -f "$CSR_FILE" ]]; then
    warn "Intermediate CA CSR already exists. Skipping."
else
    info "Generating Intermediate CA Certificate Signing Request (CSR)..."
    openssl req -config "$INT_CONFIG" \
        -new -sha256 \
        -key "$KEY_FILE" \
        -out "$CSR_FILE" \
        -subj "$SUBJECT"
    info "CSR generated: $CSR_FILE"
fi

# ── Root CA Signs the Intermediate CA CSR ────────────────────────────────────
CERT_FILE="$INT_DIR/certs/intermediate.cert.pem"

if [[ -f "$CERT_FILE" ]]; then
    warn "Intermediate CA certificate already exists. Skipping."
else
    info "Root CA is signing the Intermediate CA CSR (${DAYS} days)..."
    echo -e "${YELLOW}Enter Root CA key passphrase when prompted.${NC}"
    openssl ca -config "$ROOT_CONFIG" \
        -extensions v3_intermediate_ca \
        -days $DAYS -notext -md sha256 \
        -in "$CSR_FILE" \
        -out "$CERT_FILE"
    chmod 444 "$CERT_FILE"
    info "Intermediate CA certificate signed: $CERT_FILE"
fi

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
info "Verifying Intermediate CA certificate against Root CA..."
openssl verify -CAfile "$ROOT_DIR/certs/ca.cert.pem" "$CERT_FILE"
echo ""
openssl x509 -in "$CERT_FILE" -noout -text | grep -E "Subject:|Issuer:|Not Before:|Not After:|CA:|pathlen"
echo ""

echo "============================================================"
echo -e "  ${GREEN}Intermediate CA setup complete!${NC}"
echo "============================================================"
echo ""
echo "  Key  : $KEY_FILE"
echo "  Cert : $CERT_FILE"
echo ""
echo -e "  ${YELLOW}SECURITY: Root CA key should go OFFLINE now.${NC}"
echo ""
