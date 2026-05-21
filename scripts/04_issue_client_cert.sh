#!/usr/bin/env bash
# =============================================================================
# Script 04 — Issue mTLS Client / IoT Device Certificate
# CSE PKI — University of Dhaka
#
# Usage:  ./04_issue_client_cert.sh <device-id>
# Example: ./04_issue_client_cert.sh sensor-device-001
#          ./04_issue_client_cert.sh mqtt-client-api
#
# Issues a clientAuth certificate for mutual TLS (mTLS):
#   - IoT sensor authentication
#   - Authenticated API clients
#   - Machine-to-machine (M2M) services
# =============================================================================

set -euo pipefail

DEVICE_ID="${1:-sensor-device-001}"
INT_DIR="${PKI_INT_DIR:-./certs/intermediate}"
CLIENT_DIR="${PKI_CLIENT_DIR:-./certs/client}"
INT_CONFIG="./configs/intermediate_ca.cnf"
KEY_BITS=2048
DAYS=825

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || error "openssl not installed."
[[ -f "$INT_DIR/private/intermediate.key.pem" ]] || error "Intermediate CA key not found."
[[ -f "$INT_DIR/certs/intermediate.cert.pem"  ]] || error "Intermediate CA cert not found."

mkdir -p "$CLIENT_DIR"

echo ""
echo "============================================================"
echo "  CSE PKI — Issuing mTLS Client / IoT Device Certificate"
echo "  Device ID: $DEVICE_ID"
echo "============================================================"
echo ""

# ── Generate Client Private Key ───────────────────────────────────────────────
KEY_FILE="$CLIENT_DIR/${DEVICE_ID}.key.pem"

if [[ -f "$KEY_FILE" ]]; then
    warn "Client key already exists: $KEY_FILE. Skipping."
else
    info "Generating client private key (RSA-${KEY_BITS})..."
    openssl genrsa -out "$KEY_FILE" $KEY_BITS
    chmod 400 "$KEY_FILE"
    info "Client key: $KEY_FILE"
fi

# ── Generate CSR ──────────────────────────────────────────────────────────────
CSR_FILE="$CLIENT_DIR/${DEVICE_ID}.csr.pem"

info "Generating CSR for device: $DEVICE_ID"
openssl req -new -sha256 \
    -key "$KEY_FILE" \
    -out "$CSR_FILE" \
    -subj "/C=BD/O=University of Dhaka/OU=IoT/CN=${DEVICE_ID}"
info "CSR: $CSR_FILE"

# ── Intermediate CA Signs with clientAuth Profile ─────────────────────────────
CERT_FILE="$CLIENT_DIR/${DEVICE_ID}.cert.pem"

if [[ -f "$CERT_FILE" ]]; then
    warn "Client certificate already exists: $CERT_FILE. Skipping."
else
    info "Intermediate CA is signing the client certificate (clientAuth, ${DAYS} days)..."
    echo -e "${YELLOW}Enter Intermediate CA key passphrase when prompted.${NC}"
    openssl ca -config "$INT_CONFIG" \
        -extensions client_cert \
        -days $DAYS -notext -md sha256 \
        -in "$CSR_FILE" \
        -out "$CERT_FILE"
    chmod 444 "$CERT_FILE"
fi

# ── Package as PKCS#12 (optional — useful for IoT devices) ────────────────────
P12_FILE="$CLIENT_DIR/${DEVICE_ID}.p12"
info "Packaging as PKCS#12 (for IoT device provisioning)..."
openssl pkcs12 -export \
    -out "$P12_FILE" \
    -inkey "$KEY_FILE" \
    -in "$CERT_FILE" \
    -certfile "$INT_DIR/certs/intermediate.cert.pem" \
    -name "$DEVICE_ID"
info "PKCS#12 bundle: $P12_FILE"

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
info "Verifying client certificate..."
openssl verify \
    -CAfile <(cat "$INT_DIR/certs/intermediate.cert.pem" ./certs/root/ca.cert.pem 2>/dev/null || cat "$INT_DIR/certs/intermediate.cert.pem") \
    "$CERT_FILE"
echo ""
openssl x509 -in "$CERT_FILE" -noout -text | grep -E "Subject:|Extended Key Usage:|clientAuth"
echo ""

echo "============================================================"
echo -e "  ${GREEN}mTLS Client Certificate issued!${NC}"
echo "============================================================"
echo ""
echo "  Key   : $KEY_FILE"
echo "  Cert  : $CERT_FILE"
echo "  PKCS12: $P12_FILE"
echo ""
echo "  Use in Python:"
echo "    requests.get(url, cert=('$CERT_FILE', '$KEY_FILE'), verify='certs/root/ca.cert.pem')"
echo ""
