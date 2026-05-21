#!/usr/bin/env bash
# =============================================================================
# Script 03 — Issue TLS Server Certificate
# CSE PKI — University of Dhaka
#
# Usage:  ./03_issue_server_cert.sh <hostname> [<extra_san1> <extra_san2>]
# Example: ./03_issue_server_cert.sh iot-cse.du.ac.bd mqtt.cse.du.ac.bd
#
# Generates a server private key + CSR on the application server side,
# then has the Intermediate CA sign it with the server_cert profile.
# SAN is injected automatically from arguments.
# =============================================================================

set -euo pipefail

HOSTNAME="${1:-iot-cse.du.ac.bd}"
INT_DIR="${PKI_INT_DIR:-./certs/intermediate}"
SERVER_DIR="${PKI_SERVER_DIR:-./certs/server}"
INT_CONFIG="./configs/intermediate_ca.cnf"
KEY_BITS=2048
DAYS=825     # CA/B Forum max for TLS certs

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || error "openssl not installed."
[[ -f "$INT_DIR/private/intermediate.key.pem" ]] || error "Intermediate CA key not found. Run 02_build_intermediate_ca.sh first."
[[ -f "$INT_DIR/certs/intermediate.cert.pem" ]]  || error "Intermediate CA cert not found. Run 02_build_intermediate_ca.sh first."

mkdir -p "$SERVER_DIR"

echo ""
echo "============================================================"
echo "  CSE PKI — Issuing TLS Server Certificate"
echo "  Hostname: $HOSTNAME"
echo "============================================================"
echo ""

# ── Build dynamic SAN config ──────────────────────────────────────────────────
SAN_FILE=$(mktemp /tmp/san_XXXXXX.cnf)
trap "rm -f $SAN_FILE" EXIT

# Start with primary hostname
SANS="DNS.1 = ${HOSTNAME}"
IDX=2

# Add www. prefix variant
SANS+="\nDNS.${IDX} = www.${HOSTNAME}"
IDX=$((IDX + 1))

# Add any extra SANs passed as arguments
shift || true
for extra_san in "$@"; do
    SANS+="\nDNS.${IDX} = ${extra_san}"
    IDX=$((IDX + 1))
done

cat > "$SAN_FILE" <<EOF
[ san_override ]
basicConstraints       = CA:false
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names

[ alt_names ]
$(echo -e "$SANS")
EOF

info "SANs configured:"
grep "DNS\." "$SAN_FILE" | sed 's/^/    /'
echo ""

# ── Generate Server Private Key ───────────────────────────────────────────────
KEY_FILE="$SERVER_DIR/${HOSTNAME}.key.pem"

if [[ -f "$KEY_FILE" ]]; then
    warn "Server key already exists: $KEY_FILE. Skipping."
else
    info "Generating server private key (RSA-${KEY_BITS})..."
    openssl genrsa -out "$KEY_FILE" $KEY_BITS
    chmod 400 "$KEY_FILE"
    info "Server key: $KEY_FILE"
fi

# ── Generate CSR ──────────────────────────────────────────────────────────────
CSR_FILE="$SERVER_DIR/${HOSTNAME}.csr.pem"

info "Generating Certificate Signing Request (CSR)..."
openssl req -new -sha256 \
    -key "$KEY_FILE" \
    -out "$CSR_FILE" \
    -subj "/C=BD/O=University of Dhaka/OU=CSE/CN=${HOSTNAME}"
info "CSR generated: $CSR_FILE"

# ── Intermediate CA Signs the Server CSR ─────────────────────────────────────
CERT_FILE="$SERVER_DIR/${HOSTNAME}.cert.pem"

if [[ -f "$CERT_FILE" ]]; then
    warn "Server certificate already exists: $CERT_FILE. Skipping."
else
    info "Intermediate CA is signing the server certificate (${DAYS} days)..."
    echo -e "${YELLOW}Enter Intermediate CA key passphrase when prompted.${NC}"
    openssl ca -config "$INT_CONFIG" \
        -extfile "$SAN_FILE" \
        -extensions san_override \
        -days $DAYS -notext -md sha256 \
        -in "$CSR_FILE" \
        -out "$CERT_FILE"
    chmod 444 "$CERT_FILE"
fi

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
info "Verifying server certificate..."
openssl verify \
    -CAfile <(cat "$INT_DIR/certs/intermediate.cert.pem" ./certs/root/ca.cert.pem 2>/dev/null || cat "$INT_DIR/certs/intermediate.cert.pem") \
    "$CERT_FILE"

echo ""
info "Certificate details:"
openssl x509 -in "$CERT_FILE" -noout -text | grep -A 10 "Subject Alternative Name"
echo ""

echo "============================================================"
echo -e "  ${GREEN}TLS Server Certificate issued!${NC}"
echo "============================================================"
echo ""
echo "  Key  : $KEY_FILE"
echo "  Cert : $CERT_FILE"
echo ""
echo "  Deploy to server:"
echo "    ssl_certificate     $CERT_FILE;"
echo "    ssl_certificate_key $KEY_FILE;"
echo ""
echo -e "  ${YELLOW}NOTE: The private key must NEVER leave the application server.${NC}"
echo ""
