#!/usr/bin/env bash
# =============================================================================
# Script 05 — Build Trust Chain Bundle
# CSE PKI — University of Dhaka
#
# Assembles the CA chain: Intermediate cert + Root cert → ca-chain.cert.pem
#
# TLS Handshake Roles:
#   SERVER sends  : server.cert.pem + intermediate.cert.pem
#   CLIENT checks : root.cert.pem (from its trust store)
#   Root CA cert  : NEVER transmitted by the server
# =============================================================================

set -euo pipefail

ROOT_DIR="${PKI_ROOT_DIR:-./certs/root}"
INT_DIR="${PKI_INT_DIR:-./certs/intermediate}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ -f "$INT_DIR/certs/intermediate.cert.pem" ]] || error "Intermediate cert not found."
[[ -f "$ROOT_DIR/certs/ca.cert.pem"          ]] || error "Root CA cert not found."

echo ""
echo "============================================================"
echo "  CSE PKI — Building Trust Chain Bundle"
echo "============================================================"
echo ""

CHAIN_FILE="$INT_DIR/certs/ca-chain.cert.pem"

info "Combining: Intermediate CA + Root CA → ca-chain.cert.pem"
cat "$INT_DIR/certs/intermediate.cert.pem" \
    "$ROOT_DIR/certs/ca.cert.pem" \
    > "$CHAIN_FILE"
chmod 444 "$CHAIN_FILE"

# ── Verify chain integrity ────────────────────────────────────────────────────
info "Verifying chain integrity..."
openssl verify -CAfile "$ROOT_DIR/certs/ca.cert.pem" \
    "$INT_DIR/certs/intermediate.cert.pem"

# Count certs in bundle
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CHAIN_FILE")
info "Chain bundle contains $CERT_COUNT certificate(s)."

# Print chain summary
echo ""
info "Chain summary:"
openssl crl2pkcs7 -nocrl -certfile "$CHAIN_FILE" \
    | openssl pkcs7 -print_certs -noout 2>/dev/null \
    | grep -E "subject=|issuer=" \
    | sed 's/^/    /' || true

echo ""
echo "============================================================"
echo -e "  ${GREEN}Trust chain built!${NC}"
echo "============================================================"
echo ""
echo "  Chain bundle : $CHAIN_FILE"
echo ""
echo "  TLS Deployment:"
echo "    ssl_certificate      certs/server/<hostname>.cert.pem  ← server cert only"
echo "    ssl_trusted_certificate $INT_DIR/certs/intermediate.cert.pem"
echo ""
echo "  Client verification:"
echo "    openssl verify -CAfile $CHAIN_FILE <server.cert.pem>"
echo ""
echo -e "  ${YELLOW}REMINDER: Root CA cert is NOT sent by the server.${NC}"
echo "    It must be pre-installed in the client trust store."
echo ""
