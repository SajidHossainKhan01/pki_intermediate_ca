#!/usr/bin/env bash
# =============================================================================
# Script 07 — Revoke a Certificate & Update CRL
# CSE PKI — University of Dhaka
#
# Usage: ./07_revoke_cert.sh <path/to/cert.pem> [reason]
#
# Reasons (RFC 5280):
#   unspecified | keyCompromise | CACompromise | affiliationChanged
#   superseded  | cessationOfOperation | certificateHold
#
# Example:
#   ./07_revoke_cert.sh certs/server/iot-cse.du.ac.bd.cert.pem keyCompromise
# =============================================================================

set -euo pipefail

CERT_TO_REVOKE="${1:-}"
REASON="${2:-unspecified}"
INT_DIR="${PKI_INT_DIR:-./certs/intermediate}"
INT_CONFIG="./configs/intermediate_ca.cnf"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ -z "$CERT_TO_REVOKE" ]] && error "Usage: $0 <cert.pem> [reason]"
[[ -f "$CERT_TO_REVOKE" ]] || error "Certificate not found: $CERT_TO_REVOKE"
[[ -f "$INT_DIR/private/intermediate.key.pem" ]] || error "Intermediate CA key not found."

VALID_REASONS="unspecified keyCompromise CACompromise affiliationChanged superseded cessationOfOperation certificateHold"
echo "$VALID_REASONS" | grep -qw "$REASON" || error "Invalid reason: $REASON. Valid: $VALID_REASONS"

echo ""
echo "============================================================"
echo "  CSE PKI — Certificate Revocation"
echo "============================================================"
echo ""
warn "You are about to REVOKE the following certificate:"
openssl x509 -in "$CERT_TO_REVOKE" -noout -subject -serial -dates
echo ""
echo -e "  Reason: ${YELLOW}${REASON}${NC}"
echo ""
read -p "Confirm revocation? [yes/N]: " CONFIRM
[[ "$CONFIRM" == "yes" ]] || { echo "Aborted."; exit 0; }

# ── Revoke ────────────────────────────────────────────────────────────────────
info "Revoking certificate (reason: $REASON)..."
echo -e "${YELLOW}Enter Intermediate CA key passphrase when prompted.${NC}"
openssl ca -config "$INT_CONFIG" \
    -revoke "$CERT_TO_REVOKE" \
    -crl_reason "$REASON"
info "Certificate revoked."

# ── Generate Updated CRL ──────────────────────────────────────────────────────
CRL_FILE="$INT_DIR/crl/intermediate.crl.pem"
info "Generating updated CRL..."
openssl ca -config "$INT_CONFIG" -gencrl -out "$CRL_FILE"
info "CRL updated: $CRL_FILE"

# ── Display CRL ───────────────────────────────────────────────────────────────
echo ""
info "Current CRL contents:"
openssl crl -in "$CRL_FILE" -noout -text | grep -E "Serial Number:|Reason:|Revocation Date:" | sed 's/^/    /'
echo ""

echo "============================================================"
echo -e "  ${GREEN}Revocation complete!${NC}"
echo "============================================================"
echo ""
echo "  CRL file : $CRL_FILE"
echo ""
echo "  Distribute CRL to clients:"
echo "    - Publish to CRL Distribution Point URL"
echo "    - Or embed in TLS config for offline checking"
echo ""
echo "  Verify revocation locally:"
echo "    openssl verify -CAfile certs/intermediate/ca-chain.cert.pem \\"
echo "        -CRLfile $CRL_FILE -crl_check $CERT_TO_REVOKE"
echo ""
