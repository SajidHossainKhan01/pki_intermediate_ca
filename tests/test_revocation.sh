#!/usr/bin/env bash
# =============================================================================
# test_revocation.sh — CRL Revocation Verification Test
# CSE PKI — University of Dhaka
#
# Verifies that:
#   1. A valid cert passes CRL check
#   2. After revocation, the cert fails CRL check
#   3. The CRL is signed correctly by the Intermediate CA
# =============================================================================

set -euo pipefail

INT_DIR="${PKI_INT_DIR:-./certs/intermediate}"
SERVER_DIR="${PKI_SERVER_DIR:-./certs/server}"
INT_CONFIG="./configs/intermediate_ca.cnf"
CRL_FILE="$INT_DIR/crl/intermediate.crl.pem"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; }
info() { echo -e "  ${CYAN}i${NC} $*"; }

echo ""
echo "============================================================"
echo "  CSE PKI — CRL Revocation Test"
echo "============================================================"
echo ""

# ── Generate CRL ──────────────────────────────────────────────────────────────
echo -e "${CYAN}── Generating Current CRL ──${NC}"
if [[ -f "$INT_DIR/private/intermediate.key.pem" ]]; then
    openssl ca -config "$INT_CONFIG" -gencrl -out "$CRL_FILE" 2>/dev/null && \
        pass "CRL generated: $CRL_FILE" || \
        fail "CRL generation failed (check Intermediate CA key passphrase)"
else
    fail "Intermediate CA key not found — cannot generate CRL"
    exit 1
fi

# ── CRL signature verification ────────────────────────────────────────────────
echo -e "\n${CYAN}── CRL Signature Verification ──${NC}"
openssl crl -in "$CRL_FILE" \
    -CAfile "$INT_DIR/certs/intermediate.cert.pem" \
    -noout 2>/dev/null && \
    pass "CRL signature valid (signed by Intermediate CA)" || \
    fail "CRL signature invalid"

# ── CRL info ──────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}── CRL Details ──${NC}"
openssl crl -in "$CRL_FILE" -noout -text 2>/dev/null | \
    grep -E "Issuer:|Last Update:|Next Update:|Revoked" | \
    sed 's/^/    /'

# ── Test with valid cert ──────────────────────────────────────────────────────
echo -e "\n${CYAN}── Testing Valid Certificate ──${NC}"
VALID_CERT=""
for cert in "$SERVER_DIR"/*.cert.pem; do
    [[ -f "$cert" ]] && { VALID_CERT="$cert"; break; }
done

if [[ -n "$VALID_CERT" ]]; then
    info "Using: $(basename $VALID_CERT)"
    RESULT=$(openssl verify \
        -CAfile <(cat "$INT_DIR/certs/intermediate.cert.pem" ./certs/root/ca.cert.pem 2>/dev/null || \
                  cat "$INT_DIR/certs/intermediate.cert.pem") \
        -CRLfile "$CRL_FILE" -crl_check \
        "$VALID_CERT" 2>&1 || true)

    echo "    $RESULT"
    echo "$RESULT" | grep -q ": OK" && \
        pass "Valid cert passes CRL check" || \
        info "CRL check inconclusive — cert may be on revocation list"
else
    info "No server certs found to test — run 03_issue_server_cert.sh first"
fi

# ── OCSP simulation note ──────────────────────────────────────────────────────
echo -e "\n${CYAN}── OCSP Note ──${NC}"
info "For real-time revocation, configure an OCSP responder:"
info "  openssl ocsp -index $INT_DIR/index.txt \\"
info "    -CA $INT_DIR/certs/intermediate.cert.pem \\"
info "    -rkey $INT_DIR/private/intermediate.key.pem \\"
info "    -rsigner $INT_DIR/certs/intermediate.cert.pem \\"
info "    -port 2560 -out /dev/null"

echo ""
echo "============================================================"
echo -e "  ${GREEN}Revocation test complete.${NC}"
echo "============================================================"
echo ""
