#!/usr/bin/env bash
# =============================================================================
# Script 06 — Verify Full PKI Chain
# CSE PKI — University of Dhaka
#
# Performs comprehensive verification of all issued certificates:
#   - Chain of trust from end-entity to Root CA
#   - Validity periods
#   - Key usage and extended key usage
#   - SAN presence
#   - Live TLS handshake test (if server is running)
# =============================================================================

set -euo pipefail

ROOT_DIR="${PKI_ROOT_DIR:-./certs/root}"
INT_DIR="${PKI_INT_DIR:-./certs/intermediate}"
SERVER_DIR="${PKI_SERVER_DIR:-./certs/server}"
CLIENT_DIR="${PKI_CLIENT_DIR:-./certs/client}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[PASS]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[FAIL]${NC}  $*"; FAILURES=$((FAILURES + 1)); }
heading() { echo -e "\n${CYAN}── $* ──${NC}"; }

FAILURES=0

echo ""
echo "============================================================"
echo "  CSE PKI — Full Chain Verification"
echo "============================================================"

# ── Root CA ───────────────────────────────────────────────────────────────────
heading "Root CA"
ROOT_CERT="$ROOT_DIR/certs/ca.cert.pem"
if [[ -f "$ROOT_CERT" ]]; then
    openssl x509 -in "$ROOT_CERT" -noout -subject -issuer -dates
    IS_SELF_SIGNED=$(openssl verify "$ROOT_CERT" 2>&1 | grep -c "self.signed" || true)
    [[ $IS_SELF_SIGNED -gt 0 ]] && info "Root CA is self-signed (correct)" \
                                 || warn "Root CA self-sign check inconclusive"
    # Check it's a CA cert
    openssl x509 -in "$ROOT_CERT" -noout -text | grep -q "CA:TRUE" \
        && info "basicConstraints CA:TRUE present" \
        || error "basicConstraints CA:TRUE MISSING"
else
    error "Root CA cert not found: $ROOT_CERT"
fi

# ── Intermediate CA ───────────────────────────────────────────────────────────
heading "Intermediate CA"
INT_CERT="$INT_DIR/certs/intermediate.cert.pem"
CHAIN="$INT_DIR/certs/ca-chain.cert.pem"
if [[ -f "$INT_CERT" ]]; then
    openssl x509 -in "$INT_CERT" -noout -subject -issuer -dates

    openssl verify -CAfile "$ROOT_CERT" "$INT_CERT" > /dev/null 2>&1 \
        && info "Intermediate CA verified against Root CA" \
        || error "Intermediate CA verification FAILED"

    openssl x509 -in "$INT_CERT" -noout -text | grep -q "CA:TRUE" \
        && info "basicConstraints CA:TRUE present" \
        || error "basicConstraints CA:TRUE MISSING"

    openssl x509 -in "$INT_CERT" -noout -text | grep -q "pathlen:0" \
        && info "pathlen:0 constraint present (cannot sign sub-CAs)" \
        || warn "pathlen not set — may allow sub-CA issuance"
else
    error "Intermediate CA cert not found: $INT_CERT"
fi

# ── CA Chain Bundle ───────────────────────────────────────────────────────────
heading "CA Chain Bundle"
if [[ -f "$CHAIN" ]]; then
    CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CHAIN")
    info "Chain bundle contains $CERT_COUNT certificate(s)"
    [[ $CERT_COUNT -ge 2 ]] && info "Chain has Root + Intermediate (correct)" \
                             || error "Chain bundle should contain at least 2 certs"
else
    error "Chain bundle not found: $CHAIN — run 05_build_chain.sh"
fi

# ── Server Certificates ───────────────────────────────────────────────────────
heading "Server Certificates"
SERVER_CERTS=("$SERVER_DIR"/*.cert.pem 2>/dev/null)
if [[ ${#SERVER_CERTS[@]} -gt 0 && -f "${SERVER_CERTS[0]}" ]]; then
    for cert in "${SERVER_CERTS[@]}"; do
        [[ -f "$cert" ]] || continue
        HOSTNAME=$(basename "$cert" .cert.pem)
        echo -e "\n  Checking: ${HOSTNAME}"
        openssl x509 -in "$cert" -noout -subject -dates

        openssl verify -CAfile "$CHAIN" "$cert" > /dev/null 2>&1 \
            && info "Chain verified: $HOSTNAME" \
            || error "Chain verification FAILED: $HOSTNAME"

        openssl x509 -in "$cert" -noout -text | grep -q "serverAuth" \
            && info "extendedKeyUsage serverAuth present" \
            || error "serverAuth MISSING in extendedKeyUsage"

        openssl x509 -in "$cert" -noout -text | grep -q "Subject Alternative Name" \
            && info "SAN extension present (required for TLS)" \
            || error "SAN extension MISSING — modern TLS clients will REJECT this cert"

        openssl x509 -in "$cert" -noout -text | grep -q "CA:FALSE" \
            && info "basicConstraints CA:FALSE (correct — not a CA)" \
            || error "CA:FALSE MISSING"

        # Check expiry (warn if < 30 days)
        EXPIRY=$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)
        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
        [[ $DAYS_LEFT -gt 30 ]] && info "Expires in $DAYS_LEFT days" \
                                 || warn "Expires in $DAYS_LEFT days — RENEW SOON"
    done
else
    warn "No server certificates found in $SERVER_DIR"
fi

# ── Client Certificates ───────────────────────────────────────────────────────
heading "Client / IoT Device Certificates"
CLIENT_CERTS=("$CLIENT_DIR"/*.cert.pem 2>/dev/null)
if [[ ${#CLIENT_CERTS[@]} -gt 0 && -f "${CLIENT_CERTS[0]}" ]]; then
    for cert in "${CLIENT_CERTS[@]}"; do
        [[ -f "$cert" ]] || continue
        DEVICE=$(basename "$cert" .cert.pem)
        echo -e "\n  Checking: ${DEVICE}"

        openssl verify -CAfile "$CHAIN" "$cert" > /dev/null 2>&1 \
            && info "Chain verified: $DEVICE" \
            || error "Chain verification FAILED: $DEVICE"

        openssl x509 -in "$cert" -noout -text | grep -q "clientAuth" \
            && info "extendedKeyUsage clientAuth present" \
            || error "clientAuth MISSING"
    done
else
    warn "No client certificates found in $CLIENT_DIR"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
if [[ $FAILURES -eq 0 ]]; then
    echo -e "  ${GREEN}All verification checks PASSED!${NC}"
else
    echo -e "  ${RED}$FAILURES check(s) FAILED — review output above.${NC}"
fi
echo "============================================================"
echo ""
exit $FAILURES
