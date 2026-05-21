#!/usr/bin/env bash
# =============================================================================
# test_tls_handshake.sh — Live TLS Handshake Test
# CSE PKI — University of Dhaka
#
# Usage: ./test_tls_handshake.sh [hostname] [port]
# Example: ./test_tls_handshake.sh iot-cse.du.ac.bd 443
#          ./test_tls_handshake.sh iot-cse.du.ac.bd 8883   (MQTT/TLS)
#
# Tests live TLS connectivity, protocol version, cipher, and chain validity.
# =============================================================================

set -euo pipefail

HOSTNAME="${1:-iot-cse.du.ac.bd}"
PORT="${2:-443}"
ROOT_CA="${PKI_ROOT_DIR:-./certs/root}/certs/ca.cert.pem"
TIMEOUT=10

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; }
info() { echo -e "  ${CYAN}i${NC} $*"; }

echo ""
echo "============================================================"
echo "  CSE PKI — Live TLS Handshake Test"
echo "  Host: $HOSTNAME:$PORT"
echo "============================================================"
echo ""

[[ -f "$ROOT_CA" ]] || { echo -e "${RED}[ERROR]${NC} Root CA not found: $ROOT_CA"; exit 1; }

# ── Run s_client and capture full output ──────────────────────────────────────
TLS_OUTPUT=$(echo "Q" | timeout $TIMEOUT openssl s_client \
    -connect "${HOSTNAME}:${PORT}" \
    -CAfile "$ROOT_CA" \
    -servername "$HOSTNAME" \
    -status \
    2>&1 || true)

echo -e "${CYAN}── Connection ──${NC}"
# Check if connection succeeded
if echo "$TLS_OUTPUT" | grep -q "CONNECTED"; then
    pass "TCP connection established"
else
    fail "TCP connection FAILED to ${HOSTNAME}:${PORT}"
    echo "    → Is the server running?"
    exit 1
fi

echo -e "\n${CYAN}── Certificate Verification ──${NC}"
VERIFY_CODE=$(echo "$TLS_OUTPUT" | grep "Verify return code:" | awk -F': ' '{print $2}')
if echo "$VERIFY_CODE" | grep -q "^0 (ok)"; then
    pass "Certificate chain verified: $VERIFY_CODE"
else
    fail "Verification failed: $VERIFY_CODE"
fi

echo -e "\n${CYAN}── TLS Protocol ──${NC}"
PROTOCOL=$(echo "$TLS_OUTPUT" | grep "Protocol  :" | awk -F': ' '{print $2}' | tr -d ' ')
if [[ "$PROTOCOL" == "TLSv1.3" || "$PROTOCOL" == "TLSv1.2" ]]; then
    pass "TLS version: $PROTOCOL"
else
    fail "Weak or unknown TLS version: $PROTOCOL (require TLSv1.2+)"
fi

echo -e "\n${CYAN}── Cipher Suite ──${NC}"
CIPHER=$(echo "$TLS_OUTPUT" | grep "Cipher    :" | awk -F': ' '{print $2}' | tr -d ' ')
info "Cipher: $CIPHER"
# Check for weak ciphers
if echo "$CIPHER" | grep -qE "RC4|DES|NULL|EXPORT|MD5|aNULL"; then
    fail "WEAK cipher in use: $CIPHER"
else
    pass "Cipher suite is acceptable: $CIPHER"
fi

echo -e "\n${CYAN}── Certificate Chain ──${NC}"
# Extract cert chain depth
DEPTH=$(echo "$TLS_OUTPUT" | grep -c "^---" || true)
info "TLS output sections: $DEPTH"

# Check intermediate was presented
SERVER_CERT=$(echo "$TLS_OUTPUT" | grep " 0 s:" | head -1)
INTERMEDIATE=$(echo "$TLS_OUTPUT" | grep " 1 s:" | head -1)
[[ -n "$SERVER_CERT"   ]] && pass "Server cert present in chain:       $SERVER_CERT" \
                           || fail "Server cert missing from chain"
[[ -n "$INTERMEDIATE"  ]] && pass "Intermediate cert present in chain: $INTERMEDIATE" \
                           || fail "Intermediate cert NOT presented by server"

# Confirm Root CA is NOT sent
ROOT_SENT=$(echo "$TLS_OUTPUT" | grep " 2 s:" | head -1 || true)
[[ -z "$ROOT_SENT" ]] && pass "Root CA NOT transmitted (correct)" \
                       || fail "Root CA was transmitted — should NOT be sent by server"

echo -e "\n${CYAN}── OCSP Stapling ──${NC}"
if echo "$TLS_OUTPUT" | grep -q "OCSP response:"; then
    pass "OCSP stapling is configured"
else
    info "OCSP stapling not detected (optional for private PKI)"
fi

echo -e "\n${CYAN}── SAN Verification ──${NC}"
# Extract server cert and check SAN
SERVER_CERT_PEM=$(echo "$TLS_OUTPUT" | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' | head -25)
if [[ -n "$SERVER_CERT_PEM" ]]; then
    SAN=$(echo "$SERVER_CERT_PEM" | openssl x509 -noout -text 2>/dev/null \
        | grep -A 2 "Subject Alternative Name" | tail -1 | tr -d ' ' || true)
    if echo "$SAN" | grep -q "DNS:$HOSTNAME"; then
        pass "SAN contains hostname: $HOSTNAME"
    else
        fail "SAN does not contain $HOSTNAME — got: $SAN"
    fi
fi

echo ""
echo "============================================================"
echo -e "  ${GREEN}TLS handshake test complete for ${HOSTNAME}:${PORT}${NC}"
echo "============================================================"
echo ""
