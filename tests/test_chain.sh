#!/usr/bin/env bash
# =============================================================================
# test_chain.sh — Automated Certificate Chain Tests
# CSE PKI — University of Dhaka
#
# Runs assertion-based tests on the PKI chain.
# Exit code: 0 = all pass, non-zero = failures
# =============================================================================

set -euo pipefail

ROOT_DIR="${PKI_ROOT_DIR:-./certs/root}"
INT_DIR="${PKI_INT_DIR:-./certs/intermediate}"
SERVER_DIR="${PKI_SERVER_DIR:-./certs/server}"
CLIENT_DIR="${PKI_CLIENT_DIR:-./certs/client}"

PASS=0; FAIL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}✓${NC} $*"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}✗${NC} $*"; FAIL=$((FAIL+1)); }
skip() { echo -e "  ${YELLOW}~${NC} $* (skipped — cert not found)"; }

assert_file_exists() {
    [[ -f "$1" ]] && pass "File exists: $1" || fail "File missing: $1"
}

assert_is_ca() {
    openssl x509 -in "$1" -noout -text 2>/dev/null | grep -q "CA:TRUE" \
        && pass "basicConstraints CA:TRUE: $1" \
        || fail "CA:TRUE missing in: $1"
}

assert_not_ca() {
    openssl x509 -in "$1" -noout -text 2>/dev/null | grep -q "CA:FALSE" \
        && pass "basicConstraints CA:FALSE: $1" \
        || fail "CA:FALSE missing in: $1"
}

assert_verifies_against() {
    openssl verify -CAfile "$2" "$1" >/dev/null 2>&1 \
        && pass "Verified $1 against $2" \
        || fail "FAILED to verify $1 against $2"
}

assert_has_extension() {
    openssl x509 -in "$1" -noout -text 2>/dev/null | grep -q "$2" \
        && pass "Extension '$2' present: $(basename $1)" \
        || fail "Extension '$2' MISSING: $(basename $1)"
}

assert_key_matches_cert() {
    local key_hash cert_hash
    key_hash=$(openssl pkey  -in "$1" -pubout 2>/dev/null | openssl sha256 | awk '{print $2}')
    cert_hash=$(openssl x509 -in "$2" -pubkey -noout 2>/dev/null | openssl sha256 | awk '{print $2}')
    [[ "$key_hash" == "$cert_hash" ]] \
        && pass "Key matches cert: $(basename $2)" \
        || fail "Key MISMATCH: $1 vs $2"
}

assert_not_expired() {
    openssl x509 -in "$1" -checkend 0 >/dev/null 2>&1 \
        && pass "Not expired: $(basename $1)" \
        || fail "EXPIRED: $1"
}

echo ""
echo "============================================================"
echo "  CSE PKI — Automated Chain Tests"
echo "============================================================"

# ── File existence ────────────────────────────────────────────────────────────
echo -e "\n${CYAN}── File Existence ──${NC}"
assert_file_exists "$ROOT_DIR/certs/ca.cert.pem"
assert_file_exists "$ROOT_DIR/private/ca.key.pem"
assert_file_exists "$INT_DIR/certs/intermediate.cert.pem"
assert_file_exists "$INT_DIR/private/intermediate.key.pem"
assert_file_exists "$INT_DIR/certs/ca-chain.cert.pem"

# ── Root CA properties ────────────────────────────────────────────────────────
echo -e "\n${CYAN}── Root CA ──${NC}"
ROOT_CERT="$ROOT_DIR/certs/ca.cert.pem"
if [[ -f "$ROOT_CERT" ]]; then
    assert_is_ca "$ROOT_CERT"
    assert_not_expired "$ROOT_CERT"
    # Self-signed check
    SUBJ=$(openssl x509 -in "$ROOT_CERT" -noout -subject 2>/dev/null | sed 's/subject=//')
    ISSUER=$(openssl x509 -in "$ROOT_CERT" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    [[ "$SUBJ" == "$ISSUER" ]] \
        && pass "Root CA is self-signed" \
        || fail "Root CA subject != issuer (not self-signed?)"
else
    skip "Root CA cert"
fi

# ── Intermediate CA properties ────────────────────────────────────────────────
echo -e "\n${CYAN}── Intermediate CA ──${NC}"
INT_CERT="$INT_DIR/certs/intermediate.cert.pem"
if [[ -f "$INT_CERT" && -f "$ROOT_CERT" ]]; then
    assert_is_ca "$INT_CERT"
    assert_not_expired "$INT_CERT"
    assert_verifies_against "$INT_CERT" "$ROOT_CERT"
    assert_has_extension "$INT_CERT" "pathlen:0"
    assert_has_extension "$INT_CERT" "keyCertSign"
else
    skip "Intermediate CA cert"
fi

# ── CA chain bundle ───────────────────────────────────────────────────────────
echo -e "\n${CYAN}── CA Chain Bundle ──${NC}"
CHAIN="$INT_DIR/certs/ca-chain.cert.pem"
if [[ -f "$CHAIN" ]]; then
    COUNT=$(grep -c "BEGIN CERTIFICATE" "$CHAIN")
    [[ $COUNT -ge 2 ]] \
        && pass "Chain contains $COUNT certificates (>= 2 required)" \
        || fail "Chain contains only $COUNT certificate — need Root + Intermediate"
fi

# ── Server certificates ───────────────────────────────────────────────────────
echo -e "\n${CYAN}── Server Certificates ──${NC}"
if compgen -G "$SERVER_DIR/*.cert.pem" > /dev/null 2>&1; then
    for cert in "$SERVER_DIR"/*.cert.pem; do
        [[ -f "$cert" ]] || continue
        name=$(basename "$cert" .cert.pem)
        echo -e "  ${CYAN}  $name${NC}"
        assert_not_ca "$cert"
        assert_not_expired "$cert"
        [[ -f "$CHAIN" ]] && assert_verifies_against "$cert" "$CHAIN"
        assert_has_extension "$cert" "serverAuth"
        assert_has_extension "$cert" "Subject Alternative Name"
        assert_has_extension "$cert" "CA:FALSE"
        # Key match
        key_file="$SERVER_DIR/${name}.key.pem"
        [[ -f "$key_file" ]] && assert_key_matches_cert "$key_file" "$cert" \
                             || skip "Key file for $name"
    done
else
    skip "No server certs found in $SERVER_DIR"
fi

# ── Client certificates ───────────────────────────────────────────────────────
echo -e "\n${CYAN}── Client / IoT Device Certificates ──${NC}"
if compgen -G "$CLIENT_DIR/*.cert.pem" > /dev/null 2>&1; then
    for cert in "$CLIENT_DIR"/*.cert.pem; do
        [[ -f "$cert" ]] || continue
        name=$(basename "$cert" .cert.pem)
        echo -e "  ${CYAN}  $name${NC}"
        assert_not_ca "$cert"
        assert_not_expired "$cert"
        [[ -f "$CHAIN" ]] && assert_verifies_against "$cert" "$CHAIN"
        assert_has_extension "$cert" "clientAuth"
    done
else
    skip "No client certs found in $CLIENT_DIR"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "  Tests passed : ${GREEN}$PASS${NC}"
echo -e "  Tests failed : ${RED}$FAIL${NC}"
echo "============================================================"
echo ""

exit $FAIL
