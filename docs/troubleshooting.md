# Troubleshooting Guide
**CSE PKI — University of Dhaka**

---

## Common Errors & Fixes

---

### ❌ `certificate verify failed: unable to get local issuer certificate`

**Cause:** The client doesn't trust the CA that signed the certificate.

**Fix:**
```bash
# Python — pass the Root CA cert
requests.get(url, verify="certs/root/ca.cert.pem")

# curl
curl --cacert certs/root/ca.cert.pem https://iot-cse.du.ac.bd

# openssl s_client
openssl s_client -connect iot-cse.du.ac.bd:443 -CAfile certs/root/ca.cert.pem
```

---

### ❌ `SSL: CERTIFICATE_VERIFY_FAILED` / Verify return code: 20

**Cause:** Unable to get local issuer — Intermediate CA cert not presented by server, or Root CA not in client trust store.

**Check 1:** Does the server present the Intermediate CA cert?
```bash
openssl s_client -connect iot-cse.du.ac.bd:443 -showcerts 2>/dev/null \
    | grep -c "BEGIN CERTIFICATE"
# Should return 2 (server cert + intermediate)
# If returns 1: server is not sending the intermediate cert — fix Nginx/Apache config
```

**Check 2:** Is the chain bundle correct?
```bash
openssl verify -CAfile certs/root/ca.cert.pem \
    certs/intermediate/intermediate.cert.pem
# Should return: OK
```

---

### ❌ `hostname mismatch` / `SSL: WRONG_HOST`

**Cause:** The certificate's SAN does not include the hostname being connected to.

**Check:**
```bash
openssl x509 -in certs/server/iot-cse.du.ac.bd.cert.pem \
    -noout -text | grep -A 3 "Subject Alternative Name"
```

**Fix:** Re-issue the certificate with the correct hostname in `configs/san_ext.cnf`.

---

### ❌ `certificate has expired`

**Check:**
```bash
openssl x509 -in cert.pem -noout -dates
# Not After : Jun 20 00:00:00 2028 GMT
```

**Fix:** Re-issue the certificate:
```bash
./scripts/03_issue_server_cert.sh iot-cse.du.ac.bd
```

---

### ❌ `no certificate or crl found` during verify

**Cause:** The `index.txt` or `serial` file in the CA directory is missing or corrupt.

**Fix:**
```bash
# Check CA database
cat certs/intermediate/index.txt
cat certs/intermediate/serial

# Re-initialize if corrupt
echo "1000" > certs/intermediate/serial
touch certs/intermediate/index.txt
```

---

### ❌ `TLS_ERROR: The certificate is not yet valid`

**Cause:** Clock skew — the server or client clock is behind the certificate's `Not Before` date.

**Fix:**
```bash
# Check system time
date
timedatectl status

# Sync with NTP
sudo timedatectl set-ntp true
```

---

### ❌ `error:0200100D:system library:fopen:Permission denied`

**Cause:** The process doesn't have read permission on the private key file.

**Fix:**
```bash
ls -la certs/intermediate/private/intermediate.key.pem
# Should be: -r-------- (400) owned by the CA user

# Fix permissions
chmod 400 certs/intermediate/private/intermediate.key.pem
chown pki-ca:pki-ca certs/intermediate/private/intermediate.key.pem
```

---

### ❌ mTLS: `SSL alert number 42` / `bad certificate`

**Cause:** Server required client certificate but client didn't present one (or presented an untrusted one).

**Check:** Is the client cert signed by the CA the server trusts?
```bash
openssl verify \
    -CAfile certs/intermediate/ca-chain.cert.pem \
    certs/client/sensor-device-001.cert.pem
# Should return: OK
```

**Check:** Does the client cert have `extendedKeyUsage = clientAuth`?
```bash
openssl x509 -in certs/client/sensor-device-001.cert.pem \
    -noout -text | grep -A 1 "Extended Key Usage"
# Should show: clientAuth
```

---

## Useful Diagnostic Commands

```bash
# Full certificate inspection
openssl x509 -in cert.pem -noout -text

# Check cert + key match
openssl x509 -in cert.pem -pubkey -noout | openssl md5
openssl pkey  -in key.pem -pubout      | openssl md5
# Both hashes must match

# Decode a CSR
openssl req -in csr.pem -noout -text

# Check what cert a server is presenting
echo | openssl s_client -connect host:443 -servername host 2>/dev/null \
    | openssl x509 -noout -text

# List all certs issued by the Intermediate CA
cat certs/intermediate/index.txt

# Check CRL
openssl crl -in certs/intermediate/crl/intermediate.crl.pem -noout -text

# Test MQTT/TLS on port 8883
openssl s_client -connect iot-cse.du.ac.bd:8883 \
    -CAfile certs/root/ca.cert.pem

# Verify entire chain explicitly
openssl verify \
    -CAfile certs/root/ca.cert.pem \
    -untrusted certs/intermediate/intermediate.cert.pem \
    certs/server/iot-cse.du.ac.bd.cert.pem
```
