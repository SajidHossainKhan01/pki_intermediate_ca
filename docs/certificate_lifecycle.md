# Certificate Lifecycle — Deep Dive
**CSE PKI — University of Dhaka**

---

## 1. Certificate Issuance Flow

```
Entity (Server/Device)              Intermediate CA
────────────────────               ─────────────────
1. Generate key pair
   openssl genrsa 2048
   ↓
2. Create CSR
   openssl req -new ...
   ↓
3. Submit CSR ─────────────────────→ 4. Validate identity
                                         & policy compliance
                                      ↓
                                    5. Sign with CA private key
                                         openssl ca ...
                                      ↓
6. Receive signed cert ←──────────── 6. Return signed certificate
   ↓
7. Deploy cert + key on server
```

**Key Principle:** The private key **never leaves** the entity that generated it.
Only the CSR (containing the public key) is sent to the CA.

---

## 2. Certificate Validation Flow (TLS Handshake)

When a client connects to an HTTPS/TLS server:

```
Client                              Server
──────                              ──────
1. TCP connect
   ──────────────────────────────→
2. ClientHello (TLS version, ciphers)
   ──────────────────────────────→
                                   3. ServerHello + Certificate Chain
   ←──────────────────────────────    [server.cert + intermediate.cert]
                                       (Root CA cert NOT sent)
4. Verify certificate chain:
   a. Check CA signature on server cert
   b. Check CA signature on intermediate cert
   c. Traverse to Root CA (from trust store)
   d. Check validity period (not expired)
   e. Check revocation (CRL / OCSP)
   f. Verify hostname matches SAN
   ↓
5. All checks pass → Encrypted channel
   ──────────────────────────────→
   ←──────────────────────────────
```

---

## 3. X.509 v3 Certificate Structure

```
Certificate:
  Data:
    Version: 3 (0x2)
    Serial Number: 4096 (0x1000)
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: C=BD, O=University of Dhaka, CN=CSE Intermediate CA
    Validity:
        Not Before: Jan 16 00:00:00 2026 GMT
        Not After:  Jun 20 00:00:00 2028 GMT   ← 825 days max
    Subject: C=BD, O=University of Dhaka, CN=iot-cse.du.ac.bd
    Public Key: RSA 2048-bit
    Extensions:
        basicConstraints: CA:FALSE
        keyUsage: critical, digitalSignature, keyEncipherment
        extendedKeyUsage: serverAuth
        subjectAltName:              ← MANDATORY — CN alone rejected
            DNS:iot-cse.du.ac.bd
            DNS:www.iot-cse.du.ac.bd
        authorityKeyIdentifier: keyid:...
        cRLDistributionPoints: URI:http://crl.cse.du.ac.bd/crl.pem
  Signature: sha256WithRSAEncryption [CA signature]
```

---

## 4. Certificate Profiles

### TLS Server Certificate
| Field | Value |
|---|---|
| basicConstraints | `CA:FALSE` |
| keyUsage | `digitalSignature, keyEncipherment` |
| extendedKeyUsage | `serverAuth` |
| subjectAltName | Required (DNS names / IPs) |
| Validity | Max 825 days |

### mTLS Client / IoT Device Certificate
| Field | Value |
|---|---|
| basicConstraints | `CA:FALSE` |
| keyUsage | `digitalSignature` |
| extendedKeyUsage | `clientAuth` |
| subjectAltName | Optional for client certs |
| Validity | Max 825 days |

### Intermediate CA Certificate
| Field | Value |
|---|---|
| basicConstraints | `CA:TRUE, pathlen:0` |
| keyUsage | `keyCertSign, cRLSign, digitalSignature` |
| Validity | 3–5 years |

---

## 5. Certificate Revocation

### CRL (Certificate Revocation List)
- A signed list of revoked serial numbers published by the CA
- Clients download periodically and cache locally
- Latency: up to CRL update interval (typically 24h–7 days)

```bash
# Generate/update CRL
openssl ca -config intermediate_ca.cnf -gencrl -out crl/intermediate.crl.pem

# Verify cert against CRL
openssl verify -CAfile ca-chain.cert.pem \
    -CRLfile crl/intermediate.crl.pem -crl_check \
    server.cert.pem
```

### OCSP (Online Certificate Status Protocol)
- Real-time revocation status check via HTTP
- Client sends certificate serial → OCSP responder replies: good/revoked/unknown
- Lower latency than CRL; requires an OCSP endpoint

```bash
# Start OCSP responder
openssl ocsp \
    -index certs/intermediate/index.txt \
    -CA certs/intermediate/intermediate.cert.pem \
    -rkey certs/intermediate/private/intermediate.key.pem \
    -rsigner certs/intermediate/certs/intermediate.cert.pem \
    -port 2560

# Query OCSP
openssl ocsp \
    -CAfile certs/root/ca.cert.pem \
    -issuer certs/intermediate/intermediate.cert.pem \
    -cert certs/server/iot-cse.du.ac.bd.cert.pem \
    -url http://ocsp.cse.du.ac.bd:2560
```

### OCSP Stapling
The server pre-fetches the OCSP response and "staples" it to the TLS handshake.
- Eliminates client round-trips to OCSP responder
- Configured in Nginx with `ssl_stapling on`

---

## 6. Key Management Principles

| Key | Storage | Access |
|---|---|---|
| Root CA private key | Offline (air-gapped or HSM) | Activated only for Intermediate CA signing |
| Intermediate CA private key | Online CA server, `chmod 400` | CA admin only, never transmitted |
| Server private key | Application server, `chmod 400` | Never leaves the server |
| Client/device private key | Device secure storage | Never transmitted |

**Rule:** Only the CSR (public key + metadata) travels across the network. Private keys never do.
