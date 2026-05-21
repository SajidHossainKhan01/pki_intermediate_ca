# 🔐 PKI Intermediate Certificate Authority (CA) — Full Implementation

> **Topic:** Intermediate Certificate Authority: Theory and Configuration  

[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.x-blue?logo=openssl)](https://www.openssl.org/)
[![TLS](https://img.shields.io/badge/TLS-1.2%20%2F%201.3-green)](https://tools.ietf.org/html/rfc8446)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%2F%20macOS-lightgrey)](https://www.linux.org/)

---

## 📋 Table of Contents

- [Overview](#overview)
- [PKI Architecture](#pki-architecture)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Step-by-Step Guide](#step-by-step-guide)
  - [1. Build Root CA](#1-build-root-ca)
  - [2. Build Intermediate CA](#2-build-intermediate-ca)
  - [3. Issue TLS Server Certificate](#3-issue-tls-server-certificate)
  - [4. Issue mTLS Client Certificate](#4-issue-mtls-client-certificate)
  - [5. Build Trust Chain](#5-build-trust-chain)
  - [6. Verify the Chain](#6-verify-the-chain)
- [Server Configuration](#server-configuration)
- [Client Verification Examples](#client-verification-examples)
- [CA Security Controls](#ca-security-controls)
- [Trust Model](#trust-model)
- [Key Concepts Reference](#key-concepts-reference)

---

## Overview

This repository is a **complete, production-style implementation** of a two-tier Public Key Infrastructure (PKI) using a private Intermediate Certificate Authority. It demonstrates:

- ✅ Root CA creation and offline key management
- ✅ Intermediate CA setup, signing, and configuration
- ✅ TLS server and mTLS client certificate issuance
- ✅ Trust chain construction and verification
- ✅ Server-side TLS configuration (Nginx, Apache, FastAPI/Uvicorn)
- ✅ Client-side verification (Python, Node.js, Rust, C/C++)
- ✅ CA security hardening and operational best practices

### Why a Private Intermediate CA?

| Concern | Public CA | Private Intermediate CA |
|---|---|---|
| Trust Scope | Global | Institutional / Defined boundary |
| Root Key Exposure | Provider-managed | Kept **offline** |
| IoT / Internal Hostnames | ❌ Not supported | ✅ Full support |
| Revocation Speed | External (delays) | **Immediate** |
| Cost | Per-certificate fees | **Zero** |
| Policy Control | CA/B Forum constraints | **Full autonomy** |
| mTLS Support | Limited | **Optimized** |

> The private Intermediate CA is **not** a weaker alternative to a Public CA — it is a **different security model** optimized for a defined trust boundary.

---

## PKI Architecture

```
┌─────────────────────────────────┐
│           Root CA               │  ← Self-signed · Offline · 20yr validity
│    CSE-Root-CA / SHA-256        │     4096-bit RSA key
└────────────────┬────────────────┘
                 │  signs
                 ▼
┌─────────────────────────────────┐
│        Intermediate CA          │  ← Online · Operational issuer · 5yr
│  CSE-Intermediate-CA / SHA-256  │     4096-bit RSA key
└──────────┬──────────────────────┘
           │
     ┌─────┴──────┐
     │            │
     ▼            ▼
┌─────────┐  ┌──────────┐
│  Server │  │  Client  │  ← End-entity certs (TLS server / mTLS client)
│  Cert   │  │  Cert    │     2048-bit RSA · 825 day validity
└─────────┘  └──────────┘
```

---

## Repository Structure

```
pki-intermediate-ca/
├── README.md                    ← You are here
├── LICENSE
│
├── scripts/
│   ├── 01_build_root_ca.sh      ← Automated Root CA setup
│   ├── 02_build_intermediate_ca.sh
│   ├── 03_issue_server_cert.sh  ← Issue TLS server cert
│   ├── 04_issue_client_cert.sh  ← Issue mTLS client cert
│   ├── 05_build_chain.sh        ← Assemble CA chain bundle
│   ├── 06_verify_chain.sh       ← Verify all certificates
│   └── 07_revoke_cert.sh        ← Revoke a certificate
│
├── configs/
│   ├── root_ca.cnf              ← Root CA OpenSSL config
│   ├── intermediate_ca.cnf      ← Intermediate CA OpenSSL config
│   └── san_ext.cnf              ← SAN extensions template
│
├── certs/                       ← Generated certificates (git-ignored)
│   ├── root/
│   ├── intermediate/
│   ├── server/
│   └── client/
│
├── nginx/
│   └── tls_vhost.conf           ← Production Nginx TLS config
│
├── apache/
│   └── tls_vhost.conf           ← Apache TLS VirtualHost config
│
├── examples/
│   ├── python/
│   │   ├── verify_tls.py        ← requests + chain verification
│   │   └── mtls_client.py       ← mTLS client example
│   ├── nodejs/
│   │   ├── verify_tls.js        ← Node.js https module verification
│   │   └── mtls_client.js       ← mTLS client example
│   ├── rust/
│   │   ├── Cargo.toml
│   │   └── src/main.rs          ← reqwest + rustls verification
│   └── c/
│       ├── Makefile
│       └── verify_tls.c         ← OpenSSL C API verification
│
├── tests/
│   ├── test_chain.sh            ← Chain verification tests
│   ├── test_tls_handshake.sh    ← Live TLS handshake test
│   └── test_revocation.sh       ← CRL revocation test
│
└── docs/
    ├── certificate_lifecycle.md ← Deep dive: cert issuance & validation
    ├── security_hardening.md    ← CA server security controls
    ├── trust_model.md           ← Trust model and design decisions
    └── troubleshooting.md       ← Common errors and fixes
```

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/SajidHossainKhan01/pki_intermediate_ca.git
cd pki_intermediate_ca

# Make scripts executable
chmod +x scripts/*.sh

# Build the full PKI in one go
./scripts/01_build_root_ca.sh
./scripts/02_build_intermediate_ca.sh
./scripts/03_issue_server_cert.sh
./scripts/05_build_chain.sh
./scripts/06_verify_chain.sh
```

**Requirements:** `openssl >= 1.1.1` (3.x recommended)

---

## Step-by-Step Guide

### 1. Build Root CA

```bash
./scripts/01_build_root_ca.sh
```

What this does:
1. Creates the Root CA directory structure at `/etc/pki/CSE/root/`
2. Generates a 4096-bit RSA private key (AES-256 encrypted)
3. Creates a self-signed Root CA certificate (20-year validity)
4. Initializes `index.txt` and `serial` databases

```bash
# Manual equivalent
openssl genrsa -aes256 -out certs/root/ca.key.pem 4096
chmod 400 certs/root/ca.key.pem

openssl req -config configs/root_ca.cnf \
  -key certs/root/ca.key.pem \
  -new -x509 -days 7300 -sha256 \
  -extensions v3_ca \
  -out certs/root/ca.cert.pem
```

### 2. Build Intermediate CA

```bash
./scripts/02_build_intermediate_ca.sh
```

```bash
# Manual equivalent — generate key
openssl genrsa -aes256 -out certs/intermediate/intermediate.key.pem 4096

# Create CSR
openssl req -config configs/intermediate_ca.cnf -new -sha256 \
  -key certs/intermediate/intermediate.key.pem \
  -out certs/intermediate/intermediate.csr.pem

# Root CA signs the Intermediate CA CSR
openssl ca -config configs/root_ca.cnf \
  -extensions v3_intermediate_ca \
  -days 1825 -notext -md sha256 \
  -in certs/intermediate/intermediate.csr.pem \
  -out certs/intermediate/intermediate.cert.pem
```

### 3. Issue TLS Server Certificate

```bash
./scripts/03_issue_server_cert.sh iot-cse.du.ac.bd
```

```bash
# Manual equivalent
openssl genrsa -out certs/server/iot-cse.du.ac.bd.key.pem 2048

openssl req -new -sha256 \
  -key certs/server/iot-cse.du.ac.bd.key.pem \
  -out certs/server/iot-cse.du.ac.bd.csr.pem \
  -subj "/C=BD/O=University of Dhaka/OU=CSE/CN=iot-cse.du.ac.bd"

# Intermediate CA signs the server CSR
openssl ca -config configs/intermediate_ca.cnf \
  -extensions server_cert \
  -days 825 -notext -md sha256 \
  -in certs/server/iot-cse.du.ac.bd.csr.pem \
  -out certs/server/iot-cse.du.ac.bd.cert.pem
```

> ⚠️ **825 days** is the maximum for publicly-trusted TLS certificates (per CA/B Forum Ballot SC31). We follow this even for private PKI as best practice.

### 4. Issue mTLS Client Certificate

```bash
./scripts/04_issue_client_cert.sh sensor-device-001
```

```bash
# Manual equivalent
openssl genrsa -out certs/client/sensor-device-001.key.pem 2048

openssl req -new -sha256 \
  -key certs/client/sensor-device-001.key.pem \
  -out certs/client/sensor-device-001.csr.pem \
  -subj "/C=BD/O=University of Dhaka/OU=IoT/CN=sensor-device-001"

openssl ca -config configs/intermediate_ca.cnf \
  -extensions client_cert \
  -days 825 -notext -md sha256 \
  -in certs/client/sensor-device-001.csr.pem \
  -out certs/client/sensor-device-001.cert.pem
```

### 5. Build Trust Chain

```bash
./scripts/05_build_chain.sh
```

```bash
# Combine Intermediate + Root into a chain bundle
cat certs/intermediate/intermediate.cert.pem \
    certs/root/ca.cert.pem \
    > certs/intermediate/ca-chain.cert.pem

chmod 444 certs/intermediate/ca-chain.cert.pem
```

> 🔑 **Important:** The server presents `server.cert.pem + intermediate.cert.pem` during TLS handshake. The Root CA cert is **never** transmitted — it lives only in the client trust store.

### 6. Verify the Chain

```bash
./scripts/06_verify_chain.sh
```

```bash
# Verify server cert against the chain
openssl verify \
  -CAfile certs/intermediate/ca-chain.cert.pem \
  certs/server/iot-cse.du.ac.bd.cert.pem

# Expected: iot-cse.du.ac.bd.cert.pem: OK

# Inspect the certificate
openssl x509 -in certs/server/iot-cse.du.ac.bd.cert.pem \
  -noout -text | grep -A 5 "Subject Alternative Name"

# Live TLS test (requires running server)
openssl s_client \
  -connect iot-cse.du.ac.bd:8883 \
  -CAfile certs/root/ca.cert.pem
# Expected: Verify return code: 0 (ok)
```

---

## Server Configuration

### Nginx

```nginx
# nginx/tls_vhost.conf
server {
    listen 443 ssl http2;
    server_name iot-cse.du.ac.bd;

    ssl_certificate     /etc/ssl/iot-cse/server.cert.pem;
    ssl_certificate_key /etc/ssl/iot-cse/server.key.pem;

    # Chain: Intermediate cert (NOT Root CA)
    ssl_trusted_certificate /etc/ssl/iot-cse/intermediate.cert.pem;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    # HSTS (optional for private PKI)
    add_header Strict-Transport-Security "max-age=63072000" always;
}
```

### Apache

```apache
# apache/tls_vhost.conf
<VirtualHost *:443>
    ServerName iot-cse.du.ac.bd

    SSLEngine on
    SSLCertificateFile    /etc/ssl/iot-cse/server.cert.pem
    SSLCertificateKeyFile /etc/ssl/iot-cse/server.key.pem
    SSLCertificateChainFile /etc/ssl/iot-cse/intermediate.cert.pem

    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5
</VirtualHost>
```

### FastAPI / Uvicorn (Python)

```bash
uvicorn app:app \
  --host 0.0.0.0 --port 443 \
  --ssl-keyfile  certs/server/server.key.pem \
  --ssl-certfile certs/server/server.cert.pem \
  --ssl-ca-certs certs/intermediate/intermediate.cert.pem
```

---

## Client Verification Examples

### Python

```python
# examples/python/verify_tls.py
import requests

response = requests.get(
    "https://iot-cse.du.ac.bd/status",
    verify="certs/root/ca.cert.pem"   # validate against our Root CA
)
print(response.status_code, response.json())
```

### Python mTLS

```python
# examples/python/mtls_client.py
import requests

response = requests.get(
    "https://iot-cse.du.ac.bd/api/data",
    cert=(
        "certs/client/sensor-device-001.cert.pem",
        "certs/client/sensor-device-001.key.pem"
    ),
    verify="certs/root/ca.cert.pem"
)
print(response.json())
```

### Node.js

```javascript
// examples/nodejs/verify_tls.js
const https = require('https');
const fs    = require('fs');

const options = {
    hostname: 'iot-cse.du.ac.bd',
    port: 443,
    path: '/status',
    ca: fs.readFileSync('certs/root/ca.cert.pem'),
    rejectUnauthorized: true
};

const req = https.request(options, res => {
    res.on('data', d => process.stdout.write(d));
});
req.on('error', console.error);
req.end();
```

### Rust (reqwest + rustls)

```rust
// examples/rust/src/main.rs
use reqwest::Certificate;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca_pem = std::fs::read("certs/root/ca.cert.pem")?;
    let ca_cert = Certificate::from_pem(&ca_pem)?;

    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .use_rustls_tls()
        .build()?;

    let response = client
        .get("https://iot-cse.du.ac.bd/status")
        .send().await?
        .text().await?;

    println!("{}", response);
    Ok(())
}
```

### C / C++ (OpenSSL API)

```c
// examples/c/verify_tls.c
#include <openssl/ssl.h>
#include <openssl/bio.h>

int main() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    SSL_CTX_load_verify_locations(ctx, "certs/root/ca.cert.pem", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    BIO *bio = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(bio, "iot-cse.du.ac.bd:443");
    BIO_do_connect(bio);
    BIO_do_handshake(bio);

    // Connection established and verified
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
```

---

## CA Security Controls

| Control Category | Measure |
|---|---|
| **Physical** | Controlled-access facility, UPS-protected power |
| **Root CA Key** | Stored **offline**, activated only for controlled signing |
| **Intermediate Key** | Strict filesystem permissions (`chmod 400`), never transmitted |
| **Network** | Default-deny firewall, SSH key-based access only |
| **Segmentation** | Isolated from production, user, and IoT networks |
| **Access Control** | Role-based access, separation of duties (admin vs. approver) |
| **Audit** | All CA operations logged, logs protected against modification |
| **Crypto** | RSA-4096, SHA-256 minimum, TLS 1.2+ only |
| **Rotation** | TLS certificates rotated annually |
| **Revocation** | CRL maintained, immediate revocation on compromise |
| **Backups** | Key backups encrypted at rest |

---

## Trust Model

```
[CSE Root CA] ──────────────────────── NOT in browser/OS trust stores
      │                                 Clients must explicitly install
      │ signs
      ▼
[CSE Intermediate CA] ──────────────── Operational issuer (online)
      │
      ├── [iot-cse.du.ac.bd]           Backend / MQTT / APIs
      ├── [sensor-device-001]          IoT device mTLS
      └── [api.cse.du.ac.bd]           Internal microservices

[Public CA (DigiCert / Let's Encrypt)] ── Public-facing HTTPS websites
```

**No cross-signing** exists between the CSE PKI and any public CA. Trust domains are strictly separated. Public-facing services use a public CA; backend and IoT use the private Intermediate CA.

---

## Key Concepts Reference

| Concept | Description |
|---|---|
| **PKI** | Framework of policies, hardware, software for creating and managing digital certificates |
| **Root CA** | Self-signed trust anchor; kept offline; 20+ year validity |
| **Intermediate CA** | Operational issuer signed by Root CA; online |
| **CSR** | Certificate Signing Request — carries the public key to the CA |
| **X.509 v3** | Standard certificate format; includes SAN, Key Usage extensions |
| **SAN** | Subject Alternative Name — mandatory in modern TLS (CN alone rejected by browsers) |
| **Chain of Trust** | Root CA → Intermediate CA → End-entity cert |
| **mTLS** | Mutual TLS — both client and server authenticate with certificates |
| **CRL** | Certificate Revocation List — list of revoked certificates |
| **OCSP** | Online Certificate Status Protocol — real-time revocation check |
| **basicConstraints** | X.509 extension indicating whether a cert can sign other certs |
| **keyUsage** | Specifies allowed operations: digitalSignature, keyEncipherment, etc. |

---

## License

MIT License — see [LICENSE](LICENSE)

---

## References

- [RFC 5280 — X.509 PKI Certificate Profile](https://tools.ietf.org/html/rfc5280)
- [RFC 8446 — TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [CA/B Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
