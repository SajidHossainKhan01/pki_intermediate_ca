# Trust Model & Design Decisions
**CSE PKI — University of Dhaka**

---

## 1. Private vs. Public Trust

The CSE Intermediate CA operates under a **private trust model**:

| Property | This PKI | Public CA (DigiCert, Let's Encrypt) |
|---|---|---|
| Trust anchor location | Clients must install Root CA cert | Pre-installed in OS / browser |
| Trust scope | Explicitly configured clients only | Global (all browsers, devices) |
| Hostname restrictions | None — internal names supported | Must be publicly registered domains |
| Cross-organization trust | No | Yes |

### Implication for Clients

Clients connecting to services protected by the CSE Intermediate CA **must**:

1. Obtain the Root CA certificate (`ca.cert.pem`) through a trusted channel
2. Install it in their trust store:

```bash
# Linux (system-wide)
sudo cp certs/root/ca.cert.pem /usr/local/share/ca-certificates/cse-root-ca.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain certs/root/ca.cert.pem

# Application-level (Python)
requests.get(url, verify="certs/root/ca.cert.pem")

# Application-level (Node.js)
{ ca: fs.readFileSync("certs/root/ca.cert.pem") }
```

---

## 2. Two-Tier Architecture Rationale

```
Root CA (offline)           Why offline?
├── Never issues            → Compromise of Root CA = complete loss of trust
│   end-entity certs        → Keeping it offline eliminates remote attack surface
├── Only signs              → Activated only when signing a new Intermediate CA cert
│   Intermediate CA         → This happens rarely (every 3–5 years)
└── Self-signed             → The trust anchor itself

Intermediate CA (online)    Why online?
├── Issues all              → Must be reachable for day-to-day certificate operations
│   end-entity certs        → Signs server and client certificates
├── Signed by Root CA       → If compromised: revoke this cert, issue new Intermediate
└── Pathlen = 0             → Cannot create sub-CAs (depth constraint)
```

**Blast radius containment:** If the Intermediate CA is compromised, we revoke it and issue a new one from the Root CA. All certs issued by the compromised Intermediate are automatically invalidated. The Root CA trust anchor remains untouched.

If a Public CA's root is compromised, the blast radius is **global** — millions of websites are affected. With a private CA, the blast radius is limited to the institution's trust domain.

---

## 3. No Cross-Signing

There is **no cross-signing** between the CSE PKI and any public CA.

- The CSE Root CA is not certified by DigiCert, GlobalSign, or any other public CA.
- No CSE-issued certificate will be trusted by browsers or OS trust stores by default.
- This is intentional: it prevents unintended external reliance and keeps the trust domain isolated.

---

## 4. Dual-Certificate Deployment Strategy

For the CSE deployment, two certificate types are used in parallel:

```
                    ┌──────────────────────────────────────┐
                    │        Certificate Strategy          │
                    └──────────────────────────────────────┘
                              │                  │
              ┌───────────────┘                  └──────────────────┐
              ▼                                                      ▼
   Public-facing services                         Backend / IoT services
   ─────────────────────                          ──────────────────────
   • HTTPS websites                               • MQTT brokers (port 8883)
   • Public REST APIs                             • Internal APIs
   • Student-facing portals                       • IoT sensor endpoints
                                                  • Machine-to-machine auth
              │                                                      │
              ▼                                                      ▼
   Public CA certificate                          CSE Intermediate CA certificate
   (Let's Encrypt / DigiCert)                     (this repository)
   Trusted by all browsers                        Trusted by explicitly configured
   automatically                                  clients / devices only
```

---

## 5. mTLS Trust Flow

For mutual TLS (both parties authenticate):

```
IoT Device                           MQTT Broker / API Server
──────────                           ────────────────────────
Has:                                 Has:
  client.cert (signed by Int. CA)      server.cert (signed by Int. CA)
  client.key                           server.key
  root ca.cert (trust store)           root ca.cert (trust store)

Handshake:
1. Device → Server: "Hello, here is my client cert"
2. Server verifies client cert chain → Root CA ✓
3. Server → Device: "Hello, here is my server cert"
4. Device verifies server cert chain → Root CA ✓
5. Both authenticated → Encrypted channel established

Server knows: This request came from sensor-device-001
Device knows: This is the legitimate CSE MQTT broker
```

**No username/password required.** Identity is cryptographically proven by the certificate chain.
