# CA Server Security Hardening
**CSE PKI — University of Dhaka**

---

## 1. Physical & Infrastructure Controls

| Control | Implementation |
|---|---|
| Physical access | Controlled-access server room, key-card entry |
| Power | UPS with automatic failover |
| Root CA machine | Air-gapped or network-isolated |
| Backups | Encrypted at rest, stored offline, tested quarterly |

---

## 2. Operating System Hardening

```bash
# Minimal OS — no unnecessary services
systemctl disable bluetooth avahi-daemon cups

# Firewall: default-deny
ufw default deny incoming
ufw default deny outgoing
ufw allow from <ADMIN_IP_RANGE> to any port 22  # SSH only from admin hosts
ufw allow out 53    # DNS for system ops
ufw allow out 123   # NTP
ufw enable

# Disable root login
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
# SSH key-based authentication only
systemctl restart sshd

# Automatic security updates
apt install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# Audit logging
apt install auditd
auditctl -w /etc/pki/CSE/intermediate/private/ -p rwxa -k ca_key_access
auditctl -w /etc/pki/CSE/intermediate/index.txt -p rwa -k cert_issuance
```

---

## 3. Filesystem Permissions

```bash
# Root CA (offline machine)
chmod 700 /etc/pki/CSE/root/
chmod 700 /etc/pki/CSE/root/private/
chmod 400 /etc/pki/CSE/root/private/ca.key.pem      # Owner read only
chmod 444 /etc/pki/CSE/root/certs/ca.cert.pem        # World readable

# Intermediate CA (online machine)
chmod 700 /etc/pki/CSE/intermediate/
chmod 700 /etc/pki/CSE/intermediate/private/
chmod 400 /etc/pki/CSE/intermediate/private/intermediate.key.pem
chmod 444 /etc/pki/CSE/intermediate/certs/intermediate.cert.pem
chmod 600 /etc/pki/CSE/intermediate/index.txt
chmod 600 /etc/pki/CSE/intermediate/serial

# CA process runs as dedicated user
useradd -r -s /usr/sbin/nologin pki-ca
chown -R pki-ca:pki-ca /etc/pki/CSE/intermediate/
```

---

## 4. Network Segmentation

```
Internet
   │
   └── [Firewall]
         │
         ├── DMZ (public services — Public CA certs)
         │     └── HTTPS web, public APIs
         │
         ├── Internal Network
         │     └── API servers, MQTT brokers (Intermediate CA certs)
         │
         └── PKI VLAN (isolated)
               └── Intermediate CA Server
                     ← SSH from Admin VLAN only
                     ← No inbound from DMZ or Internet
                     → Outbound: NTP, DNS only
```

---

## 5. Access Control & Separation of Duties

| Role | Responsibilities | Access |
|---|---|---|
| CA Admin | Configure CA, manage keys | Full CA access |
| Certificate Approver | Review and approve CSRs | CSR access only |
| Auditor | Review logs, compliance | Read-only log access |
| No single person | Can both approve and sign | Enforced by policy |

```bash
# Example: separate groups
groupadd ca-admins
groupadd cert-approvers
usermod -aG ca-admins    alice
usermod -aG cert-approvers bob

# CA key: only ca-admins can read
chown root:ca-admins /etc/pki/CSE/intermediate/private/intermediate.key.pem
chmod 440 /etc/pki/CSE/intermediate/private/intermediate.key.pem
```

---

## 6. Operational Security Checklist

### Certificate Issuance
- [ ] CSR reviewed before signing (correct CN, no wildcard abuse)
- [ ] SAN fields validated against approved domain list
- [ ] Validity period within policy limits (≤ 825 days for TLS)
- [ ] Extension profile matches intended use (serverAuth / clientAuth)
- [ ] Serial number recorded in CA database (`index.txt`)

### Ongoing Operations
- [ ] TLS certificates rotated at least annually
- [ ] CRL regenerated and published regularly (< 7 day intervals)
- [ ] CA key passphrases stored in institutional password vault
- [ ] CA server receives only security patches (minimal change window)
- [ ] Logs reviewed monthly for anomalous certificate requests

### Incident Response
- [ ] Immediate revocation procedure documented and tested
- [ ] CA issuance suspension procedure documented
- [ ] Key regeneration procedure documented
- [ ] Incident log template prepared
- [ ] Recovery contact list maintained

---

## 7. Cryptographic Standards

| Parameter | Minimum | Recommended |
|---|---|---|
| Key algorithm | RSA-2048 | RSA-4096 (CA), ECDSA P-256 (server) |
| Hash algorithm | SHA-256 | SHA-256 or SHA-384 |
| TLS version | TLS 1.2 | TLS 1.3 preferred |
| CA validity | N/A | Root: 20yr, Intermediate: 5yr |
| End-entity validity | N/A | Max 825 days |

```bash
# Verify digest used in issued cert
openssl x509 -in cert.pem -noout -text | grep "Signature Algorithm"
# Expected: sha256WithRSAEncryption  (or better)

# Check TLS version and cipher on a running server
openssl s_client -connect host:443 -tls1_1 2>&1 | grep "alert"
# Expected: "alert protocol version" — TLS 1.1 correctly rejected
```
