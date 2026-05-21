"""
verify_tls.py — TLS Certificate Chain Verification (Python)
CSE PKI — University of Dhaka

Demonstrates client-side TLS verification against a private Root CA
using the 'requests' library.

Install:  pip install requests
Run:      python verify_tls.py
"""

import sys
import requests
from requests.exceptions import SSLError, ConnectionError

# Path to our private Root CA certificate
# Clients MUST explicitly trust this CA (not in browser/OS stores)
ROOT_CA_CERT = "../../certs/root/ca.cert.pem"

BASE_URL = "https://iot-cse.du.ac.bd"


def check_status() -> None:
    """Simple GET with CA verification."""
    print(f"\n[1] GET {BASE_URL}/status")
    try:
        response = requests.get(
            f"{BASE_URL}/status",
            verify=ROOT_CA_CERT,   # <-- chain validated against our Root CA
            timeout=10,
        )
        response.raise_for_status()
        print(f"    Status : {response.status_code}")
        print(f"    Body   : {response.text[:200]}")
    except SSLError as e:
        print(f"    [FAIL] SSL/TLS error: {e}")
        sys.exit(1)
    except ConnectionError as e:
        print(f"    [WARN] Could not connect (server may not be running): {e}")


def check_with_session() -> None:
    """Reuse a session across multiple requests (efficient for IoT polling)."""
    print(f"\n[2] Session-based requests to {BASE_URL}")
    session = requests.Session()
    session.verify = ROOT_CA_CERT

    endpoints = ["/status", "/api/sensors", "/api/health"]
    for endpoint in endpoints:
        try:
            response = session.get(f"{BASE_URL}{endpoint}", timeout=5)
            print(f"    {endpoint:20s} → {response.status_code}")
        except ConnectionError:
            print(f"    {endpoint:20s} → [not reachable]")


def check_wrong_ca() -> None:
    """Show that verification fails if we use the wrong CA (security check)."""
    print(f"\n[3] Verifying that wrong CA triggers rejection...")
    try:
        response = requests.get(
            f"{BASE_URL}/status",
            verify=False,  # <-- INSECURE: disables verification
        )
        print("    [WARN] verify=False bypasses all certificate checks — NEVER do this in production!")
    except ConnectionError:
        print("    [not reachable — expected in demo environment]")


if __name__ == "__main__":
    print("=" * 60)
    print("  CSE PKI — Python TLS Verification Demo")
    print("=" * 60)
    print(f"  Root CA: {ROOT_CA_CERT}")

    check_status()
    check_with_session()
    check_wrong_ca()

    print("\nDone.\n")
