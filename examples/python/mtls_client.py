"""
mtls_client.py — Mutual TLS (mTLS) Client Authentication (Python)
CSE PKI — University of Dhaka

Demonstrates bidirectional TLS authentication:
  - Server authenticates to client using its TLS certificate
  - Client authenticates to server using its client certificate
  - Used for: IoT device auth, authenticated APIs, M2M services

Install:  pip install requests
Run:      python mtls_client.py
"""

import sys
import json
import requests
from requests.exceptions import SSLError, ConnectionError

# ── Certificate paths ──────────────────────────────────────────────────────────
ROOT_CA_CERT    = "../../certs/root/ca.cert.pem"
CLIENT_CERT     = "../../certs/client/sensor-device-001.cert.pem"
CLIENT_KEY      = "../../certs/client/sensor-device-001.key.pem"

BASE_URL        = "https://iot-cse.du.ac.bd"


def publish_sensor_data(device_id: str, payload: dict) -> None:
    """
    POST sensor data to the IoT API using mTLS.
    Server verifies the device identity via its client certificate.
    """
    print(f"\n[1] mTLS POST — Device: {device_id}")
    try:
        response = requests.post(
            f"{BASE_URL}/api/sensors/{device_id}/data",
            json=payload,
            cert=(CLIENT_CERT, CLIENT_KEY),   # Client presents its certificate
            verify=ROOT_CA_CERT,               # Validates server cert chain
            timeout=10,
        )
        print(f"    Status  : {response.status_code}")
        print(f"    Response: {response.text[:200]}")

    except SSLError as e:
        print(f"    [FAIL] mTLS handshake failed: {e}")
        print("    → Check: client cert is signed by the trusted Intermediate CA")
        sys.exit(1)
    except ConnectionError:
        print("    [not reachable — expected in demo environment]")


def get_device_config(device_id: str) -> None:
    """Fetch device config from API — server identifies device from client cert."""
    print(f"\n[2] mTLS GET — Fetching config for device: {device_id}")
    try:
        response = requests.get(
            f"{BASE_URL}/api/devices/{device_id}/config",
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=ROOT_CA_CERT,
            timeout=10,
        )
        print(f"    Status: {response.status_code}")
        if response.ok:
            config = response.json()
            print(f"    Config: {json.dumps(config, indent=6)}")
    except ConnectionError:
        print("    [not reachable — expected in demo environment]")


def demonstrate_auth_failure() -> None:
    """Show that a request WITHOUT a client cert is rejected by the mTLS server."""
    print(f"\n[3] Request WITHOUT client certificate (should be rejected):")
    try:
        response = requests.get(
            f"{BASE_URL}/api/sensors",
            verify=ROOT_CA_CERT,
            # No cert=(CLIENT_CERT, CLIENT_KEY) → server should reject
            timeout=5,
        )
        print(f"    Status: {response.status_code}")
        if response.status_code in (400, 401, 403):
            print("    [PASS] Server correctly rejected unauthenticated request")
        else:
            print("    [WARN] Server may not enforce mTLS on this endpoint")
    except SSLError as e:
        print(f"    [PASS] SSL error — server enforced mTLS: {e}")
    except ConnectionError:
        print("    [not reachable — expected in demo environment]")


if __name__ == "__main__":
    print("=" * 60)
    print("  CSE PKI — Python mTLS Client Demo")
    print("=" * 60)
    print(f"  Root CA     : {ROOT_CA_CERT}")
    print(f"  Client Cert : {CLIENT_CERT}")
    print(f"  Client Key  : {CLIENT_KEY}")

    sensor_payload = {
        "device_id": "sensor-device-001",
        "temperature": 27.4,
        "humidity": 65.2,
        "timestamp": "2026-01-16T10:30:00Z",
    }

    publish_sensor_data("sensor-device-001", sensor_payload)
    get_device_config("sensor-device-001")
    demonstrate_auth_failure()

    print("\nDone.\n")
