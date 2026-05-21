// verify_tls.rs — TLS Verification & mTLS Client (Rust)
// CSE PKI — University of Dhaka
//
// Demonstrates:
//   1. Server TLS verification against private Root CA (reqwest + rustls)
//   2. Mutual TLS (mTLS) — client presents its certificate to the server
//
// Build: cargo build --release
// Run:   cargo run

use reqwest::{Certificate, Client, Identity};
use std::fs;

const ROOT_CA_CERT: &str = "../../certs/root/ca.cert.pem";
const CLIENT_CERT:  &str = "../../certs/client/sensor-device-001.cert.pem";
const CLIENT_KEY:   &str = "../../certs/client/sensor-device-001.key.pem";
const BASE_URL:     &str = "https://iot-cse.du.ac.bd";

// ── Build a standard TLS client (server verification only) ───────────────────
fn build_tls_client() -> Result<Client, Box<dyn std::error::Error>> {
    let ca_pem = fs::read(ROOT_CA_CERT)?;
    let ca_cert = Certificate::from_pem(&ca_pem)?;

    let client = Client::builder()
        .add_root_certificate(ca_cert)   // Trust our private Root CA
        .use_rustls_tls()                // Use rustls instead of native-tls
        .build()?;

    Ok(client)
}

// ── Build an mTLS client (server + client certificate verification) ───────────
fn build_mtls_client() -> Result<Client, Box<dyn std::error::Error>> {
    let ca_pem   = fs::read(ROOT_CA_CERT)?;
    let ca_cert  = Certificate::from_pem(&ca_pem)?;

    // Combine client cert + key into a PKCS#8/PEM identity
    // Note: reqwest expects a PEM bundle: cert followed by key
    let mut identity_pem = fs::read(CLIENT_CERT)?;
    identity_pem.extend_from_slice(&fs::read(CLIENT_KEY)?);
    let identity = Identity::from_pem(&identity_pem)?;

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)              // Present client certificate during handshake
        .use_rustls_tls()
        .build()?;

    Ok(client)
}

// ── Check server TLS ──────────────────────────────────────────────────────────
async fn check_status(client: &Client) {
    println!("\n[1] GET {BASE_URL}/status");
    match client.get(format!("{BASE_URL}/status")).send().await {
        Ok(resp) => {
            println!("    Status : {}", resp.status());
            match resp.text().await {
                Ok(body) => println!("    Body   : {}", &body[..body.len().min(200)]),
                Err(e)   => println!("    [WARN] Could not read body: {e}"),
            }
        }
        Err(e) => println!("    [WARN] {e} (server may not be running in demo env)"),
    }
}

// ── Publish IoT sensor data via mTLS ─────────────────────────────────────────
async fn publish_sensor_data(client: &Client) {
    println!("\n[2] mTLS POST — Publishing sensor data");
    let payload = serde_json::json!({
        "device_id":   "sensor-device-001",
        "temperature": 26.8,
        "humidity":    67.3,
        "timestamp":   "2026-01-16T10:30:00Z",
    });

    match client
        .post(format!("{BASE_URL}/api/sensors/sensor-device-001/data"))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => println!("    Status: {}", resp.status()),
        Err(e)   => println!("    [WARN] {e} (demo env — server not running)"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=".repeat(60));
    println!("  CSE PKI — Rust TLS Verification & mTLS Demo");
    println!("{}", "=".repeat(60));
    println!("  Root CA     : {ROOT_CA_CERT}");
    println!("  Client Cert : {CLIENT_CERT}");

    // ── Standard TLS verification ─────────────────────────────────────────
    match build_tls_client() {
        Ok(client) => {
            println!("\n--- Standard TLS (server verification) ---");
            check_status(&client).await;
        }
        Err(e) => {
            eprintln!("\n[WARN] Could not build TLS client: {e}");
            eprintln!("       Ensure certificates are generated first.");
        }
    }

    // ── Mutual TLS ────────────────────────────────────────────────────────
    match build_mtls_client() {
        Ok(client) => {
            println!("\n--- Mutual TLS (client + server verification) ---");
            check_status(&client).await;
            publish_sensor_data(&client).await;
        }
        Err(e) => {
            eprintln!("\n[WARN] Could not build mTLS client: {e}");
            eprintln!("       Ensure client certificates are generated first.");
        }
    }

    println!("\nDone.\n");
    Ok(())
}
