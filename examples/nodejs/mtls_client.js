/**
 * mtls_client.js — Mutual TLS (mTLS) Client Authentication (Node.js)
 * CSE PKI — University of Dhaka
 *
 * Demonstrates bidirectional certificate authentication:
 *   - Client presents its certificate → server verifies device identity
 *   - Server presents its certificate → client verifies server identity
 *
 * Run: node mtls_client.js
 */

"use strict";

const https = require("https");
const fs    = require("fs");
const path  = require("path");

const ROOT_CA_CERT  = path.resolve(__dirname, "../../certs/root/ca.cert.pem");
const CLIENT_CERT   = path.resolve(__dirname, "../../certs/client/sensor-device-001.cert.pem");
const CLIENT_KEY    = path.resolve(__dirname, "../../certs/client/sensor-device-001.key.pem");

const BASE_HOSTNAME = "iot-cse.du.ac.bd";
const BASE_PORT     = 443;


function mTLSRequest(method, urlPath, body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;

    const options = {
      hostname: BASE_HOSTNAME,
      port:     BASE_PORT,
      path:     urlPath,
      method,
      // Server verification
      ca: fs.readFileSync(ROOT_CA_CERT),
      rejectUnauthorized: true,
      // Client certificate (mTLS)
      cert: fs.readFileSync(CLIENT_CERT),
      key:  fs.readFileSync(CLIENT_KEY),
      headers: {
        "Content-Type":   "application/json",
        "Content-Length": payload ? Buffer.byteLength(payload) : 0,
      },
    };

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ statusCode: res.statusCode, body: data }));
    });

    req.on("error", reject);
    req.setTimeout(10_000, () => req.destroy(new Error("Timeout")));

    if (payload) req.write(payload);
    req.end();
  });
}


async function publishSensorData() {
  console.log(`\n[1] mTLS POST — Publishing sensor data`);
  const payload = {
    device_id:   "sensor-device-001",
    temperature: 28.1,
    humidity:    62.5,
    timestamp:   new Date().toISOString(),
  };

  try {
    const { statusCode, body } = await mTLSRequest(
      "POST",
      "/api/sensors/sensor-device-001/data",
      payload
    );
    console.log(`    Status  : ${statusCode}`);
    console.log(`    Response: ${body.slice(0, 200)}`);
  } catch (err) {
    console.log(`    [WARN] ${err.message} (demo env — server not running)`);
  }
}


async function getDeviceConfig() {
  console.log(`\n[2] mTLS GET — Fetching device configuration`);
  try {
    const { statusCode, body } = await mTLSRequest(
      "GET",
      "/api/devices/sensor-device-001/config"
    );
    console.log(`    Status: ${statusCode}`);
    console.log(`    Config: ${body.slice(0, 200)}`);
  } catch (err) {
    console.log(`    [WARN] ${err.message} (demo env — server not running)`);
  }
}


async function main() {
  console.log("=".repeat(60));
  console.log("  CSE PKI — Node.js mTLS Client Demo");
  console.log("=".repeat(60));
  console.log(`  Root CA     : ${ROOT_CA_CERT}`);
  console.log(`  Client Cert : ${CLIENT_CERT}`);
  console.log(`  Client Key  : ${CLIENT_KEY}`);

  const missing = [ROOT_CA_CERT, CLIENT_CERT, CLIENT_KEY].filter(
    (f) => !fs.existsSync(f)
  );
  if (missing.length > 0) {
    console.warn("\n  [WARN] Missing certificate files:");
    missing.forEach((f) => console.warn(`    - ${f}`));
    console.warn("  Run the setup scripts first.\n");
  }

  await publishSensorData();
  await getDeviceConfig();

  console.log("\nDone.\n");
}

main().catch(console.error);
