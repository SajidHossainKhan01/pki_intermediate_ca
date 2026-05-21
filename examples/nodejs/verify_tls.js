/**
 * verify_tls.js — TLS Certificate Chain Verification (Node.js)
 * CSE PKI — University of Dhaka
 *
 * Demonstrates client-side TLS verification against a private Root CA
 * using Node.js built-in 'https' module.
 *
 * Run: node verify_tls.js
 */

"use strict";

const https = require("https");
const fs    = require("fs");
const path  = require("path");

// Path to our private Root CA certificate
// Clients MUST explicitly configure this — not in OS/browser trust stores
const ROOT_CA_CERT = path.resolve(__dirname, "../../certs/root/ca.cert.pem");

const BASE_HOSTNAME = "iot-cse.du.ac.bd";
const BASE_PORT     = 443;


/**
 * Make an HTTPS GET request, verifying against our private Root CA.
 */
function httpsGet(hostname, port, urlPath, extraOptions = {}) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname,
      port,
      path: urlPath,
      method: "GET",
      ca: fs.readFileSync(ROOT_CA_CERT),   // Custom CA — replaces system trust store
      rejectUnauthorized: true,            // ALWAYS true in production
      ...extraOptions,
    };

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ statusCode: res.statusCode, body: data }));
    });

    req.on("error", reject);
    req.setTimeout(10_000, () => {
      req.destroy(new Error("Request timed out"));
    });
    req.end();
  });
}


async function checkStatus() {
  console.log(`\n[1] GET https://${BASE_HOSTNAME}/status`);
  try {
    const { statusCode, body } = await httpsGet(BASE_HOSTNAME, BASE_PORT, "/status");
    console.log(`    Status : ${statusCode}`);
    console.log(`    Body   : ${body.slice(0, 200)}`);
  } catch (err) {
    console.log(`    [WARN] ${err.message} (server may not be running in demo env)`);
  }
}


async function checkMultipleEndpoints() {
  console.log(`\n[2] Checking multiple endpoints...`);
  const endpoints = ["/status", "/api/health", "/api/sensors"];

  for (const endpoint of endpoints) {
    try {
      const { statusCode } = await httpsGet(BASE_HOSTNAME, BASE_PORT, endpoint);
      console.log(`    ${endpoint.padEnd(20)} → ${statusCode}`);
    } catch (err) {
      console.log(`    ${endpoint.padEnd(20)} → [${err.code || err.message}]`);
    }
  }
}


async function demonstrateInsecure() {
  console.log(`\n[3] Demonstrating rejectUnauthorized: false (INSECURE — demo only)`);
  try {
    const result = await httpsGet(
      BASE_HOSTNAME, BASE_PORT, "/status",
      { rejectUnauthorized: false }
    );
    console.log(`    Status: ${result.statusCode}`);
    console.log(`    [WARN] rejectUnauthorized=false disables ALL certificate checks.`);
    console.log(`    [WARN] NEVER use this in production — it enables MITM attacks.`);
  } catch (err) {
    console.log(`    [not reachable — expected in demo environment]`);
  }
}


async function main() {
  console.log("=".repeat(60));
  console.log("  CSE PKI — Node.js TLS Verification Demo");
  console.log("=".repeat(60));

  if (!fs.existsSync(ROOT_CA_CERT)) {
    console.warn(`\n  [WARN] Root CA cert not found at: ${ROOT_CA_CERT}`);
    console.warn("  Run scripts/01_build_root_ca.sh first.\n");
  } else {
    console.log(`  Root CA: ${ROOT_CA_CERT}`);
  }

  await checkStatus();
  await checkMultipleEndpoints();
  await demonstrateInsecure();

  console.log("\nDone.\n");
}

main().catch(console.error);
