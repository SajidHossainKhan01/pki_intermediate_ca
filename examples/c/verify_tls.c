/*
 * verify_tls.c — TLS Certificate Verification using OpenSSL C API
 * CSE PKI — University of Dhaka
 *
 * Demonstrates:
 *   1. Server TLS verification against our private Root CA
 *   2. mTLS — presenting a client certificate to the server
 *   3. Printing certificate chain details from a live connection
 *
 * Compile: make  (or see Makefile)
 * Run:     ./verify_tls
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define ROOT_CA_CERT  "../../certs/root/ca.cert.pem"
#define CLIENT_CERT   "../../certs/client/sensor-device-001.cert.pem"
#define CLIENT_KEY    "../../certs/client/sensor-device-001.key.pem"
#define SERVER_HOST   "iot-cse.du.ac.bd"
#define SERVER_PORT   "443"
#define CONNECT_ADDR  SERVER_HOST ":" SERVER_PORT


/* Print last OpenSSL error and exit */
static void ssl_die(const char *msg) {
    fprintf(stderr, "[ERROR] %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}


/* Print certificate subject, issuer, and validity */
static void print_cert_info(X509 *cert, const char *label) {
    if (!cert) return;

    char subject[256], issuer[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    X509_NAME_oneline(X509_get_issuer_name(cert),  issuer,  sizeof(issuer));

    printf("  %s:\n", label);
    printf("    Subject : %s\n", subject);
    printf("    Issuer  : %s\n", issuer);
}


/* ── Standard TLS connection (server cert verification only) ─────────────── */
int verify_server_tls(void) {
    printf("\n[1] Standard TLS — Verifying server certificate\n");

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) ssl_die("SSL_CTX_new failed");

    /* Load our private Root CA — required for chain verification */
    if (SSL_CTX_load_verify_locations(ctx, ROOT_CA_CERT, NULL) != 1)
        ssl_die("Failed to load Root CA cert");

    /* Enforce certificate verification — NEVER disable in production */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    /* Minimum TLS 1.2 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    BIO *bio = BIO_new_ssl_connect(ctx);
    if (!bio) ssl_die("BIO_new_ssl_connect failed");

    BIO_set_conn_hostname(bio, CONNECT_ADDR);

    SSL *ssl = NULL;
    BIO_get_ssl(bio, &ssl);
    if (!ssl) ssl_die("Failed to get SSL object");

    /* Set SNI (Server Name Indication) — required for virtual hosting */
    SSL_set_tlsext_host_name(ssl, SERVER_HOST);

    printf("  Connecting to %s...\n", CONNECT_ADDR);

    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "  [WARN] Connection failed (server may not be running in demo env)\n");
        ERR_clear_error();
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    if (BIO_do_handshake(bio) <= 0)
        ssl_die("TLS handshake failed");

    /* Verify result — SSL_get_verify_result returns X509_V_OK (0) on success */
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result == X509_V_OK) {
        printf("  [PASS] Certificate chain verified (Verify return code: 0 ok)\n");
    } else {
        printf("  [FAIL] Verification failed: %s\n",
               X509_verify_cert_error_string(verify_result));
    }

    /* Print peer certificate details */
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    print_cert_info(peer_cert, "Server Certificate");
    X509_free(peer_cert);

    printf("  Protocol : %s\n", SSL_get_version(ssl));
    printf("  Cipher   : %s\n", SSL_get_cipher(ssl));

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return (verify_result == X509_V_OK) ? 1 : 0;
}


/* ── mTLS connection (client + server cert verification) ─────────────────── */
int verify_mtls(void) {
    printf("\n[2] Mutual TLS (mTLS) — Client certificate authentication\n");

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) ssl_die("SSL_CTX_new failed");

    /* Load Root CA for server verification */
    if (SSL_CTX_load_verify_locations(ctx, ROOT_CA_CERT, NULL) != 1)
        ssl_die("Failed to load Root CA cert");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* Load client certificate and private key */
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) != 1)
        ssl_die("Failed to load client certificate");

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) != 1)
        ssl_die("Failed to load client private key");

    /* Verify the client cert and key match */
    if (SSL_CTX_check_private_key(ctx) != 1)
        ssl_die("Client cert and private key do not match");

    printf("  Client cert loaded: %s\n", CLIENT_CERT);

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    BIO *bio = BIO_new_ssl_connect(ctx);
    if (!bio) ssl_die("BIO_new_ssl_connect failed");
    BIO_set_conn_hostname(bio, CONNECT_ADDR);

    SSL *ssl = NULL;
    BIO_get_ssl(bio, &ssl);
    SSL_set_tlsext_host_name(ssl, SERVER_HOST);

    printf("  Connecting to %s (presenting client cert)...\n", CONNECT_ADDR);

    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "  [WARN] Connection failed (server may not be running in demo env)\n");
        ERR_clear_error();
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    if (BIO_do_handshake(bio) <= 0)
        ssl_die("mTLS handshake failed");

    long verify_result = SSL_get_verify_result(ssl);
    printf("  [%s] mTLS handshake complete (verify code: %ld)\n",
           verify_result == X509_V_OK ? "PASS" : "FAIL", verify_result);

    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    print_cert_info(peer_cert, "Server Certificate");
    X509_free(peer_cert);

    /* Send a simple HTTP GET request */
    const char *request =
        "GET /api/status HTTP/1.1\r\n"
        "Host: " SERVER_HOST "\r\n"
        "Connection: close\r\n\r\n";

    BIO_write(bio, request, (int)strlen(request));

    char buf[4096];
    int bytes_read;
    printf("  Response:\n");
    while ((bytes_read = BIO_read(bio, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes_read] = '\0';
        printf("    %s", buf);
        break;  /* Print first chunk only */
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return (verify_result == X509_V_OK) ? 1 : 0;
}


int main(void) {
    /* Initialise OpenSSL */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                     OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    printf("=============================================================\n");
    printf("  CSE PKI — C/OpenSSL TLS Verification & mTLS Demo\n");
    printf("=============================================================\n");
    printf("  Root CA     : %s\n", ROOT_CA_CERT);
    printf("  Client Cert : %s\n", CLIENT_CERT);

    int pass = 0;
    pass += verify_server_tls();
    pass += verify_mtls();

    printf("\n=============================================================\n");
    printf("  Results: %d/2 connections succeeded\n", pass);
    printf("=============================================================\n\n");

    return (pass > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
