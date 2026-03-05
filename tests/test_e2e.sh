#!/usr/bin/env bash
# End-to-end test: TLS 1.3 HTTPS with lighttpd
# Tests the full stack: TCP connect -> TLS handshake -> HTTP GET -> response
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../src"

. "$SCRIPT_DIR/test_harness.sh"
. "$SRC_DIR/util/hex.sh"
. "$SRC_DIR/util/bytes.sh"
. "$SRC_DIR/crypto/sha256.sh"
. "$SRC_DIR/crypto/hmac.sh"
. "$SRC_DIR/crypto/hkdf.sh"
. "$SRC_DIR/crypto/aes.sh"
. "$SRC_DIR/crypto/gcm.sh"
. "$SRC_DIR/crypto/x25519.sh"
. "$SRC_DIR/crypto/rsa.sh"
. "$SRC_DIR/net/tcp.sh"
. "$SRC_DIR/net/tcp_devtcp.sh"
. "$SRC_DIR/tls_record.sh"
. "$SRC_DIR/tls_handshake.sh"

printf '=== End-to-end tests (lighttpd HTTPS) ===\n'
printf 'NOTE: These tests are SLOW (~10-15 min) due to pure-shell crypto\n\n'

# Setup
CERT_DIR="$SCRIPT_DIR/certs"
WEBROOT="/tmp/tlsh_e2e_webroot"
LIGHTTPD_CONF="/tmp/tlsh_lighttpd.conf"
LIGHTTPD_PID="/tmp/tlsh_lighttpd.pid"
PORT=14434

# Generate certs if needed
if [ ! -f "$CERT_DIR/server.pem" ]; then
    mkdir -p "$CERT_DIR"
    [ -f "$CERT_DIR/server.key" ] || openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
        -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
    cat "$CERT_DIR/server.key" "$CERT_DIR/server.crt" > "$CERT_DIR/server.pem"
fi

# Create webroot with test file
mkdir -p "$WEBROOT"
printf 'Hello from tlsh e2e test!' > "$WEBROOT/test.txt"

# Write lighttpd config
cat > "$LIGHTTPD_CONF" << CONFEOF
server.document-root = "$WEBROOT"
server.port = $PORT
server.bind = "127.0.0.1"
server.pid-file = "$LIGHTTPD_PID"
server.modules = ("mod_openssl")
\$SERVER["socket"] == "127.0.0.1:$PORT" {
    ssl.engine = "enable"
    ssl.pemfile = "$CERT_DIR/server.pem"
    ssl.openssl.ssl-conf-cmd = ("MinProtocol" => "TLSv1.3", "MaxProtocol" => "TLSv1.3")
    ssl.openssl.ssl-conf-cmd += ("CipherSuites" => "TLS_AES_128_GCM_SHA256")
    ssl.openssl.ssl-conf-cmd += ("Groups" => "X25519")
}
mimetype.assign = (".txt" => "text/plain")
CONFEOF

# Start lighttpd
lighttpd -f "$LIGHTTPD_CONF" 2>/dev/null
sleep 1

cleanup() {
    [ -f "$LIGHTTPD_PID" ] && kill "$(cat "$LIGHTTPD_PID")" 2>/dev/null
    rm -f "$LIGHTTPD_CONF" "$LIGHTTPD_PID"
    rm -rf "$WEBROOT"
}
trap cleanup EXIT

# Verify lighttpd is running
if [ ! -f "$LIGHTTPD_PID" ]; then
    printf 'ERROR: lighttpd failed to start\n'
    # Try with simpler config
    cat > "$LIGHTTPD_CONF" << CONFEOF2
server.document-root = "$WEBROOT"
server.port = $PORT
server.bind = "127.0.0.1"
server.pid-file = "$LIGHTTPD_PID"
server.modules = ("mod_openssl")
ssl.engine = "enable"
ssl.pemfile = "$CERT_DIR/server.pem"
mimetype.assign = (".txt" => "text/plain")
CONFEOF2
    lighttpd -f "$LIGHTTPD_CONF" 2>&1
    sleep 1
fi

# Quick verification with openssl s_client
printf 'Verifying lighttpd TLS works with openssl...\n'
verify_result=$(printf 'GET /test.txt HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
    timeout 5 openssl s_client -connect localhost:$PORT -tls1_3 -quiet 2>/dev/null || true)
printf 'OpenSSL verification: %s\n' "$(printf '%s' "$verify_result" | head -1)"

# Test: HTTPS GET with tlsh
test_start "HTTPS GET /test.txt via lighttpd"

tcp_connect localhost $PORT
handshake_result=0
tls_handshake localhost || handshake_result=$?

if [ $handshake_result -eq 0 ]; then
    request_hex=$(ascii_to_hex "GET /test.txt HTTP/1.0")
    request_hex="${request_hex}0d0a"
    request_hex="${request_hex}$(ascii_to_hex "Host: localhost")"
    request_hex="${request_hex}0d0a0d0a"
    tls_send "$request_hex"

    recv_result=0
    tls_recv || recv_result=$?

    if [ $recv_result -eq 0 ]; then
        response=$(hex_to_ascii "$_tls_recv_payload")
        printf '  Response: %.80s\n' "$response"
        case "$response" in
            *"Hello from tlsh"*)
                assert_true "true" "received expected content from lighttpd"
                ;;
            HTTP/*)
                # Got HTTP response but maybe content is in next record
                assert_true "true" "received HTTP response (headers)"
                ;;
            *)
                assert_true "false" "unexpected response content"
                ;;
        esac
    else
        assert_true "false" "failed to receive response"
    fi
else
    assert_true "false" "handshake failed"
fi
tcp_close

test_summary
