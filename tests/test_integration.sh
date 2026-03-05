#!/usr/bin/env bash
# Integration test: TLS 1.3 handshake + application data exchange
# Requires: openssl (for s_server)
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

printf '=== Integration tests (TLS 1.3 handshake) ===\n'
printf 'NOTE: These tests are SLOW (~10-15 min) due to pure-shell crypto\n\n'

# Generate test certs if needed
CERT_DIR="$SCRIPT_DIR/certs"
if [ ! -f "$CERT_DIR/server.key" ] || [ ! -f "$CERT_DIR/server.crt" ]; then
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
fi

# Start s_server with -www (serves HTTP status page)
PORT=14433
mkfifo /tmp/tlsh_test_fifo 2>/dev/null || true
cat /tmp/tlsh_test_fifo | openssl s_server \
    -key "$CERT_DIR/server.key" -cert "$CERT_DIR/server.crt" \
    -accept $PORT -tls1_3 \
    -ciphersuites TLS_AES_128_GCM_SHA256 \
    -groups X25519 -www > /tmp/tlsh_s_server.log 2>&1 &
SERVER_PID=$!
sleep 2

cleanup() {
    kill $SERVER_PID 2>/dev/null
    rm -f /tmp/tlsh_test_fifo
}
trap cleanup EXIT

# Test 1: Full TLS 1.3 handshake + HTTP GET
test_start "TLS 1.3 handshake with openssl s_server"

tcp_connect localhost $PORT
handshake_result=0
tls_handshake localhost || handshake_result=$?

if [ $handshake_result -eq 0 ]; then
    printf '  Handshake succeeded. Sending HTTP GET...\n'

    # Send HTTP request
    request_hex=$(ascii_to_hex "GET / HTTP/1.0")
    request_hex="${request_hex}0d0a"
    request_hex="${request_hex}$(ascii_to_hex "Host: localhost")"
    request_hex="${request_hex}0d0a0d0a"
    tls_send "$request_hex"

    # Receive response
    recv_result=0
    tls_recv || recv_result=$?

    if [ $recv_result -eq 0 ]; then
        response=$(hex_to_ascii "$_tls_recv_payload")
        printf '  Response starts with: %.40s...\n' "$response"
        # Check if it looks like an HTTP response
        case "$response" in
            HTTP/*)
                assert_true "true" "received HTTP response"
                ;;
            *)
                assert_true "false" "expected HTTP response, got something else"
                ;;
        esac
    else
        assert_true "false" "failed to receive HTTP response (rc=$recv_result)"
    fi
else
    assert_true "false" "handshake failed (rc=$handshake_result)"
fi
tcp_close

test_summary
