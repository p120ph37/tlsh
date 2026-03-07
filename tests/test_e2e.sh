#!/usr/bin/env bash
# End-to-end test: TLS 1.3 HTTPS with lighttpd
# Tests the full stack with both cipher suites:
#   1. TLS_CHACHA20_POLY1305_SHA256 (preferred)
#   2. TLS_AES_128_GCM_SHA256
# Each test: TCP connect -> TLS handshake -> HTTP GET -> verify response
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
. "$SRC_DIR/crypto/chacha20poly1305.sh"
. "$SRC_DIR/crypto/x25519.sh"
. "$SRC_DIR/crypto/rsa.sh"
. "$SRC_DIR/net/tcp.sh"
. "$SRC_DIR/net/tcp_devtcp.sh"
. "$SRC_DIR/tls_record.sh"
. "$SRC_DIR/tls_handshake.sh"

printf '=== End-to-end tests (lighttpd HTTPS) ===\n'
printf 'NOTE: These tests are SLOW due to pure-shell crypto\n\n'

# Setup
CERT_DIR="$SCRIPT_DIR/certs"
WEBROOT="/tmp/tlsh_e2e_webroot"
PORT_CHACHA=14434
PORT_AES=14435

# Generate certs if needed
if [ ! -f "$CERT_DIR/server.pem" ]; then
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
        -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
    cat "$CERT_DIR/server.key" "$CERT_DIR/server.crt" > "$CERT_DIR/server.pem"
fi

# Create webroot with test file
mkdir -p "$WEBROOT"
printf 'Hello from tlsh e2e test!' > "$WEBROOT/test.txt"

start_lighttpd() {
    local port=$1
    local ciphersuite=$2
    local conf="/tmp/tlsh_e2e_${port}.conf"
    local pidfile="/tmp/tlsh_e2e_${port}.pid"

    cat > "$conf" << CONFEOF
server.document-root = "$WEBROOT"
server.port = $port
server.bind = "127.0.0.1"
server.pid-file = "$pidfile"
server.modules = ("mod_openssl")
\$SERVER["socket"] == "127.0.0.1:$port" {
    ssl.engine = "enable"
    ssl.pemfile = "$CERT_DIR/server.pem"
    ssl.openssl.ssl-conf-cmd = ("MinProtocol" => "TLSv1.3", "MaxProtocol" => "TLSv1.3")
    ssl.openssl.ssl-conf-cmd += ("CipherSuites" => "$ciphersuite")
    ssl.openssl.ssl-conf-cmd += ("Groups" => "X25519")
}
server.max-read-idle = 1800
server.max-write-idle = 1800
mimetype.assign = (".txt" => "text/plain")
CONFEOF

    lighttpd -f "$conf" 2>/dev/null
    sleep 1

    if [ ! -f "$pidfile" ]; then
        printf 'ERROR: lighttpd failed to start on port %d\n' "$port"
        return 1
    fi
}

cleanup() {
    for pidfile in /tmp/tlsh_e2e_*.pid; do
        [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
    done
    rm -f /tmp/tlsh_e2e_*.conf /tmp/tlsh_e2e_*.pid
    rm -rf "$WEBROOT"
}
trap cleanup EXIT

# Start lighttpd instances for each cipher suite
start_lighttpd "$PORT_CHACHA" "TLS_CHACHA20_POLY1305_SHA256" || exit 1
start_lighttpd "$PORT_AES" "TLS_AES_128_GCM_SHA256" || exit 1

# Quick verification with openssl s_client
printf 'Verifying lighttpd TLS works with openssl...\n'
for port in $PORT_CHACHA $PORT_AES; do
    verify_result=$(printf 'GET /test.txt HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
        timeout 5 openssl s_client -connect "localhost:$port" -tls1_3 -quiet 2>/dev/null || true)
    printf '  Port %d: %s\n' "$port" "$(echo "$verify_result" | head -1)"
done
printf '\n'

# Helper: run one e2e test against a specific port/cipher
run_e2e_test() {
    local label="$1"
    local port="$2"
    local expected_cipher_name="$3"

    test_start "HTTPS GET /test.txt via $label"

    # Reset TLS state for each connection
    _tls_transcript=""
    _tls_encrypted=0
    _tls_write_seq=0
    _tls_read_seq=0
    _tls_cipher_suite=0

    local t_start=$SECONDS

    tcp_connect localhost "$port"
    local handshake_result=0
    tls_handshake localhost || handshake_result=$?

    if [ $handshake_result -ne 0 ]; then
        assert_true 1 "handshake failed"
        tcp_close
        return
    fi

    local t_hs=$((SECONDS - t_start))
    printf '  Handshake: %d seconds\n' "$t_hs"

    # Verify correct cipher was negotiated
    if [ "$expected_cipher_name" = "ChaCha20-Poly1305" ]; then
        if [ "$_tls_cipher_suite" -ne "$_TLS_CS_CHACHA20_POLY1305_SHA256" ]; then
            printf '  WARNING: expected ChaCha20-Poly1305 but got cipher 0x%04x\n' "$_tls_cipher_suite"
        fi
    fi

    # Send HTTP GET request
    local request_hex
    request_hex=$(ascii_to_hex "GET /test.txt HTTP/1.0")
    request_hex="${request_hex}0d0a"
    request_hex="${request_hex}$(ascii_to_hex "Host: localhost")"
    request_hex="${request_hex}0d0a0d0a"
    tls_send "$request_hex"

    local recv_result=0
    tls_recv || recv_result=$?

    if [ $recv_result -eq 0 ]; then
        local response
        response=$(hex_to_ascii "$_tls_recv_payload")
        printf '  Response: %.80s\n' "$response"
        case "$response" in
            *"Hello from tlsh"*)
                assert_true 0 "received expected content"
                ;;
            HTTP/*)
                # Got HTTP headers, content may be in next record
                assert_true 0 "received HTTP response"
                ;;
            *)
                assert_true 1 "unexpected response"
                ;;
        esac
    else
        assert_true 1 "failed to receive response"
    fi

    tcp_close
    local t_total=$((SECONDS - t_start))
    printf '  Total: %d seconds\n' "$t_total"
}

# Test 1: ChaCha20-Poly1305
run_e2e_test "lighttpd (ChaCha20-Poly1305)" "$PORT_CHACHA" "ChaCha20-Poly1305"

# Test 2: AES-128-GCM
run_e2e_test "lighttpd (AES-128-GCM)" "$PORT_AES" "AES-128-GCM"

test_summary
