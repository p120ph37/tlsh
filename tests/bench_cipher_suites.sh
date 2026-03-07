#!/usr/bin/env bash
# Benchmark: compare TLS 1.3 handshake + data exchange time for both cipher suites
# Uses lighttpd as the TLS endpoint.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../src"

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

CERT_DIR="$SCRIPT_DIR/certs"
WEBROOT="/tmp/tlsh_bench_webroot"
PORT_CHACHA=14450
PORT_AES=14451

# Generate certs if needed
mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/server.pem" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
        -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
    cat "$CERT_DIR/server.key" "$CERT_DIR/server.crt" > "$CERT_DIR/server.pem"
fi

# Create webroot
mkdir -p "$WEBROOT"
printf 'Hello from tlsh benchmark!' > "$WEBROOT/test.txt"

start_lighttpd() {
    local port=$1
    local ciphersuite=$2
    local conf="/tmp/tlsh_bench_${port}.conf"
    local pid="/tmp/tlsh_bench_${port}.pid"

    cat > "$conf" << CONFEOF
server.document-root = "$WEBROOT"
server.port = $port
server.bind = "127.0.0.1"
server.pid-file = "$pid"
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

    if [ ! -f "$pid" ]; then
        printf 'ERROR: lighttpd failed to start on port %d\n' "$port" >&2
        return 1
    fi
    printf '%s' "$pid"
}

cleanup() {
    for pidfile in /tmp/tlsh_bench_*.pid; do
        [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
    done
    rm -f /tmp/tlsh_bench_*.conf /tmp/tlsh_bench_*.pid
    rm -rf "$WEBROOT"
}
trap cleanup EXIT

printf '=== TLS 1.3 Cipher Suite Benchmark ===\n\n'

# Start servers
printf 'Starting lighttpd instances...\n'
start_lighttpd "$PORT_CHACHA" "TLS_CHACHA20_POLY1305_SHA256" || exit 1
start_lighttpd "$PORT_AES" "TLS_AES_128_GCM_SHA256" || exit 1
printf 'Servers ready.\n\n'

# Verify with openssl
printf 'Quick verification with openssl s_client:\n'
result=$(printf 'GET /test.txt HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
    timeout 5 openssl s_client -connect "localhost:$PORT_CHACHA" -tls1_3 -quiet 2>/dev/null || true)
printf '  ChaCha20 server: %s\n' "$(echo "$result" | grep -c 'Hello' | xargs -I{} sh -c '[ {} -gt 0 ] && echo OK || echo FAIL')"
result=$(printf 'GET /test.txt HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
    timeout 5 openssl s_client -connect "localhost:$PORT_AES" -tls1_3 -quiet 2>/dev/null || true)
printf '  AES server: %s\n\n' "$(echo "$result" | grep -c 'Hello' | xargs -I{} sh -c '[ {} -gt 0 ] && echo OK || echo FAIL')"

run_handshake_benchmark() {
    local label="$1"
    local port="$2"

    printf -- '--- %s ---\n' "$label"

    # Reset global state
    _tls_transcript=""
    _tls_encrypted=0
    _tls_write_seq=0
    _tls_read_seq=0
    _tls_cipher_suite=0

    local t_start t_hs_end t_total_end

    t_start=$SECONDS

    tcp_connect localhost "$port"

    if ! tls_handshake localhost; then
        printf '  HANDSHAKE FAILED\n\n'
        tcp_close
        return 1
    fi
    t_hs_end=$SECONDS

    local cipher_name
    if [ "$_tls_cipher_suite" -eq "$_TLS_CS_CHACHA20_POLY1305_SHA256" ]; then
        cipher_name="ChaCha20-Poly1305"
    else
        cipher_name="AES-128-GCM"
    fi
    printf '  Negotiated cipher: %s\n' "$cipher_name"
    printf '  Handshake time: %d seconds\n' "$((t_hs_end - t_start))"

    # Send HTTP request
    local req_hex
    req_hex=$(ascii_to_hex "GET /test.txt HTTP/1.0")
    req_hex="${req_hex}0d0a"
    req_hex="${req_hex}$(ascii_to_hex "Host: localhost")"
    req_hex="${req_hex}0d0a0d0a"
    tls_send "$req_hex"

    if tls_recv; then
        local response
        response=$(hex_to_ascii "$_tls_recv_payload")
        printf '  Response: %.70s\n' "$response"
    else
        printf '  No response received\n'
    fi

    tcp_close
    t_total_end=$SECONDS
    printf '  Total time: %d seconds\n\n' "$((t_total_end - t_start))"
}

# Run benchmarks
run_handshake_benchmark "TLS_CHACHA20_POLY1305_SHA256" "$PORT_CHACHA"
run_handshake_benchmark "TLS_AES_128_GCM_SHA256" "$PORT_AES"

printf '=== Benchmark complete ===\n'
