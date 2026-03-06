#!/usr/bin/env bash
# bench_jit.sh - Benchmark e2e with and without JIT inlining
# Compares: no-JIT baseline vs JIT-inlined performance
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

JIT_MODE="${1:-nojit}"

if [ "$JIT_MODE" = "jit" ]; then
    . "$SRC_DIR/util/jit.sh"
    _jit_mark_inlinable uint8_to_hex uint16_to_hex uint24_to_hex uint32_to_hex ascii_to_hex
    _jit_inline hkdf_expand_label _tls_build_client_hello hmac_sha256 hex_xor hkdf_expand
    printf '=== Benchmark: JIT ENABLED ===\n'
else
    printf '=== Benchmark: NO JIT (baseline) ===\n'
fi

# Setup
CERT_DIR="$SCRIPT_DIR/certs"
WEBROOT="/tmp/tlsh_bench_webroot"
PORT_CHACHA=14534
PORT_AES=14535

# Generate certs if needed
if [ ! -f "$CERT_DIR/server.pem" ]; then
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
        -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
    cat "$CERT_DIR/server.key" "$CERT_DIR/server.crt" > "$CERT_DIR/server.pem"
fi

mkdir -p "$WEBROOT"
printf 'Hello from tlsh bench!' > "$WEBROOT/test.txt"

start_lighttpd() {
    local port=$1
    local ciphersuite=$2
    local conf="/tmp/tlsh_bench_${port}.conf"
    local pidfile="/tmp/tlsh_bench_${port}.pid"

    # Kill existing if any
    [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
    rm -f "$pidfile"

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
    for pidfile in /tmp/tlsh_bench_*.pid; do
        [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
    done
    rm -f /tmp/tlsh_bench_*.conf /tmp/tlsh_bench_*.pid
    rm -rf "$WEBROOT"
}
trap cleanup EXIT

start_lighttpd "$PORT_CHACHA" "TLS_CHACHA20_POLY1305_SHA256" || exit 1
start_lighttpd "$PORT_AES" "TLS_AES_128_GCM_SHA256" || exit 1

run_bench() {
    local label="$1"
    local port="$2"

    printf '\n--- %s ---\n' "$label"

    _tls_transcript=""
    _tls_encrypted=0
    _tls_write_seq=0
    _tls_read_seq=0
    _tls_cipher_suite=0

    local t_start=$SECONDS

    tcp_connect localhost "$port"
    tls_handshake localhost || { printf 'Handshake FAILED\n'; tcp_close; return 1; }

    local t_hs=$((SECONDS - t_start))
    printf 'Handshake: %d seconds\n' "$t_hs"

    local request_hex
    request_hex=$(ascii_to_hex "GET /test.txt HTTP/1.0")
    request_hex="${request_hex}0d0a"
    request_hex="${request_hex}$(ascii_to_hex "Host: localhost")"
    request_hex="${request_hex}0d0a0d0a"
    tls_send "$request_hex"

    tls_recv && printf 'Response received OK\n' || printf 'No response\n'

    tcp_close
    local t_total=$((SECONDS - t_start))
    printf 'Total: %d seconds\n' "$t_total"
    printf 'RESULT:%s:%s:hs=%d:total=%d\n' "$JIT_MODE" "$label" "$t_hs" "$t_total"
}

run_bench "ChaCha20-Poly1305" "$PORT_CHACHA"
run_bench "AES-128-GCM" "$PORT_AES"
