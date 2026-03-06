#!/usr/bin/env bash
# Quick debug test for TLS handshake (handshake only, no HTTP)
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
. "$SRC_DIR/crypto/x25519.sh"
. "$SRC_DIR/crypto/rsa.sh"
. "$SRC_DIR/net/tcp.sh"
. "$SRC_DIR/net/tcp_devtcp.sh"
. "$SRC_DIR/tls_record.sh"
. "$SRC_DIR/tls_handshake.sh"

HOST="${1:-localhost}"
PORT="${2:-14433}"

printf 'Connecting to %s:%s...\n' "$HOST" "$PORT"
tcp_connect "$HOST" "$PORT"
printf 'Connected. Starting TLS handshake...\n'

if tls_handshake "$HOST"; then
    printf '\n=== TLS HANDSHAKE SUCCEEDED ===\n'
else
    printf '\n=== TLS HANDSHAKE FAILED ===\n'
fi

tcp_close
