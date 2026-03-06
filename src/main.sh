#!/usr/bin/env bash
# main.sh - tlsh entry point
# Sources all modules and provides the s_client interface.

set -euo pipefail

# Determine script directory for sourcing modules
_TLSH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source utility modules
. "$_TLSH_DIR/util/hex.sh"
. "$_TLSH_DIR/util/bytes.sh"
. "$_TLSH_DIR/util/jit.sh"

# Source crypto modules
. "$_TLSH_DIR/crypto/sha256.sh"
. "$_TLSH_DIR/crypto/hmac.sh"
. "$_TLSH_DIR/crypto/hkdf.sh"
. "$_TLSH_DIR/crypto/aes.sh"
. "$_TLSH_DIR/crypto/gcm.sh"
. "$_TLSH_DIR/crypto/chacha20poly1305.sh"
. "$_TLSH_DIR/crypto/x25519.sh"
. "$_TLSH_DIR/crypto/rsa.sh"

# Source network modules
. "$_TLSH_DIR/net/tcp.sh"
. "$_TLSH_DIR/net/tcp_devtcp.sh"

# Source TLS protocol modules
. "$_TLSH_DIR/tls_record.sh"
. "$_TLSH_DIR/tls_handshake.sh"

# Register small utility functions as inlinable (body-copy candidates)
_jit_mark_inlinable uint8_to_hex uint16_to_hex uint24_to_hex uint32_to_hex ascii_to_hex

# JIT-optimize functions that still benefit from body-copy inlining of callees.
# Note: printf -v optimizations are now in source directly (sha256, hex_xor, hmac,
# aes, chacha20, gcm, x25519, bytes). JIT focuses on inlining utility function
# calls (ascii_to_hex, uint*_to_hex) to eliminate remaining subshell forks.
_jit_inline hkdf_expand_label _tls_build_client_hello hkdf_expand

# s_client - TLS client (equivalent to openssl s_client)
# Usage: s_client -connect host:port
s_client() {
    local host=""
    local port=""

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -connect)
                shift
                host="${1%%:*}"
                port="${1##*:}"
                ;;
            *)
                printf 'Unknown option: %s\n' "$1" >&2
                return 1
                ;;
        esac
        shift
    done

    if [ -z "$host" ] || [ -z "$port" ]; then
        printf 'Usage: s_client -connect host:port\n' >&2
        return 1
    fi

    printf 'Connecting to %s:%s...\n' "$host" "$port" >&2
    tcp_connect "$host" "$port"
    printf 'Connected.\n' >&2

    # Perform TLS 1.3 handshake
    if ! tls_handshake "$host"; then
        printf 'TLS handshake failed.\n' >&2
        tcp_close
        return 1
    fi

    # Interactive mode: read from stdin, send to server
    # Also read from server and print to stdout
    printf 'TLS connection established. Type to send data.\n' >&2

    # Simple loop: read a line, send it, receive response
    local line
    while IFS= read -r line; do
        local line_hex
        line_hex=$(ascii_to_hex "${line}")
        # Add CRLF
        line_hex="${line_hex}0d0a"
        tls_send "$line_hex"

        # Try to receive response
        if tls_recv; then
            hex_to_ascii "$_tls_recv_payload"
            printf '\n'
        fi
    done

    tcp_close
}

# Main dispatch
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        s_client)
            shift
            s_client "$@"
            ;;
        "")
            printf 'Usage: %s s_client -connect host:port\n' "$0"
            ;;
        *)
            printf 'Unknown command: %s\n' "$1" >&2
            exit 1
            ;;
    esac
fi
