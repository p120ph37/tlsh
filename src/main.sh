#!/usr/bin/env bash
# main.sh - tlsh entry point
# Sources all modules and provides the s_client interface.

set -euo pipefail

# Determine script directory for sourcing modules
_TLSH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source utility modules
. "$_TLSH_DIR/util/hex.sh"
. "$_TLSH_DIR/util/bytes.sh"

# Source crypto modules
. "$_TLSH_DIR/crypto/sha256.sh"
. "$_TLSH_DIR/crypto/hmac.sh"
. "$_TLSH_DIR/crypto/hkdf.sh"
. "$_TLSH_DIR/crypto/aes.sh"
. "$_TLSH_DIR/crypto/gcm.sh"

# Source network modules
. "$_TLSH_DIR/net/tcp.sh"
. "$_TLSH_DIR/net/tcp_devtcp.sh"

# Source TLS protocol modules (when they exist)
# . "$_TLSH_DIR/tls_record.sh"
# . "$_TLSH_DIR/tls_handshake.sh"

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

    # TODO: TLS handshake
    printf 'TLS handshake not yet implemented.\n' >&2

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
