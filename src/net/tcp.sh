#!/usr/bin/env bash
# tcp.sh - Abstract TCP connection interface
# This file defines the TCP API. The actual implementation is provided by
# a backend module (tcp_devtcp.sh, tcp_ztcp.sh, tcp_nc.sh).
#
# Backend modules must implement:
#   _tcp_backend_connect <host> <port>   - establish connection, set up fds
#   _tcp_backend_close                   - close connection and fds
#
# After _tcp_backend_connect, the backend must set:
#   _TCP_FD_READ  - file descriptor for reading
#   _TCP_FD_WRITE - file descriptor for writing
#   (these may be the same fd)

_TCP_FD_READ=""
_TCP_FD_WRITE=""
_TCP_CONNECTED=0

# tcp_connect <host> <port> - Open a TCP connection
tcp_connect() {
    local host="$1"
    local port="$2"
    _tcp_backend_connect "$host" "$port"
    _TCP_CONNECTED=1
}

# tcp_send_hex <hex_data> - Send hex-encoded data over the connection
tcp_send_hex() {
    local hex="$1"
    hex_to_bytes "$hex" >&"$_TCP_FD_WRITE"
}

# tcp_recv_hex <byte_count> - Receive exact number of bytes, return as hex
# Blocks until all bytes are received.
tcp_recv_hex() {
    local count="$1"
    local result=""
    local remaining=$count
    while [ $remaining -gt 0 ]; do
        local byte
        IFS= read -r -n 1 -d '' byte <&"$_TCP_FD_READ" || true
        if [ -z "$byte" ]; then
            result="${result}00"
        else
            result="${result}$(printf '%02x' "'$byte")"
        fi
        remaining=$((remaining - 1))
    done
    printf '%s' "$result"
}

# tcp_close - Close the TCP connection
tcp_close() {
    if [ "$_TCP_CONNECTED" -eq 1 ]; then
        _tcp_backend_close
        _TCP_CONNECTED=0
    fi
}
