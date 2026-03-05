#!/usr/bin/env bash
# tcp_devtcp.sh - /dev/tcp backend for TCP connections (bash/ksh93)
# Uses bash's built-in /dev/tcp/host/port pseudo-device.

_TCP_DEVTCP_FD=7  # Default fd to use

# _tcp_backend_connect <host> <port>
_tcp_backend_connect() {
    local host="$1"
    local port="$2"

    # Open bidirectional connection on fd 7
    eval "exec $_TCP_DEVTCP_FD<>/dev/tcp/$host/$port" || {
        printf 'ERROR: failed to connect to %s:%s\n' "$host" "$port" >&2
        return 1
    }

    _TCP_FD_READ=$_TCP_DEVTCP_FD
    _TCP_FD_WRITE=$_TCP_DEVTCP_FD
}

# _tcp_backend_close
_tcp_backend_close() {
    eval "exec $_TCP_DEVTCP_FD<&-" 2>/dev/null
}
