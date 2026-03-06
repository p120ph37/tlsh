#!/usr/bin/env bash
# hex.sh - Hex string manipulation utilities
# All binary data is represented as lowercase hex strings (2 chars per byte).

# Lookup table for byte-to-hex conversion (built once at source time)
_hex_digits="0123456789abcdef"

# hex_length <hex> - Return length in bytes (number of hex chars / 2)
hex_length() {
    printf '%d' $(( ${#1} / 2 ))
}

# hex_substr <hex> <byte_offset> <byte_count> - Extract substring
# Offset and count are in bytes (not hex chars).
hex_substr() {
    local hex="$1"
    local offset="$2"
    local count="$3"
    printf '%s' "${hex:$((offset * 2)):$((count * 2))}"
}

# hex_xor <hex_a> <hex_b> - XOR two hex strings of equal length
# Result is same length as inputs. If lengths differ, XORs up to shorter length.
hex_xor() {
    local a="$1"
    local b="$2"
    local len=${#a}
    [ ${#b} -lt "$len" ] && len=${#b}
    local result=""
    local i=0
    while [ $i -lt "$len" ]; do
        local byte_a=$((16#${a:$i:2}))
        local byte_b=$((16#${b:$i:2}))
        result="${result}$(printf '%02x' $(( byte_a ^ byte_b )))"
        i=$((i + 2))
    done
    printf '%s' "$result"
}

# hex_pad <hex> <target_byte_length> - Left-pad hex string with zeros to target byte length
hex_pad() {
    local hex="$1"
    local target=$(( $2 * 2 ))
    while [ ${#hex} -lt "$target" ]; do
        hex="00${hex}"
    done
    printf '%s' "$hex"
}

# hex_to_bytes <hex> - Write raw bytes to stdout
# Converts hex string to binary output via printf.
hex_to_bytes() {
    local hex="$1"
    local i=0
    local len=${#hex}
    local chunk=""
    while [ $i -lt "$len" ]; do
        chunk="${chunk}\\x${hex:$i:2}"
        i=$((i + 2))
        # Flush every 64 bytes to avoid argument-too-long issues
        if [ $((i % 128)) -eq 0 ]; then
            printf '%b' "$chunk"
            chunk=""
        fi
    done
    [ -n "$chunk" ] && printf '%b' "$chunk"
}

# bytes_to_hex <fd> <count> - Read count raw bytes from fd 0 (stdin), output hex
# Note: Cannot handle NUL bytes (shell limitation). For NUL-safe I/O, use
# the raw fd read/write in tcp.sh which avoids variable capture.
bytes_to_hex() {
    local count="$1"
    local result=""
    local i=0
    while [ $i -lt "$count" ]; do
        local byte
        IFS= read -r -n 1 byte || byte=""
        if [ -z "$byte" ]; then
            result="${result}00"
        else
            result="${result}$(printf '%02x' "'$byte")"
        fi
        i=$((i + 1))
    done
    printf '%s' "$result"
}

# hex_to_ascii <hex> - Convert hex string to ASCII (non-NUL bytes only)
hex_to_ascii() {
    local hex="$1"
    local i=0
    local len=${#hex}
    while [ $i -lt "$len" ]; do
        printf "\\x${hex:$i:2}"
        i=$((i + 2))
    done
}
