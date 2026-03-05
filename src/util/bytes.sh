#!/usr/bin/env bash
# bytes.sh - Integer <-> hex conversion helpers (big-endian network byte order)

# uint8_to_hex <int> - Convert 8-bit integer to 2-char hex
uint8_to_hex() {
    printf '%02x' "$(( $1 & 0xFF ))"
}

# uint16_to_hex <int> - Convert 16-bit integer to 4-char hex (big-endian)
uint16_to_hex() {
    printf '%04x' "$(( $1 & 0xFFFF ))"
}

# uint24_to_hex <int> - Convert 24-bit integer to 6-char hex (big-endian)
uint24_to_hex() {
    printf '%06x' "$(( $1 & 0xFFFFFF ))"
}

# uint32_to_hex <int> - Convert 32-bit integer to 8-char hex (big-endian)
uint32_to_hex() {
    printf '%08x' "$(( $1 & 0xFFFFFFFF ))"
}

# uint64_to_hex <int> - Convert 64-bit integer to 16-char hex (big-endian)
uint64_to_hex() {
    printf '%016x' "$(( $1 ))"
}

# hex_to_uint8 <hex2> - Convert 2-char hex to integer
hex_to_uint8() {
    printf '%d' "$((16#$1))"
}

# hex_to_uint16 <hex4> - Convert 4-char hex to integer
hex_to_uint16() {
    printf '%d' "$((16#$1))"
}

# hex_to_uint32 <hex8> - Convert 8-char hex to integer
hex_to_uint32() {
    printf '%d' "$((16#$1))"
}

# hex_to_int <hex> - Convert arbitrary-length hex to integer (may overflow for >8 bytes)
hex_to_int() {
    printf '%d' "$((16#$1))"
}

# ascii_to_hex <string> - Convert ASCII string to hex
ascii_to_hex() {
    local str="$1"
    local hex=""
    local i=0
    while [ $i -lt ${#str} ]; do
        hex="${hex}$(printf '%02x' "'${str:$i:1}")"
        i=$((i + 1))
    done
    printf '%s' "$hex"
}
