#!/usr/bin/env bash
# hmac.sh - HMAC-SHA-256 (RFC 2104 / RFC 4231)
# Requires: sha256.sh, hex.sh

# HMAC-SHA-256 block size is 64 bytes (128 hex chars)
_HMAC_BLOCK_SIZE=64
_HMAC_BLOCK_SIZE_HEX=128

# hmac_sha256 <key_hex> <message_hex> - Compute HMAC-SHA-256
# Returns 64-char lowercase hex string.
hmac_sha256() {
    local key="$1"
    local msg="$2"

    # If key is longer than block size, hash it
    if [ $(( ${#key} / 2 )) -gt $_HMAC_BLOCK_SIZE ]; then
        key=$(sha256 "$key")
    fi

    # Pad key with zeros to block size
    while [ ${#key} -lt $_HMAC_BLOCK_SIZE_HEX ]; do
        key="${key}00"
    done

    # Create ipad and opad (0x36 and 0x5c repeated)
    local ipad=""
    local opad=""
    local i=0
    while [ $i -lt $_HMAC_BLOCK_SIZE_HEX ]; do
        local key_byte=$((16#${key:$i:2}))
        ipad="${ipad}$(printf '%02x' $(( key_byte ^ 0x36 )))"
        opad="${opad}$(printf '%02x' $(( key_byte ^ 0x5c )))"
        i=$((i + 2))
    done

    # HMAC = H(opad || H(ipad || message))
    local inner_hash
    inner_hash=$(sha256 "${ipad}${msg}")
    sha256 "${opad}${inner_hash}"
}
