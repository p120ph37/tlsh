#!/usr/bin/env bash
# aes.sh - AES-128 block cipher (encrypt only)
# Reference: FIPS 197 (AES standard)
# Only encryption is needed for AES-GCM (CTR mode uses encrypt in both directions).

# AES S-box (SubBytes lookup table)
_aes_sbox=(
    0x63 0x7c 0x77 0x7b 0xf2 0x6b 0x6f 0xc5 0x30 0x01 0x67 0x2b 0xfe 0xd7 0xab 0x76
    0xca 0x82 0xc9 0x7d 0xfa 0x59 0x47 0xf0 0xad 0xd4 0xa2 0xaf 0x9c 0xa4 0x72 0xc0
    0xb7 0xfd 0x93 0x26 0x36 0x3f 0xf7 0xcc 0x34 0xa5 0xe5 0xf1 0x71 0xd8 0x31 0x15
    0x04 0xc7 0x23 0xc3 0x18 0x96 0x05 0x9a 0x07 0x12 0x80 0xe2 0xeb 0x27 0xb2 0x75
    0x09 0x83 0x2c 0x1a 0x1b 0x6e 0x5a 0xa0 0x52 0x3b 0xd6 0xb3 0x29 0xe3 0x2f 0x84
    0x53 0xd1 0x00 0xed 0x20 0xfc 0xb1 0x5b 0x6a 0xcb 0xbe 0x39 0x4a 0x4c 0x58 0xcf
    0xd0 0xef 0xaa 0xfb 0x43 0x4d 0x33 0x85 0x45 0xf9 0x02 0x7f 0x50 0x3c 0x9f 0xa8
    0x51 0xa3 0x40 0x8f 0x92 0x9d 0x38 0xf5 0xbc 0xb6 0xda 0x21 0x10 0xff 0xf3 0xd2
    0xcd 0x0c 0x13 0xec 0x5f 0x97 0x44 0x17 0xc4 0xa7 0x7e 0x3d 0x64 0x5d 0x19 0x73
    0x60 0x81 0x4f 0xdc 0x22 0x2a 0x90 0x88 0x46 0xee 0xb8 0x14 0xde 0x5e 0x0b 0xdb
    0xe0 0x32 0x3a 0x0a 0x49 0x06 0x24 0x5c 0xc2 0xd3 0xac 0x62 0x91 0x95 0xe4 0x79
    0xe7 0xc8 0x37 0x6d 0x8d 0xd5 0x4e 0xa9 0x6c 0x56 0xf4 0xea 0x65 0x7a 0xae 0x08
    0xba 0x78 0x25 0x2e 0x1c 0xa6 0xb4 0xc6 0xe8 0xdd 0x74 0x1f 0x4b 0xbd 0x8b 0x8a
    0x70 0x3e 0xb5 0x66 0x48 0x03 0xf6 0x0e 0x61 0x35 0x57 0xb9 0x86 0xc1 0x1d 0x9e
    0xe1 0xf8 0x98 0x11 0x69 0xd9 0x8e 0x94 0x9b 0x1e 0x87 0xe9 0xce 0x55 0x28 0xdf
    0x8c 0xa1 0x89 0x0d 0xbf 0xe6 0x42 0x68 0x41 0x99 0x2d 0x0f 0xb0 0x54 0xbb 0x16
)

# Round constants
_aes_rcon=(0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80 0x1b 0x36)

# aes128_expand_key <key_hex_32chars>
# Expands 128-bit key into 11 round keys (44 32-bit words).
# Stores result in global array _aes_rk[] (44 elements, each a 32-bit integer).
aes128_expand_key() {
    local key="$1"
    _aes_rk=()

    # First 4 words come directly from the key
    local i=0
    while [ $i -lt 4 ]; do
        _aes_rk[$i]=$((16#${key:$((i*8)):8}))
        i=$((i + 1))
    done

    # Expand to 44 words
    i=4
    while [ $i -lt 44 ]; do
        local temp=${_aes_rk[$((i-1))]}
        if [ $((i % 4)) -eq 0 ]; then
            # RotWord: rotate left by 8 bits
            temp=$(( ((temp << 8) | ((temp >> 24) & 0xFF)) & 0xFFFFFFFF ))
            # SubWord: apply S-box to each byte
            local b0=$(( (temp >> 24) & 0xFF ))
            local b1=$(( (temp >> 16) & 0xFF ))
            local b2=$(( (temp >> 8) & 0xFF ))
            local b3=$(( temp & 0xFF ))
            temp=$(( (${_aes_sbox[$b0]} << 24) | (${_aes_sbox[$b1]} << 16) | (${_aes_sbox[$b2]} << 8) | ${_aes_sbox[$b3]} ))
            # XOR with round constant
            temp=$(( temp ^ (${_aes_rcon[$((i/4 - 1))]} << 24) ))
        fi
        _aes_rk[$i]=$(( (${_aes_rk[$((i-4))]} ^ temp) & 0xFFFFFFFF ))
        i=$((i + 1))
    done
}

# _aes_sub_bytes <state array name> - Apply S-box substitution
# State is 16 bytes as array indices 0..15
_aes_sub_bytes() {
    local i=0
    while [ $i -lt 16 ]; do
        _aes_state[$i]=${_aes_sbox[${_aes_state[$i]}]}
        i=$((i + 1))
    done
}

# _aes_shift_rows - Shift rows of state matrix
_aes_shift_rows() {
    local tmp
    # Row 1: shift left by 1
    tmp=${_aes_state[1]}
    _aes_state[1]=${_aes_state[5]}
    _aes_state[5]=${_aes_state[9]}
    _aes_state[9]=${_aes_state[13]}
    _aes_state[13]=$tmp
    # Row 2: shift left by 2
    tmp=${_aes_state[2]}
    _aes_state[2]=${_aes_state[10]}
    _aes_state[10]=$tmp
    tmp=${_aes_state[6]}
    _aes_state[6]=${_aes_state[14]}
    _aes_state[14]=$tmp
    # Row 3: shift left by 3 (= right by 1)
    tmp=${_aes_state[15]}
    _aes_state[15]=${_aes_state[11]}
    _aes_state[11]=${_aes_state[7]}
    _aes_state[7]=${_aes_state[3]}
    _aes_state[3]=$tmp
}

# _aes_xtime <byte> - Multiply by 2 in GF(2^8)
_aes_xtime() {
    local b=$1
    if [ $((b & 0x80)) -ne 0 ]; then
        printf '%d' $(( ((b << 1) ^ 0x1b) & 0xFF ))
    else
        printf '%d' $(( (b << 1) & 0xFF ))
    fi
}

# _aes_mix_columns - MixColumns transformation
_aes_mix_columns() {
    local c=0
    while [ $c -lt 4 ]; do
        local i0=$(( c * 4 ))
        local a0=${_aes_state[$i0]}
        local a1=${_aes_state[$((i0+1))]}
        local a2=${_aes_state[$((i0+2))]}
        local a3=${_aes_state[$((i0+3))]}
        local t=$(( a0 ^ a1 ^ a2 ^ a3 ))
        local u

        u=$(_aes_xtime $(( a0 ^ a1 )))
        _aes_state[$i0]=$(( a0 ^ u ^ t ))
        u=$(_aes_xtime $(( a1 ^ a2 )))
        _aes_state[$((i0+1))]=$(( a1 ^ u ^ t ))
        u=$(_aes_xtime $(( a2 ^ a3 )))
        _aes_state[$((i0+2))]=$(( a2 ^ u ^ t ))
        u=$(_aes_xtime $(( a3 ^ a0 )))
        _aes_state[$((i0+3))]=$(( a3 ^ u ^ t ))

        c=$((c + 1))
    done
}

# _aes_add_round_key <round> - XOR state with round key
_aes_add_round_key() {
    local round=$1
    local rk_offset=$((round * 4))
    local c=0
    while [ $c -lt 4 ]; do
        local w=${_aes_rk[$((rk_offset + c))]}
        _aes_state[$((c*4))]=$(( ${_aes_state[$((c*4))]} ^ ((w >> 24) & 0xFF) ))
        _aes_state[$((c*4+1))]=$(( ${_aes_state[$((c*4+1))]} ^ ((w >> 16) & 0xFF) ))
        _aes_state[$((c*4+2))]=$(( ${_aes_state[$((c*4+2))]} ^ ((w >> 8) & 0xFF) ))
        _aes_state[$((c*4+3))]=$(( ${_aes_state[$((c*4+3))]} ^ (w & 0xFF) ))
        c=$((c + 1))
    done
}

# aes128_encrypt_block <plaintext_hex_32chars>
# Encrypts a single 16-byte block. Key must be expanded first via aes128_expand_key.
# Returns 32-char hex string (16 bytes).
# State layout: column-major (state[row + 4*col])
aes128_encrypt_block() {
    local pt="$1"
    _aes_state=()

    # Load plaintext into state (column-major order)
    local col=0
    while [ $col -lt 4 ]; do
        local row=0
        while [ $row -lt 4 ]; do
            _aes_state[$((row + col * 4))]=$((16#${pt:$((col * 8 + row * 2)):2}))
            row=$((row + 1))
        done
        col=$((col + 1))
    done

    # Initial round key addition
    _aes_add_round_key 0

    # Rounds 1-9
    local round=1
    while [ $round -lt 10 ]; do
        _aes_sub_bytes
        _aes_shift_rows
        _aes_mix_columns
        _aes_add_round_key "$round"
        round=$((round + 1))
    done

    # Final round (no MixColumns)
    _aes_sub_bytes
    _aes_shift_rows
    _aes_add_round_key 10

    # Output state as hex (column-major)
    local result=""
    col=0
    while [ $col -lt 4 ]; do
        local row=0
        while [ $row -lt 4 ]; do
            result="${result}$(printf '%02x' "${_aes_state[$((row + col * 4))]}")"
            row=$((row + 1))
        done
        col=$((col + 1))
    done
    printf '%s' "$result"
}
