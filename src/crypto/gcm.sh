#!/usr/bin/env bash
# gcm.sh - AES-128-GCM (Galois Counter Mode)
# Reference: NIST SP 800-38D, McGrew & Viega GCM spec
# Requires: aes.sh

# GCM operates on 128-bit (16-byte) blocks.
# The GHASH field is GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1.
# We represent 128-bit values as 4 x 32-bit integers (big-endian word order).

# _gcm_gf_mult <a_hex_32> <b_hex_32> - GF(2^128) multiplication
# Both inputs are 32-char hex strings (16 bytes).
# Returns 32-char hex string.
_gcm_gf_mult() {
    local a_hex="$1"
    local b_hex="$2"

    # Parse a and b into 4 x 32-bit words each
    local a0=$((16#${a_hex:0:8}))
    local a1=$((16#${a_hex:8:8}))
    local a2=$((16#${a_hex:16:8}))
    local a3=$((16#${a_hex:24:8}))

    local v0=$((16#${b_hex:0:8}))
    local v1=$((16#${b_hex:8:8}))
    local v2=$((16#${b_hex:16:8}))
    local v3=$((16#${b_hex:24:8}))

    local z0=0 z1=0 z2=0 z3=0

    # For each bit of a (128 bits total, MSB first)
    local w=0
    while [ $w -lt 4 ]; do
        local a_word
        case $w in
            0) a_word=$a0 ;; 1) a_word=$a1 ;; 2) a_word=$a2 ;; 3) a_word=$a3 ;;
        esac
        local bit=31
        while [ $bit -ge 0 ]; do
            if [ $(( (a_word >> bit) & 1 )) -ne 0 ]; then
                z0=$((z0 ^ v0))
                z1=$((z1 ^ v1))
                z2=$((z2 ^ v2))
                z3=$((z3 ^ v3))
            fi
            # Shift V right by 1 (as 128-bit value), if LSB was set, XOR with R
            local lsb=$(( v3 & 1 ))
            v3=$(( ((v3 >> 1) | ((v2 & 1) << 31)) & 0xFFFFFFFF ))
            v2=$(( ((v2 >> 1) | ((v1 & 1) << 31)) & 0xFFFFFFFF ))
            v1=$(( ((v1 >> 1) | ((v0 & 1) << 31)) & 0xFFFFFFFF ))
            v0=$(( (v0 >> 1) & 0xFFFFFFFF ))
            if [ $lsb -ne 0 ]; then
                # R = 0xE1000000 00000000 00000000 00000000
                v0=$((v0 ^ 0xE1000000))
            fi
            bit=$((bit - 1))
        done
        w=$((w + 1))
    done

    printf '%08x%08x%08x%08x' \
        $((z0 & 0xFFFFFFFF)) $((z1 & 0xFFFFFFFF)) \
        $((z2 & 0xFFFFFFFF)) $((z3 & 0xFFFFFFFF))
}

# _gcm_ghash <h_hex> <data_hex> - GHASH function
# H is the hash subkey (16 bytes hex). Data is arbitrary length hex (must be
# multiple of 16 bytes, caller pads if needed).
# Returns 16-byte hex string.
_gcm_ghash() {
    local h="$1"
    local data="$2"
    local y="00000000000000000000000000000000"
    local len=${#data}
    local i=0
    while [ $i -lt "$len" ]; do
        local block="${data:$i:32}"
        # Pad block to 16 bytes if needed
        while [ ${#block} -lt 32 ]; do
            block="${block}00"
        done
        y=$(hex_xor "$y" "$block")
        y=$(_gcm_gf_mult "$y" "$h")
        i=$((i + 32))
    done
    printf '%s' "$y"
}

# _gcm_inc32 <counter_hex_32> - Increment the rightmost 32 bits of a 128-bit counter
_gcm_inc32() {
    local ctr="$1"
    local left="${ctr:0:24}"  # Upper 96 bits (24 hex chars)
    local right=$((16#${ctr:24:8}))  # Lower 32 bits
    right=$(( (right + 1) & 0xFFFFFFFF ))
    printf '%s%08x' "$left" "$right"
}

# _gcm_gctr <icb_hex> <plaintext_hex> - GCTR function (CTR mode encryption)
# ICB is initial counter block (16 bytes hex).
# Returns ciphertext hex of same length as plaintext.
_gcm_gctr() {
    local cb="$1"
    local pt="$2"
    local pt_len=${#pt}
    local result=""
    local i=0

    while [ $i -lt "$pt_len" ]; do
        local block="${pt:$i:32}"
        local block_len=${#block}
        local encrypted_cb
        encrypted_cb=$(aes128_encrypt_block "$cb")
        # XOR only the bytes we have (handles partial last block)
        local xored
        xored=$(hex_xor "$encrypted_cb" "$block")
        # Truncate to actual block length
        result="${result}${xored:0:$block_len}"
        cb=$(_gcm_inc32 "$cb")
        i=$((i + 32))
    done
    printf '%s' "$result"
}

# gcm_encrypt <key_hex> <iv_hex> <plaintext_hex> <aad_hex>
# AES-128-GCM authenticated encryption.
# Key: 32 hex chars (16 bytes). IV: 24 hex chars (12 bytes, standard).
# Returns: ciphertext_hex followed by 32-char tag_hex, separated by space.
gcm_encrypt() {
    local key="$1"
    local iv="$2"
    local pt="$3"
    local aad="$4"

    aes128_expand_key "$key"

    # Compute H = AES_K(0^128)
    local h
    h=$(aes128_encrypt_block "00000000000000000000000000000000")

    # Compute J0 (initial counter)
    local j0
    if [ ${#iv} -eq 24 ]; then
        # 96-bit IV: J0 = IV || 0^31 || 1
        j0="${iv}00000001"
    else
        # Non-96-bit IV: J0 = GHASH_H(IV || pad || len64)
        # Not implemented (96-bit IV is standard for TLS)
        printf 'ERROR: only 96-bit IV supported\n' >&2
        return 1
    fi

    # Encrypt plaintext with GCTR (starting from inc32(J0))
    local cb
    cb=$(_gcm_inc32 "$j0")
    local ct=""
    if [ -n "$pt" ]; then
        ct=$(_gcm_gctr "$cb" "$pt")
    fi

    # Compute GHASH over AAD and CT
    # Build: AAD || pad_to_128(AAD) || CT || pad_to_128(CT) || len(AAD)_64 || len(CT)_64
    local aad_bits=$(( ${#aad} * 4 ))
    local ct_bits=$(( ${#ct} * 4 ))

    local ghash_input=""
    # AAD padded to 128-bit boundary
    if [ -n "$aad" ]; then
        ghash_input="$aad"
        while [ $(( ${#ghash_input} % 32 )) -ne 0 ]; do
            ghash_input="${ghash_input}00"
        done
    fi
    # CT padded to 128-bit boundary
    if [ -n "$ct" ]; then
        ghash_input="${ghash_input}${ct}"
        while [ $(( ${#ghash_input} % 32 )) -ne 0 ]; do
            ghash_input="${ghash_input}00"
        done
    fi
    # Append lengths (each 64-bit big-endian)
    ghash_input="${ghash_input}$(printf '%016x%016x' "$aad_bits" "$ct_bits")"

    local s
    s=$(_gcm_ghash "$h" "$ghash_input")

    # Tag = GCTR_K(J0, S) -- encrypt S with counter J0
    local tag
    tag=$(_gcm_gctr "$j0" "$s")

    printf '%s %s' "$ct" "${tag:0:32}"
}

# gcm_decrypt <key_hex> <iv_hex> <ciphertext_hex> <aad_hex> <tag_hex>
# AES-128-GCM authenticated decryption.
# Returns plaintext hex on success, exits with error if tag mismatch.
gcm_decrypt() {
    local key="$1"
    local iv="$2"
    local ct="$3"
    local aad="$4"
    local expected_tag="$5"

    aes128_expand_key "$key"

    local h
    h=$(aes128_encrypt_block "00000000000000000000000000000000")

    local j0
    if [ ${#iv} -eq 24 ]; then
        j0="${iv}00000001"
    else
        printf 'ERROR: only 96-bit IV supported\n' >&2
        return 1
    fi

    # Verify tag first: compute GHASH over AAD and CT
    local aad_bits=$(( ${#aad} * 4 ))
    local ct_bits=$(( ${#ct} * 4 ))

    local ghash_input=""
    if [ -n "$aad" ]; then
        ghash_input="$aad"
        while [ $(( ${#ghash_input} % 32 )) -ne 0 ]; do
            ghash_input="${ghash_input}00"
        done
    fi
    if [ -n "$ct" ]; then
        ghash_input="${ghash_input}${ct}"
        while [ $(( ${#ghash_input} % 32 )) -ne 0 ]; do
            ghash_input="${ghash_input}00"
        done
    fi
    ghash_input="${ghash_input}$(printf '%016x%016x' "$aad_bits" "$ct_bits")"

    local s
    s=$(_gcm_ghash "$h" "$ghash_input")
    local computed_tag
    computed_tag=$(_gcm_gctr "$j0" "$s")
    computed_tag="${computed_tag:0:32}"

    if [ "$computed_tag" != "$expected_tag" ]; then
        printf 'ERROR: GCM tag mismatch\n' >&2
        return 1
    fi

    # Decrypt ciphertext
    local cb
    cb=$(_gcm_inc32 "$j0")
    local pt=""
    if [ -n "$ct" ]; then
        pt=$(_gcm_gctr "$cb" "$ct")
    fi
    printf '%s' "$pt"
}
