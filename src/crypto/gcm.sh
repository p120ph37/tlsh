#!/usr/bin/env bash
# gcm.sh - AES-128-GCM (Galois Counter Mode)
# Reference: NIST SP 800-38D, McGrew & Viega GCM spec
# Requires: aes.sh
#
# All internal functions return results via globals to avoid subshell forks.

# _gcm_gf_mult <a_hex_32> <b_hex_32> - GF(2^128) multiplication
# Result stored in _gcm_gf_result (32-char hex string).
_gcm_gf_mult() {
    local a_hex="$1"
    local b_hex="$2"

    local a0=$((16#${a_hex:0:8}))
    local a1=$((16#${a_hex:8:8}))
    local a2=$((16#${a_hex:16:8}))
    local a3=$((16#${a_hex:24:8}))

    local v0=$((16#${b_hex:0:8}))
    local v1=$((16#${b_hex:8:8}))
    local v2=$((16#${b_hex:16:8}))
    local v3=$((16#${b_hex:24:8}))

    local z0=0 z1=0 z2=0 z3=0

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
            local lsb=$(( v3 & 1 ))
            v3=$(( ((v3 >> 1) | ((v2 & 1) << 31)) & 0xFFFFFFFF ))
            v2=$(( ((v2 >> 1) | ((v1 & 1) << 31)) & 0xFFFFFFFF ))
            v1=$(( ((v1 >> 1) | ((v0 & 1) << 31)) & 0xFFFFFFFF ))
            v0=$(( (v0 >> 1) & 0xFFFFFFFF ))
            if [ $lsb -ne 0 ]; then
                v0=$((v0 ^ 0xE1000000))
            fi
            bit=$((bit - 1))
        done
        w=$((w + 1))
    done

    printf -v _gcm_gf_result '%08x%08x%08x%08x' \
        $((z0 & 0xFFFFFFFF)) $((z1 & 0xFFFFFFFF)) \
        $((z2 & 0xFFFFFFFF)) $((z3 & 0xFFFFFFFF))
}

# _gcm_ghash <h_hex> <data_hex> - GHASH function
# Result stored in _gcm_ghash_result (32-char hex string).
_gcm_ghash() {
    local h="$1"
    local data="$2"
    local y="00000000000000000000000000000000"
    local len=${#data}
    local i=0
    while [ $i -lt "$len" ]; do
        local block="${data:$i:32}"
        while [ ${#block} -lt 32 ]; do
            block="${block}00"
        done
        y=$(hex_xor "$y" "$block")
        _gcm_gf_mult "$y" "$h"
        y="$_gcm_gf_result"
        i=$((i + 32))
    done
    _gcm_ghash_result="$y"
}

# _gcm_inc32 <counter_hex_32> - Increment the rightmost 32 bits
# Result stored in _gcm_inc32_result.
_gcm_inc32() {
    local ctr="$1"
    local left="${ctr:0:24}"
    local right=$((16#${ctr:24:8}))
    right=$(( (right + 1) & 0xFFFFFFFF ))
    printf -v _gcm_inc32_result '%s%08x' "$left" "$right"
}

# _gcm_gctr <icb_hex> <plaintext_hex> - GCTR function (CTR mode encryption)
# Result stored in _gcm_gctr_result.
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
        local xored
        xored=$(hex_xor "$encrypted_cb" "$block")
        result="${result}${xored:0:$block_len}"
        _gcm_inc32 "$cb"
        cb="$_gcm_inc32_result"
        i=$((i + 32))
    done
    _gcm_gctr_result="$result"
}

# gcm_encrypt <key_hex> <iv_hex> <plaintext_hex> <aad_hex>
# Returns: ciphertext_hex followed by 32-char tag_hex, separated by space.
gcm_encrypt() {
    local key="$1"
    local iv="$2"
    local pt="$3"
    local aad="$4"

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

    _gcm_inc32 "$j0"
    local cb="$_gcm_inc32_result"
    local ct=""
    if [ -n "$pt" ]; then
        _gcm_gctr "$cb" "$pt"
        ct="$_gcm_gctr_result"
    fi

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
    local _gcm_len_tmp
    printf -v _gcm_len_tmp '%016x%016x' "$aad_bits" "$ct_bits"
    ghash_input="${ghash_input}${_gcm_len_tmp}"

    _gcm_ghash "$h" "$ghash_input"

    _gcm_gctr "$j0" "$_gcm_ghash_result"
    local tag="${_gcm_gctr_result:0:32}"

    printf '%s %s' "$ct" "$tag"
}

# gcm_decrypt <key_hex> <iv_hex> <ciphertext_hex> <aad_hex> <tag_hex>
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
    local _gcm_len_tmp
    printf -v _gcm_len_tmp '%016x%016x' "$aad_bits" "$ct_bits"
    ghash_input="${ghash_input}${_gcm_len_tmp}"

    _gcm_ghash "$h" "$ghash_input"
    _gcm_gctr "$j0" "$_gcm_ghash_result"
    local computed_tag="${_gcm_gctr_result:0:32}"

    if [ "$computed_tag" != "$expected_tag" ]; then
        printf 'ERROR: GCM tag mismatch\n' >&2
        return 1
    fi

    _gcm_inc32 "$j0"
    local cb="$_gcm_inc32_result"
    local pt=""
    if [ -n "$ct" ]; then
        _gcm_gctr "$cb" "$ct"
        pt="$_gcm_gctr_result"
    fi
    printf '%s' "$pt"
}
