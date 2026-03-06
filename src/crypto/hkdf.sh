#!/usr/bin/env bash
# hkdf.sh - HKDF key derivation (RFC 5869)
# Requires: hmac.sh (which requires sha256.sh)

# hkdf_extract <salt_hex> <ikm_hex> - HKDF-Extract
# If salt is empty, uses HashLen zeros (32 bytes for SHA-256).
# Returns PRK as 64-char hex string.
hkdf_extract() {
    local salt="$1"
    local ikm="$2"
    # If salt not provided, default to HashLen zeros
    if [ -z "$salt" ]; then
        salt="0000000000000000000000000000000000000000000000000000000000000000"
    fi
    hmac_sha256 "$salt" "$ikm"
}

# hkdf_expand <prk_hex> <info_hex> <length_bytes> - HKDF-Expand
# Returns OKM of specified length as hex string.
hkdf_expand() {
    local prk="$1"
    local info="$2"
    local length=$3

    local hash_len=32  # SHA-256 output = 32 bytes
    local n=$(( (length + hash_len - 1) / hash_len ))
    local okm=""
    local t=""  # T(0) = empty string
    local i=1

    while [ $i -le "$n" ]; do
        local counter
        printf -v counter '%02x' "$i"
        t=$(hmac_sha256 "$prk" "${t}${info}${counter}")
        okm="${okm}${t}"
        i=$((i + 1))
    done

    # Truncate to requested length
    printf '%s' "${okm:0:$((length * 2))}"
}

# hkdf_expand_label <secret_hex> <label_ascii> <context_hex> <length_bytes>
# TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1)
# label is prefixed with "tls13 " automatically.
hkdf_expand_label() {
    local secret="$1"
    local label="$2"
    local context="$3"
    local length=$4

    # Build HkdfLabel structure:
    #   uint16 length
    #   opaque label<7..255> = "tls13 " + label
    #   opaque context<0..255>
    local full_label="tls13 ${label}"
    local label_hex
    label_hex=$(ascii_to_hex "$full_label")
    local label_len=$(( ${#label_hex} / 2 ))
    local context_len=$(( ${#context} / 2 ))

    local _hel_u16 _hel_u8a _hel_u8b
    printf -v _hel_u16 '%04x' "$(( length & 0xFFFF ))"
    printf -v _hel_u8a '%02x' "$(( label_len & 0xFF ))"
    printf -v _hel_u8b '%02x' "$(( context_len & 0xFF ))"

    local hkdf_label="${_hel_u16}${_hel_u8a}${label_hex}${_hel_u8b}${context}"

    hkdf_expand "$secret" "$hkdf_label" "$length"
}

# derive_secret <secret_hex> <label_ascii> <messages_hex>
# TLS 1.3 Derive-Secret (RFC 8446 Section 7.1)
# Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length)
derive_secret() {
    local secret="$1"
    local label="$2"
    local messages="$3"

    local transcript_hash
    transcript_hash=$(sha256 "$messages")
    hkdf_expand_label "$secret" "$label" "$transcript_hash" 32
}
