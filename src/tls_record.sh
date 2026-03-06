#!/usr/bin/env bash
# tls_record.sh - TLS 1.3 record layer
# Handles record framing, encryption, and decryption.
# Requires: hex.sh, bytes.sh, gcm.sh

# TLS content types
TLS_CT_CHANGE_CIPHER=20
TLS_CT_ALERT=21
TLS_CT_HANDSHAKE=22
TLS_CT_APPLICATION_DATA=23

# TLS record version (always 0x0303 = TLS 1.2 for compat)
TLS_RECORD_VERSION="0303"

# Maximum plaintext record size
TLS_MAX_PLAINTEXT=16384

# Record encryption state
_tls_write_key=""
_tls_write_iv=""
_tls_write_seq=0
_tls_read_key=""
_tls_read_iv=""
_tls_read_seq=0
_tls_encrypted=0

# tls_record_set_write_keys <key_hex> <iv_hex>
tls_record_set_write_keys() {
    _tls_write_key="$1"
    _tls_write_iv="$2"
    _tls_write_seq=0
}

# tls_record_set_read_keys <key_hex> <iv_hex>
tls_record_set_read_keys() {
    _tls_read_key="$1"
    _tls_read_iv="$2"
    _tls_read_seq=0
}

# tls_record_enable_encryption
tls_record_enable_encryption() {
    _tls_encrypted=1
}

# _tls_make_nonce <iv_hex> <seq_num> - Construct per-record nonce
# nonce = iv XOR (sequence number left-padded to 12 bytes)
_tls_make_nonce() {
    local iv="$1"
    local seq=$2
    local seq_hex
    seq_hex=$(printf '%024x' "$seq")  # 12 bytes = 24 hex chars
    hex_xor "$iv" "$seq_hex"
}

# tls_record_send <content_type_int> <payload_hex>
# Send a TLS record. If encryption is enabled, encrypts with AES-128-GCM.
tls_record_send() {
    local ct=$1
    local payload="$2"

    if [ "$_tls_encrypted" -eq 1 ]; then
        # TLS 1.3 encrypted record: append actual content type to plaintext
        local inner_plaintext="${payload}$(uint8_to_hex "$ct")"

        # Construct nonce
        local nonce
        nonce=$(_tls_make_nonce "$_tls_write_iv" "$_tls_write_seq")

        # AAD = record header (with outer content type = application_data)
        local inner_len=$(( ${#inner_plaintext} / 2 ))
        local ct_len=$((inner_len + 16))  # ciphertext + 16-byte tag
        local aad="$(uint8_to_hex $TLS_CT_APPLICATION_DATA)${TLS_RECORD_VERSION}$(uint16_to_hex "$ct_len")"

        # Encrypt
        local result
        result=$(gcm_encrypt "$_tls_write_key" "$nonce" "$inner_plaintext" "$aad")
        local ciphertext="${result%% *}"
        local tag="${result##* }"

        # Send record: header + ciphertext + tag
        local record="${aad}${ciphertext}${tag}"
        tcp_send_hex "$record"

        _tls_write_seq=$((_tls_write_seq + 1))
    else
        # Plaintext record
        local payload_len=$(( ${#payload} / 2 ))
        local header="$(uint8_to_hex "$ct")${TLS_RECORD_VERSION}$(uint16_to_hex "$payload_len")"
        tcp_send_hex "${header}${payload}"
    fi
}

# tls_record_recv - Receive one TLS record
# Sets globals: _tls_recv_ct (content type), _tls_recv_payload (hex payload)
tls_record_recv() {
    # Read 5-byte header: content_type(1) + version(2) + length(2)
    local header
    header=$(tcp_recv_hex 5)
    _tls_recv_ct=$((16#${header:0:2}))
    local version="${header:2:4}"
    local length=$((16#${header:6:4}))

    # Read fragment
    local fragment
    fragment=$(tcp_recv_hex "$length")

    if [ "$_tls_encrypted" -eq 1 ] && [ "$_tls_recv_ct" -eq "$TLS_CT_APPLICATION_DATA" ]; then
        # Decrypt TLS 1.3 encrypted record
        local ct_len=$((length - 16))  # subtract 16-byte tag
        local ciphertext="${fragment:0:$((ct_len * 2))}"
        local tag="${fragment:$((ct_len * 2)):32}"

        # AAD = received record header
        local aad="${header}"

        # Construct nonce
        local nonce
        nonce=$(_tls_make_nonce "$_tls_read_iv" "$_tls_read_seq")

        # Decrypt
        local plaintext
        plaintext=$(gcm_decrypt "$_tls_read_key" "$nonce" "$ciphertext" "$aad" "$tag")
        if [ $? -ne 0 ]; then
            printf 'ERROR: record decryption failed (bad tag)\n' >&2
            return 1
        fi

        _tls_read_seq=$((_tls_read_seq + 1))

        # Inner content type is the last byte of plaintext
        # Strip padding zeros and find actual content type
        local pt_len=${#plaintext}
        while [ $pt_len -gt 0 ]; do
            local last_byte="${plaintext:$((pt_len - 2)):2}"
            if [ "$last_byte" != "00" ]; then
                _tls_recv_ct=$((16#$last_byte))
                _tls_recv_payload="${plaintext:0:$((pt_len - 2))}"
                return 0
            fi
            pt_len=$((pt_len - 2))
        done
        printf 'ERROR: no content type in decrypted record\n' >&2
        return 1
    else
        _tls_recv_payload="$fragment"
    fi
}
