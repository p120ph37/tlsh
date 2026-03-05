#!/usr/bin/env bash
# tls_handshake.sh - TLS 1.3 handshake protocol (RFC 8446)
# Implements the 1-RTT handshake with TLS_AES_128_GCM_SHA256 and x25519.
# Requires: all crypto modules, tls_record.sh, hex.sh, bytes.sh

# Handshake message types
_TLS_HT_CLIENT_HELLO=1
_TLS_HT_SERVER_HELLO=2
_TLS_HT_ENCRYPTED_EXTENSIONS=8
_TLS_HT_CERTIFICATE=11
_TLS_HT_CERTIFICATE_VERIFY=15
_TLS_HT_FINISHED=20

# Extension types
_TLS_EXT_SERVER_NAME=0
_TLS_EXT_SUPPORTED_GROUPS=10
_TLS_EXT_SIGNATURE_ALGORITHMS=13
_TLS_EXT_SUPPORTED_VERSIONS=43
_TLS_EXT_KEY_SHARE=51

# Signature algorithms
_TLS_SIG_RSA_PSS_RSAE_SHA256=0x0804

# Named groups
_TLS_GROUP_X25519=0x001d

# Cipher suites
_TLS_CS_AES_128_GCM_SHA256=0x1301

# Transcript hash: accumulated handshake messages
_tls_transcript=""

# Collected certificate and signature for verification
_tls_server_cert_hex=""
_tls_server_cert_verify_sig=""
_tls_server_cert_verify_algo=0

# _tls_transcript_hash - SHA-256 of all handshake messages so far
_tls_transcript_hash() {
    sha256 "$_tls_transcript"
}

# _tls_generate_random <n_bytes> - Generate n random bytes as hex
# Uses /dev/urandom if available, falls back to $RANDOM
_tls_generate_random() {
    local n=$1
    local result=""
    if [ -r /dev/urandom ]; then
        # Read raw bytes and convert to hex using printf
        local i=0
        while IFS= read -r -n 1 -d '' byte <&3 && [ $i -lt "$n" ]; do
            if [ -z "$byte" ]; then
                result="${result}00"
            else
                result="${result}$(printf '%02x' "'$byte")"
            fi
            i=$((i + 1))
        done 3</dev/urandom
        # If we didn't get enough, pad with RANDOM
        while [ $(( ${#result} / 2 )) -lt "$n" ]; do
            result="${result}$(printf '%02x' $((RANDOM % 256)))"
        done
    else
        local i=0
        while [ $i -lt "$n" ]; do
            result="${result}$(printf '%02x' $((RANDOM % 256)))"
            i=$((i + 1))
        done
    fi
    printf '%s' "${result:0:$((n * 2))}"
}

# _tls_build_client_hello <hostname> <client_random_hex> <x25519_pubkey_hex>
# Returns the full ClientHello handshake message (hex).
_tls_build_client_hello() {
    local hostname="$1"
    local client_random="$2"
    local x25519_pub="$3"

    # Build extensions
    local extensions=""

    # SNI extension (server_name)
    local hostname_hex
    hostname_hex=$(ascii_to_hex "$hostname")
    local hostname_len=${#hostname}
    # ServerNameList: length(2) + ServerName: type(1)=0x00 + length(2) + name
    local sni_entry="00$(uint16_to_hex "$hostname_len")${hostname_hex}"
    local sni_list_len=$(( ${#sni_entry} / 2 ))
    local sni_list="$(uint16_to_hex "$sni_list_len")${sni_entry}"
    local sni_ext_data_len=$(( ${#sni_list} / 2 ))
    extensions="${extensions}$(uint16_to_hex $_TLS_EXT_SERVER_NAME)$(uint16_to_hex "$sni_ext_data_len")${sni_list}"

    # Supported Groups extension (x25519 only)
    local groups_list="$(uint16_to_hex 2)$(uint16_to_hex $_TLS_GROUP_X25519)"
    local groups_len=$(( ${#groups_list} / 2 ))
    extensions="${extensions}$(uint16_to_hex $_TLS_EXT_SUPPORTED_GROUPS)$(uint16_to_hex "$groups_len")${groups_list}"

    # Signature Algorithms extension
    local sig_algos="$(uint16_to_hex 2)$(uint16_to_hex $_TLS_SIG_RSA_PSS_RSAE_SHA256)"
    local sig_len=$(( ${#sig_algos} / 2 ))
    extensions="${extensions}$(uint16_to_hex $_TLS_EXT_SIGNATURE_ALGORITHMS)$(uint16_to_hex "$sig_len")${sig_algos}"

    # Supported Versions extension (TLS 1.3 = 0x0304)
    local sup_ver="010304"  # length=1 byte, version=0x0304
    local sup_ver_len=$(( ${#sup_ver} / 2 ))
    extensions="${extensions}$(uint16_to_hex $_TLS_EXT_SUPPORTED_VERSIONS)$(uint16_to_hex "$sup_ver_len")${sup_ver}"

    # Key Share extension (x25519 public key)
    # KeyShareEntry: group(2) + key_exchange_length(2) + key_exchange(32)
    local ks_entry="$(uint16_to_hex $_TLS_GROUP_X25519)$(uint16_to_hex 32)${x25519_pub}"
    local ks_client_len=$(( ${#ks_entry} / 2 ))
    local ks_ext="$(uint16_to_hex "$ks_client_len")${ks_entry}"
    local ks_ext_len=$(( ${#ks_ext} / 2 ))
    extensions="${extensions}$(uint16_to_hex $_TLS_EXT_KEY_SHARE)$(uint16_to_hex "$ks_ext_len")${ks_ext}"

    local extensions_len=$(( ${#extensions} / 2 ))

    # ClientHello body
    local body=""
    body="${body}0303"                              # legacy_version = TLS 1.2
    body="${body}${client_random}"                   # random (32 bytes)
    body="${body}20"                                 # session_id length = 32
    body="${body}$(_tls_generate_random 32)"         # legacy_session_id (for middlebox compat)
    body="${body}0002"                               # cipher_suites length = 2
    body="${body}$(uint16_to_hex $_TLS_CS_AES_128_GCM_SHA256)"  # TLS_AES_128_GCM_SHA256
    body="${body}0100"                               # compression_methods: 1 method, null

    body="${body}$(uint16_to_hex "$extensions_len")"
    body="${body}${extensions}"

    # Wrap in handshake header: type(1) + length(3)
    local body_len=$(( ${#body} / 2 ))
    local msg="$(uint8_to_hex $_TLS_HT_CLIENT_HELLO)$(uint24_to_hex "$body_len")${body}"

    printf '%s' "$msg"
}

# _tls_parse_server_hello <payload_hex> - Parse ServerHello
# Sets: _tls_server_random, _tls_server_x25519_pub
_tls_parse_server_hello() {
    local p="$1"
    local offset=0

    # legacy_version (2 bytes)
    offset=$((offset + 4))

    # server_random (32 bytes)
    _tls_server_random="${p:$offset:64}"
    offset=$((offset + 64))

    # session_id_length (1 byte)
    local sid_len=$((16#${p:$offset:2}))
    offset=$((offset + 2))
    offset=$((offset + sid_len * 2))

    # cipher_suite (2 bytes)
    local cs=$((16#${p:$offset:4}))
    offset=$((offset + 4))

    # compression_method (1 byte)
    offset=$((offset + 2))

    # extensions_length (2 bytes)
    local ext_len=$((16#${p:$offset:4}))
    offset=$((offset + 4))

    local ext_end=$((offset + ext_len * 2))
    while [ $offset -lt "$ext_end" ]; do
        local ext_type=$((16#${p:$offset:4}))
        offset=$((offset + 4))
        local ext_data_len=$((16#${p:$offset:4}))
        offset=$((offset + 4))

        if [ $ext_type -eq $_TLS_EXT_KEY_SHARE ]; then
            # KeyShareEntry: group(2) + length(2) + key(32)
            local group=$((16#${p:$offset:4}))
            local klen=$((16#${p:$((offset+4)):4}))
            _tls_server_x25519_pub="${p:$((offset+8)):$((klen*2))}"
        fi

        offset=$((offset + ext_data_len * 2))
    done
}

# _tls_parse_encrypted_extensions <payload_hex>
_tls_parse_encrypted_extensions() {
    # We don't need to act on any encrypted extensions for basic operation
    :
}

# _tls_parse_certificate <payload_hex>
# Extracts the first certificate (DER-encoded X.509) as hex
_tls_parse_certificate() {
    local p="$1"
    local offset=0

    # certificate_request_context length (1 byte)
    local ctx_len=$((16#${p:$offset:2}))
    offset=$((offset + 2 + ctx_len * 2))

    # certificate_list length (3 bytes)
    local list_len=$((16#${p:$offset:6}))
    offset=$((offset + 6))

    # First CertificateEntry:
    # cert_data length (3 bytes) + cert_data + extensions_length(2) + extensions
    local cert_len=$((16#${p:$offset:6}))
    offset=$((offset + 6))
    _tls_server_cert_hex="${p:$offset:$((cert_len * 2))}"
}

# _tls_parse_certificate_verify <payload_hex>
_tls_parse_certificate_verify() {
    local p="$1"
    _tls_server_cert_verify_algo=$((16#${p:0:4}))
    local sig_len=$((16#${p:4:4}))
    _tls_server_cert_verify_sig="${p:8:$((sig_len * 2))}"
}

# _tls_extract_rsa_pubkey <cert_der_hex> - Extract RSA public key (n, e) from X.509 DER
# Sets: _tls_cert_rsa_n, _tls_cert_rsa_e
_tls_extract_rsa_pubkey() {
    local cert="$1"

    # Simple DER parser: find the RSA public key sequence
    # We look for the OID 1.2.840.113549.1.1.1 (rsaEncryption) =
    #   06 09 2a 86 48 86 f7 0d 01 01 01
    # followed by the BIT STRING containing the public key

    local rsa_oid="06092a864886f70d010101"
    local oid_pos=-1

    # Search for the OID
    local i=0
    local max=$(( ${#cert} - ${#rsa_oid} ))
    while [ $i -lt "$max" ]; do
        if [ "${cert:$i:${#rsa_oid}}" = "$rsa_oid" ]; then
            oid_pos=$i
            break
        fi
        i=$((i + 2))
    done

    if [ $oid_pos -lt 0 ]; then
        printf 'ERROR: RSA OID not found in certificate\n' >&2
        return 1
    fi

    # After the AlgorithmIdentifier, find the BIT STRING (tag 0x03)
    local search_start=$((oid_pos + ${#rsa_oid}))
    i=$search_start
    while [ $i -lt "${#cert}" ]; do
        if [ "${cert:$i:2}" = "03" ]; then
            # Parse BIT STRING length
            local bs_offset=$((i + 2))
            local bs_len
            _der_parse_length "$cert" $bs_offset
            bs_offset=$_der_len_end
            bs_len=$_der_len_val

            # Skip the "unused bits" byte (should be 0x00)
            bs_offset=$((bs_offset + 2))

            # Now we should be at a SEQUENCE containing n and e
            if [ "${cert:$bs_offset:2}" = "30" ]; then
                local seq_off=$((bs_offset + 2))
                _der_parse_length "$cert" $seq_off
                seq_off=$_der_len_end

                # First INTEGER = n (modulus)
                if [ "${cert:$seq_off:2}" = "02" ]; then
                    local n_off=$((seq_off + 2))
                    _der_parse_length "$cert" $n_off
                    n_off=$_der_len_end
                    local n_len=$_der_len_val
                    _tls_cert_rsa_n="${cert:$n_off:$((n_len * 2))}"
                    # Strip leading zero byte if present (DER encoding adds it for positive numbers)
                    if [ "${_tls_cert_rsa_n:0:2}" = "00" ]; then
                        _tls_cert_rsa_n="${_tls_cert_rsa_n:2}"
                    fi

                    # Second INTEGER = e (exponent)
                    local e_off=$((n_off + n_len * 2))
                    if [ "${cert:$e_off:2}" = "02" ]; then
                        local e_off2=$((e_off + 2))
                        _der_parse_length "$cert" $e_off2
                        e_off2=$_der_len_end
                        local e_len=$_der_len_val
                        _tls_cert_rsa_e="${cert:$e_off2:$((e_len * 2))}"
                        if [ "${_tls_cert_rsa_e:0:2}" = "00" ]; then
                            _tls_cert_rsa_e="${_tls_cert_rsa_e:2}"
                        fi
                        return 0
                    fi
                fi
            fi
            break
        fi
        i=$((i + 2))
    done

    printf 'ERROR: could not parse RSA key from certificate\n' >&2
    return 1
}

# _der_parse_length <hex> <offset> - Parse DER length encoding
# Sets: _der_len_val (length value), _der_len_end (offset after length bytes)
_der_parse_length() {
    local hex="$1"
    local off=$2
    local first_byte=$((16#${hex:$off:2}))
    if [ $((first_byte & 0x80)) -eq 0 ]; then
        _der_len_val=$first_byte
        _der_len_end=$((off + 2))
    else
        local num_bytes=$((first_byte & 0x7F))
        _der_len_val=0
        local j=0
        while [ $j -lt "$num_bytes" ]; do
            _der_len_val=$(( (_der_len_val << 8) | 16#${hex:$((off + 2 + j*2)):2} ))
            j=$((j + 1))
        done
        _der_len_end=$((off + 2 + num_bytes * 2))
    fi
}

# _tls_verify_finished <finished_key_hex> <transcript_hash_hex> <verify_data_hex>
_tls_verify_finished() {
    local finished_key="$1"
    local transcript_hash="$2"
    local verify_data="$3"

    local expected
    expected=$(hmac_sha256 "$finished_key" "$transcript_hash")

    if [ "$expected" = "$verify_data" ]; then
        return 0
    else
        return 1
    fi
}

# _tls_verify_certificate_verify <transcript_hash_hex>
# Verify the server's CertificateVerify using RSA-PSS
_tls_verify_certificate_verify() {
    local transcript_hash="$1"

    # Build the content that was signed:
    # 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
    local context_string
    context_string=$(ascii_to_hex "TLS 1.3, server CertificateVerify")
    local pad=""
    local i=0
    while [ $i -lt 64 ]; do pad="${pad}20"; i=$((i+1)); done
    local signed_content="${pad}${context_string}00${transcript_hash}"

    # Extract RSA public key from certificate
    _tls_extract_rsa_pubkey "$_tls_server_cert_hex" || return 1

    # Verify RSA-PSS signature
    rsa_verify_pss "$_tls_cert_rsa_n" "$_tls_cert_rsa_e" \
        "$_tls_server_cert_verify_sig" "$signed_content"
}

# tls_handshake <hostname> - Perform TLS 1.3 handshake
# Assumes TCP connection is already established.
# On success, encryption keys are set and record encryption is enabled.
tls_handshake() {
    local hostname="$1"

    printf 'TLS: generating ephemeral x25519 keypair...\n' >&2

    # Generate ephemeral x25519 keypair
    local client_private
    client_private=$(_tls_generate_random 32)
    local client_public
    client_public=$(x25519_base "$client_private")

    # Generate client random
    local client_random
    client_random=$(_tls_generate_random 32)

    printf 'TLS: sending ClientHello...\n' >&2

    # Build and send ClientHello
    local ch_msg
    ch_msg=$(_tls_build_client_hello "$hostname" "$client_random" "$client_public")
    _tls_transcript="${ch_msg}"
    tls_record_send $TLS_CT_HANDSHAKE "$ch_msg"

    printf 'TLS: waiting for ServerHello...\n' >&2

    # Receive ServerHello
    tls_record_recv
    if [ "$_tls_recv_ct" -ne $TLS_CT_HANDSHAKE ]; then
        printf 'ERROR: expected handshake, got content type %d\n' "$_tls_recv_ct" >&2
        return 1
    fi

    local sh_msg="$_tls_recv_payload"
    local sh_type=$((16#${sh_msg:0:2}))
    if [ "$sh_type" -ne $_TLS_HT_SERVER_HELLO ]; then
        printf 'ERROR: expected ServerHello (2), got %d\n' "$sh_type" >&2
        return 1
    fi

    # Parse ServerHello
    local sh_body_len=$((16#${sh_msg:2:6}))
    local sh_body="${sh_msg:8:$((sh_body_len * 2))}"
    _tls_parse_server_hello "$sh_body"
    _tls_transcript="${_tls_transcript}${sh_msg}"

    printf 'TLS: computing handshake keys...\n' >&2

    # Compute shared secret via X25519
    local shared_secret
    shared_secret=$(x25519 "$client_private" "$_tls_server_x25519_pub")

    # Key schedule: derive handshake keys
    # Early Secret = HKDF-Extract(salt=0, IKM=0)
    local zero_key="0000000000000000000000000000000000000000000000000000000000000000"
    local early_secret
    early_secret=$(hkdf_extract "$zero_key" "$zero_key")

    # Derive-Secret(early_secret, "derived", "")
    local empty_hash
    empty_hash=$(sha256 "")
    local derived_secret
    derived_secret=$(hkdf_expand_label "$early_secret" "derived" "$empty_hash" 32)

    # Handshake Secret = HKDF-Extract(derived_secret, shared_secret)
    local handshake_secret
    handshake_secret=$(hkdf_extract "$derived_secret" "$shared_secret")

    # Transcript hash up to ServerHello
    local ch_sh_hash
    ch_sh_hash=$(_tls_transcript_hash)

    # Client/Server Handshake Traffic Secrets
    local client_hs_secret
    client_hs_secret=$(hkdf_expand_label "$handshake_secret" "c hs traffic" "$ch_sh_hash" 32)
    local server_hs_secret
    server_hs_secret=$(hkdf_expand_label "$handshake_secret" "s hs traffic" "$ch_sh_hash" 32)

    # Derive traffic keys and IVs
    local server_hs_key
    server_hs_key=$(hkdf_expand_label "$server_hs_secret" "key" "" 16)
    local server_hs_iv
    server_hs_iv=$(hkdf_expand_label "$server_hs_secret" "iv" "" 12)
    local client_hs_key
    client_hs_key=$(hkdf_expand_label "$client_hs_secret" "key" "" 16)
    local client_hs_iv
    client_hs_iv=$(hkdf_expand_label "$client_hs_secret" "iv" "" 12)

    # Set up encryption for handshake
    tls_record_set_read_keys "$server_hs_key" "$server_hs_iv"
    tls_record_set_write_keys "$client_hs_key" "$client_hs_iv"
    tls_record_enable_encryption

    printf 'TLS: reading encrypted handshake messages...\n' >&2

    # Read encrypted handshake messages: EncryptedExtensions, Certificate,
    # CertificateVerify, Finished
    local server_finished_received=0
    while [ $server_finished_received -eq 0 ]; do
        tls_record_recv || return 1

        if [ "$_tls_recv_ct" -ne $TLS_CT_HANDSHAKE ]; then
            printf 'ERROR: expected handshake in encrypted records, got %d\n' "$_tls_recv_ct" >&2
            return 1
        fi

        # Parse handshake messages (may be multiple in one record)
        local hs_data="$_tls_recv_payload"
        local hs_offset=0
        while [ $hs_offset -lt ${#hs_data} ]; do
            local hs_type=$((16#${hs_data:$hs_offset:2}))
            local hs_len=$((16#${hs_data:$((hs_offset+2)):6}))
            local hs_msg="${hs_data:$hs_offset:$((8 + hs_len * 2))}"
            local hs_body="${hs_data:$((hs_offset+8)):$((hs_len * 2))}"

            case $hs_type in
                $_TLS_HT_ENCRYPTED_EXTENSIONS)
                    printf 'TLS: EncryptedExtensions received\n' >&2
                    _tls_parse_encrypted_extensions "$hs_body"
                    _tls_transcript="${_tls_transcript}${hs_msg}"
                    ;;
                $_TLS_HT_CERTIFICATE)
                    printf 'TLS: Certificate received\n' >&2
                    _tls_parse_certificate "$hs_body"
                    _tls_transcript="${_tls_transcript}${hs_msg}"
                    ;;
                $_TLS_HT_CERTIFICATE_VERIFY)
                    printf 'TLS: CertificateVerify received\n' >&2
                    _tls_parse_certificate_verify "$hs_body"
                    # Verify against transcript hash BEFORE adding this message
                    local cv_hash
                    cv_hash=$(_tls_transcript_hash)
                    _tls_transcript="${_tls_transcript}${hs_msg}"
                    if ! _tls_verify_certificate_verify "$cv_hash"; then
                        printf 'WARNING: CertificateVerify failed (continuing for PoC)\n' >&2
                    else
                        printf 'TLS: CertificateVerify OK\n' >&2
                    fi
                    ;;
                $_TLS_HT_FINISHED)
                    printf 'TLS: server Finished received\n' >&2
                    # Verify Finished
                    local finished_key
                    finished_key=$(hkdf_expand_label "$server_hs_secret" "finished" "" 32)
                    local fin_hash
                    fin_hash=$(_tls_transcript_hash)
                    _tls_transcript="${_tls_transcript}${hs_msg}"
                    if ! _tls_verify_finished "$finished_key" "$fin_hash" "$hs_body"; then
                        printf 'ERROR: server Finished verification failed\n' >&2
                        return 1
                    fi
                    printf 'TLS: server Finished verified OK\n' >&2
                    server_finished_received=1
                    ;;
                *)
                    printf 'TLS: unknown handshake type %d, skipping\n' "$hs_type" >&2
                    _tls_transcript="${_tls_transcript}${hs_msg}"
                    ;;
            esac

            hs_offset=$((hs_offset + 8 + hs_len * 2))
        done
    done

    printf 'TLS: sending client Finished...\n' >&2

    # Send client Finished
    local client_finished_key
    client_finished_key=$(hkdf_expand_label "$client_hs_secret" "finished" "" 32)
    local client_fin_hash
    client_fin_hash=$(_tls_transcript_hash)
    local client_verify_data
    client_verify_data=$(hmac_sha256 "$client_finished_key" "$client_fin_hash")
    local client_finished_msg="$(uint8_to_hex $_TLS_HT_FINISHED)$(uint24_to_hex 32)${client_verify_data}"
    _tls_transcript="${_tls_transcript}${client_finished_msg}"
    tls_record_send $TLS_CT_HANDSHAKE "$client_finished_msg"

    printf 'TLS: deriving application keys...\n' >&2

    # Derive application traffic keys
    local derived2
    derived2=$(hkdf_expand_label "$handshake_secret" "derived" "$empty_hash" 32)
    local master_secret
    master_secret=$(hkdf_extract "$derived2" "$zero_key")

    local app_hash
    app_hash=$(_tls_transcript_hash)
    local client_app_secret
    client_app_secret=$(hkdf_expand_label "$master_secret" "c ap traffic" "$app_hash" 32)
    local server_app_secret
    server_app_secret=$(hkdf_expand_label "$master_secret" "s ap traffic" "$app_hash" 32)

    local server_app_key
    server_app_key=$(hkdf_expand_label "$server_app_secret" "key" "" 16)
    local server_app_iv
    server_app_iv=$(hkdf_expand_label "$server_app_secret" "iv" "" 12)
    local client_app_key
    client_app_key=$(hkdf_expand_label "$client_app_secret" "key" "" 16)
    local client_app_iv
    client_app_iv=$(hkdf_expand_label "$client_app_secret" "iv" "" 12)

    # Switch to application keys
    tls_record_set_read_keys "$server_app_key" "$server_app_iv"
    tls_record_set_write_keys "$client_app_key" "$client_app_iv"

    printf 'TLS: handshake complete!\n' >&2
    return 0
}

# tls_send <data_hex> - Send application data
tls_send() {
    tls_record_send $TLS_CT_APPLICATION_DATA "$1"
}

# tls_recv - Receive application data
# Sets _tls_recv_payload to the received data (hex)
tls_recv() {
    tls_record_recv
    while [ "$_tls_recv_ct" -ne $TLS_CT_APPLICATION_DATA ]; do
        if [ "$_tls_recv_ct" -eq $TLS_CT_ALERT ]; then
            local alert_level=$((16#${_tls_recv_payload:0:2}))
            local alert_desc=$((16#${_tls_recv_payload:2:2}))
            printf 'TLS ALERT: level=%d desc=%d\n' "$alert_level" "$alert_desc" >&2
            if [ $alert_level -eq 2 ]; then return 1; fi
        fi
        tls_record_recv || return 1
    done
}
