#!/usr/bin/env bash
# chacha20poly1305.sh - ChaCha20-Poly1305 AEAD (RFC 8439)
# Pure shell implementation using only 32-bit arithmetic.
#
# ChaCha20 uses add/xor/rotate on 32-bit words (no S-box, no GF multiply).
# Poly1305 uses 130-bit modular arithmetic with 5 × 26-bit limbs.
# Both are significantly cheaper in shell than AES-GCM.

# _chacha20_quarter_round - Quarter round on state words a,b,c,d
# Modifies _cc state array at indices $1,$2,$3,$4
# Rotation is inlined to avoid function call overhead (32 calls per block).
_chacha20_quarter_round() {
    local ai=$1 bi=$2 ci=$3 di=$4
    local a=${_cc[$ai]} b=${_cc[$bi]} c=${_cc[$ci]} d=${_cc[$di]}

    a=$(( (a + b) & 0xFFFFFFFF )); d=$((d ^ a))
    d=$(( ((d << 16) | ((d >> 16) & 0xFFFF)) & 0xFFFFFFFF ))
    c=$(( (c + d) & 0xFFFFFFFF )); b=$((b ^ c))
    b=$(( ((b << 12) | ((b >> 20) & 0xFFF)) & 0xFFFFFFFF ))
    a=$(( (a + b) & 0xFFFFFFFF )); d=$((d ^ a))
    d=$(( ((d << 8) | ((d >> 24) & 0xFF)) & 0xFFFFFFFF ))
    c=$(( (c + d) & 0xFFFFFFFF )); b=$((b ^ c))
    b=$(( ((b << 7) | ((b >> 25) & 0x7F)) & 0xFFFFFFFF ))

    _cc[$ai]=$a; _cc[$bi]=$b; _cc[$ci]=$c; _cc[$di]=$d
}

# _chacha20_block <key_hex_64> <counter_int> <nonce_hex_24>
# Generates one 64-byte keystream block. Result in _cc20_block (128 hex chars).
_chacha20_block() {
    local key="$1"
    local counter=$2
    local nonce="$3"

    # Initialize state: constants, key, counter, nonce
    # "expand 32-byte k" = 0x61707865 0x3320646e 0x79622d32 0x6b206574
    local s0=0x61707865 s1=0x3320646e s2=0x79622d32 s3=0x6b206574
    # Key (8 words, little-endian)
    local s4 s5 s6 s7 s8 s9 s10 s11
    s4=$(( 16#${key:6:2}${key:4:2}${key:2:2}${key:0:2} ))
    s5=$(( 16#${key:14:2}${key:12:2}${key:10:2}${key:8:2} ))
    s6=$(( 16#${key:22:2}${key:20:2}${key:18:2}${key:16:2} ))
    s7=$(( 16#${key:30:2}${key:28:2}${key:26:2}${key:24:2} ))
    s8=$(( 16#${key:38:2}${key:36:2}${key:34:2}${key:32:2} ))
    s9=$(( 16#${key:46:2}${key:44:2}${key:42:2}${key:40:2} ))
    s10=$(( 16#${key:54:2}${key:52:2}${key:50:2}${key:48:2} ))
    s11=$(( 16#${key:62:2}${key:60:2}${key:58:2}${key:56:2} ))
    # Counter (1 word)
    local s12=$counter
    # Nonce (3 words, little-endian)
    local s13 s14 s15
    s13=$(( 16#${nonce:6:2}${nonce:4:2}${nonce:2:2}${nonce:0:2} ))
    s14=$(( 16#${nonce:14:2}${nonce:12:2}${nonce:10:2}${nonce:8:2} ))
    s15=$(( 16#${nonce:22:2}${nonce:20:2}${nonce:18:2}${nonce:16:2} ))

    # Working state
    _cc=($s0 $s1 $s2 $s3 $s4 $s5 $s6 $s7 $s8 $s9 $s10 $s11 $s12 $s13 $s14 $s15)

    # 20 rounds (10 double rounds)
    local round=0
    while [ $round -lt 10 ]; do
        # Column rounds
        _chacha20_quarter_round 0 4 8 12
        _chacha20_quarter_round 1 5 9 13
        _chacha20_quarter_round 2 6 10 14
        _chacha20_quarter_round 3 7 11 15
        # Diagonal rounds
        _chacha20_quarter_round 0 5 10 15
        _chacha20_quarter_round 1 6 11 12
        _chacha20_quarter_round 2 7 8 13
        _chacha20_quarter_round 3 4 9 14
        round=$((round + 1))
    done

    # Add original state
    _cc[0]=$(( (${_cc[0]} + s0) & 0xFFFFFFFF ))
    _cc[1]=$(( (${_cc[1]} + s1) & 0xFFFFFFFF ))
    _cc[2]=$(( (${_cc[2]} + s2) & 0xFFFFFFFF ))
    _cc[3]=$(( (${_cc[3]} + s3) & 0xFFFFFFFF ))
    _cc[4]=$(( (${_cc[4]} + s4) & 0xFFFFFFFF ))
    _cc[5]=$(( (${_cc[5]} + s5) & 0xFFFFFFFF ))
    _cc[6]=$(( (${_cc[6]} + s6) & 0xFFFFFFFF ))
    _cc[7]=$(( (${_cc[7]} + s7) & 0xFFFFFFFF ))
    _cc[8]=$(( (${_cc[8]} + s8) & 0xFFFFFFFF ))
    _cc[9]=$(( (${_cc[9]} + s9) & 0xFFFFFFFF ))
    _cc[10]=$(( (${_cc[10]} + s10) & 0xFFFFFFFF ))
    _cc[11]=$(( (${_cc[11]} + s11) & 0xFFFFFFFF ))
    _cc[12]=$(( (${_cc[12]} + s12) & 0xFFFFFFFF ))
    _cc[13]=$(( (${_cc[13]} + s13) & 0xFFFFFFFF ))
    _cc[14]=$(( (${_cc[14]} + s14) & 0xFFFFFFFF ))
    _cc[15]=$(( (${_cc[15]} + s15) & 0xFFFFFFFF ))

    # Serialize to little-endian hex
    _cc20_block=""
    local wi=0
    local _cc_tmp
    while [ $wi -lt 16 ]; do
        local w=${_cc[$wi]}
        printf -v _cc_tmp '%02x%02x%02x%02x' $((w & 0xFF)) $(((w >> 8) & 0xFF)) $(((w >> 16) & 0xFF)) $(((w >> 24) & 0xFF))
        _cc20_block="${_cc20_block}${_cc_tmp}"
        wi=$((wi + 1))
    done
}

# chacha20_encrypt <key_hex_64> <nonce_hex_24> <counter_int> <plaintext_hex>
# Returns ciphertext hex.
chacha20_encrypt() {
    local key="$1"
    local nonce="$2"
    local counter=$3
    local pt="$4"
    local pt_len=${#pt}
    local result=""
    local offset=0

    while [ $offset -lt "$pt_len" ]; do
        _chacha20_block "$key" "$counter" "$nonce"
        local block_hex=${pt:$offset:128}
        local block_len=${#block_hex}
        # XOR plaintext with keystream (truncate keystream to block length)
        local ks="${_cc20_block:0:$block_len}"
        result="${result}$(hex_xor "$block_hex" "$ks")"
        counter=$((counter + 1))
        offset=$((offset + 128))
    done
    printf '%s' "$result"
}

# --- Poly1305 MAC ---
# Uses 5 limbs of 26 bits each to represent 130-bit numbers mod 2^130-5.

# poly1305_mac <key_hex_64> <msg_hex> - Compute Poly1305 MAC
# Key: 32 bytes (r in first 16, s in last 16). Returns 16-byte hex tag.
poly1305_mac() {
    local key="$1"
    local msg="$2"

    # Parse r (first 16 bytes, clamped) and s (last 16 bytes) as little-endian
    local r_hex="${key:0:32}"
    local s_hex="${key:32:32}"

    # Clamp r: clear bits 4,8,12,16,20,24,28,32,...,124 (every 4th bit from bit 4)
    # Per RFC 8439: r[3],r[7],r[11],r[15] have top 4 bits cleared;
    # r[4],r[8],r[12] have bottom 2 bits cleared
    local r0=$((16#${r_hex:0:2}))
    local r1=$((16#${r_hex:2:2}))
    local r2=$((16#${r_hex:4:2}))
    local r3=$(( 16#${r_hex:6:2} & 0x0F ))
    local r4=$(( 16#${r_hex:8:2} & 0xFC ))
    local r5=$((16#${r_hex:10:2}))
    local r6=$((16#${r_hex:12:2}))
    local r7=$(( 16#${r_hex:14:2} & 0x0F ))
    local r8=$(( 16#${r_hex:16:2} & 0xFC ))
    local r9=$((16#${r_hex:18:2}))
    local r10=$((16#${r_hex:20:2}))
    local r11=$(( 16#${r_hex:22:2} & 0x0F ))
    local r12=$(( 16#${r_hex:24:2} & 0xFC ))
    local r13=$((16#${r_hex:26:2}))
    local r14=$((16#${r_hex:28:2}))
    local r15=$(( 16#${r_hex:30:2} & 0x0F ))

    # Pack r into 5 × 26-bit limbs (little-endian, 130 bits total)
    local r_val=$(( r0 | (r1 << 8) | (r2 << 16) | (r3 << 24) ))
    local rl0=$(( r_val & 0x3FFFFFF ))
    r_val=$(( (r3 >> 2) | (r4 << 6) | (r5 << 14) | (r6 << 22) ))
    local rl1=$(( r_val & 0x3FFFFFF ))
    r_val=$(( (r6 >> 4) | (r7 << 4) | (r8 << 12) | (r9 << 20) ))
    local rl2=$(( r_val & 0x3FFFFFF ))
    r_val=$(( (r9 >> 6) | (r10 << 2) | (r11 << 10) | (r12 << 18) ))
    local rl3=$(( r_val & 0x3FFFFFF ))
    local rl4=$(( (r12 >> 8) | (r13 << 0) | (r14 << 8) | (r15 << 16) ))

    # Pre-compute r*5 for reduction
    local rl1_5=$((rl1 * 5)) rl2_5=$((rl2 * 5)) rl3_5=$((rl3 * 5)) rl4_5=$((rl4 * 5))

    # Parse s (little-endian 128-bit integer stored as 4 × 32-bit words)
    local s0=$(( 16#${s_hex:6:2}${s_hex:4:2}${s_hex:2:2}${s_hex:0:2} ))
    local s1=$(( 16#${s_hex:14:2}${s_hex:12:2}${s_hex:10:2}${s_hex:8:2} ))
    local s2=$(( 16#${s_hex:22:2}${s_hex:20:2}${s_hex:18:2}${s_hex:16:2} ))
    local s3=$(( 16#${s_hex:30:2}${s_hex:28:2}${s_hex:26:2}${s_hex:24:2} ))

    # Accumulator (5 limbs, initialized to 0)
    local a0=0 a1=0 a2=0 a3=0 a4=0

    local msg_len=${#msg}
    local offset=0

    while [ $offset -lt "$msg_len" ]; do
        # Read up to 16 bytes
        local block="${msg:$offset:32}"
        local block_bytes=$(( ${#block} / 2 ))
        offset=$((offset + 32))

        # Convert block to 5 limbs (little-endian) and add hibit
        local n0=0 n1=0 n2=0 n3=0 n4=0
        local bi=0 bit_pos=0
        while [ $bi -lt "$block_bytes" ]; do
            local byte_val=$((16#${block:$((bi*2)):2}))
            local limb_idx=$((bit_pos / 26))
            local limb_off=$((bit_pos % 26))
            case $limb_idx in
                0) n0=$((n0 | (byte_val << limb_off))) ;;
                1) n1=$((n1 | (byte_val << limb_off))) ;;
                2) n2=$((n2 | (byte_val << limb_off))) ;;
                3) n3=$((n3 | (byte_val << limb_off))) ;;
                4) n4=$((n4 | (byte_val << limb_off))) ;;
            esac
            # Handle byte spanning two limbs
            local remaining=$((26 - limb_off))
            if [ $remaining -lt 8 ]; then
                local next_idx=$((limb_idx + 1))
                local overflow=$((byte_val >> remaining))
                case $next_idx in
                    1) n1=$((n1 | overflow)) ;;
                    2) n2=$((n2 | overflow)) ;;
                    3) n3=$((n3 | overflow)) ;;
                    4) n4=$((n4 | overflow)) ;;
                esac
            fi
            bit_pos=$((bit_pos + 8))
            bi=$((bi + 1))
        done
        # Mask to 26 bits
        n0=$((n0 & 0x3FFFFFF))
        n1=$((n1 & 0x3FFFFFF))
        n2=$((n2 & 0x3FFFFFF))
        n3=$((n3 & 0x3FFFFFF))
        # n4 can be up to 2 bits (128 bits in 4 full limbs + remainder) + hibit
        # Add hibit (2^(block_bytes*8)) if this is a full or partial block
        local hibit_pos=$((block_bytes * 8))
        local hibit_limb=$((hibit_pos / 26))
        local hibit_off=$((hibit_pos % 26))
        case $hibit_limb in
            0) n0=$((n0 | (1 << hibit_off))) ;;
            1) n1=$((n1 | (1 << hibit_off))) ;;
            2) n2=$((n2 | (1 << hibit_off))) ;;
            3) n3=$((n3 | (1 << hibit_off))) ;;
            4) n4=$((n4 | (1 << hibit_off))) ;;
        esac

        # Accumulate: a += n
        a0=$((a0 + n0))
        a1=$((a1 + n1))
        a2=$((a2 + n2))
        a3=$((a3 + n3))
        a4=$((a4 + n4))

        # Multiply: a = a * r mod (2^130 - 5)
        # Since all limbs are uniform 26-bit, no both-odd correction needed
        local t0=$(( a0*rl0 + a1*rl4_5 + a2*rl3_5 + a3*rl2_5 + a4*rl1_5 ))
        local t1=$(( a0*rl1 + a1*rl0 + a2*rl4_5 + a3*rl3_5 + a4*rl2_5 ))
        local t2=$(( a0*rl2 + a1*rl1 + a2*rl0 + a3*rl4_5 + a4*rl3_5 ))
        local t3=$(( a0*rl3 + a1*rl2 + a2*rl1 + a3*rl0 + a4*rl4_5 ))
        local t4=$(( a0*rl4 + a1*rl3 + a2*rl2 + a3*rl1 + a4*rl0 ))

        # Carry chain
        local carry
        carry=$((t0 >> 26)); a0=$((t0 & 0x3FFFFFF)); t1=$((t1 + carry))
        carry=$((t1 >> 26)); a1=$((t1 & 0x3FFFFFF)); t2=$((t2 + carry))
        carry=$((t2 >> 26)); a2=$((t2 & 0x3FFFFFF)); t3=$((t3 + carry))
        carry=$((t3 >> 26)); a3=$((t3 & 0x3FFFFFF)); t4=$((t4 + carry))
        carry=$((t4 >> 26)); a4=$((t4 & 0x3FFFFFF)); a0=$((a0 + carry * 5))
        carry=$((a0 >> 26)); a0=$((a0 & 0x3FFFFFF)); a1=$((a1 + carry))
    done

    # Final reduction mod 2^130 - 5
    local carry
    carry=$((a0 >> 26)); a0=$((a0 & 0x3FFFFFF)); a1=$((a1 + carry))
    carry=$((a1 >> 26)); a1=$((a1 & 0x3FFFFFF)); a2=$((a2 + carry))
    carry=$((a2 >> 26)); a2=$((a2 & 0x3FFFFFF)); a3=$((a3 + carry))
    carry=$((a3 >> 26)); a3=$((a3 & 0x3FFFFFF)); a4=$((a4 + carry))
    carry=$((a4 >> 26)); a4=$((a4 & 0x3FFFFFF)); a0=$((a0 + carry * 5))
    carry=$((a0 >> 26)); a0=$((a0 & 0x3FFFFFF)); a1=$((a1 + carry))

    # Compute a - p (conditional): g = a - (2^130 - 5) = a + 5 - 2^130
    local g0=$((a0 + 5))
    carry=$((g0 >> 26)); g0=$((g0 & 0x3FFFFFF))
    local g1=$((a1 + carry)); carry=$((g1 >> 26)); g1=$((g1 & 0x3FFFFFF))
    local g2=$((a2 + carry)); carry=$((g2 >> 26)); g2=$((g2 & 0x3FFFFFF))
    local g3=$((a3 + carry)); carry=$((g3 >> 26)); g3=$((g3 & 0x3FFFFFF))
    local g4=$((a4 + carry - (1 << 26)))

    # Select: if g4 >= 0 (no borrow), use g; else use a
    # g4 >> 63 gives the sign bit (1 if negative)
    local mask=$(( (g4 >> 63) & 1 ))  # 1 if g4 < 0 (keep a), 0 if g4 >= 0 (use g)
    # mask=1 → use a, mask=0 → use g
    # Construct: result = mask ? a : g  =  a ^ (mask_bits & (a ^ g))
    # But simpler in shell:
    if [ $mask -eq 1 ]; then
        g0=$a0; g1=$a1; g2=$a2; g3=$a3; g4=$a4
    fi

    # Convert 5 limbs to 4 × 32-bit words (little-endian packing)
    # f0..f3 = 128-bit result as 4 × 32-bit LE words
    local f0=$(( (g0 | (g1 << 26)) & 0xFFFFFFFF ))
    local f1=$(( ((g1 >> 6) | (g2 << 20)) & 0xFFFFFFFF ))
    local f2=$(( ((g2 >> 12) | (g3 << 14)) & 0xFFFFFFFF ))
    local f3=$(( ((g3 >> 18) | (g4 << 8)) & 0xFFFFFFFF ))

    # Add s (mod 2^128)
    local c
    f0=$(( f0 + s0 )); c=$(( (f0 >> 32) & 1 )); f0=$(( f0 & 0xFFFFFFFF ))
    f1=$(( f1 + s1 + c )); c=$(( (f1 >> 32) & 1 )); f1=$(( f1 & 0xFFFFFFFF ))
    f2=$(( f2 + s2 + c )); c=$(( (f2 >> 32) & 1 )); f2=$(( f2 & 0xFFFFFFFF ))
    f3=$(( f3 + s3 + c )); f3=$(( f3 & 0xFFFFFFFF ))

    # Output as 16 bytes little-endian
    printf '%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x' \
        $((f0 & 0xFF)) $(((f0 >> 8) & 0xFF)) $(((f0 >> 16) & 0xFF)) $(((f0 >> 24) & 0xFF)) \
        $((f1 & 0xFF)) $(((f1 >> 8) & 0xFF)) $(((f1 >> 16) & 0xFF)) $(((f1 >> 24) & 0xFF)) \
        $((f2 & 0xFF)) $(((f2 >> 8) & 0xFF)) $(((f2 >> 16) & 0xFF)) $(((f2 >> 24) & 0xFF)) \
        $((f3 & 0xFF)) $(((f3 >> 8) & 0xFF)) $(((f3 >> 16) & 0xFF)) $(((f3 >> 24) & 0xFF))
}

# --- ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8) ---

# chacha20poly1305_encrypt <key_hex_64> <nonce_hex_24> <plaintext_hex> <aad_hex>
# Returns: ciphertext_hex followed by 32-char tag_hex, separated by space.
chacha20poly1305_encrypt() {
    local key="$1"
    local nonce="$2"
    local pt="$3"
    local aad="$4"

    # Generate Poly1305 one-time key (counter=0, first 32 bytes)
    _chacha20_block "$key" 0 "$nonce"
    local poly_key="${_cc20_block:0:64}"

    # Encrypt plaintext (counter starts at 1)
    local ct=""
    if [ -n "$pt" ]; then
        ct=$(chacha20_encrypt "$key" "$nonce" 1 "$pt")
    fi

    # Build Poly1305 mac_data: aad || pad16(aad) || ct || pad16(ct) || len_aad_le64 || len_ct_le64
    local aad_len=$(( ${#aad} / 2 ))
    local ct_len=$(( ${#ct} / 2 ))
    local mac_data="$aad"
    # Pad AAD to 16-byte boundary
    local pad=$(( (16 - (aad_len % 16)) % 16 ))
    local pi=0
    while [ $pi -lt "$pad" ]; do mac_data="${mac_data}00"; pi=$((pi+1)); done
    mac_data="${mac_data}${ct}"
    # Pad CT to 16-byte boundary
    pad=$(( (16 - (ct_len % 16)) % 16 ))
    pi=0
    while [ $pi -lt "$pad" ]; do mac_data="${mac_data}00"; pi=$((pi+1)); done
    # Append lengths as 64-bit little-endian
    mac_data="${mac_data}$(printf '%02x%02x%02x%02x%02x%02x%02x%02x' \
        $((aad_len & 0xFF)) $(((aad_len >> 8) & 0xFF)) $(((aad_len >> 16) & 0xFF)) $(((aad_len >> 24) & 0xFF)) 0 0 0 0)"
    mac_data="${mac_data}$(printf '%02x%02x%02x%02x%02x%02x%02x%02x' \
        $((ct_len & 0xFF)) $(((ct_len >> 8) & 0xFF)) $(((ct_len >> 16) & 0xFF)) $(((ct_len >> 24) & 0xFF)) 0 0 0 0)"

    local tag
    tag=$(poly1305_mac "$poly_key" "$mac_data")

    printf '%s %s' "$ct" "$tag"
}

# chacha20poly1305_decrypt <key_hex_64> <nonce_hex_24> <ciphertext_hex> <aad_hex> <tag_hex>
# Returns plaintext hex on success, exits with rc=1 on tag mismatch.
chacha20poly1305_decrypt() {
    local key="$1"
    local nonce="$2"
    local ct="$3"
    local aad="$4"
    local expected_tag="$5"

    # Generate Poly1305 one-time key (counter=0, first 32 bytes)
    _chacha20_block "$key" 0 "$nonce"
    local poly_key="${_cc20_block:0:64}"

    # Verify tag first
    local aad_len=$(( ${#aad} / 2 ))
    local ct_len=$(( ${#ct} / 2 ))
    local mac_data="$aad"
    local pad=$(( (16 - (aad_len % 16)) % 16 ))
    local pi=0
    while [ $pi -lt "$pad" ]; do mac_data="${mac_data}00"; pi=$((pi+1)); done
    mac_data="${mac_data}${ct}"
    pad=$(( (16 - (ct_len % 16)) % 16 ))
    pi=0
    while [ $pi -lt "$pad" ]; do mac_data="${mac_data}00"; pi=$((pi+1)); done
    mac_data="${mac_data}$(printf '%02x%02x%02x%02x%02x%02x%02x%02x' \
        $((aad_len & 0xFF)) $(((aad_len >> 8) & 0xFF)) $(((aad_len >> 16) & 0xFF)) $(((aad_len >> 24) & 0xFF)) 0 0 0 0)"
    mac_data="${mac_data}$(printf '%02x%02x%02x%02x%02x%02x%02x%02x' \
        $((ct_len & 0xFF)) $(((ct_len >> 8) & 0xFF)) $(((ct_len >> 16) & 0xFF)) $(((ct_len >> 24) & 0xFF)) 0 0 0 0)"

    local computed_tag
    computed_tag=$(poly1305_mac "$poly_key" "$mac_data")

    if [ "$computed_tag" != "$expected_tag" ]; then
        printf 'ERROR: ChaCha20-Poly1305 tag mismatch\n' >&2
        return 1
    fi

    # Decrypt (same as encrypt - counter starts at 1)
    local pt=""
    if [ -n "$ct" ]; then
        pt=$(chacha20_encrypt "$key" "$nonce" 1 "$ct")
    fi
    printf '%s' "$pt"
}
