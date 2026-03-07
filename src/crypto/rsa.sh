#!/usr/bin/env bash
# rsa.sh - RSA public key operations and RSASSA-PSS verification
# Requires: sha256.sh, hex.sh, bytes.sh
#
# Big-number arithmetic using base-10000 (14-bit safe) limbs in arrays.
# Actually we use base-65536 but with careful overflow handling.
# Numbers are stored little-endian (limb 0 = least significant).

# _bn_from_hex <hex> - Convert hex to limb array in _bn_result[]
_bn_from_hex() {
    local hex="$1"
    _bn_result=()
    while [ $(( ${#hex} % 4 )) -ne 0 ]; do
        hex="0${hex}"
    done
    local n_limbs=$(( ${#hex} / 4 ))
    local i=0
    while [ $i -lt "$n_limbs" ]; do
        local offset=$(( (n_limbs - 1 - i) * 4 ))
        _bn_result[$i]=$((16#${hex:$offset:4}))
        i=$((i + 1))
    done
}

# _bn_to_hex <n_limbs> - Convert _bn_a[] to big-endian hex
_bn_to_hex() {
    local n=$1
    local result=""
    local i=$((n - 1))
    local started=0
    while [ $i -ge 0 ]; do
        local v=${_bn_a[$i]:-0}
        if [ $started -eq 1 ] || [ $v -ne 0 ] || [ $i -eq 0 ]; then
            if [ $started -eq 0 ]; then
                result="$(printf '%x' "$v")"
                started=1
            else
                result="${result}$(printf '%04x' "$v")"
            fi
        fi
        i=$((i - 1))
    done
    [ -z "$result" ] && result="0"
    printf '%s' "$result"
}

# _bn_mul - Multiply _bn_op_a[0..mlen-1] * _bn_op_b[0..mlen-1] -> _bn_prod[0..2*mlen]
_bn_mul() {
    local len=$_bn_mlen
    local prod_len=$((len * 2 + 1))
    local i=0
    while [ $i -lt "$prod_len" ]; do _bn_prod[$i]=0; i=$((i+1)); done

    i=0
    while [ $i -lt "$len" ]; do
        local ai=${_bn_op_a[$i]:-0}
        if [ "$ai" -ne 0 ]; then
            local carry=0
            local j=0
            while [ $j -lt "$len" ]; do
                local t=$(( ${_bn_prod[$((i+j))]} + ai * ${_bn_op_b[$j]:-0} + carry ))
                _bn_prod[$((i+j))]=$(( t & 0xFFFF ))
                carry=$(( t >> 16 ))
                j=$((j + 1))
            done
            _bn_prod[$((i+len))]=$(( ${_bn_prod[$((i+len))]} + carry ))
        fi
        i=$((i + 1))
    done
}

# _bn_divrem - Divide _bn_prod[] by _bn_mod[], remainder left in _bn_prod[0..mlen-1]
# Uses Algorithm D from Knuth TAOCP Vol 2 (simplified for our use case).
# _bn_prod has prod_len limbs, _bn_mod has mlen limbs.
_bn_divrem() {
    local mod_len=$_bn_mlen
    local prod_len=$((_bn_mlen * 2 + 1))

    # Find actual top of modulus
    local n=$mod_len
    while [ $n -gt 1 ] && [ ${_bn_mod[$((n-1))]:-0} -eq 0 ]; do n=$((n - 1)); done

    # Find actual top of product
    local m=$prod_len
    while [ $m -gt 0 ] && [ ${_bn_prod[$((m-1))]:-0} -eq 0 ]; do m=$((m - 1)); done

    if [ $m -lt "$n" ]; then return; fi  # product shorter than modulus
    if [ $m -eq "$n" ]; then
        # Same length: compare to see if product < modulus
        local cmp_i=$((n - 1))
        local need_reduce=0
        while [ $cmp_i -ge 0 ]; do
            if [ ${_bn_prod[$cmp_i]:-0} -gt ${_bn_mod[$cmp_i]:-0} ]; then need_reduce=1; break; fi
            if [ ${_bn_prod[$cmp_i]:-0} -lt ${_bn_mod[$cmp_i]:-0} ]; then break; fi
            cmp_i=$((cmp_i - 1))
        done
        if [ $need_reduce -eq 0 ] && [ $cmp_i -ge 0 ]; then return; fi
        # Equal or greater: fall through to reduce (handle with simple subtraction)
        if [ $need_reduce -eq 0 ] && [ $cmp_i -lt 0 ]; then
            # Exactly equal: result is 0
            local zz=0
            while [ $zz -lt "$n" ]; do _bn_prod[$zz]=0; zz=$((zz+1)); done
            return
        fi
    fi

    # Normalization: compute d such that mod[n-1]*d >= base/2
    # d = floor(65536 / (mod[n-1] + 1))
    local d=$(( 65536 / (${_bn_mod[$((n-1))]} + 1) ))

    # Multiply both product and mod by d
    if [ $d -gt 1 ]; then
        local carry=0
        local i=0
        while [ $i -lt "$m" ]; do
            local t=$(( ${_bn_prod[$i]:-0} * d + carry ))
            _bn_prod[$i]=$(( t & 0xFFFF ))
            carry=$(( t >> 16 ))
            i=$((i + 1))
        done
        if [ $carry -ne 0 ]; then
            _bn_prod[$m]=$carry
            m=$((m + 1))
        fi

        # Multiply modulus into temp array
        carry=0
        i=0
        while [ $i -lt "$n" ]; do
            local t=$(( ${_bn_mod[$i]} * d + carry ))
            _bn_norm_mod[$i]=$(( t & 0xFFFF ))
            carry=$(( t >> 16 ))
            i=$((i + 1))
        done
    else
        local i=0
        while [ $i -lt "$n" ]; do
            _bn_norm_mod[$i]=${_bn_mod[$i]}
            i=$((i + 1))
        done
    fi

    local v_top=${_bn_norm_mod[$((n-1))]}

    # Main loop: for each position j from m-n down to 0
    local j=$((m - n))
    while [ $j -ge 0 ]; do
        # Estimate quotient digit qhat
        local u_hi=${_bn_prod[$((j + n))]:-0}
        local u_lo=${_bn_prod[$((j + n - 1))]:-0}

        local qhat
        if [ $u_hi -eq "$v_top" ]; then
            qhat=65535
        else
            qhat=$(( (u_hi * 65536 + u_lo) / v_top ))
        fi
        [ $qhat -gt 65535 ] && qhat=65535

        # Multiply-subtract: prod[j..j+n] -= qhat * mod[0..n-1]
        if [ $qhat -gt 0 ]; then
            local carry=0
            local i=0
            while [ $i -lt "$n" ]; do
                local t=$(( carry + qhat * ${_bn_norm_mod[$i]} ))
                local lo=$(( t & 0xFFFF ))
                carry=$(( t >> 16 ))
                local diff=$(( ${_bn_prod[$((j + i))]} - lo ))
                if [ $diff -lt 0 ]; then
                    diff=$((diff + 65536))
                    carry=$((carry + 1))
                fi
                _bn_prod[$((j + i))]=$diff
                i=$((i + 1))
            done
            local diff=$(( ${_bn_prod[$((j + n))]:-0} - carry ))
            _bn_prod[$((j + n))]=$diff
        fi

        # If we overshot (top went negative), add back once
        if [ ${_bn_prod[$((j + n))]:-0} -lt 0 ]; then
            local carry=0
            local i=0
            while [ $i -lt "$n" ]; do
                local t=$(( ${_bn_prod[$((j + i))]} + ${_bn_norm_mod[$i]} + carry ))
                _bn_prod[$((j + i))]=$(( t & 0xFFFF ))
                carry=$(( t >> 16 ))
                i=$((i + 1))
            done
            _bn_prod[$((j + n))]=$(( ${_bn_prod[$((j + n))]} + carry ))
        fi

        j=$((j - 1))
    done

    # Unnormalize: divide remainder by d
    if [ $d -gt 1 ]; then
        local rem=0
        local i=$((n - 1))
        while [ $i -ge 0 ]; do
            local t=$(( rem * 65536 + ${_bn_prod[$i]} ))
            _bn_prod[$i]=$(( t / d ))
            rem=$(( t % d ))
            i=$((i - 1))
        done
    fi

    # Clear upper limbs
    local i=$n
    while [ $i -lt "$prod_len" ]; do _bn_prod[$i]=0; i=$((i+1)); done
}

# _bn_mul_mod_global - Multiply _bn_op_a * _bn_op_b mod _bn_mod -> _bn_res
_bn_mul_mod_global() {
    _bn_mul
    _bn_divrem
    local i=0
    while [ $i -lt "$_bn_mlen" ]; do
        _bn_res[$i]=${_bn_prod[$i]:-0}
        i=$((i + 1))
    done
}

# _bn_modexp <base_hex> <exp_hex> <mod_hex> - Modular exponentiation
_bn_modexp() {
    local base_hex="$1"
    local exp_hex="$2"
    local mod_hex="$3"

    _bn_from_hex "$mod_hex"
    _bn_mlen=${#_bn_result[@]}
    local i=0
    while [ $i -lt "$_bn_mlen" ]; do _bn_mod[$i]=${_bn_result[$i]}; i=$((i + 1)); done

    _bn_from_hex "$base_hex"
    i=0
    while [ $i -lt "$_bn_mlen" ]; do _bn_base[$i]=${_bn_result[$i]:-0}; i=$((i + 1)); done

    # Result = 1
    i=0; while [ $i -lt "$_bn_mlen" ]; do _bn_res[$i]=0; i=$((i+1)); done
    _bn_res[0]=1

    # Process exponent bits MSB-first
    local exp_bits=$(( ${#exp_hex} * 4 ))
    local bit=$((exp_bits - 1))

    # Skip leading zero bits
    while [ $bit -ge 0 ]; do
        local char_idx=$(( (exp_bits - 1 - bit) / 4 ))
        local bit_in_char=$(( (exp_bits - 1 - bit) % 4 ))
        local nibble=$((16#${exp_hex:$char_idx:1}))
        local bv=$(( (nibble >> (3 - bit_in_char)) & 1 ))
        if [ $bv -eq 1 ]; then break; fi
        bit=$((bit - 1))
    done

    while [ $bit -ge 0 ]; do
        # Square
        i=0; while [ $i -lt "$_bn_mlen" ]; do
            _bn_op_a[$i]=${_bn_res[$i]}
            _bn_op_b[$i]=${_bn_res[$i]}
            i=$((i+1))
        done
        _bn_mul_mod_global

        # Get current exponent bit
        local char_idx=$(( (exp_bits - 1 - bit) / 4 ))
        local bit_in_char=$(( (exp_bits - 1 - bit) % 4 ))
        local nibble=$((16#${exp_hex:$char_idx:1}))
        local bv=$(( (nibble >> (3 - bit_in_char)) & 1 ))

        if [ $bv -eq 1 ]; then
            # Multiply by base
            i=0; while [ $i -lt "$_bn_mlen" ]; do
                _bn_op_a[$i]=${_bn_res[$i]}
                _bn_op_b[$i]=${_bn_base[$i]}
                i=$((i+1))
            done
            _bn_mul_mod_global
        fi

        bit=$((bit - 1))
    done

    i=0; while [ $i -lt "$_bn_mlen" ]; do _bn_a[$i]=${_bn_res[$i]}; i=$((i+1)); done
    _bn_to_hex "$_bn_mlen"
}

# rsa_raw_public <message_hex> <exponent_hex> <modulus_hex>
rsa_raw_public() {
    _bn_modexp "$1" "$2" "$3"
}

# rsa_verify_pss <modulus_hex> <exponent_hex> <signature_hex> <message_hex>
# RSASSA-PSS-VERIFY with SHA-256, MGF1-SHA-256, salt length = 32
rsa_verify_pss() {
    local mod_hex="$1"
    local exp_hex="$2"
    local sig_hex="$3"
    local msg_hex="$4"

    local mod_bits=$(( ${#mod_hex} * 4 ))
    local em_len=$(( (mod_bits + 7) / 8 ))

    local em_hex
    em_hex=$(rsa_raw_public "$sig_hex" "$exp_hex" "$mod_hex")
    em_hex=$(hex_pad "$em_hex" "$em_len")

    local last_byte="${em_hex:$(( (em_len - 1) * 2)):2}"
    if [ "$last_byte" != "bc" ]; then
        return 1
    fi

    local hash_len=32
    local db_len=$((em_len - hash_len - 1))
    local masked_db="${em_hex:0:$((db_len * 2))}"
    local h="${em_hex:$((db_len * 2)):$((hash_len * 2))}"

    local top_bits=$(( 8 * em_len - (mod_bits - 1) ))
    local mask=255
    if [ $top_bits -gt 0 ]; then
        mask=$(( 0xFF >> top_bits ))
        local top_byte=$((16#${masked_db:0:2}))
        if [ $(( top_byte & ~mask )) -ne 0 ]; then
            return 1
        fi
    fi

    local db_mask
    db_mask=$(_mgf1_sha256 "$h" "$db_len")

    local db
    db=$(hex_xor "$masked_db" "$db_mask")

    if [ $top_bits -gt 0 ]; then
        local top_byte=$((16#${db:0:2}))
        top_byte=$(( top_byte & mask ))
        db="$(printf '%02x' "$top_byte")${db:2}"
    fi

    local salt_len=32
    local padding_len=$((db_len - salt_len - 1))

    local j=0
    while [ $j -lt "$padding_len" ]; do
        local b="${db:$((j*2)):2}"
        if [ "$b" != "00" ]; then
            return 1
        fi
        j=$((j + 1))
    done

    local sep="${db:$((padding_len * 2)):2}"
    if [ "$sep" != "01" ]; then
        return 1
    fi

    local salt="${db:$(((padding_len + 1) * 2)):$((salt_len * 2))}"

    local m_hash
    m_hash=$(sha256 "$msg_hex")
    local m_prime="0000000000000000${m_hash}${salt}"

    local h_prime
    h_prime=$(sha256 "$m_prime")

    if [ "$h" = "$h_prime" ]; then
        return 0
    else
        return 1
    fi
}

# _mgf1_sha256 <seed_hex> <output_len_bytes>
_mgf1_sha256() {
    local seed="$1"
    local out_len=$2
    local result=""
    local counter=0
    while [ $(( ${#result} / 2 )) -lt "$out_len" ]; do
        local c_hex
        printf -v c_hex '%08x' "$(( counter & 0xFFFFFFFF ))"
        result="${result}$(sha256 "${seed}${c_hex}")"
        counter=$((counter + 1))
    done
    printf '%s' "${result:0:$((out_len * 2))}"
}
