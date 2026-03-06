#!/usr/bin/env bash
# x25519.sh - X25519 Diffie-Hellman key exchange (RFC 7748)
# Implements Curve25519 scalar multiplication using the Montgomery ladder.
#
# Field: GF(2^255 - 19), represented as 10 limbs with alternating 26/25-bit widths.
# Limb layout (little-endian): 26, 25, 26, 25, 26, 25, 26, 25, 26, 25 = 255 bits total.
# Products of two limbs fit in ~52 bits; accumulated sums of 10 products fit in ~56 bits,
# well within 64-bit shell integer range.
#
# Performance: 10-limb representation reduces multiply inner loop from 256 to 100 ops.
# Dedicated squaring function exploits symmetry for ~2x speedup over generic multiply.
# All field element data stored in scalar locals to avoid array indexing overhead.
#
# Reference: RFC 7748, Monocypher (public domain), TweetNaCl (public domain)

# Limb bit-widths: alternating 26, 25
_x25519_lbits=(26 25 26 25 26 25 26 25 26 25)
# Limb masks
_x25519_lmask=(0x3FFFFFF 0x1FFFFFF 0x3FFFFFF 0x1FFFFFF 0x3FFFFFF 0x1FFFFFF 0x3FFFFFF 0x1FFFFFF 0x3FFFFFF 0x1FFFFFF)

# p = 2^255 - 19, stored as 10 limbs
_x25519_p=(0x3FFFFED 0x1FFFFFF 0x3FFFFFF 0x1FFFFFF 0x3FFFFFF 0x1FFFFFF 0x3FFFFFF 0x1FFFFFF 0x3FFFFFF 0x1FFFFFF)

# _fe_unpack <hex_32bytes> - Unpack 32-byte little-endian hex into 10-limb array
# Sets global _fe_result[]
_fe_unpack() {
    local hex="$1"
    _fe_result=()

    # Read all 32 bytes into a flat array
    local b=()
    local i=0
    while [ $i -lt 32 ]; do
        b[$i]=$((16#${hex:$((i*2)):2}))
        i=$((i + 1))
    done

    # Pack bytes into 10 limbs of alternating 26/25 bits
    local bit_pos=0
    i=0
    while [ $i -lt 10 ]; do
        local width=${_x25519_lbits[$i]}
        local mask=${_x25519_lmask[$i]}
        local byte_idx=$(( bit_pos / 8 ))
        local bit_off=$(( bit_pos % 8 ))
        local val=$(( ${b[$byte_idx]:-0} >> bit_off ))
        local bits_have=$(( 8 - bit_off ))
        local next_byte=$((byte_idx + 1))
        while [ $bits_have -lt "$width" ] && [ $next_byte -lt 32 ]; do
            val=$(( val | (${b[$next_byte]:-0} << bits_have) ))
            bits_have=$((bits_have + 8))
            next_byte=$((next_byte + 1))
        done
        _fe_result[$i]=$(( val & mask ))
        bit_pos=$((bit_pos + width))
        i=$((i + 1))
    done
}

# _fe_pack - Pack _fe_a[] (10 limbs) back to 32-byte little-endian hex
_fe_pack() {
    _fe_reduce

    local bytes=()
    local i=0
    while [ $i -lt 32 ]; do bytes[$i]=0; i=$((i+1)); done

    local bit_pos=0
    i=0
    while [ $i -lt 10 ]; do
        local val=${_fe_a[$i]}
        local width=${_x25519_lbits[$i]}
        local byte_idx=$(( bit_pos / 8 ))
        local bit_off=$(( bit_pos % 8 ))
        local remaining=$width
        while [ $remaining -gt 0 ]; do
            local space=$(( 8 - bit_off ))
            local take=$remaining
            [ $take -gt $space ] && take=$space
            local mask_take=$(( (1 << take) - 1 ))
            bytes[$byte_idx]=$(( ${bytes[$byte_idx]} | ((val & mask_take) << bit_off) ))
            val=$((val >> take))
            remaining=$((remaining - take))
            bit_off=$((bit_off + take))
            if [ $bit_off -ge 8 ]; then
                bit_off=0
                byte_idx=$((byte_idx + 1))
            fi
        done
        bit_pos=$((bit_pos + width))
        i=$((i + 1))
    done

    local result=""
    local _fe_tmp
    i=0
    while [ $i -lt 32 ]; do
        printf -v _fe_tmp '%02x' $(( ${bytes[$i]} & 0xFF ))
        result="${result}${_fe_tmp}"
        i=$((i + 1))
    done
    printf '%s' "$result"
}

# _fe_reduce - Fully reduce _fe_a[] mod p
_fe_reduce() {
    local i carry
    # Carry propagation (two passes to handle wraparound)
    local pass=0
    while [ $pass -lt 2 ]; do
        i=0
        while [ $i -lt 9 ]; do
            carry=$(( ${_fe_a[$i]} >> ${_x25519_lbits[$i]} ))
            _fe_a[$i]=$(( ${_fe_a[$i]} & ${_x25519_lmask[$i]} ))
            _fe_a[$((i+1))]=$(( ${_fe_a[$((i+1))]} + carry ))
            i=$((i + 1))
        done
        carry=$(( ${_fe_a[9]} >> 25 ))
        _fe_a[9]=$(( ${_fe_a[9]} & 0x1FFFFFF ))
        _fe_a[0]=$(( ${_fe_a[0]} + carry * 19 ))
        pass=$((pass + 1))
    done

    # Final carry from limb 0
    carry=$(( ${_fe_a[0]} >> 26 ))
    _fe_a[0]=$(( ${_fe_a[0]} & 0x3FFFFFF ))
    _fe_a[1]=$(( ${_fe_a[1]} + carry ))

    # Conditional subtraction of p if >= p
    local t=()
    local borrow=0
    i=0
    while [ $i -lt 10 ]; do
        local diff=$(( ${_fe_a[$i]} - ${_x25519_p[$i]} - borrow ))
        if [ $diff -lt 0 ]; then
            diff=$(( diff + (1 << ${_x25519_lbits[$i]}) ))
            borrow=1
        else
            borrow=0
        fi
        t[$i]=$diff
        i=$((i + 1))
    done
    if [ $borrow -eq 0 ]; then
        i=0
        while [ $i -lt 10 ]; do _fe_a[$i]=${t[$i]}; i=$((i+1)); done
    fi
}

# _fe_add -> _fe_a[] = _fe_x[] + _fe_y[]
_fe_add() {
    _fe_a[0]=$(( ${_fe_x[0]} + ${_fe_y[0]} ))
    _fe_a[1]=$(( ${_fe_x[1]} + ${_fe_y[1]} ))
    _fe_a[2]=$(( ${_fe_x[2]} + ${_fe_y[2]} ))
    _fe_a[3]=$(( ${_fe_x[3]} + ${_fe_y[3]} ))
    _fe_a[4]=$(( ${_fe_x[4]} + ${_fe_y[4]} ))
    _fe_a[5]=$(( ${_fe_x[5]} + ${_fe_y[5]} ))
    _fe_a[6]=$(( ${_fe_x[6]} + ${_fe_y[6]} ))
    _fe_a[7]=$(( ${_fe_x[7]} + ${_fe_y[7]} ))
    _fe_a[8]=$(( ${_fe_x[8]} + ${_fe_y[8]} ))
    _fe_a[9]=$(( ${_fe_x[9]} + ${_fe_y[9]} ))
}

# _fe_sub -> _fe_a[] = _fe_x[] - _fe_y[] (mod p, add 2*p to avoid negatives)
# Includes carry propagation to keep limbs within nominal widths, preventing
# overflow in subsequent mul/sq (28-bit limbs would overflow 63-bit signed ints).
_fe_sub() {
    local t0=$(( ${_fe_x[0]} - ${_fe_y[0]} + 0x7FFFFDA ))
    local t1=$(( ${_fe_x[1]} - ${_fe_y[1]} + 0x3FFFFFE ))
    local t2=$(( ${_fe_x[2]} - ${_fe_y[2]} + 0x7FFFFFE ))
    local t3=$(( ${_fe_x[3]} - ${_fe_y[3]} + 0x3FFFFFE ))
    local t4=$(( ${_fe_x[4]} - ${_fe_y[4]} + 0x7FFFFFE ))
    local t5=$(( ${_fe_x[5]} - ${_fe_y[5]} + 0x3FFFFFE ))
    local t6=$(( ${_fe_x[6]} - ${_fe_y[6]} + 0x7FFFFFE ))
    local t7=$(( ${_fe_x[7]} - ${_fe_y[7]} + 0x3FFFFFE ))
    local t8=$(( ${_fe_x[8]} - ${_fe_y[8]} + 0x7FFFFFE ))
    local t9=$(( ${_fe_x[9]} - ${_fe_y[9]} + 0x3FFFFFE ))
    local carry
    carry=$((t0 >> 26)); t0=$((t0 & 0x3FFFFFF)); t1=$((t1 + carry))
    carry=$((t1 >> 25)); t1=$((t1 & 0x1FFFFFF)); t2=$((t2 + carry))
    carry=$((t2 >> 26)); t2=$((t2 & 0x3FFFFFF)); t3=$((t3 + carry))
    carry=$((t3 >> 25)); t3=$((t3 & 0x1FFFFFF)); t4=$((t4 + carry))
    carry=$((t4 >> 26)); t4=$((t4 & 0x3FFFFFF)); t5=$((t5 + carry))
    carry=$((t5 >> 25)); t5=$((t5 & 0x1FFFFFF)); t6=$((t6 + carry))
    carry=$((t6 >> 26)); t6=$((t6 & 0x3FFFFFF)); t7=$((t7 + carry))
    carry=$((t7 >> 25)); t7=$((t7 & 0x1FFFFFF)); t8=$((t8 + carry))
    carry=$((t8 >> 26)); t8=$((t8 & 0x3FFFFFF)); t9=$((t9 + carry))
    carry=$((t9 >> 25)); t9=$((t9 & 0x1FFFFFF)); t0=$((t0 + carry * 19))
    carry=$((t0 >> 26)); t0=$((t0 & 0x3FFFFFF)); t1=$((t1 + carry))
    _fe_a[0]=$t0; _fe_a[1]=$t1; _fe_a[2]=$t2; _fe_a[3]=$t3; _fe_a[4]=$t4
    _fe_a[5]=$t5; _fe_a[6]=$t6; _fe_a[7]=$t7; _fe_a[8]=$t8; _fe_a[9]=$t9
}

# _fe_mul -> _fe_a[] = _fe_x[] * _fe_y[]
# Fully unrolled 10x10 limb multiply with inline reduction.
# Due to alternating 26/25-bit limb widths, products where both indices are odd
# need a factor of 2 (ref10/donna convention: pre-double odd x, use ×38 for odd y).
_fe_mul() {
    local x0=${_fe_x[0]} x1=${_fe_x[1]} x2=${_fe_x[2]} x3=${_fe_x[3]} x4=${_fe_x[4]}
    local x5=${_fe_x[5]} x6=${_fe_x[6]} x7=${_fe_x[7]} x8=${_fe_x[8]} x9=${_fe_x[9]}
    local y0=${_fe_y[0]} y1=${_fe_y[1]} y2=${_fe_y[2]} y3=${_fe_y[3]} y4=${_fe_y[4]}
    local y5=${_fe_y[5]} y6=${_fe_y[6]} y7=${_fe_y[7]} y8=${_fe_y[8]} y9=${_fe_y[9]}

    # Pre-double odd-indexed x values for both-odd correction
    local x1_2=$((x1 * 2)) x3_2=$((x3 * 2)) x5_2=$((x5 * 2))
    local x7_2=$((x7 * 2)) x9_2=$((x9 * 2))

    # Pre-scale y values by 19 for reduction of cross terms where i+j >= 10
    local y1_19=$((y1 * 19)) y2_19=$((y2 * 19)) y3_19=$((y3 * 19))
    local y4_19=$((y4 * 19)) y5_19=$((y5 * 19)) y6_19=$((y6 * 19))
    local y7_19=$((y7 * 19)) y8_19=$((y8 * 19)) y9_19=$((y9 * 19))

    # Even-indexed outputs use x_odd_2 for both-odd pairs; odd-indexed don't
    local t0=$(( x0*y0 + x1_2*y9_19 + x2*y8_19 + x3_2*y7_19 + x4*y6_19 + x5_2*y5_19 + x6*y4_19 + x7_2*y3_19 + x8*y2_19 + x9_2*y1_19 ))
    local t1=$(( x0*y1 + x1*y0 + x2*y9_19 + x3*y8_19 + x4*y7_19 + x5*y6_19 + x6*y5_19 + x7*y4_19 + x8*y3_19 + x9*y2_19 ))
    local t2=$(( x0*y2 + x1_2*y1 + x2*y0 + x3_2*y9_19 + x4*y8_19 + x5_2*y7_19 + x6*y6_19 + x7_2*y5_19 + x8*y4_19 + x9_2*y3_19 ))
    local t3=$(( x0*y3 + x1*y2 + x2*y1 + x3*y0 + x4*y9_19 + x5*y8_19 + x6*y7_19 + x7*y6_19 + x8*y5_19 + x9*y4_19 ))
    local t4=$(( x0*y4 + x1_2*y3 + x2*y2 + x3_2*y1 + x4*y0 + x5_2*y9_19 + x6*y8_19 + x7_2*y7_19 + x8*y6_19 + x9_2*y5_19 ))
    local t5=$(( x0*y5 + x1*y4 + x2*y3 + x3*y2 + x4*y1 + x5*y0 + x6*y9_19 + x7*y8_19 + x8*y7_19 + x9*y6_19 ))
    local t6=$(( x0*y6 + x1_2*y5 + x2*y4 + x3_2*y3 + x4*y2 + x5_2*y1 + x6*y0 + x7_2*y9_19 + x8*y8_19 + x9_2*y7_19 ))
    local t7=$(( x0*y7 + x1*y6 + x2*y5 + x3*y4 + x4*y3 + x5*y2 + x6*y1 + x7*y0 + x8*y9_19 + x9*y8_19 ))
    local t8=$(( x0*y8 + x1_2*y7 + x2*y6 + x3_2*y5 + x4*y4 + x5_2*y3 + x6*y2 + x7_2*y1 + x8*y0 + x9_2*y9_19 ))
    local t9=$(( x0*y9 + x1*y8 + x2*y7 + x3*y6 + x4*y5 + x5*y4 + x6*y3 + x7*y2 + x8*y1 + x9*y0 ))

    local carry
    carry=$(( t0 >> 26 )); t0=$(( t0 & 0x3FFFFFF )); t1=$((t1 + carry))
    carry=$(( t1 >> 25 )); t1=$(( t1 & 0x1FFFFFF )); t2=$((t2 + carry))
    carry=$(( t2 >> 26 )); t2=$(( t2 & 0x3FFFFFF )); t3=$((t3 + carry))
    carry=$(( t3 >> 25 )); t3=$(( t3 & 0x1FFFFFF )); t4=$((t4 + carry))
    carry=$(( t4 >> 26 )); t4=$(( t4 & 0x3FFFFFF )); t5=$((t5 + carry))
    carry=$(( t5 >> 25 )); t5=$(( t5 & 0x1FFFFFF )); t6=$((t6 + carry))
    carry=$(( t6 >> 26 )); t6=$(( t6 & 0x3FFFFFF )); t7=$((t7 + carry))
    carry=$(( t7 >> 25 )); t7=$(( t7 & 0x1FFFFFF )); t8=$((t8 + carry))
    carry=$(( t8 >> 26 )); t8=$(( t8 & 0x3FFFFFF )); t9=$((t9 + carry))
    carry=$(( t9 >> 25 )); t9=$(( t9 & 0x1FFFFFF )); t0=$((t0 + carry * 19))
    carry=$(( t0 >> 26 )); t0=$(( t0 & 0x3FFFFFF )); t1=$((t1 + carry))

    _fe_a[0]=$t0; _fe_a[1]=$t1; _fe_a[2]=$t2; _fe_a[3]=$t3; _fe_a[4]=$t4
    _fe_a[5]=$t5; _fe_a[6]=$t6; _fe_a[7]=$t7; _fe_a[8]=$t8; _fe_a[9]=$t9
}

# _fe_sq -> _fe_a[] = _fe_x[] ^ 2
# Optimized squaring exploits symmetry: cross terms appear twice.
# Uses ×38 (=2×19) for odd-indexed reduced terms to account for alternating widths.
_fe_sq() {
    local x0=${_fe_x[0]} x1=${_fe_x[1]} x2=${_fe_x[2]} x3=${_fe_x[3]} x4=${_fe_x[4]}
    local x5=${_fe_x[5]} x6=${_fe_x[6]} x7=${_fe_x[7]} x8=${_fe_x[8]} x9=${_fe_x[9]}

    local x0_2=$((x0 * 2)) x1_2=$((x1 * 2)) x2_2=$((x2 * 2)) x3_2=$((x3 * 2))
    local x4_2=$((x4 * 2)) x5_2=$((x5 * 2)) x6_2=$((x6 * 2)) x7_2=$((x7 * 2))
    local x8_2=$((x8 * 2))

    # ×38 for odd indices (both-odd correction: 2×19), ×19 for even indices
    local x5_38=$((x5 * 38)) x6_19=$((x6 * 19)) x7_38=$((x7 * 38))
    local x8_19=$((x8 * 19)) x9_38=$((x9 * 38))

    local t0=$(( x0*x0 + x1_2*x9_38 + x2_2*x8_19 + x3_2*x7_38 + x4_2*x6_19 + x5*x5_38 ))
    local t1=$(( x0_2*x1 + x2*x9_38 + x3_2*x8_19 + x4*x7_38 + x5_2*x6_19 ))
    local t2=$(( x0_2*x2 + x1_2*x1 + x3_2*x9_38 + x4_2*x8_19 + x5_2*x7_38 + x6*x6_19 ))
    local t3=$(( x0_2*x3 + x1_2*x2 + x4*x9_38 + x5_2*x8_19 + x6*x7_38 ))
    local t4=$(( x0_2*x4 + x1_2*x3_2 + x2*x2 + x5_2*x9_38 + x6_2*x8_19 + x7*x7_38 ))
    local t5=$(( x0_2*x5 + x1_2*x4 + x2_2*x3 + x6*x9_38 + x7_2*x8_19 ))
    local t6=$(( x0_2*x6 + x1_2*x5_2 + x2_2*x4 + x3_2*x3 + x7_2*x9_38 + x8*x8_19 ))
    local t7=$(( x0_2*x7 + x1_2*x6 + x2_2*x5 + x3_2*x4 + x8*x9_38 ))
    local t8=$(( x0_2*x8 + x1_2*x7_2 + x2_2*x6 + x3_2*x5_2 + x4*x4 + x9*x9_38 ))
    local t9=$(( x0_2*x9 + x1_2*x8 + x2_2*x7 + x3_2*x6 + x4_2*x5 ))

    local carry
    carry=$(( t0 >> 26 )); t0=$(( t0 & 0x3FFFFFF )); t1=$((t1 + carry))
    carry=$(( t1 >> 25 )); t1=$(( t1 & 0x1FFFFFF )); t2=$((t2 + carry))
    carry=$(( t2 >> 26 )); t2=$(( t2 & 0x3FFFFFF )); t3=$((t3 + carry))
    carry=$(( t3 >> 25 )); t3=$(( t3 & 0x1FFFFFF )); t4=$((t4 + carry))
    carry=$(( t4 >> 26 )); t4=$(( t4 & 0x3FFFFFF )); t5=$((t5 + carry))
    carry=$(( t5 >> 25 )); t5=$(( t5 & 0x1FFFFFF )); t6=$((t6 + carry))
    carry=$(( t6 >> 26 )); t6=$(( t6 & 0x3FFFFFF )); t7=$((t7 + carry))
    carry=$(( t7 >> 25 )); t7=$(( t7 & 0x1FFFFFF )); t8=$((t8 + carry))
    carry=$(( t8 >> 26 )); t8=$(( t8 & 0x3FFFFFF )); t9=$((t9 + carry))
    carry=$(( t9 >> 25 )); t9=$(( t9 & 0x1FFFFFF )); t0=$((t0 + carry * 19))
    carry=$(( t0 >> 26 )); t0=$(( t0 & 0x3FFFFFF )); t1=$((t1 + carry))

    _fe_a[0]=$t0; _fe_a[1]=$t1; _fe_a[2]=$t2; _fe_a[3]=$t3; _fe_a[4]=$t4
    _fe_a[5]=$t5; _fe_a[6]=$t6; _fe_a[7]=$t7; _fe_a[8]=$t8; _fe_a[9]=$t9
}

# _fe_inv -> _fe_a[] = _fe_x[] ^ (-1) mod p
# Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p
# p-2 = 2^255 - 21
# Binary: bits 254..5 all 1, bit 4=0, bit 3=1, bit 2=0, bits 1,0=1
_fe_inv() {
    local in0=${_fe_x[0]} in1=${_fe_x[1]} in2=${_fe_x[2]} in3=${_fe_x[3]} in4=${_fe_x[4]}
    local in5=${_fe_x[5]} in6=${_fe_x[6]} in7=${_fe_x[7]} in8=${_fe_x[8]} in9=${_fe_x[9]}

    # Start with result = input (bit 254 is always 1)
    local r0=$in0 r1=$in1 r2=$in2 r3=$in3 r4=$in4
    local r5=$in5 r6=$in6 r7=$in7 r8=$in8 r9=$in9

    local bit=253
    while [ $bit -ge 0 ]; do
        # Square
        _fe_x[0]=$r0; _fe_x[1]=$r1; _fe_x[2]=$r2; _fe_x[3]=$r3; _fe_x[4]=$r4
        _fe_x[5]=$r5; _fe_x[6]=$r6; _fe_x[7]=$r7; _fe_x[8]=$r8; _fe_x[9]=$r9
        _fe_sq
        r0=${_fe_a[0]}; r1=${_fe_a[1]}; r2=${_fe_a[2]}; r3=${_fe_a[3]}; r4=${_fe_a[4]}
        r5=${_fe_a[5]}; r6=${_fe_a[6]}; r7=${_fe_a[7]}; r8=${_fe_a[8]}; r9=${_fe_a[9]}

        # Multiply by input if bit is set (all bits 1 except bits 4 and 2)
        if [ $bit -ne 4 ] && [ $bit -ne 2 ]; then
            _fe_x[0]=$r0; _fe_x[1]=$r1; _fe_x[2]=$r2; _fe_x[3]=$r3; _fe_x[4]=$r4
            _fe_x[5]=$r5; _fe_x[6]=$r6; _fe_x[7]=$r7; _fe_x[8]=$r8; _fe_x[9]=$r9
            _fe_y[0]=$in0; _fe_y[1]=$in1; _fe_y[2]=$in2; _fe_y[3]=$in3; _fe_y[4]=$in4
            _fe_y[5]=$in5; _fe_y[6]=$in6; _fe_y[7]=$in7; _fe_y[8]=$in8; _fe_y[9]=$in9
            _fe_mul
            r0=${_fe_a[0]}; r1=${_fe_a[1]}; r2=${_fe_a[2]}; r3=${_fe_a[3]}; r4=${_fe_a[4]}
            r5=${_fe_a[5]}; r6=${_fe_a[6]}; r7=${_fe_a[7]}; r8=${_fe_a[8]}; r9=${_fe_a[9]}
        fi

        bit=$((bit - 1))
    done

    _fe_a[0]=$r0; _fe_a[1]=$r1; _fe_a[2]=$r2; _fe_a[3]=$r3; _fe_a[4]=$r4
    _fe_a[5]=$r5; _fe_a[6]=$r6; _fe_a[7]=$r7; _fe_a[8]=$r8; _fe_a[9]=$r9
}

# _x25519_clamp <scalar_hex> - Apply clamping to scalar (RFC 7748 Section 5)
_x25519_clamp() {
    local hex="$1"
    local b0=$((16#${hex:0:2}))
    local b31=$((16#${hex:62:2}))
    b0=$(( b0 & 248 ))
    b31=$(( (b31 & 127) | 64 ))
    printf '%02x%s%02x' "$b0" "${hex:2:60}" "$b31"
}

# x25519 <scalar_hex_32bytes> <u_coord_hex_32bytes> - Scalar multiplication
x25519() {
    local scalar_hex
    scalar_hex=$(_x25519_clamp "$1")
    local u_hex="$2"

    # Unpack u-coordinate
    _fe_unpack "$u_hex"
    local u0=${_fe_result[0]} u1=${_fe_result[1]} u2=${_fe_result[2]} u3=${_fe_result[3]} u4=${_fe_result[4]}
    local u5=${_fe_result[5]} u6=${_fe_result[6]} u7=${_fe_result[7]} u8=${_fe_result[8]} u9=${_fe_result[9]}
    # Clear top bit (reduce to 255 bits)
    u9=$((u9 & 0x1FFFFFF))

    # Montgomery ladder: x_2=1, z_2=0, x_3=u, z_3=1
    local x2_0=1 x2_1=0 x2_2=0 x2_3=0 x2_4=0 x2_5=0 x2_6=0 x2_7=0 x2_8=0 x2_9=0
    local z2_0=0 z2_1=0 z2_2=0 z2_3=0 z2_4=0 z2_5=0 z2_6=0 z2_7=0 z2_8=0 z2_9=0
    local x3_0=$u0 x3_1=$u1 x3_2=$u2 x3_3=$u3 x3_4=$u4 x3_5=$u5 x3_6=$u6 x3_7=$u7 x3_8=$u8 x3_9=$u9
    local z3_0=1 z3_1=0 z3_2=0 z3_3=0 z3_4=0 z3_5=0 z3_6=0 z3_7=0 z3_8=0 z3_9=0

    local swap=0
    local bit=254
    while [ $bit -ge 0 ]; do
        local byte_idx=$(( bit / 8 ))
        local bit_idx=$(( bit % 8 ))
        local byte_hex="${scalar_hex:$((byte_idx * 2)):2}"
        local k_t=$(( (16#$byte_hex >> bit_idx) & 1 ))

        swap=$((swap ^ k_t))
        if [ $swap -ne 0 ]; then
            local tmp
            tmp=$x2_0; x2_0=$x3_0; x3_0=$tmp; tmp=$x2_1; x2_1=$x3_1; x3_1=$tmp
            tmp=$x2_2; x2_2=$x3_2; x3_2=$tmp; tmp=$x2_3; x2_3=$x3_3; x3_3=$tmp
            tmp=$x2_4; x2_4=$x3_4; x3_4=$tmp; tmp=$x2_5; x2_5=$x3_5; x3_5=$tmp
            tmp=$x2_6; x2_6=$x3_6; x3_6=$tmp; tmp=$x2_7; x2_7=$x3_7; x3_7=$tmp
            tmp=$x2_8; x2_8=$x3_8; x3_8=$tmp; tmp=$x2_9; x2_9=$x3_9; x3_9=$tmp
            tmp=$z2_0; z2_0=$z3_0; z3_0=$tmp; tmp=$z2_1; z2_1=$z3_1; z3_1=$tmp
            tmp=$z2_2; z2_2=$z3_2; z3_2=$tmp; tmp=$z2_3; z2_3=$z3_3; z3_3=$tmp
            tmp=$z2_4; z2_4=$z3_4; z3_4=$tmp; tmp=$z2_5; z2_5=$z3_5; z3_5=$tmp
            tmp=$z2_6; z2_6=$z3_6; z3_6=$tmp; tmp=$z2_7; z2_7=$z3_7; z3_7=$tmp
            tmp=$z2_8; z2_8=$z3_8; z3_8=$tmp; tmp=$z2_9; z2_9=$z3_9; z3_9=$tmp
        fi
        swap=$k_t

        # A = x_2 + z_2
        _fe_x[0]=$x2_0; _fe_x[1]=$x2_1; _fe_x[2]=$x2_2; _fe_x[3]=$x2_3; _fe_x[4]=$x2_4
        _fe_x[5]=$x2_5; _fe_x[6]=$x2_6; _fe_x[7]=$x2_7; _fe_x[8]=$x2_8; _fe_x[9]=$x2_9
        _fe_y[0]=$z2_0; _fe_y[1]=$z2_1; _fe_y[2]=$z2_2; _fe_y[3]=$z2_3; _fe_y[4]=$z2_4
        _fe_y[5]=$z2_5; _fe_y[6]=$z2_6; _fe_y[7]=$z2_7; _fe_y[8]=$z2_8; _fe_y[9]=$z2_9
        _fe_add
        local A0=${_fe_a[0]} A1=${_fe_a[1]} A2=${_fe_a[2]} A3=${_fe_a[3]} A4=${_fe_a[4]}
        local A5=${_fe_a[5]} A6=${_fe_a[6]} A7=${_fe_a[7]} A8=${_fe_a[8]} A9=${_fe_a[9]}

        # AA = A^2
        _fe_x[0]=$A0; _fe_x[1]=$A1; _fe_x[2]=$A2; _fe_x[3]=$A3; _fe_x[4]=$A4
        _fe_x[5]=$A5; _fe_x[6]=$A6; _fe_x[7]=$A7; _fe_x[8]=$A8; _fe_x[9]=$A9
        _fe_sq
        local AA0=${_fe_a[0]} AA1=${_fe_a[1]} AA2=${_fe_a[2]} AA3=${_fe_a[3]} AA4=${_fe_a[4]}
        local AA5=${_fe_a[5]} AA6=${_fe_a[6]} AA7=${_fe_a[7]} AA8=${_fe_a[8]} AA9=${_fe_a[9]}

        # B = x_2 - z_2
        _fe_x[0]=$x2_0; _fe_x[1]=$x2_1; _fe_x[2]=$x2_2; _fe_x[3]=$x2_3; _fe_x[4]=$x2_4
        _fe_x[5]=$x2_5; _fe_x[6]=$x2_6; _fe_x[7]=$x2_7; _fe_x[8]=$x2_8; _fe_x[9]=$x2_9
        _fe_y[0]=$z2_0; _fe_y[1]=$z2_1; _fe_y[2]=$z2_2; _fe_y[3]=$z2_3; _fe_y[4]=$z2_4
        _fe_y[5]=$z2_5; _fe_y[6]=$z2_6; _fe_y[7]=$z2_7; _fe_y[8]=$z2_8; _fe_y[9]=$z2_9
        _fe_sub
        local B0=${_fe_a[0]} B1=${_fe_a[1]} B2=${_fe_a[2]} B3=${_fe_a[3]} B4=${_fe_a[4]}
        local B5=${_fe_a[5]} B6=${_fe_a[6]} B7=${_fe_a[7]} B8=${_fe_a[8]} B9=${_fe_a[9]}

        # BB = B^2
        _fe_x[0]=$B0; _fe_x[1]=$B1; _fe_x[2]=$B2; _fe_x[3]=$B3; _fe_x[4]=$B4
        _fe_x[5]=$B5; _fe_x[6]=$B6; _fe_x[7]=$B7; _fe_x[8]=$B8; _fe_x[9]=$B9
        _fe_sq
        local BB0=${_fe_a[0]} BB1=${_fe_a[1]} BB2=${_fe_a[2]} BB3=${_fe_a[3]} BB4=${_fe_a[4]}
        local BB5=${_fe_a[5]} BB6=${_fe_a[6]} BB7=${_fe_a[7]} BB8=${_fe_a[8]} BB9=${_fe_a[9]}

        # E = AA - BB
        _fe_x[0]=$AA0; _fe_x[1]=$AA1; _fe_x[2]=$AA2; _fe_x[3]=$AA3; _fe_x[4]=$AA4
        _fe_x[5]=$AA5; _fe_x[6]=$AA6; _fe_x[7]=$AA7; _fe_x[8]=$AA8; _fe_x[9]=$AA9
        _fe_y[0]=$BB0; _fe_y[1]=$BB1; _fe_y[2]=$BB2; _fe_y[3]=$BB3; _fe_y[4]=$BB4
        _fe_y[5]=$BB5; _fe_y[6]=$BB6; _fe_y[7]=$BB7; _fe_y[8]=$BB8; _fe_y[9]=$BB9
        _fe_sub
        local E0=${_fe_a[0]} E1=${_fe_a[1]} E2=${_fe_a[2]} E3=${_fe_a[3]} E4=${_fe_a[4]}
        local E5=${_fe_a[5]} E6=${_fe_a[6]} E7=${_fe_a[7]} E8=${_fe_a[8]} E9=${_fe_a[9]}

        # C = x_3 + z_3
        _fe_x[0]=$x3_0; _fe_x[1]=$x3_1; _fe_x[2]=$x3_2; _fe_x[3]=$x3_3; _fe_x[4]=$x3_4
        _fe_x[5]=$x3_5; _fe_x[6]=$x3_6; _fe_x[7]=$x3_7; _fe_x[8]=$x3_8; _fe_x[9]=$x3_9
        _fe_y[0]=$z3_0; _fe_y[1]=$z3_1; _fe_y[2]=$z3_2; _fe_y[3]=$z3_3; _fe_y[4]=$z3_4
        _fe_y[5]=$z3_5; _fe_y[6]=$z3_6; _fe_y[7]=$z3_7; _fe_y[8]=$z3_8; _fe_y[9]=$z3_9
        _fe_add
        local C0=${_fe_a[0]} C1=${_fe_a[1]} C2=${_fe_a[2]} C3=${_fe_a[3]} C4=${_fe_a[4]}
        local C5=${_fe_a[5]} C6=${_fe_a[6]} C7=${_fe_a[7]} C8=${_fe_a[8]} C9=${_fe_a[9]}

        # D = x_3 - z_3
        _fe_x[0]=$x3_0; _fe_x[1]=$x3_1; _fe_x[2]=$x3_2; _fe_x[3]=$x3_3; _fe_x[4]=$x3_4
        _fe_x[5]=$x3_5; _fe_x[6]=$x3_6; _fe_x[7]=$x3_7; _fe_x[8]=$x3_8; _fe_x[9]=$x3_9
        _fe_y[0]=$z3_0; _fe_y[1]=$z3_1; _fe_y[2]=$z3_2; _fe_y[3]=$z3_3; _fe_y[4]=$z3_4
        _fe_y[5]=$z3_5; _fe_y[6]=$z3_6; _fe_y[7]=$z3_7; _fe_y[8]=$z3_8; _fe_y[9]=$z3_9
        _fe_sub
        local D0=${_fe_a[0]} D1=${_fe_a[1]} D2=${_fe_a[2]} D3=${_fe_a[3]} D4=${_fe_a[4]}
        local D5=${_fe_a[5]} D6=${_fe_a[6]} D7=${_fe_a[7]} D8=${_fe_a[8]} D9=${_fe_a[9]}

        # DA = D * A
        _fe_x[0]=$D0; _fe_x[1]=$D1; _fe_x[2]=$D2; _fe_x[3]=$D3; _fe_x[4]=$D4
        _fe_x[5]=$D5; _fe_x[6]=$D6; _fe_x[7]=$D7; _fe_x[8]=$D8; _fe_x[9]=$D9
        _fe_y[0]=$A0; _fe_y[1]=$A1; _fe_y[2]=$A2; _fe_y[3]=$A3; _fe_y[4]=$A4
        _fe_y[5]=$A5; _fe_y[6]=$A6; _fe_y[7]=$A7; _fe_y[8]=$A8; _fe_y[9]=$A9
        _fe_mul
        local DA0=${_fe_a[0]} DA1=${_fe_a[1]} DA2=${_fe_a[2]} DA3=${_fe_a[3]} DA4=${_fe_a[4]}
        local DA5=${_fe_a[5]} DA6=${_fe_a[6]} DA7=${_fe_a[7]} DA8=${_fe_a[8]} DA9=${_fe_a[9]}

        # CB = C * B
        _fe_x[0]=$C0; _fe_x[1]=$C1; _fe_x[2]=$C2; _fe_x[3]=$C3; _fe_x[4]=$C4
        _fe_x[5]=$C5; _fe_x[6]=$C6; _fe_x[7]=$C7; _fe_x[8]=$C8; _fe_x[9]=$C9
        _fe_y[0]=$B0; _fe_y[1]=$B1; _fe_y[2]=$B2; _fe_y[3]=$B3; _fe_y[4]=$B4
        _fe_y[5]=$B5; _fe_y[6]=$B6; _fe_y[7]=$B7; _fe_y[8]=$B8; _fe_y[9]=$B9
        _fe_mul
        local CB0=${_fe_a[0]} CB1=${_fe_a[1]} CB2=${_fe_a[2]} CB3=${_fe_a[3]} CB4=${_fe_a[4]}
        local CB5=${_fe_a[5]} CB6=${_fe_a[6]} CB7=${_fe_a[7]} CB8=${_fe_a[8]} CB9=${_fe_a[9]}

        # x_3 = (DA + CB)^2
        _fe_x[0]=$DA0; _fe_x[1]=$DA1; _fe_x[2]=$DA2; _fe_x[3]=$DA3; _fe_x[4]=$DA4
        _fe_x[5]=$DA5; _fe_x[6]=$DA6; _fe_x[7]=$DA7; _fe_x[8]=$DA8; _fe_x[9]=$DA9
        _fe_y[0]=$CB0; _fe_y[1]=$CB1; _fe_y[2]=$CB2; _fe_y[3]=$CB3; _fe_y[4]=$CB4
        _fe_y[5]=$CB5; _fe_y[6]=$CB6; _fe_y[7]=$CB7; _fe_y[8]=$CB8; _fe_y[9]=$CB9
        _fe_add
        _fe_x[0]=${_fe_a[0]}; _fe_x[1]=${_fe_a[1]}; _fe_x[2]=${_fe_a[2]}; _fe_x[3]=${_fe_a[3]}; _fe_x[4]=${_fe_a[4]}
        _fe_x[5]=${_fe_a[5]}; _fe_x[6]=${_fe_a[6]}; _fe_x[7]=${_fe_a[7]}; _fe_x[8]=${_fe_a[8]}; _fe_x[9]=${_fe_a[9]}
        _fe_sq
        x3_0=${_fe_a[0]}; x3_1=${_fe_a[1]}; x3_2=${_fe_a[2]}; x3_3=${_fe_a[3]}; x3_4=${_fe_a[4]}
        x3_5=${_fe_a[5]}; x3_6=${_fe_a[6]}; x3_7=${_fe_a[7]}; x3_8=${_fe_a[8]}; x3_9=${_fe_a[9]}

        # z_3 = u * (DA - CB)^2
        _fe_x[0]=$DA0; _fe_x[1]=$DA1; _fe_x[2]=$DA2; _fe_x[3]=$DA3; _fe_x[4]=$DA4
        _fe_x[5]=$DA5; _fe_x[6]=$DA6; _fe_x[7]=$DA7; _fe_x[8]=$DA8; _fe_x[9]=$DA9
        _fe_y[0]=$CB0; _fe_y[1]=$CB1; _fe_y[2]=$CB2; _fe_y[3]=$CB3; _fe_y[4]=$CB4
        _fe_y[5]=$CB5; _fe_y[6]=$CB6; _fe_y[7]=$CB7; _fe_y[8]=$CB8; _fe_y[9]=$CB9
        _fe_sub
        _fe_x[0]=${_fe_a[0]}; _fe_x[1]=${_fe_a[1]}; _fe_x[2]=${_fe_a[2]}; _fe_x[3]=${_fe_a[3]}; _fe_x[4]=${_fe_a[4]}
        _fe_x[5]=${_fe_a[5]}; _fe_x[6]=${_fe_a[6]}; _fe_x[7]=${_fe_a[7]}; _fe_x[8]=${_fe_a[8]}; _fe_x[9]=${_fe_a[9]}
        _fe_sq
        _fe_x[0]=${_fe_a[0]}; _fe_x[1]=${_fe_a[1]}; _fe_x[2]=${_fe_a[2]}; _fe_x[3]=${_fe_a[3]}; _fe_x[4]=${_fe_a[4]}
        _fe_x[5]=${_fe_a[5]}; _fe_x[6]=${_fe_a[6]}; _fe_x[7]=${_fe_a[7]}; _fe_x[8]=${_fe_a[8]}; _fe_x[9]=${_fe_a[9]}
        _fe_y[0]=$u0; _fe_y[1]=$u1; _fe_y[2]=$u2; _fe_y[3]=$u3; _fe_y[4]=$u4
        _fe_y[5]=$u5; _fe_y[6]=$u6; _fe_y[7]=$u7; _fe_y[8]=$u8; _fe_y[9]=$u9
        _fe_mul
        z3_0=${_fe_a[0]}; z3_1=${_fe_a[1]}; z3_2=${_fe_a[2]}; z3_3=${_fe_a[3]}; z3_4=${_fe_a[4]}
        z3_5=${_fe_a[5]}; z3_6=${_fe_a[6]}; z3_7=${_fe_a[7]}; z3_8=${_fe_a[8]}; z3_9=${_fe_a[9]}

        # x_2 = AA * BB
        _fe_x[0]=$AA0; _fe_x[1]=$AA1; _fe_x[2]=$AA2; _fe_x[3]=$AA3; _fe_x[4]=$AA4
        _fe_x[5]=$AA5; _fe_x[6]=$AA6; _fe_x[7]=$AA7; _fe_x[8]=$AA8; _fe_x[9]=$AA9
        _fe_y[0]=$BB0; _fe_y[1]=$BB1; _fe_y[2]=$BB2; _fe_y[3]=$BB3; _fe_y[4]=$BB4
        _fe_y[5]=$BB5; _fe_y[6]=$BB6; _fe_y[7]=$BB7; _fe_y[8]=$BB8; _fe_y[9]=$BB9
        _fe_mul
        x2_0=${_fe_a[0]}; x2_1=${_fe_a[1]}; x2_2=${_fe_a[2]}; x2_3=${_fe_a[3]}; x2_4=${_fe_a[4]}
        x2_5=${_fe_a[5]}; x2_6=${_fe_a[6]}; x2_7=${_fe_a[7]}; x2_8=${_fe_a[8]}; x2_9=${_fe_a[9]}

        # z_2 = E * (AA + a24 * E) where a24 = 121665
        local aE0=$((E0 * 121665)) aE1=$((E1 * 121665)) aE2=$((E2 * 121665))
        local aE3=$((E3 * 121665)) aE4=$((E4 * 121665)) aE5=$((E5 * 121665))
        local aE6=$((E6 * 121665)) aE7=$((E7 * 121665)) aE8=$((E8 * 121665))
        local aE9=$((E9 * 121665))
        local carry
        carry=$((aE0 >> 26)); aE0=$((aE0 & 0x3FFFFFF)); aE1=$((aE1 + carry))
        carry=$((aE1 >> 25)); aE1=$((aE1 & 0x1FFFFFF)); aE2=$((aE2 + carry))
        carry=$((aE2 >> 26)); aE2=$((aE2 & 0x3FFFFFF)); aE3=$((aE3 + carry))
        carry=$((aE3 >> 25)); aE3=$((aE3 & 0x1FFFFFF)); aE4=$((aE4 + carry))
        carry=$((aE4 >> 26)); aE4=$((aE4 & 0x3FFFFFF)); aE5=$((aE5 + carry))
        carry=$((aE5 >> 25)); aE5=$((aE5 & 0x1FFFFFF)); aE6=$((aE6 + carry))
        carry=$((aE6 >> 26)); aE6=$((aE6 & 0x3FFFFFF)); aE7=$((aE7 + carry))
        carry=$((aE7 >> 25)); aE7=$((aE7 & 0x1FFFFFF)); aE8=$((aE8 + carry))
        carry=$((aE8 >> 26)); aE8=$((aE8 & 0x3FFFFFF)); aE9=$((aE9 + carry))
        carry=$((aE9 >> 25)); aE9=$((aE9 & 0x1FFFFFF)); aE0=$((aE0 + carry * 19))

        _fe_x[0]=$AA0; _fe_x[1]=$AA1; _fe_x[2]=$AA2; _fe_x[3]=$AA3; _fe_x[4]=$AA4
        _fe_x[5]=$AA5; _fe_x[6]=$AA6; _fe_x[7]=$AA7; _fe_x[8]=$AA8; _fe_x[9]=$AA9
        _fe_y[0]=$aE0; _fe_y[1]=$aE1; _fe_y[2]=$aE2; _fe_y[3]=$aE3; _fe_y[4]=$aE4
        _fe_y[5]=$aE5; _fe_y[6]=$aE6; _fe_y[7]=$aE7; _fe_y[8]=$aE8; _fe_y[9]=$aE9
        _fe_add
        _fe_y[0]=${_fe_a[0]}; _fe_y[1]=${_fe_a[1]}; _fe_y[2]=${_fe_a[2]}; _fe_y[3]=${_fe_a[3]}; _fe_y[4]=${_fe_a[4]}
        _fe_y[5]=${_fe_a[5]}; _fe_y[6]=${_fe_a[6]}; _fe_y[7]=${_fe_a[7]}; _fe_y[8]=${_fe_a[8]}; _fe_y[9]=${_fe_a[9]}
        _fe_x[0]=$E0; _fe_x[1]=$E1; _fe_x[2]=$E2; _fe_x[3]=$E3; _fe_x[4]=$E4
        _fe_x[5]=$E5; _fe_x[6]=$E6; _fe_x[7]=$E7; _fe_x[8]=$E8; _fe_x[9]=$E9
        _fe_mul
        z2_0=${_fe_a[0]}; z2_1=${_fe_a[1]}; z2_2=${_fe_a[2]}; z2_3=${_fe_a[3]}; z2_4=${_fe_a[4]}
        z2_5=${_fe_a[5]}; z2_6=${_fe_a[6]}; z2_7=${_fe_a[7]}; z2_8=${_fe_a[8]}; z2_9=${_fe_a[9]}

        bit=$((bit - 1))
    done

    # Final conditional swap
    if [ $swap -ne 0 ]; then
        local tmp
        tmp=$x2_0; x2_0=$x3_0; x3_0=$tmp; tmp=$x2_1; x2_1=$x3_1; x3_1=$tmp
        tmp=$x2_2; x2_2=$x3_2; x3_2=$tmp; tmp=$x2_3; x2_3=$x3_3; x3_3=$tmp
        tmp=$x2_4; x2_4=$x3_4; x3_4=$tmp; tmp=$x2_5; x2_5=$x3_5; x3_5=$tmp
        tmp=$x2_6; x2_6=$x3_6; x3_6=$tmp; tmp=$x2_7; x2_7=$x3_7; x3_7=$tmp
        tmp=$x2_8; x2_8=$x3_8; x3_8=$tmp; tmp=$x2_9; x2_9=$x3_9; x3_9=$tmp
        tmp=$z2_0; z2_0=$z3_0; z3_0=$tmp; tmp=$z2_1; z2_1=$z3_1; z3_1=$tmp
        tmp=$z2_2; z2_2=$z3_2; z3_2=$tmp; tmp=$z2_3; z2_3=$z3_3; z3_3=$tmp
        tmp=$z2_4; z2_4=$z3_4; z3_4=$tmp; tmp=$z2_5; z2_5=$z3_5; z3_5=$tmp
        tmp=$z2_6; z2_6=$z3_6; z3_6=$tmp; tmp=$z2_7; z2_7=$z3_7; z3_7=$tmp
        tmp=$z2_8; z2_8=$z3_8; z3_8=$tmp; tmp=$z2_9; z2_9=$z3_9; z3_9=$tmp
    fi

    # Result = x_2 * z_2^(-1)
    _fe_x[0]=$z2_0; _fe_x[1]=$z2_1; _fe_x[2]=$z2_2; _fe_x[3]=$z2_3; _fe_x[4]=$z2_4
    _fe_x[5]=$z2_5; _fe_x[6]=$z2_6; _fe_x[7]=$z2_7; _fe_x[8]=$z2_8; _fe_x[9]=$z2_9
    _fe_inv
    local zi0=${_fe_a[0]} zi1=${_fe_a[1]} zi2=${_fe_a[2]} zi3=${_fe_a[3]} zi4=${_fe_a[4]}
    local zi5=${_fe_a[5]} zi6=${_fe_a[6]} zi7=${_fe_a[7]} zi8=${_fe_a[8]} zi9=${_fe_a[9]}

    _fe_x[0]=$x2_0; _fe_x[1]=$x2_1; _fe_x[2]=$x2_2; _fe_x[3]=$x2_3; _fe_x[4]=$x2_4
    _fe_x[5]=$x2_5; _fe_x[6]=$x2_6; _fe_x[7]=$x2_7; _fe_x[8]=$x2_8; _fe_x[9]=$x2_9
    _fe_y[0]=$zi0; _fe_y[1]=$zi1; _fe_y[2]=$zi2; _fe_y[3]=$zi3; _fe_y[4]=$zi4
    _fe_y[5]=$zi5; _fe_y[6]=$zi6; _fe_y[7]=$zi7; _fe_y[8]=$zi8; _fe_y[9]=$zi9
    _fe_mul
    _fe_pack
}

# x25519_base <scalar_hex> - Compute public key: X25519(scalar, 9)
x25519_base() {
    local scalar="$1"
    local basepoint="0900000000000000000000000000000000000000000000000000000000000000"
    x25519 "$scalar" "$basepoint"
}
