#!/usr/bin/env bash
# x25519.sh - X25519 Diffie-Hellman key exchange (RFC 7748)
# Implements Curve25519 scalar multiplication using the Montgomery ladder.
#
# Field: GF(2^255 - 19), represented as 16 limbs of 16 bits each (256 bits total).
# The final reduce step ensures the value is < 2^255 - 19.
#
# Reference: RFC 7748, Monocypher (public domain), TweetNaCl (public domain)

# Number of limbs (16 x 16-bit = 256 bits)
_X25519_LIMBS=16

# p = 2^255 - 19, stored as 16 limbs (little-endian, 16 bits each)
# p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
_x25519_p=(65517 65535 65535 65535 65535 65535 65535 65535 65535 65535 65535 65535 65535 65535 65535 32767)

# _fe_unpack <hex_32bytes> - Unpack 32-byte little-endian hex into limb array
# Sets global _fe_result[] (16 limbs)
_fe_unpack() {
    local hex="$1"
    _fe_result=()
    # Input is 32 bytes in wire order. X25519 uses little-endian.
    # Each limb is 2 bytes (16 bits), little-endian
    local i=0
    while [ $i -lt 16 ]; do
        local offset=$((i * 4))
        local b0=$((16#${hex:$offset:2}))
        local b1=$((16#${hex:$((offset+2)):2}))
        _fe_result[$i]=$(( b0 | (b1 << 8) ))
        i=$((i + 1))
    done
}

# _fe_pack <limb_array_name> - Pack limbs back to 32-byte little-endian hex
# Reads from _fe_a[] and outputs 64-char hex string
_fe_pack() {
    # First, fully reduce mod p
    _fe_reduce
    local result=""
    local i=0
    while [ $i -lt 16 ]; do
        local v=${_fe_a[$i]}
        result="${result}$(printf '%02x%02x' $((v & 0xFF)) $(((v >> 8) & 0xFF)))"
        i=$((i + 1))
    done
    printf '%s' "$result"
}

# _fe_reduce - Reduce _fe_a[] mod p (2^255 - 19)
_fe_reduce() {
    # Carry propagation
    local i=0
    while [ $i -lt 15 ]; do
        local carry=$(( ${_fe_a[$i]} >> 16 ))
        _fe_a[$i]=$(( ${_fe_a[$i]} & 0xFFFF ))
        _fe_a[$((i+1))]=$(( ${_fe_a[$((i+1))]} + carry ))
        i=$((i + 1))
    done
    # Top limb: carry wraps with factor 19 (since 2^256 ≡ 2*19 = 38 mod p,
    # but we have 2^255 ≡ 19 mod p; top limb bit 15 = 2^255)
    local carry=$(( ${_fe_a[15]} >> 15 ))
    _fe_a[15]=$(( ${_fe_a[15]} & 0x7FFF ))
    _fe_a[0]=$(( ${_fe_a[0]} + carry * 19 ))

    # Propagate again
    i=0
    while [ $i -lt 15 ]; do
        carry=$(( ${_fe_a[$i]} >> 16 ))
        _fe_a[$i]=$(( ${_fe_a[$i]} & 0xFFFF ))
        _fe_a[$((i+1))]=$(( ${_fe_a[$((i+1))]} + carry ))
        i=$((i + 1))
    done
    carry=$(( ${_fe_a[15]} >> 15 ))
    _fe_a[15]=$(( ${_fe_a[15]} & 0x7FFF ))
    _fe_a[0]=$(( ${_fe_a[0]} + carry * 19 ))

    # Final carry
    i=0
    while [ $i -lt 15 ]; do
        carry=$(( ${_fe_a[$i]} >> 16 ))
        _fe_a[$i]=$(( ${_fe_a[$i]} & 0xFFFF ))
        _fe_a[$((i+1))]=$(( ${_fe_a[$((i+1))]} + carry ))
        i=$((i + 1))
    done

    # Conditional subtraction of p if >= p
    # Check if _fe_a >= p by subtracting p and checking borrow
    local t=()
    local borrow=0
    i=0
    while [ $i -lt 16 ]; do
        local diff=$(( ${_fe_a[$i]} - ${_x25519_p[$i]} - borrow ))
        if [ $diff -lt 0 ]; then
            diff=$((diff + 65536))
            borrow=1
        else
            borrow=0
        fi
        t[$i]=$diff
        i=$((i + 1))
    done
    # If no borrow, a >= p, use t; otherwise keep a
    if [ $borrow -eq 0 ]; then
        i=0
        while [ $i -lt 16 ]; do
            _fe_a[$i]=${t[$i]}
            i=$((i + 1))
        done
    fi
}

# _fe_add <a[]> <b[]> -> _fe_a[] = a + b
# Reads from _fe_x[] and _fe_y[], stores in _fe_a[]
_fe_add() {
    local i=0
    while [ $i -lt 16 ]; do
        _fe_a[$i]=$(( ${_fe_x[$i]} + ${_fe_y[$i]} ))
        i=$((i + 1))
    done
}

# _fe_sub <a[]> <b[]> -> _fe_a[] = a - b (mod p)
# Reads from _fe_x[] and _fe_y[], stores in _fe_a[]
_fe_sub() {
    # Add 2*p to avoid negative values before subtraction
    local i=0
    while [ $i -lt 16 ]; do
        _fe_a[$i]=$(( ${_fe_x[$i]} - ${_fe_y[$i]} + 2 * ${_x25519_p[$i]} ))
        i=$((i + 1))
    done
}

# _fe_mul -> _fe_a[] = _fe_x[] * _fe_y[]
# Uses 16x16-bit limb multiplication. Products fit in 64-bit integers.
_fe_mul() {
    local t=()
    local i=0
    while [ $i -lt 31 ]; do
        t[$i]=0
        i=$((i + 1))
    done

    i=0
    while [ $i -lt 16 ]; do
        local j=0
        while [ $j -lt 16 ]; do
            t[$((i+j))]=$(( ${t[$((i+j))]} + ${_fe_x[$i]} * ${_fe_y[$j]} ))
            j=$((j + 1))
        done
        i=$((i + 1))
    done

    # Reduce: limbs 16..30 fold back with factor 38
    # Since 2^256 = 2^(16*16) ≡ 38 (mod p) [because 2^256 = 2 * 2^255 = 2*(p+19) = 2p+38 ≡ 38]
    i=0
    while [ $i -lt 15 ]; do
        t[$i]=$(( ${t[$i]} + 38 * ${t[$((i+16))]} ))
        i=$((i + 1))
    done
    # Limb 15 is special: it gets t[31] doesn't exist (only 31 product limbs max)
    # Actually products go up to index 30 (i+j max = 15+15=30)
    t[15]=$(( ${t[15]} + 38 * ${t[31]:-0} ))

    # Carry propagation
    i=0
    while [ $i -lt 15 ]; do
        local carry=$(( ${t[$i]} >> 16 ))
        t[$i]=$(( ${t[$i]} & 0xFFFF ))
        t[$((i+1))]=$(( ${t[$((i+1))]} + carry ))
        i=$((i + 1))
    done
    local carry=$(( ${t[15]} >> 15 ))
    t[15]=$(( ${t[15]} & 0x7FFF ))
    t[0]=$(( ${t[0]} + carry * 19 ))
    # One more carry from t[0]
    carry=$(( ${t[0]} >> 16 ))
    t[0]=$(( ${t[0]} & 0xFFFF ))
    t[1]=$(( ${t[1]} + carry ))

    i=0
    while [ $i -lt 16 ]; do
        _fe_a[$i]=${t[$i]}
        i=$((i + 1))
    done
}

# _fe_sq -> _fe_a[] = _fe_x[] ^ 2
# Squaring is just mul with x==y
_fe_sq() {
    local i=0
    while [ $i -lt 16 ]; do
        _fe_y[$i]=${_fe_x[$i]}
        i=$((i + 1))
    done
    _fe_mul
}

# _fe_inv -> _fe_a[] = _fe_x[] ^ (-1) mod p
# Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p
# p-2 = 2^255 - 21
_fe_inv() {
    # Save input
    local input=()
    local i=0
    while [ $i -lt 16 ]; do
        input[$i]=${_fe_x[$i]}
        i=$((i + 1))
    done

    # Compute z^(2^255 - 21) using repeated squaring
    # Strategy: compute z^(p-2) via addition chain
    # z2 = z^2
    _fe_sq
    local z2=()
    i=0; while [ $i -lt 16 ]; do z2[$i]=${_fe_a[$i]}; i=$((i+1)); done

    # z9: z^9
    # z^4
    i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${z2[$i]}; i=$((i+1)); done
    _fe_sq
    local z4=()
    i=0; while [ $i -lt 16 ]; do z4[$i]=${_fe_a[$i]}; i=$((i+1)); done

    # z^8
    i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${z4[$i]}; i=$((i+1)); done
    _fe_sq
    local z8=()
    i=0; while [ $i -lt 16 ]; do z8[$i]=${_fe_a[$i]}; i=$((i+1)); done

    # z^9 = z^8 * z
    i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${z8[$i]}; _fe_y[$i]=${input[$i]}; i=$((i+1)); done
    _fe_mul
    local z9=()
    i=0; while [ $i -lt 16 ]; do z9[$i]=${_fe_a[$i]}; i=$((i+1)); done

    # z^11 = z^9 * z^2
    i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${z9[$i]}; _fe_y[$i]=${z2[$i]}; i=$((i+1)); done
    _fe_mul
    local z11=()
    i=0; while [ $i -lt 16 ]; do z11[$i]=${_fe_a[$i]}; i=$((i+1)); done

    # z^(2^5 - 1) = z^31 = (z^11)^(2^1) * z^9 ... let me use a simpler approach
    # Actually, the standard approach for Curve25519 inversion uses:
    #   z^(p-2) via a carefully constructed addition chain.
    # Let me use a simpler (but slower) method: square-and-multiply over the bits of p-2.

    # p-2 = 2^255 - 21 = 2^255 - 16 - 4 - 1
    # In binary: 0111...1101011 (255 bits)
    # Let's compute it bit-by-bit using repeated squaring

    # Convert p-2 to binary (255 bits): all 1s except bits 0, 2, 4 are ... wait
    # p = 2^255 - 19, p-2 = 2^255 - 21
    # 21 = 10101 in binary
    # So p-2 in binary is: 0 followed by 250 ones, then 01011
    # Actually: 2^255 - 21 = (2^255 - 1) - 20
    # Binary of 2^255-1: 255 ones
    # 20 = 10100, so we flip bits 2 and 4 (counting from 0)
    # p-2 = 111...11101011 (255 bits with bits 2 and 4 = 0)

    # Exponent bits (MSB first): bit 254 down to bit 0
    # Bit 254 = 0 (since 2^255-21 < 2^255, the 255th bit is 0... wait)
    # 2^255 - 21: the highest bit is bit 254 (value 2^254 is set since 2^255-21 > 2^254)
    # Actually 2^255 - 21 in binary: bit 254 is 1, ..., bit 5 is 1, bit 4 is 0,
    # bit 3 is 1, bit 2 is 0, bit 1 is 1, bit 0 is 1
    # Because 2^255 - 21 = 2^255 - 10101_2
    # = 0_1 followed by 249 ones, then 01011

    # Let me just use the naive square-and-multiply with the hex representation.
    # p-2 in hex: 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
    local exp_hex="7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb"

    # Start with result = 1
    local result=()
    i=0; while [ $i -lt 16 ]; do result[$i]=0; i=$((i+1)); done
    result[0]=1

    # Square-and-multiply, MSB first (252 hex digits = 1008 bits, but we use 255 bits)
    # Process 64 hex chars = 256 bits, skip the top bit (always 0 for our exponent)
    local bit=254  # Start from bit 254 (MSB of 255-bit number)
    while [ $bit -ge 0 ]; do
        # Square
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${result[$i]}; i=$((i+1)); done
        _fe_sq
        i=0; while [ $i -lt 16 ]; do result[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # Check if bit is set in exponent
        local hex_idx=$(( (254 - bit) / 4 ))
        local bit_in_nibble=$(( 3 - (bit % 4) ))
        # Wait, we need to index from MSB. Let me reconsider.
        # exp_hex has 64 chars. Char 0 is the highest nibble.
        # bit 255 would be the highest bit of char 0, but our number is 255 bits
        # so bit 254 is the MSB.
        # Char index for bit b: (254-b)/4 ... not quite.
        # The hex is big-endian. Char 0 = bits 255..252, char 1 = bits 251..248, etc.
        # Char 63 = bits 3..0
        # For bit b: char index = (255-b)/4 ... let me think again
        # Actually with 256 bits (64 hex chars):
        # char 0 covers bits 255-252, char 63 covers bits 3-0
        # bit b is in char (255-b)/4, position (255-b)%4 within that char (0=MSB of nibble)
        local char_idx=$(( (255 - bit) / 4 ))
        local bit_in_char=$(( (255 - bit) % 4 ))
        local nibble=$((16#${exp_hex:$char_idx:1}))
        local bit_val=$(( (nibble >> (3 - bit_in_char)) & 1 ))

        if [ $bit_val -eq 1 ]; then
            # Multiply by input
            i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${result[$i]}; _fe_y[$i]=${input[$i]}; i=$((i+1)); done
            _fe_mul
            i=0; while [ $i -lt 16 ]; do result[$i]=${_fe_a[$i]}; i=$((i+1)); done
        fi

        bit=$((bit - 1))
    done

    i=0; while [ $i -lt 16 ]; do _fe_a[$i]=${result[$i]}; i=$((i+1)); done
}

# _x25519_clamp <scalar_hex> - Apply clamping to scalar (RFC 7748 Section 5)
_x25519_clamp() {
    local hex="$1"
    # Clamp: clear bits 0,1,2 of first byte; clear bit 7 and set bit 6 of last byte
    local b0=$((16#${hex:0:2}))
    local b31=$((16#${hex:62:2}))
    b0=$(( b0 & 248 ))        # Clear bottom 3 bits
    b31=$(( (b31 & 127) | 64 ))  # Clear bit 7, set bit 6
    printf '%02x%s%02x' "$b0" "${hex:2:60}" "$b31"
}

# x25519 <scalar_hex_32bytes> <u_coord_hex_32bytes> - Scalar multiplication
# Both inputs are 32-byte little-endian hex strings.
# Returns 32-byte little-endian hex result.
x25519() {
    local scalar_hex
    scalar_hex=$(_x25519_clamp "$1")
    local u_hex="$2"

    # Unpack u-coordinate, reduce to 255 bits (clear top bit)
    _fe_unpack "$u_hex"
    local u=()
    local i=0
    while [ $i -lt 16 ]; do
        u[$i]=${_fe_result[$i]}
        i=$((i + 1))
    done
    u[15]=$((${u[15]} & 0x7FFF))

    # Montgomery ladder
    # x_1 = u, x_2 = 1, z_2 = 0, x_3 = u, z_3 = 1
    local x_2=() z_2=() x_3=() z_3=()
    i=0; while [ $i -lt 16 ]; do x_2[$i]=0; z_2[$i]=0; x_3[$i]=${u[$i]}; z_3[$i]=0; i=$((i+1)); done
    x_2[0]=1
    z_3[0]=1

    local swap=0
    local bit=254
    while [ $bit -ge 0 ]; do
        # Get bit of scalar
        local byte_idx=$(( bit / 8 ))
        local bit_idx=$(( bit % 8 ))
        local byte_hex="${scalar_hex:$((byte_idx * 2)):2}"
        local k_t=$(( (16#$byte_hex >> bit_idx) & 1 ))

        # Conditional swap
        swap=$((swap ^ k_t))
        if [ $swap -ne 0 ]; then
            local tmp
            i=0; while [ $i -lt 16 ]; do
                tmp=${x_2[$i]}; x_2[$i]=${x_3[$i]}; x_3[$i]=$tmp
                tmp=${z_2[$i]}; z_2[$i]=${z_3[$i]}; z_3[$i]=$tmp
            i=$((i+1)); done
        fi
        swap=$k_t

        # A = x_2 + z_2
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${x_2[$i]}; _fe_y[$i]=${z_2[$i]}; i=$((i+1)); done
        _fe_add
        local A=()
        i=0; while [ $i -lt 16 ]; do A[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # AA = A^2
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${A[$i]}; i=$((i+1)); done
        _fe_sq
        local AA=()
        i=0; while [ $i -lt 16 ]; do AA[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # B = x_2 - z_2
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${x_2[$i]}; _fe_y[$i]=${z_2[$i]}; i=$((i+1)); done
        _fe_sub
        local B=()
        i=0; while [ $i -lt 16 ]; do B[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # BB = B^2
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${B[$i]}; i=$((i+1)); done
        _fe_sq
        local BB=()
        i=0; while [ $i -lt 16 ]; do BB[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # E = AA - BB
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${AA[$i]}; _fe_y[$i]=${BB[$i]}; i=$((i+1)); done
        _fe_sub
        local E=()
        i=0; while [ $i -lt 16 ]; do E[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # C = x_3 + z_3
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${x_3[$i]}; _fe_y[$i]=${z_3[$i]}; i=$((i+1)); done
        _fe_add
        local C=()
        i=0; while [ $i -lt 16 ]; do C[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # D = x_3 - z_3
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${x_3[$i]}; _fe_y[$i]=${z_3[$i]}; i=$((i+1)); done
        _fe_sub
        local D=()
        i=0; while [ $i -lt 16 ]; do D[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # DA = D * A
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${D[$i]}; _fe_y[$i]=${A[$i]}; i=$((i+1)); done
        _fe_mul
        local DA=()
        i=0; while [ $i -lt 16 ]; do DA[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # CB = C * B
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${C[$i]}; _fe_y[$i]=${B[$i]}; i=$((i+1)); done
        _fe_mul
        local CB=()
        i=0; while [ $i -lt 16 ]; do CB[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # x_3 = (DA + CB)^2
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${DA[$i]}; _fe_y[$i]=${CB[$i]}; i=$((i+1)); done
        _fe_add
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${_fe_a[$i]}; i=$((i+1)); done
        _fe_sq
        i=0; while [ $i -lt 16 ]; do x_3[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # z_3 = x_1 * (DA - CB)^2
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${DA[$i]}; _fe_y[$i]=${CB[$i]}; i=$((i+1)); done
        _fe_sub
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${_fe_a[$i]}; i=$((i+1)); done
        _fe_sq
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${_fe_a[$i]}; _fe_y[$i]=${u[$i]}; i=$((i+1)); done
        _fe_mul
        i=0; while [ $i -lt 16 ]; do z_3[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # x_2 = AA * BB
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${AA[$i]}; _fe_y[$i]=${BB[$i]}; i=$((i+1)); done
        _fe_mul
        i=0; while [ $i -lt 16 ]; do x_2[$i]=${_fe_a[$i]}; i=$((i+1)); done

        # z_2 = E * (AA + a24 * E)   where a24 = 121665
        # a24 * E: multiply each limb by 121665
        local aE=()
        i=0; while [ $i -lt 16 ]; do aE[$i]=$(( ${E[$i]} * 121665 )); i=$((i+1)); done
        # Carry propagation on aE
        i=0
        while [ $i -lt 15 ]; do
            local carry=$(( ${aE[$i]} >> 16 ))
            aE[$i]=$(( ${aE[$i]} & 0xFFFF ))
            aE[$((i+1))]=$(( ${aE[$((i+1))]} + carry ))
            i=$((i + 1))
        done
        local carry=$(( ${aE[15]} >> 15 ))
        aE[15]=$(( ${aE[15]} & 0x7FFF ))
        aE[0]=$(( ${aE[0]} + carry * 19 ))

        # AA + a24*E
        i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${AA[$i]}; _fe_y[$i]=${aE[$i]}; i=$((i+1)); done
        _fe_add
        # z_2 = E * result
        i=0; while [ $i -lt 16 ]; do _fe_y[$i]=${_fe_a[$i]}; _fe_x[$i]=${E[$i]}; i=$((i+1)); done
        _fe_mul
        i=0; while [ $i -lt 16 ]; do z_2[$i]=${_fe_a[$i]}; i=$((i+1)); done

        bit=$((bit - 1))
    done

    # Final conditional swap
    if [ $swap -ne 0 ]; then
        i=0; while [ $i -lt 16 ]; do
            local tmp=${x_2[$i]}; x_2[$i]=${x_3[$i]}; x_3[$i]=$tmp
            tmp=${z_2[$i]}; z_2[$i]=${z_3[$i]}; z_3[$i]=$tmp
        i=$((i+1)); done
    fi

    # Result = x_2 * z_2^(-1)
    i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${z_2[$i]}; i=$((i+1)); done
    _fe_inv
    local z_inv=()
    i=0; while [ $i -lt 16 ]; do z_inv[$i]=${_fe_a[$i]}; i=$((i+1)); done

    i=0; while [ $i -lt 16 ]; do _fe_x[$i]=${x_2[$i]}; _fe_y[$i]=${z_inv[$i]}; i=$((i+1)); done
    _fe_mul
    _fe_pack
}

# x25519_base <scalar_hex> - Compute public key: X25519(scalar, 9)
# The basepoint for Curve25519 is u=9.
x25519_base() {
    local scalar="$1"
    local basepoint="0900000000000000000000000000000000000000000000000000000000000000"
    x25519 "$scalar" "$basepoint"
}
