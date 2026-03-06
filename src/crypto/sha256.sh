#!/usr/bin/env bash
# sha256.sh - SHA-256 hash (FIPS 180-4)
# Pure shell implementation operating on hex strings.
# Reference: FIPS PUB 180-4, August 2015
#
# Performance: all operations inlined to avoid subshell overhead.

# SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
_sha256_k=(
    0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
    0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
    0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
    0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
    0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
    0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
    0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
    0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2
)

# _sha256_compress <block_hex_128chars> <h0..h7 as space-separated>
# Outputs updated h0..h7 as space-separated integers.
# All operations are inlined to avoid subshell fork overhead.
_sha256_compress() {
    local block="$1"
    shift
    local h0=$1 h1=$2 h2=$3 h3=$4 h4=$5 h5=$6 h6=$7 h7=$8

    # Prepare message schedule W[0..63]
    local w=()
    local i=0
    while [ $i -lt 16 ]; do
        w[$i]=$((16#${block:$((i*8)):8}))
        i=$((i + 1))
    done
    while [ $i -lt 64 ]; do
        # Inline gamma1(w[i-2]): rotr17 ^ rotr19 ^ shr10
        local _wt=${w[$((i-2))]}
        _wt=$(( _wt & 0xFFFFFFFF ))
        local _g1=$(( (((_wt >> 17) | (_wt << 15)) ^ ((_wt >> 19) | (_wt << 13)) ^ (_wt >> 10)) & 0xFFFFFFFF ))
        # Inline gamma0(w[i-15]): rotr7 ^ rotr18 ^ shr3
        _wt=${w[$((i-15))]}
        _wt=$(( _wt & 0xFFFFFFFF ))
        local _g0=$(( (((_wt >> 7) | (_wt << 25)) ^ ((_wt >> 18) | (_wt << 14)) ^ (_wt >> 3)) & 0xFFFFFFFF ))
        w[$i]=$(( (_g1 + w[$((i-7))] + _g0 + w[$((i-16))]) & 0xFFFFFFFF ))
        i=$((i + 1))
    done

    # Working variables
    local a=$h0 b=$h1 c=$h2 d=$h3 e=$h4 f=$h5 g=$h6 h=$h7

    # 64 rounds - all helper functions inlined
    i=0
    while [ $i -lt 64 ]; do
        # Inline sigma1(e): rotr6(e) ^ rotr11(e) ^ rotr25(e)
        local _ev=$(( e & 0xFFFFFFFF ))
        local _s1=$(( (((_ev >> 6) | (_ev << 26)) ^ ((_ev >> 11) | (_ev << 21)) ^ ((_ev >> 25) | (_ev << 7))) & 0xFFFFFFFF ))
        # Inline ch(e,f,g): (e & f) ^ (~e & g)
        local _ch=$(( ((_ev & f) ^ ((~_ev) & g)) & 0xFFFFFFFF ))
        local _t1=$(( (h + _s1 + _ch + ${_sha256_k[$i]} + ${w[$i]}) & 0xFFFFFFFF ))
        # Inline sigma0(a): rotr2(a) ^ rotr13(a) ^ rotr22(a)
        local _av=$(( a & 0xFFFFFFFF ))
        local _s0=$(( (((_av >> 2) | (_av << 30)) ^ ((_av >> 13) | (_av << 19)) ^ ((_av >> 22) | (_av << 10))) & 0xFFFFFFFF ))
        # Inline maj(a,b,c): (a & b) ^ (a & c) ^ (b & c)
        local _t2=$(( (_s0 + ((_av & b) ^ (_av & c) ^ (b & c))) & 0xFFFFFFFF ))

        h=$g
        g=$f
        f=$e
        e=$(( (d + _t1) & 0xFFFFFFFF ))
        d=$c
        c=$b
        b=$a
        a=$(( (_t1 + _t2) & 0xFFFFFFFF ))

        i=$((i + 1))
    done

    printf '%d %d %d %d %d %d %d %d' \
        $(( (h0 + a) & 0xFFFFFFFF )) $(( (h1 + b) & 0xFFFFFFFF )) \
        $(( (h2 + c) & 0xFFFFFFFF )) $(( (h3 + d) & 0xFFFFFFFF )) \
        $(( (h4 + e) & 0xFFFFFFFF )) $(( (h5 + f) & 0xFFFFFFFF )) \
        $(( (h6 + g) & 0xFFFFFFFF )) $(( (h7 + h) & 0xFFFFFFFF ))
}

# sha256 <hex_message> - Compute SHA-256 hash of hex-encoded message
# Returns 64-char lowercase hex string.
sha256() {
    local msg="$1"
    local msg_len_bits=$(( ${#msg} * 4 ))  # Each hex char = 4 bits

    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    local h0=0x6a09e667 h1=0xbb67ae85 h2=0x3c6ef372 h3=0xa54ff53a
    local h4=0x510e527f h5=0x9b05688c h6=0x1f83d9ab h7=0x5be0cd19

    # Padding: append bit '1', then zeros, then 64-bit big-endian length
    msg="${msg}80"
    # Pad with zeros until length in hex chars ≡ 112 (mod 128)
    # 112 hex chars = 56 bytes; block is 64 bytes = 128 hex chars
    while [ $(( ${#msg} % 128 )) -ne 112 ]; do
        msg="${msg}00"
    done
    # Append 64-bit big-endian message length in bits
    msg="${msg}$(printf '%016x' "$msg_len_bits")"

    # Process each 64-byte (128 hex char) block
    local offset=0
    local total=${#msg}
    while [ $offset -lt "$total" ]; do
        local block="${msg:$offset:128}"
        local result
        result=$(_sha256_compress "$block" "$h0" "$h1" "$h2" "$h3" "$h4" "$h5" "$h6" "$h7")
        # shellcheck disable=SC2086
        set -- $result
        h0=$1 h1=$2 h2=$3 h3=$4 h4=$5 h5=$6 h6=$7 h7=$8
        offset=$((offset + 128))
    done

    printf '%08x%08x%08x%08x%08x%08x%08x%08x' \
        "$h0" "$h1" "$h2" "$h3" "$h4" "$h5" "$h6" "$h7"
}
