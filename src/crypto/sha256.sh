#!/usr/bin/env bash
# sha256.sh - SHA-256 hash (FIPS 180-4)
# Pure shell implementation operating on hex strings.
# Reference: FIPS PUB 180-4, August 2015

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

# _sha256_rotr <value> <bits> - Right rotate a 32-bit value
_sha256_rotr() {
    local val=$(( $1 & 0xFFFFFFFF ))
    local n=$2
    printf '%d' $(( ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF ))
}

# _sha256_shr <value> <bits> - Right shift a 32-bit value
_sha256_shr() {
    printf '%d' $(( ($1 >> $2) & 0xFFFFFFFF ))
}

# _sha256_ch <x> <y> <z>
_sha256_ch() {
    printf '%d' $(( (($1 & $2) ^ ((~$1) & $3)) & 0xFFFFFFFF ))
}

# _sha256_maj <x> <y> <z>
_sha256_maj() {
    printf '%d' $(( (($1 & $2) ^ ($1 & $3) ^ ($2 & $3)) & 0xFFFFFFFF ))
}

# _sha256_sigma0 <x> - Big sigma 0
_sha256_sigma0() {
    local x=$1
    local r2 r13 r22
    r2=$(_sha256_rotr "$x" 2)
    r13=$(_sha256_rotr "$x" 13)
    r22=$(_sha256_rotr "$x" 22)
    printf '%d' $(( (r2 ^ r13 ^ r22) & 0xFFFFFFFF ))
}

# _sha256_sigma1 <x> - Big sigma 1
_sha256_sigma1() {
    local x=$1
    local r6 r11 r25
    r6=$(_sha256_rotr "$x" 6)
    r11=$(_sha256_rotr "$x" 11)
    r25=$(_sha256_rotr "$x" 25)
    printf '%d' $(( (r6 ^ r11 ^ r25) & 0xFFFFFFFF ))
}

# _sha256_gamma0 <x> - Small sigma 0
_sha256_gamma0() {
    local x=$1
    local r7 r18 s3
    r7=$(_sha256_rotr "$x" 7)
    r18=$(_sha256_rotr "$x" 18)
    s3=$(_sha256_shr "$x" 3)
    printf '%d' $(( (r7 ^ r18 ^ s3) & 0xFFFFFFFF ))
}

# _sha256_gamma1 <x> - Small sigma 1
_sha256_gamma1() {
    local x=$1
    local r17 r19 s10
    r17=$(_sha256_rotr "$x" 17)
    r19=$(_sha256_rotr "$x" 19)
    s10=$(_sha256_shr "$x" 10)
    printf '%d' $(( (r17 ^ r19 ^ s10) & 0xFFFFFFFF ))
}

# _sha256_compress <block_hex_128chars> <h0..h7 as space-separated>
# Outputs updated h0..h7 as space-separated integers.
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
        local g1 g0
        g1=$(_sha256_gamma1 "${w[$((i-2))]}")
        g0=$(_sha256_gamma0 "${w[$((i-15))]}")
        w[$i]=$(( (g1 + w[$((i-7))] + g0 + w[$((i-16))]) & 0xFFFFFFFF ))
        i=$((i + 1))
    done

    # Working variables
    local a=$h0 b=$h1 c=$h2 d=$h3 e=$h4 f=$h5 g=$h6 h=$h7

    # 64 rounds
    i=0
    while [ $i -lt 64 ]; do
        local s1 ch temp1 s0 maj temp2
        s1=$(_sha256_sigma1 "$e")
        ch=$(_sha256_ch "$e" "$f" "$g")
        temp1=$(( (h + s1 + ch + ${_sha256_k[$i]} + ${w[$i]}) & 0xFFFFFFFF ))
        s0=$(_sha256_sigma0 "$a")
        maj=$(_sha256_maj "$a" "$b" "$c")
        temp2=$(( (s0 + maj) & 0xFFFFFFFF ))

        h=$g
        g=$f
        f=$e
        e=$(( (d + temp1) & 0xFFFFFFFF ))
        d=$c
        c=$b
        b=$a
        a=$(( (temp1 + temp2) & 0xFFFFFFFF ))

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
