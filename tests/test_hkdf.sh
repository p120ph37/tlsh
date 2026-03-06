#!/usr/bin/env bash
# Unit tests for src/crypto/hkdf.sh against RFC 5869 test vectors

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"
. "$SCRIPT_DIR/../src/util/bytes.sh"
. "$SCRIPT_DIR/../src/crypto/sha256.sh"
. "$SCRIPT_DIR/../src/crypto/hmac.sh"
. "$SCRIPT_DIR/../src/crypto/hkdf.sh"

printf "=== hkdf.sh tests (RFC 5869) ===\n"

# Test Case 1
test_start "HKDF-Extract RFC5869 Case 1"
prk=$(hkdf_extract "000102030405060708090a0b0c" "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
assert_equal "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" "$prk"

test_start "HKDF-Expand RFC5869 Case 1"
okm=$(hkdf_expand "$prk" "f0f1f2f3f4f5f6f7f8f9" 42)
assert_equal "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" "$okm"

# Test Case 2
test_start "HKDF-Extract RFC5869 Case 2"
ikm2=""
i=0; while [ $i -lt 80 ]; do ikm2="${ikm2}$(printf '%02x' "$i")"; i=$((i+1)); done
salt2=""
i=96; while [ $i -lt 176 ]; do salt2="${salt2}$(printf '%02x' "$i")"; i=$((i+1)); done
info2=""
i=176; while [ $i -lt 256 ]; do info2="${info2}$(printf '%02x' "$i")"; i=$((i+1)); done

prk2=$(hkdf_extract "$salt2" "$ikm2")
assert_equal "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244" "$prk2"

test_start "HKDF-Expand RFC5869 Case 2"
okm2=$(hkdf_expand "$prk2" "$info2" 82)
assert_equal "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87" "$okm2"

# Test Case 3: zero-length salt and info
test_start "HKDF-Extract RFC5869 Case 3"
prk3=$(hkdf_extract "" "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
assert_equal "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04" "$prk3"

test_start "HKDF-Expand RFC5869 Case 3"
okm3=$(hkdf_expand "$prk3" "" 42)
assert_equal "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8" "$okm3"

test_summary
