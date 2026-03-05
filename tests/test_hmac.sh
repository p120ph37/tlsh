#!/usr/bin/env bash
# Unit tests for src/crypto/hmac.sh against RFC 4231 test vectors

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"
. "$SCRIPT_DIR/../src/util/bytes.sh"
. "$SCRIPT_DIR/../src/crypto/sha256.sh"
. "$SCRIPT_DIR/../src/crypto/hmac.sh"

printf "=== hmac.sh tests (RFC 4231) ===\n"

# Test Case 1: Key=20 bytes of 0x0b, Data="Hi There"
test_start "HMAC-SHA-256 RFC4231 Case 1"
result=$(hmac_sha256 "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" "4869205468657265")
assert_equal "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" "$result"

# Test Case 2: Key="Jefe", Data="what do ya want for nothing?"
test_start "HMAC-SHA-256 RFC4231 Case 2"
result=$(hmac_sha256 "4a656665" "7768617420646f2079612077616e7420666f72206e6f7468696e673f")
assert_equal "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" "$result"

# Test Case 3: Key=20 bytes of 0xaa, Data=50 bytes of 0xdd
test_start "HMAC-SHA-256 RFC4231 Case 3"
key3="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
data3=""
i=0; while [ $i -lt 50 ]; do data3="${data3}dd"; i=$((i+1)); done
result=$(hmac_sha256 "$key3" "$data3")
assert_equal "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" "$result"

# Test Case 4: Key=25 bytes (0x01..0x19), Data=50 bytes of 0xcd
test_start "HMAC-SHA-256 RFC4231 Case 4"
key4="0102030405060708090a0b0c0d0e0f10111213141516171819"
data4=""
i=0; while [ $i -lt 50 ]; do data4="${data4}cd"; i=$((i+1)); done
result=$(hmac_sha256 "$key4" "$data4")
assert_equal "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" "$result"

# Test Case 6: Key=131 bytes of 0xaa (longer than block size),
# Data="Test Using Larger Than Block-Size Key - Hash Key First"
test_start "HMAC-SHA-256 RFC4231 Case 6"
key6=""
i=0; while [ $i -lt 131 ]; do key6="${key6}aa"; i=$((i+1)); done
data6=$(ascii_to_hex "Test Using Larger Than Block-Size Key - Hash Key First")
result=$(hmac_sha256 "$key6" "$data6")
assert_equal "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" "$result"

# Test Case 7: Key=131 bytes of 0xaa, Data = longer message
test_start "HMAC-SHA-256 RFC4231 Case 7"
data7=$(ascii_to_hex "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.")
result=$(hmac_sha256 "$key6" "$data7")
assert_equal "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" "$result"

test_summary
