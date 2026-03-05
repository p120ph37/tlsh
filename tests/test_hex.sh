#!/usr/bin/env bash
# Unit tests for src/util/hex.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"

printf "=== hex.sh tests ===\n"

# hex_length
test_start "hex_length empty"
assert_equal "0" "$(hex_length "")"

test_start "hex_length 1 byte"
assert_equal "1" "$(hex_length "ab")"

test_start "hex_length 16 bytes"
assert_equal "16" "$(hex_length "00112233445566778899aabbccddeeff")"

# hex_substr
test_start "hex_substr offset=0 count=3"
assert_equal "001122" "$(hex_substr "00112233445566" 0 3)"

test_start "hex_substr offset=2 count=2"
assert_equal "2233" "$(hex_substr "00112233445566" 2 2)"

test_start "hex_substr offset=5 count=2"
assert_equal "5566" "$(hex_substr "00112233445566" 5 2)"

# hex_xor
test_start "hex_xor zeros"
assert_equal "00000000" "$(hex_xor "00000000" "00000000")"

test_start "hex_xor ff ^ ff = 00"
assert_equal "0000" "$(hex_xor "ffff" "ffff")"

test_start "hex_xor ab ^ cd"
assert_equal "66" "$(hex_xor "ab" "cd")"

test_start "hex_xor multi-byte"
assert_equal "ffff0000" "$(hex_xor "ff000000" "00ff0000")"

# hex_pad
test_start "hex_pad short to 4 bytes"
assert_equal "000000ab" "$(hex_pad "ab" 4)"

test_start "hex_pad already correct length"
assert_equal "aabbccdd" "$(hex_pad "aabbccdd" 4)"

# hex_to_ascii
test_start "hex_to_ascii 'abc'"
assert_equal "abc" "$(hex_to_ascii "616263")"

test_start "hex_to_ascii 'Hi There'"
assert_equal "Hi There" "$(hex_to_ascii "4869205468657265")"

test_summary
