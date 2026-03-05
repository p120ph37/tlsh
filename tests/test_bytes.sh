#!/usr/bin/env bash
# Unit tests for src/util/bytes.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"
. "$SCRIPT_DIR/../src/util/bytes.sh"

printf "=== bytes.sh tests ===\n"

# uint8
test_start "uint8_to_hex 0"
assert_equal "00" "$(uint8_to_hex 0)"

test_start "uint8_to_hex 255"
assert_equal "ff" "$(uint8_to_hex 255)"

test_start "uint8_to_hex 171"
assert_equal "ab" "$(uint8_to_hex 171)"

# uint16
test_start "uint16_to_hex 0"
assert_equal "0000" "$(uint16_to_hex 0)"

test_start "uint16_to_hex 443"
assert_equal "01bb" "$(uint16_to_hex 443)"

test_start "uint16_to_hex 65535"
assert_equal "ffff" "$(uint16_to_hex 65535)"

# uint32
test_start "uint32_to_hex 0"
assert_equal "00000000" "$(uint32_to_hex 0)"

test_start "uint32_to_hex 305419896"
assert_equal "12345678" "$(uint32_to_hex 305419896)"

# hex_to_uint8
test_start "hex_to_uint8 ff"
assert_equal "255" "$(hex_to_uint8 "ff")"

test_start "hex_to_uint8 00"
assert_equal "0" "$(hex_to_uint8 "00")"

# hex_to_uint16
test_start "hex_to_uint16 01bb"
assert_equal "443" "$(hex_to_uint16 "01bb")"

# hex_to_uint32
test_start "hex_to_uint32 12345678"
assert_equal "305419896" "$(hex_to_uint32 "12345678")"

# ascii_to_hex
test_start "ascii_to_hex 'abc'"
assert_equal "616263" "$(ascii_to_hex "abc")"

test_start "ascii_to_hex 'Hi There'"
assert_equal "4869205468657265" "$(ascii_to_hex "Hi There")"

# roundtrip
test_start "ascii_to_hex roundtrip"
local_str="Hello, TLS!"
assert_equal "$local_str" "$(hex_to_ascii "$(ascii_to_hex "$local_str")")"

test_summary
