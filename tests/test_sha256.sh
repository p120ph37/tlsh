#!/usr/bin/env bash
# Unit tests for src/crypto/sha256.sh against FIPS 180-4 test vectors

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"
. "$SCRIPT_DIR/../src/util/bytes.sh"
. "$SCRIPT_DIR/../src/crypto/sha256.sh"

printf "=== sha256.sh tests ===\n"

# Test 1: Empty string
test_start "SHA-256 empty string"
result=$(sha256 "")
assert_equal "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" "$result"

# Test 2: "abc" (616263)
test_start "SHA-256 'abc'"
result=$(sha256 "616263")
assert_equal "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" "$result"

# Test 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (448 bits = 56 bytes)
test_start "SHA-256 448-bit message"
# Hex of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
msg_hex="6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"
result=$(sha256 "$msg_hex")
assert_equal "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" "$result"

# Test 4: Single byte 0x00
test_start "SHA-256 single null byte"
result=$(sha256 "00")
assert_equal "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" "$result"

# Test 5: "Hello, World!" (short ASCII)
test_start "SHA-256 'Hello, World!'"
msg_hex=$(ascii_to_hex "Hello, World!")
result=$(sha256 "$msg_hex")
# Known: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
assert_equal "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f" "$result"

test_summary
