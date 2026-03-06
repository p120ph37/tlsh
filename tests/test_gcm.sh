#!/usr/bin/env bash
# Unit tests for src/crypto/gcm.sh against GCM specification test vectors

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"
. "$SCRIPT_DIR/../src/util/bytes.sh"
. "$SCRIPT_DIR/../src/crypto/aes.sh"
. "$SCRIPT_DIR/../src/crypto/gcm.sh"

printf "=== gcm.sh tests (GCM spec) ===\n"

# Test Case 1: empty plaintext, no AAD (all zero key and IV)
test_start "GCM Test Case 1 (empty PT, no AAD)"
result=$(gcm_encrypt "00000000000000000000000000000000" "000000000000000000000000" "" "")
ct="${result%% *}"
tag="${result##* }"
assert_equal "" "$ct" "ciphertext"
test_start "GCM Test Case 1 tag"
assert_equal "58e2fccefa7e3061367f1d57a4e7455a" "$tag"

# Test Case 2: 16-byte zero plaintext, no AAD
test_start "GCM Test Case 2 (zero PT)"
result=$(gcm_encrypt "00000000000000000000000000000000" "000000000000000000000000" "00000000000000000000000000000000" "")
ct="${result%% *}"
tag="${result##* }"
assert_equal "0388dace60b6a392f328c2b971b2fe78" "$ct" "ciphertext"
test_start "GCM Test Case 2 tag"
assert_equal "ab6e47d42cec13bdf53a67b21257bddf" "$tag"

# Test Case 3: 64-byte plaintext (from GCM spec)
test_start "GCM Test Case 3 (64B PT)"
key3="feffe9928665731c6d6a8f9467308308"
iv3="cafebabefacedbaddecaf888"
pt3="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
result=$(gcm_encrypt "$key3" "$iv3" "$pt3" "")
ct="${result%% *}"
tag="${result##* }"
assert_equal "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985" "$ct" "ciphertext"
test_start "GCM Test Case 3 tag"
assert_equal "4d5c2af327cd64a62cf35abd2ba6fab4" "$tag"

# Test Case 4: 60-byte plaintext + 20-byte AAD
test_start "GCM Test Case 4 (PT + AAD)"
key4="feffe9928665731c6d6a8f9467308308"
iv4="cafebabefacedbaddecaf888"
pt4="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
aad4="feedfacedeadbeeffeedfacedeadbeefabaddad2"
result=$(gcm_encrypt "$key4" "$iv4" "$pt4" "$aad4")
ct="${result%% *}"
tag="${result##* }"
assert_equal "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091" "$ct" "ciphertext"
test_start "GCM Test Case 4 tag"
assert_equal "5bc94fbc3221a5db94fae95ae7121a47" "$tag"

# Test decryption roundtrip
test_start "GCM decrypt roundtrip (Test Case 2)"
pt_dec=$(gcm_decrypt "00000000000000000000000000000000" "000000000000000000000000" "0388dace60b6a392f328c2b971b2fe78" "" "ab6e47d42cec13bdf53a67b21257bddf")
assert_equal "00000000000000000000000000000000" "$pt_dec"

# Test tag verification failure
test_start "GCM decrypt bad tag fails"
bad_result=$(gcm_decrypt "00000000000000000000000000000000" "000000000000000000000000" "0388dace60b6a392f328c2b971b2fe78" "" "0000000000000000000000000000dead" 2>/dev/null)
bad_rc=$?
assert_equal "1" "$bad_rc" "should fail with rc=1"

test_summary
