#!/usr/bin/env bash
# Unit tests for ChaCha20-Poly1305 against RFC 8439 test vectors

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"
. "$SCRIPT_DIR/../src/util/bytes.sh"
. "$SCRIPT_DIR/../src/crypto/chacha20poly1305.sh"

printf "=== chacha20poly1305.sh tests (RFC 8439) ===\n"

# RFC 8439 Section 2.3.2 - ChaCha20 block function test vector
test_start "ChaCha20 block (RFC 8439 Section 2.3.2)"
key="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
nonce="000000090000004a00000000"
_chacha20_block "$key" 1 "$nonce"
# Expected first 16 bytes: 10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
expected_start="10f1e7e4d13b5915500fdd1fa32071c4"
actual_start="${_cc20_block:0:32}"
assert_equal "$expected_start" "$actual_start"

# RFC 8439 Section 2.4.2 - ChaCha20 encryption test vector
test_start "ChaCha20 encrypt (RFC 8439 Section 2.4.2)"
key="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
nonce="000000000000004a00000000"
counter=1
pt_hex="4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
ct_expected="6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
result=$(chacha20_encrypt "$key" "$nonce" "$counter" "$pt_hex")
assert_equal "$ct_expected" "$result"

# RFC 8439 Section 2.5.2 - Poly1305 MAC test vector
test_start "Poly1305 MAC (RFC 8439 Section 2.5.2)"
poly_key="85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
msg_hex="43727970746f6772617068696320466f72756d2052657365617263682047726f7570"
tag_expected="a8061dc1305136c6c22b8baf0c0127a9"
tag=$(poly1305_mac "$poly_key" "$msg_hex")
assert_equal "$tag_expected" "$tag"

# RFC 8439 Section 2.8.2 - AEAD test vector
test_start "ChaCha20-Poly1305 AEAD encrypt (RFC 8439 Section 2.8.2)"
key="808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
nonce="070000004041424344454647"
aad="50515253c0c1c2c3c4c5c6c7"
pt="4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
ct_expected="d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
tag_expected="1ae10b594f09e26a7e902ecbd0600691"
result=$(chacha20poly1305_encrypt "$key" "$nonce" "$pt" "$aad")
ct_actual="${result%% *}"
tag_actual="${result##* }"
assert_equal "$ct_expected" "$ct_actual"

test_start "ChaCha20-Poly1305 AEAD tag (RFC 8439 Section 2.8.2)"
assert_equal "$tag_expected" "$tag_actual"

# Decrypt test
test_start "ChaCha20-Poly1305 AEAD decrypt (RFC 8439 Section 2.8.2)"
pt_result=$(chacha20poly1305_decrypt "$key" "$nonce" "$ct_expected" "$aad" "$tag_expected")
assert_equal "$pt" "$pt_result"

# Bad tag should fail
test_start "ChaCha20-Poly1305 bad tag (should fail with rc=1)"
bad_tag="0000000000000000000000000000dead"
chacha20poly1305_decrypt "$key" "$nonce" "$ct_expected" "$aad" "$bad_tag" 2>/dev/null
assert_equal "1" "$?"

test_summary
