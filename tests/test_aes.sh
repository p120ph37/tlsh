#!/usr/bin/env bash
# Unit tests for src/crypto/aes.sh against FIPS 197 and NIST SP 800-38A

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"
. "$SCRIPT_DIR/../src/util/bytes.sh"
. "$SCRIPT_DIR/../src/crypto/aes.sh"

printf "=== aes.sh tests ===\n"

# FIPS 197 Appendix C.1: AES-128 test vector
test_start "AES-128 FIPS 197 Appendix C"
aes128_expand_key "000102030405060708090a0b0c0d0e0f"
result=$(aes128_encrypt_block "00112233445566778899aabbccddeeff")
assert_equal "69c4e0d86a7b0430d8cdb78070b4c55a" "$result"

# NIST SP 800-38A ECB-AES128 Block 1
test_start "AES-128 SP800-38A Block 1"
aes128_expand_key "2b7e151628aed2a6abf7158809cf4f3c"
result=$(aes128_encrypt_block "6bc1bee22e409f96e93d7e117393172a")
assert_equal "3ad77bb40d7a3660a89ecaf32466ef97" "$result"

# NIST SP 800-38A ECB-AES128 Block 2
test_start "AES-128 SP800-38A Block 2"
result=$(aes128_encrypt_block "ae2d8a571e03ac9c9eb76fac45af8e51")
assert_equal "f5d3d58503b9699de785895a96fdbaaf" "$result"

# NIST SP 800-38A ECB-AES128 Block 3
test_start "AES-128 SP800-38A Block 3"
result=$(aes128_encrypt_block "30c81c46a35ce411e5fbc1191a0a52ef")
assert_equal "43b1cd7f598ece23881b00e3ed030688" "$result"

# NIST SP 800-38A ECB-AES128 Block 4
test_start "AES-128 SP800-38A Block 4"
result=$(aes128_encrypt_block "f69f2445df4f9b17ad2b417be66c3710")
assert_equal "7b0c785e27e8ad3f8223207104725dd4" "$result"

# All zeros test
test_start "AES-128 all zeros"
aes128_expand_key "00000000000000000000000000000000"
result=$(aes128_encrypt_block "00000000000000000000000000000000")
assert_equal "66e94bd4ef8a2c3b884cfa59ca342b2e" "$result"

test_summary
