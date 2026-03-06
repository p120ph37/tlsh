#!/usr/bin/env bash
# Unit tests for src/crypto/x25519.sh against RFC 7748 test vectors

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/test_harness.sh"
. "$SCRIPT_DIR/../src/util/hex.sh"
. "$SCRIPT_DIR/../src/util/bytes.sh"
. "$SCRIPT_DIR/../src/crypto/x25519.sh"

printf "=== x25519.sh tests (RFC 7748) ===\n"

# RFC 7748 Section 5.2 - Test Vector 1
test_start "X25519 RFC7748 vector 1"
result=$(x25519 \
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4" \
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
assert_equal "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" "$result"

# RFC 7748 Section 5.2 - Test Vector 2
test_start "X25519 RFC7748 vector 2"
result=$(x25519 \
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d" \
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
assert_equal "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957" "$result"

# RFC 7748 Section 6.1 - Diffie-Hellman test
# Alice's keys
test_start "X25519 Alice public key"
alice_priv="77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
alice_pub=$(x25519_base "$alice_priv")
assert_equal "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" "$alice_pub"

# Bob's keys
test_start "X25519 Bob public key"
bob_priv="5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
bob_pub=$(x25519_base "$bob_priv")
assert_equal "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f" "$bob_pub"

# Shared secret (Alice side)
test_start "X25519 DH shared secret (Alice)"
shared_a=$(x25519 "$alice_priv" "$bob_pub")
assert_equal "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" "$shared_a"

# Shared secret (Bob side)
test_start "X25519 DH shared secret (Bob)"
shared_b=$(x25519 "$bob_priv" "$alice_pub")
assert_equal "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" "$shared_b"

# Iterated test: 1 iteration (scalar = u = basepoint 9)
test_start "X25519 iterated (1 iteration)"
u="0900000000000000000000000000000000000000000000000000000000000000"
k="0900000000000000000000000000000000000000000000000000000000000000"
result=$(x25519 "$k" "$u")
assert_equal "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079" "$result"

test_summary
