#!/usr/bin/env bash
# test_jit_real.sh - Test JIT inliner on real functions from the codebase
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
. src/util/hex.sh
. src/util/bytes.sh
. src/crypto/sha256.sh
. src/crypto/hmac.sh
. src/crypto/hkdf.sh
. src/util/jit.sh

_pass=0
_fail=0

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        printf 'PASS: %s\n' "$label"
        _pass=$((_pass + 1))
    else
        printf 'FAIL: %s\n  expected: %s\n  actual:   %s\n' "$label" "$expected" "$actual"
        _fail=$((_fail + 1))
    fi
}

# ---- Test 1: hkdf_expand_label before/after JIT ----
test_hkdf_expand_label() {
    # RFC 8446 test vector values (from our HKDF test)
    local secret="33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
    local label="derived"
    local context="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    local before
    before=$(hkdf_expand_label "$secret" "$label" "$context" 32)

    _jit_inline hkdf_expand_label
    local after
    after=$(hkdf_expand_label "$secret" "$label" "$context" 32)

    assert_eq "hkdf_expand_label derived" "$before" "$after"

    # Test with different labels (spaces in label)
    local after2
    after2=$(hkdf_expand_label "$secret" "c hs traffic" "$context" 32)
    assert_eq "hkdf_expand_label c hs traffic" "3cc9423fbe5c03c0c51e7ace3ec9cb4d85d09a694c918fd844257b7bdb17de83" "$after2"

    # Test with empty context
    local after3
    after3=$(hkdf_expand_label "$secret" "key" "" 16)
    assert_eq "hkdf_expand_label key (empty ctx)" "ebbf95bddc9e43bd09465c5516ab2d5f" "$after3"
}

# ---- Test 2: hkdf_expand (has printf '%02x' subshell) ----
test_hkdf_expand() {
    local prk="077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    local info="f0f1f2f3f4f5f6f7f8f9"

    local before
    before=$(hkdf_expand "$prk" "$info" 42)

    _jit_inline hkdf_expand
    local after
    after=$(hkdf_expand "$prk" "$info" 42)

    assert_eq "hkdf_expand RFC5869 vector" "$before" "$after"
}

# ---- Test 3: Verify HKDF test vectors still pass after JIT ----
test_hkdf_vectors() {
    # RFC 5869 Test Case 1
    local ikm="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    local salt="000102030405060708090a0b0c"
    local info="f0f1f2f3f4f5f6f7f8f9"

    local prk
    prk=$(hkdf_extract "$salt" "$ikm")
    assert_eq "hkdf_extract TC1" "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" "$prk"

    local okm
    okm=$(hkdf_expand "$prk" "$info" 42)
    assert_eq "hkdf_expand TC1" "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" "$okm"
}

# ---- Test 4: Verify inlined function source has no subshells for known patterns ----
test_no_subshells() {
    local src
    src=$(declare -f hkdf_expand_label)
    case "$src" in
        *'$(uint16_to_hex'*|*'$(uint8_to_hex'*|*'$(ascii_to_hex'*)
            assert_eq "hkdf_expand_label no subshells" "clean" "has_subshells"
            ;;
        *)
            assert_eq "hkdf_expand_label no subshells" "clean" "clean"
            ;;
    esac
}

# ---- Run all tests ----
test_hkdf_expand_label
test_hkdf_expand
test_hkdf_vectors
test_no_subshells

printf '\n--- Results: %d passed, %d failed ---\n' "$_pass" "$_fail"
[ "$_fail" -eq 0 ] || exit 1
