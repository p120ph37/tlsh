#!/usr/bin/env bash
# test_jit.sh - Tests for generalized JIT function inliner
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
. src/util/hex.sh
. src/util/bytes.sh
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

# Register the utility functions as inlinable
_jit_mark_inlinable uint8_to_hex uint16_to_hex uint24_to_hex uint32_to_hex ascii_to_hex

# ---- Test 1: Direct assignment of uint16_to_hex ----
test_direct_uint16() {
    eval 'test_func_1() {
        local result=$(uint16_to_hex 255)
        printf "%s" "$result"
    }'
    local before
    before=$(test_func_1)

    _jit_inline test_func_1
    local after
    after=$(test_func_1)
    assert_eq "direct uint16_to_hex 255" "$before" "$after"
    assert_eq "direct uint16_to_hex value" "00ff" "$after"

    # Verify no subshell remains
    local src
    src=$(declare -f test_func_1)
    case "$src" in
        *'$(uint16_to_hex'*) assert_eq "uint16 subshell removed" "no_subshell" "has_subshell" ;;
        *) assert_eq "uint16 subshell removed" "no_subshell" "no_subshell" ;;
    esac
}

# ---- Test 2: Inline uint16_to_hex in string concatenation ----
test_inline_uint16() {
    eval 'test_func_2() {
        local val=10
        local msg="aa$(uint16_to_hex "$val")bb"
        printf "%s" "$msg"
    }'
    local before
    before=$(test_func_2)

    _jit_inline test_func_2
    local after
    after=$(test_func_2)
    assert_eq "inline uint16_to_hex in string" "$before" "$after"
    assert_eq "inline uint16 value" "aa000abb" "$after"
}

# ---- Test 3: Multiple subshell calls on one line ----
test_multi() {
    eval 'test_func_3() {
        local x="$(uint8_to_hex 16)$(uint16_to_hex 256)"
        printf "%s" "$x"
    }'
    local before
    before=$(test_func_3)

    _jit_inline test_func_3
    local after
    after=$(test_func_3)
    assert_eq "multi inlines on one line" "$before" "$after"
    assert_eq "multi value" "100100" "$after"
}

# ---- Test 4: uint24_to_hex ----
test_uint24() {
    eval 'test_func_4() {
        local x=$(uint24_to_hex 4096)
        printf "%s" "$x"
    }'
    local before
    before=$(test_func_4)

    _jit_inline test_func_4
    local after
    after=$(test_func_4)
    assert_eq "uint24_to_hex" "$before" "$after"
    assert_eq "uint24 value" "001000" "$after"
}

# ---- Test 5: ascii_to_hex direct assignment (literal) ----
test_ascii_literal() {
    eval 'test_func_5() {
        local x=$(ascii_to_hex "Hi")
        printf "%s" "$x"
    }'
    local before
    before=$(test_func_5)

    _jit_inline test_func_5
    local after
    after=$(test_func_5)
    assert_eq "ascii_to_hex literal" "$before" "$after"
    assert_eq "ascii_to_hex literal value" "4869" "$after"
}

# ---- Test 6: ascii_to_hex with variable ----
test_ascii_var() {
    eval 'test_func_6() {
        local str="AB"
        local x=$(ascii_to_hex "$str")
        printf "%s" "$x"
    }'
    local before
    before=$(test_func_6)

    _jit_inline test_func_6
    local after
    after=$(test_func_6)
    assert_eq "ascii_to_hex variable" "$before" "$after"
    assert_eq "ascii_to_hex var value" "4142" "$after"
}

# ---- Test 7: Passthrough (no inlinable calls) ----
test_passthrough() {
    eval 'test_func_7() {
        local a=5
        local b=$((a + 3))
        printf "%d" "$b"
    }'
    local before
    before=$(test_func_7)

    _jit_inline test_func_7
    local after
    after=$(test_func_7)
    assert_eq "passthrough unchanged" "$before" "$after"
    assert_eq "passthrough value" "8" "$after"
}

# ---- Test 8: Real-world hkdf_expand_label pattern ----
test_hkdf_pattern() {
    eval 'test_func_8() {
        local length=32
        local label_len=10
        local context_len=32
        local hkdf_label=""
        hkdf_label="${hkdf_label}$(uint16_to_hex "$length")"
        hkdf_label="${hkdf_label}$(uint8_to_hex "$label_len")"
        hkdf_label="${hkdf_label}$(uint8_to_hex "$context_len")"
        printf "%s" "$hkdf_label"
    }'
    local before
    before=$(test_func_8)

    _jit_inline test_func_8
    local after
    after=$(test_func_8)
    assert_eq "hkdf-style pattern" "$before" "$after"
    assert_eq "hkdf-style value" "00200a20" "$after"
}

# ---- Test 9: Mixed known and unknown subshell calls ----
test_mixed() {
    eval 'test_func_9() {
        local x="$(uint16_to_hex 1)$(printf "%02x" 2)"
        printf "%s" "$x"
    }'
    local before
    before=$(test_func_9)

    _jit_inline test_func_9
    local after
    after=$(test_func_9)
    assert_eq "mixed known/unknown" "$before" "$after"
    assert_eq "mixed value" "000102" "$after"
}

# ---- Test 10: Local variable namespacing ----
test_namespace_collision() {
    # Test that inlined locals don't collide with caller locals
    eval 'test_func_10() {
        local i=42
        local hex=$(ascii_to_hex "XY")
        local result="${hex}_${i}"
        printf "%s" "$result"
    }'
    local before
    before=$(test_func_10)

    _jit_inline test_func_10
    local after
    after=$(test_func_10)
    assert_eq "namespace collision protection" "$before" "$after"
    assert_eq "namespace value" "5859_42" "$after"
}

# ---- Test 11: uint32_to_hex ----
test_uint32() {
    eval 'test_func_11() {
        local x=$(uint32_to_hex 65536)
        printf "%s" "$x"
    }'
    local before
    before=$(test_func_11)

    _jit_inline test_func_11
    local after
    after=$(test_func_11)
    assert_eq "uint32_to_hex" "$before" "$after"
    assert_eq "uint32 value" "00010000" "$after"
}

# ---- Test 12: $(printf) inlining ----
test_printf_inline() {
    eval 'test_func_12() {
        local x=$(printf "%02x" 255)
        printf "%s" "$x"
    }'
    local before
    before=$(test_func_12)

    _jit_inline test_func_12
    local after
    after=$(test_func_12)
    assert_eq "printf inlining" "$before" "$after"
    assert_eq "printf value" "ff" "$after"

    # Verify $(printf was removed
    local src
    src=$(declare -f test_func_12)
    case "$src" in
        *'$(printf'*) assert_eq "printf subshell removed" "no_subshell" "has_subshell" ;;
        *) assert_eq "printf subshell removed" "no_subshell" "no_subshell" ;;
    esac
}

# ---- Test 13: Show inlined source for inspection ----
test_show_inlined() {
    eval 'test_func_show() {
        local val=10
        local a=$(uint16_to_hex "$val")
        local b="prefix$(uint8_to_hex 5)suffix"
        local c=$(ascii_to_hex "AB")
        printf "%s" "${a}${b}${c}"
    }'
    _jit_inline test_func_show
    local result
    result=$(test_func_show)
    assert_eq "show inlined result" "000aprefix05suffix4142" "$result"
}

# ---- Run all tests ----
test_direct_uint16
test_inline_uint16
test_multi
test_uint24
test_ascii_literal
test_ascii_var
test_passthrough
test_hkdf_pattern
test_mixed
test_namespace_collision
test_uint32
test_printf_inline
test_show_inlined

printf '\n--- Results: %d passed, %d failed ---\n' "$_pass" "$_fail"
[ "$_fail" -eq 0 ] || exit 1
