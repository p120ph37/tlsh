#!/usr/bin/env bash
# Minimal test harness for tlsh unit tests
# Usage: source this file, then call assert_equal / assert_true

_test_count=0
_test_pass=0
_test_fail=0
_test_current=""

test_start() {
    _test_current="$1"
    _test_count=$((_test_count + 1))
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local msg="${3:-}"
    if [ "$expected" = "$actual" ]; then
        _test_pass=$((_test_pass + 1))
        printf "  PASS: %s" "$_test_current"
        [ -n "$msg" ] && printf " (%s)" "$msg"
        printf "\n"
    else
        _test_fail=$((_test_fail + 1))
        printf "  FAIL: %s" "$_test_current"
        [ -n "$msg" ] && printf " (%s)" "$msg"
        printf "\n"
        printf "    expected: %s\n" "$expected"
        printf "    actual:   %s\n" "$actual"
    fi
}

assert_true() {
    local result="$1"
    local msg="${2:-}"
    if [ "$result" -eq 0 ] 2>/dev/null; then
        _test_pass=$((_test_pass + 1))
        printf "  PASS: %s" "$_test_current"
        [ -n "$msg" ] && printf " (%s)" "$msg"
        printf "\n"
    else
        _test_fail=$((_test_fail + 1))
        printf "  FAIL: %s" "$_test_current"
        [ -n "$msg" ] && printf " (%s)" "$msg"
        printf "\n"
    fi
}

test_summary() {
    printf "\n%d tests: %d passed, %d failed\n" "$_test_count" "$_test_pass" "$_test_fail"
    [ "$_test_fail" -eq 0 ] && return 0 || return 1
}
