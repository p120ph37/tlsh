#!/usr/bin/env bash
# Run all unit tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
overall_rc=0

for test_file in "$SCRIPT_DIR"/test_*.sh; do
    [ -f "$test_file" ] || continue
    printf "\n========================================\n"
    printf "Running %s\n" "$(basename "$test_file")"
    printf "========================================\n"
    bash "$test_file" || overall_rc=1
done

printf "\n========================================\n"
if [ $overall_rc -eq 0 ]; then
    printf "ALL TEST SUITES PASSED\n"
else
    printf "SOME TEST SUITES FAILED\n"
fi
printf "========================================\n"
exit $overall_rc
