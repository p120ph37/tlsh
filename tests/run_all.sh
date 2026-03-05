#!/usr/bin/env bash
# Run all unit tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
overall_rc=0

# Skip slow integration/e2e tests unless --all is passed
SKIP_SLOW=1
[ "${1:-}" = "--all" ] && SKIP_SLOW=0

for test_file in "$SCRIPT_DIR"/test_*.sh; do
    [ -f "$test_file" ] || continue
    basename="$(basename "$test_file")"
    case "$basename" in
        test_integration.sh|test_e2e.sh|test_handshake_debug.sh)
            if [ $SKIP_SLOW -eq 1 ]; then
                printf "\nSkipping %s (use --all to include)\n" "$basename"
                continue
            fi
            ;;
    esac
    printf "\n========================================\n"
    printf "Running %s\n" "$basename"
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
