#!/usr/bin/env bash
# Build script: concatenate source modules into dist/tlsh.sh
# Usage: ./build.sh

set -euo pipefail

SRCDIR="$(cd "$(dirname "$0")/src" && pwd)"
DISTDIR="$(cd "$(dirname "$0")" && pwd)/dist"

mkdir -p "$DISTDIR"

# Source files in dependency order
SOURCE_FILES=(
    "$SRCDIR/util/hex.sh"
    "$SRCDIR/util/bytes.sh"
    "$SRCDIR/crypto/sha256.sh"
    "$SRCDIR/crypto/hmac.sh"
    "$SRCDIR/crypto/hkdf.sh"
    "$SRCDIR/crypto/aes.sh"
    "$SRCDIR/crypto/gcm.sh"
    "$SRCDIR/net/tcp.sh"
    "$SRCDIR/net/tcp_devtcp.sh"
    "$SRCDIR/tls_record.sh"
    "$SRCDIR/tls_handshake.sh"
    "$SRCDIR/main.sh"
)

{
    printf '#!/usr/bin/env bash\n'
    printf '# tlsh - TLS in Shell (built %s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '# https://github.com/p120ph37/tlsh\n'
    printf 'set -euo pipefail\n\n'

    for src in "${SOURCE_FILES[@]}"; do
        if [ -f "$src" ]; then
            # Strip shebang lines, comment-only lines, and blank lines at top
            # Keep inline comments for now (stripping those is a future step)
            while IFS= read -r line; do
                # Skip shebang
                case "$line" in '#!'*) continue ;; esac
                # Skip comment-only lines (lines that are only whitespace + #)
                case "$line" in
                    ''|'#'*) continue ;;
                    *) printf '%s\n' "$line" ;;
                esac
            done < "$src"
            printf '\n'
        fi
    done
} > "$DISTDIR/tlsh.sh"

chmod +x "$DISTDIR/tlsh.sh"
printf 'Built: %s\n' "$DISTDIR/tlsh.sh"
