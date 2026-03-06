# CLAUDE.md - Development Notes for AI Assistants

## Project: tlsh (TLS in Shell)

### What This Is

A proof-of-concept pure-shell TLS implementation. The goal is to perform a
TLS 1.3 handshake and exchange data using only shell built-ins and `/dev/tcp`.

### Key Constraints

1. **No external commands**: Do not use `sed`, `awk`, `grep`, `curl`, `openssl`,
   `xxd`, `od`, `bc`, `md5sum`, `sha256sum`, or any other external binary.
   Everything must be done with shell built-ins (`printf`, parameter expansion,
   arithmetic evaluation, `read`, etc.).

2. **Network I/O**: The TCP layer is modular (`src/net/`). The default backend
   uses `/dev/tcp/host/port` (bash/ksh93). Alternative backends can be swapped
   in for other shells (e.g., `ztcp` for zsh, `nc`/`socat` for POSIX sh).
   See RESEARCH.md for compatibility details.

3. **Shell target**: The intersection of bash 3.2+ and ksh93 features. Uses
   indexed arrays, `${var:offset:length}`, `$(( ))` arithmetic with bitwise
   ops, `printf '\xHH'`, and `local`/`typeset`. See RESEARCH.md for details.

4. **Cryptography**: Ported from small open-license C implementations. The
   reference implementations and their licenses are documented in RESEARCH.md.

5. **Build model**: Development uses multiple source files (`src/*.sh`) sourced
   by `src/main.sh`. The build step (`build.sh`) concatenates them into a
   single `dist/tlsh.sh` with comments stripped.

6. **Testing**: Each module has unit tests validated against known test vectors
   (NIST, RFC). Integration tests use `openssl s_server`. End-to-end tests
   use `lighttpd`.

### Repository Structure (Planned)

```
tlsh/
  README.md          # Project overview
  CLAUDE.md          # This file
  RESEARCH.md        # Research on TLS, crypto, and shell capabilities
  PLAN.md            # Implementation plan
  build.sh           # Build script (concatenate + strip comments)
  src/
    main.sh          # Entry point, sources other modules
    net/
      tcp.sh         # TCP abstraction layer (interface)
      tcp_devtcp.sh  # /dev/tcp backend (bash/ksh93)
      tcp_ztcp.sh    # ztcp backend (zsh) [future]
      tcp_nc.sh      # netcat backend (POSIX) [future]
    tls_record.sh    # TLS record layer
    tls_handshake.sh # TLS handshake protocol
    crypto/
      aes.sh         # AES block cipher
      gcm.sh         # GCM mode
      sha256.sh      # SHA-256 hash
      hmac.sh        # HMAC
      hkdf.sh        # HKDF key derivation
      x25519.sh      # X25519 key exchange
      bignum.sh      # Big-number arithmetic in shell
    util/
      hex.sh         # Hex encode/decode using printf
      bytes.sh       # Byte-level manipulation helpers
  dist/
    tlsh.sh          # Built monolithic script (gitignored)
  tests/
    test_hex.sh      # Hex utility tests
    test_bytes.sh    # Byte utility tests
    test_sha256.sh   # SHA-256 vs NIST vectors
    test_hmac.sh     # HMAC vs RFC 4231
    test_hkdf.sh     # HKDF vs RFC 5869
    test_aes.sh      # AES-128 vs FIPS 197
    test_gcm.sh      # AES-GCM vs GCM spec
    test_x25519.sh   # X25519 vs RFC 7748
    test_integration.sh  # openssl s_server tests
    test_e2e.sh      # lighttpd end-to-end tests
```

### Coding Style

- Target `bash` (version 3.2+) unless POSIX `sh` proves viable.
- Use `shellcheck` for static analysis.
- Prefer clarity over cleverness; this is a proof of concept.
- Functions should be prefixed with their module name (e.g., `sha256_init`,
  `aes_encrypt_block`, `tls_record_send`).
- Use local variables (`local`) to avoid namespace pollution.
- All crypto functions operate on hex strings (each byte = 2 hex chars) to
  avoid shell binary-handling issues.

### Important Design Decisions

- **Hex-string representation**: Shell cannot handle NUL bytes in variables.
  All binary data (keys, ciphertext, etc.) is represented as hex strings
  and converted to raw bytes only at I/O boundaries.
- **Big-number arithmetic**: Needed for X25519/ECDH. Implemented using shell
  arithmetic on arrays of "limbs" (small integers that fit in shell's integer
  type).
- **No certificate verification**: For this proof of concept, we accept any
  server certificate. Real certificate chain validation is out of scope.
- **Modular networking**: The TCP layer is behind an abstraction so different
  backends can be used (`/dev/tcp`, `ztcp`, `nc`). Only `/dev/tcp` is
  implemented initially.
- **Future: preprocessor for portability**: A C preprocessor (`cc -E`) step
  could enable `#ifdef` blocks to provide eval-based array fallbacks for
  shells without native arrays. This is noted for future work; for now we
  use native indexed arrays directly.
