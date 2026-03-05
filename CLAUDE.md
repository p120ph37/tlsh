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

2. **Network I/O**: Use `/dev/tcp/host/port` for TCP connections. This is a
   bash-ism (not POSIX), which constrains our shell choice. See RESEARCH.md
   for compatibility details.

3. **Cryptography**: Ported from small open-license C implementations. The
   reference implementations and their licenses are documented in RESEARCH.md.

4. **Build model**: Development uses multiple source files (`src/*.sh`) sourced
   by `src/main.sh`. The build step (`build.sh`) concatenates them into a
   single `dist/tlsh.sh` with comments stripped.

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
    tcp.sh           # TCP connection helpers (/dev/tcp)
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
    ...              # Test scripts
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
