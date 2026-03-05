# PLAN.md - Implementation Plan

## Overview

Implement a TLS 1.3 client in bash that can perform `s_client`-style
connections. Target cipher suite: `TLS_AES_128_GCM_SHA256` with `x25519`
key exchange.

**Shell**: Bash 3.2+ (required for `/dev/tcp`, arrays, substring extraction)
**Validation**: `shellcheck --shell=bash`
**Data representation**: All binary data as hex strings internally
**Build**: Concatenate source files, strip comments


## Phase 1: Project Structure and Build System

- [ ] Create `src/` directory structure per CLAUDE.md
- [ ] Create `src/main.sh` entry point that sources all modules
- [ ] Create `build.sh` that concatenates sources and strips `#` comments
- [ ] Create `dist/` directory (gitignored)
- [ ] Add `.shellcheckrc` with appropriate directives
- [ ] Add basic test harness in `tests/`


## Phase 2: Utility Layer

- [ ] `src/util/hex.sh` - Hex encode/decode
  - `hex_to_bytes` — convert hex string to raw bytes via `printf '\xHH'`
  - `bytes_to_hex` — convert raw bytes to hex string
  - `hex_xor` — XOR two hex strings
  - `hex_concat` — concatenate hex strings
  - `hex_length` — length in bytes
  - `hex_substr` — substring (byte offset, byte count)

- [ ] `src/util/bytes.sh` - Byte-level helpers
  - `uint16_to_hex` — 16-bit integer to 2-byte hex (big-endian)
  - `uint32_to_hex` — 32-bit integer to 4-byte hex (big-endian)
  - `hex_to_uint16` — 2-byte hex to integer
  - `hex_to_uint32` — 4-byte hex to integer

- [ ] `src/util/bignum.sh` - Multi-precision integer arithmetic
  - Represent big numbers as arrays of limbs (16-bit values in 32-bit slots)
  - `bn_add`, `bn_sub`, `bn_mul`, `bn_mod`, `bn_modexp`
  - Used by X25519 field arithmetic and RSA verification


## Phase 3: Cryptographic Primitives

### SHA-256
- [ ] `src/crypto/sha256.sh`
  - Port from a small public-domain C implementation or adapt Qix- gist
  - Functions: `sha256_init`, `sha256_update`, `sha256_final`, `sha256`
  - Operates on hex-string input, produces 64-char hex output
  - Test against known SHA-256 test vectors

### HMAC-SHA-256
- [ ] `src/crypto/hmac.sh`
  - Standard HMAC construction using SHA-256
  - Functions: `hmac_sha256 <key_hex> <message_hex>` -> hex digest
  - Test against RFC 4231 test vectors

### HKDF
- [ ] `src/crypto/hkdf.sh`
  - HKDF-Extract and HKDF-Expand per RFC 5869
  - Functions: `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label` (TLS 1.3)
  - Test against RFC 5869 test vectors

### AES-128
- [ ] `src/crypto/aes.sh`
  - AES-128 block encryption (encrypt-only; GCM only needs encrypt direction)
  - Precomputed S-box and round constant tables (embedded as shell arrays)
  - Functions: `aes128_expand_key`, `aes128_encrypt_block`
  - Test against NIST AES test vectors

### GCM (Galois Counter Mode)
- [ ] `src/crypto/gcm.sh`
  - GCM authenticated encryption and decryption
  - GF(2^128) multiplication for GHASH
  - Functions: `gcm_encrypt`, `gcm_decrypt` (with AAD and tag)
  - Test against NIST GCM test vectors

### X25519
- [ ] `src/crypto/x25519.sh`
  - Curve25519 scalar multiplication
  - Port from Monocypher's `crypto_x25519()` (or TweetNaCl via Kleppmann)
  - Field arithmetic in GF(2^255-19) using 16-bit limbs
  - Functions: `x25519 <scalar_hex> <point_hex>` -> shared_secret_hex
  - `x25519_public_key <private_key_hex>` -> public_key_hex
  - Test against RFC 7748 test vectors

### RSA-PSS Verification
- [ ] `src/crypto/rsa.sh`
  - RSA public-key operation (modular exponentiation)
  - PSS signature verification (RSASSA-PSS with SHA-256)
  - Functions: `rsa_verify_pss <pubkey> <signature> <message>`
  - Uses bignum for modular exponentiation
  - Test against known RSA-PSS test vectors


## Phase 4: TLS Protocol

### TCP Connection
- [ ] `src/tcp.sh`
  - Open connection via `/dev/tcp/host/port`
  - Functions: `tcp_connect <host> <port>`, `tcp_send <hex>`, `tcp_recv <len>`
  - Handle fd management

### TLS Record Layer
- [ ] `src/tls_record.sh`
  - Send/receive TLS records
  - Record framing (type, version, length, fragment)
  - After handshake: encrypt/decrypt records with AES-128-GCM
  - Functions: `tls_record_send`, `tls_record_recv`
  - Nonce construction (IV XOR sequence number)

### TLS Handshake
- [ ] `src/tls_handshake.sh`
  - **ClientHello**: Build and send with required extensions
    - supported_versions (TLS 1.3)
    - key_share (x25519 ephemeral public key)
    - supported_groups (x25519)
    - signature_algorithms (rsa_pss_rsae_sha256)
    - server_name (SNI)
  - **ServerHello**: Parse, extract server's x25519 key share
  - **Key derivation**: Compute handshake secret, derive traffic keys
  - **EncryptedExtensions**: Parse (mostly ignore)
  - **Certificate**: Parse server certificate (extract RSA public key)
  - **CertificateVerify**: Verify signature (RSA-PSS)
  - **Finished** (server): Verify HMAC
  - **Finished** (client): Compute and send
  - **Key derivation**: Compute application traffic keys

### s_client Interface
- [ ] `src/main.sh` (s_client command)
  - Parse `s_client -connect host:port` arguments
  - Perform TCP connect + TLS handshake
  - Relay stdin/stdout through TLS connection
  - Display certificate info (optional)


## Phase 5: Integration and Testing

- [ ] End-to-end test against a real HTTPS server
- [ ] Test against `openssl s_server` locally
- [ ] Test against https://tls13.xargs.org/ test vectors if available
- [ ] ShellCheck validation (`shellcheck --shell=bash`)
- [ ] Performance benchmarking (informational)


## Phase 6: Build and Distribution

- [ ] Finalize `build.sh` (concatenation + comment stripping)
- [ ] Ensure `dist/tlsh.sh` is self-contained and executable
- [ ] Add `.gitignore` for `dist/`
- [ ] Consider further minification (later iteration)


## Implementation Order (Recommended)

The crypto primitives have no circular dependencies and can be implemented
bottom-up:

```
1. util/hex.sh, util/bytes.sh        (foundation)
2. crypto/sha256.sh                   (needed by everything)
3. crypto/hmac.sh                     (needs sha256)
4. crypto/hkdf.sh                     (needs hmac)
5. crypto/aes.sh                      (independent)
6. crypto/gcm.sh                      (needs aes)
7. util/bignum.sh                     (independent)
8. crypto/x25519.sh                   (needs bignum)
9. crypto/rsa.sh                      (needs bignum, sha256)
10. tcp.sh                            (independent)
11. tls_record.sh                     (needs gcm, tcp)
12. tls_handshake.sh                  (needs everything)
13. main.sh / s_client                (entry point)
```

Each primitive can be tested independently with known test vectors before
moving to the next.


## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| X25519 too slow in shell | Handshake takes minutes | Acceptable for PoC; optimize limb size |
| RSA verify too slow | Handshake takes minutes | Use small exponent (e=65537 is only 17 squarings) |
| Bash version differences | Breaks on some systems | Test on bash 3.2 (macOS) and bash 5.x (Linux) |
| Binary I/O edge cases | Garbled data | Hex-string everywhere, raw bytes only at fd boundaries |
| Server requires unsupported features | Connection fails | Test against known-compatible servers first |
| GCM tag verification failure | Silent data corruption | Implement tag check; abort on mismatch |


## Alternative Approaches Considered

### ChaCha20-Poly1305 instead of AES-128-GCM
- ChaCha20 is simpler (no lookup tables, just add/xor/rotate)
- Poly1305 is simpler than GCM's GF(2^128) multiply
- BUT: `TLS_AES_128_GCM_SHA256` is mandatory in TLS 1.3 and has wider server
  support. ChaCha20 could be added as a second cipher suite later.

### Ed25519 instead of RSA for signature verification
- Ed25519 reuses X25519 field arithmetic (less new code)
- BUT: Most servers sign with RSA. We need RSA to work with real-world servers.
- Could add Ed25519 as an option and fall back to RSA.

### Use `nc`/`ncat` instead of `/dev/tcp`
- Would allow POSIX sh compatibility
- BUT: Violates the "no external commands" constraint. Also, `nc` variants
  differ across platforms and may not support the bidirectional streaming we need.
