# RESEARCH.md - TLS-in-Shell Research Notes

## 1. Cryptographic Primitives Needed for TLS 1.3

To implement a TLS 1.3 client using the mandatory `TLS_AES_128_GCM_SHA256`
cipher suite with X25519 key exchange, we need:

| Function               | Primitive                | Notes                                    |
|------------------------|--------------------------|------------------------------------------|
| Bulk encryption (AEAD) | AES-128-GCM              | Authenticated encryption with assoc data |
| Key derivation         | HKDF (HMAC-SHA-256)      | Extract-then-expand, per RFC 5869        |
| Hash                   | SHA-256                  | Used by HKDF and transcript hash         |
| MAC                    | HMAC-SHA-256             | Used by HKDF and Finished messages       |
| Key exchange           | X25519 (Curve25519 ECDH) | Elliptic-curve Diffie-Hellman            |
| Signature verification | RSA-PSS-RSAE-SHA256      | Verify server CertificateVerify          |

### What We Can Skip (Proof of Concept)

- **Certificate chain validation**: Accept any server cert (no CA trust store).
- **Client certificates**: Not sending client certs.
- **Session resumption / PSK / 0-RTT**: Only implement the basic 1-RTT handshake.
- **Multiple cipher suites**: Only `TLS_AES_128_GCM_SHA256`.
- **Multiple key exchange groups**: Only `x25519` (0x001d).
- **Signature algorithms beyond RSA-PSS**: Most servers use RSA. We can add
  Ed25519 / ECDSA later if needed.

### Sub-Primitives Breakdown

**AES-128-GCM** requires:
- AES-128 block cipher (encrypt only; GCM uses CTR mode, no decryption needed)
- GF(2^128) multiplication (GHASH for authentication)
- CTR mode increment

**HKDF** requires:
- HMAC-SHA-256 (which requires SHA-256)

**X25519** requires:
- Modular arithmetic in GF(2^255 - 19)
- Montgomery ladder scalar multiplication
- Field operations: add, subtract, multiply, square, invert (mod p)

**RSA-PSS verification** requires:
- Big-number modular exponentiation (for RSA public key operation)
- MGF1 (mask generation function, based on SHA-256)
- PSS padding verification


## 2. Reference Implementations Survey

### Crypto Libraries (Candidates for Porting)

#### Monocypher (RECOMMENDED)
- **License**: 2-clause BSD / CC0 (public domain)
- **Size**: ~1700 SLOC in C
- **Files**: Single `monocypher.c` + `monocypher.h`
- **Primitives**: X25519, ChaCha20, Poly1305, BLAKE2b, Argon2i, Ed25519
- **Pros**: Tiny, readable, portable C99, no dependencies (not even libc),
  constant-time, well-audited. Public domain option.
- **Cons**: Uses ChaCha20/Poly1305/BLAKE2b instead of AES/GCM/SHA-256. We
  would need to get AES-GCM and SHA-256 from elsewhere, but X25519 code is
  directly usable.
- **URL**: https://monocypher.org/ / https://github.com/LoupVaillant/Monocypher

#### TweetNaCl
- **License**: Public domain
- **Size**: Fits in 100 tweets (~750 bytes of C)
- **Primitives**: X25519, Salsa20, Poly1305, SHA-512, Ed25519
- **Pros**: Absolute minimum code, public domain, well-analyzed.
- **Cons**: Extremely compressed/obfuscated for tweet-size. Uses SHA-512 not
  SHA-256. No AES or GCM. Hard to read and port.
- **URL**: https://tweetnacl.cr.yp.to/
- **Tutorial**: Martin Kleppmann's excellent X25519 tutorial analyzes TweetNaCl
  line by line: https://martin.kleppmann.com/papers/curve25519.pdf

#### TLSe
- **License**: Public domain / BSD / MIT
- **Size**: Single C file (large, uses libtomcrypt)
- **Primitives**: Full TLS 1.2/1.3 stack
- **Pros**: Complete TLS implementation in one file.
- **Cons**: Very large, depends on libtomcrypt. Too complex to port.
- **URL**: https://github.com/eduardsui/tlse

#### BearSSL
- **License**: MIT
- **Size**: ~30K SLOC
- **Primitives**: Full TLS 1.2 stack, all common ciphers
- **Pros**: Excellent code quality, well-documented, constant-time. Thomas
  Pornin (author) is a highly respected cryptographer.
- **Cons**: No TLS 1.3 support. Large codebase.
- **URL**: https://bearssl.org/

#### picotls
- **License**: MIT
- **Size**: Medium
- **Primitives**: Full TLS 1.3
- **Pros**: Complete TLS 1.3 with pluggable crypto backends.
- **Cons**: Multiple files, depends on external crypto. Not self-contained enough
  for easy porting.
- **URL**: https://github.com/h2o/picotls

#### Mbed TLS
- **License**: Apache 2.0 / GPL 2.0+
- **Pros**: Well-documented, widely used, clean code.
- **Cons**: Large (~50-100KB minimal), not BSD/MIT.
- **URL**: https://github.com/Mbed-TLS/mbedtls

### Existing Pure-Shell Crypto

#### Qix-/sha256.sh (GitHub Gist)
- SHA-256 in (mostly) pure bash
- Uses bash arithmetic and bitwise ops
- Demonstrates feasibility of crypto in shell
- **URL**: https://gist.github.com/Qix-/affef08b50686e54e1f2ca18f97a6ff7

### Recommended Porting Strategy

**For X25519**: Port from Monocypher's `crypto_x25519()`. The code is clean,
readable, and well-documented. Kleppmann's tutorial provides line-by-line
explanation of equivalent TweetNaCl code.

**For SHA-256**: Either port from a small public-domain C implementation (many
exist) or adapt the existing pure-bash SHA-256 gist by Qix-.

**For HMAC-SHA-256 / HKDF**: Straightforward to build on top of SHA-256.
These are simple constructions.

**For AES-128**: Port from the FreeBSD/WPA `aes-internal.c` or a similar small
public-domain implementation. AES is table-driven, which maps well to shell
arrays.

**For GCM**: Port from the FreeBSD/WPA `aes-gcm.c`. GCM requires GF(2^128)
multiplication, which is bitwise operations on 128-bit values (we'll represent
as arrays of 32-bit or 16-bit limbs).

**For RSA verification**: This is the hardest part. Big-number modular
exponentiation on ~2048-bit numbers in shell will be slow but feasible.
We could port from BearSSL's `i31` big-number code or Mbed TLS's `bignum.c`.
*Alternative*: If we restrict to servers that support Ed25519 signatures, we
could avoid RSA entirely and use Monocypher's Ed25519 verify. But most servers
still use RSA certificates.


## 3. Shell Compatibility Analysis

### The `/dev/tcp` Problem

`/dev/tcp/host/port` is **not POSIX**. It is a bash-specific feature (also
available in ksh93). It does not exist in `dash`, `ash`, or standard POSIX sh.

| Shell   | `/dev/tcp` Support |
|---------|-------------------|
| bash    | Yes (built-in)     |
| ksh93   | Yes               |
| zsh     | Via `zsh/net/tcp`  |
| dash    | No                |
| ash     | No                |
| POSIX sh| Not defined        |

**ShellCheck warning SC3025**: "In POSIX sh, `/dev/{tcp,udp}` is undefined."

**Verdict**: We **must** use `bash` (or ksh93) for network I/O, unless we use
an external tool like `nc`/`socat` (which violates our "no external commands"
constraint). Since `/dev/tcp` is the sole networking mechanism available as a
shell built-in, **bash is required**.

### Arithmetic and Bitwise Operations

POSIX `$(( ))` arithmetic expansion supports all C-style operators including
bitwise AND, OR, XOR, NOT, shifts. This works in `dash`, `bash`, and all
POSIX shells.

| Feature                     | POSIX sh | dash | bash |
|-----------------------------|----------|------|------|
| `$(( a & b ))` bitwise AND  | Yes      | Yes  | Yes  |
| `$(( a \| b ))` bitwise OR  | Yes      | Yes  | Yes  |
| `$(( a ^ b ))` bitwise XOR  | Yes      | Yes  | Yes  |
| `$(( ~a ))` bitwise NOT     | Yes      | Yes  | Yes  |
| `$(( a << n ))` left shift  | Yes      | Yes  | Yes  |
| `$(( a >> n ))` right shift | Yes      | Yes  | Yes  |
| Hex constants `0xFF`        | Yes      | Yes  | Yes  |
| 64-bit integers             | Platform | Platform | Platform |

Integer size is `intmax_t` (64-bit on modern platforms). This is sufficient for
most operations, but X25519 requires 255-bit field arithmetic and RSA requires
2048-bit arithmetic, so we need multi-limb big-number code regardless.

### String/Variable Features

| Feature                      | POSIX sh | dash | bash | Needed? |
|------------------------------|----------|------|------|---------|
| `local` keyword              | Common*  | Yes  | Yes  | Yes     |
| Parameter expansion `${#var}`| Yes      | Yes  | Yes  | Yes     |
| `${var:offset:length}`       | No       | No   | Yes  | Useful  |
| Arrays `arr[i]=val`          | No       | No   | Yes  | Critical|
| `printf` builtin             | Yes      | Yes  | Yes  | Yes     |
| `printf '%d'` formatting     | Yes      | Yes  | Yes  | Yes     |
| `printf '\xHH'` hex escape   | No*      | No*  | Yes  | Yes     |
| `read -n N` (read N chars)  | No       | No   | Yes  | Useful  |
| `read -r -d ''` (read to NUL)| No      | No   | Yes  | Useful  |
| Here strings `<<< "str"`    | No       | No   | Yes  | Nice    |

*`local` is not in POSIX but is supported by dash, ash, and virtually all
real-world sh implementations.

*`printf '\xHH'` is supported by most implementations but is not guaranteed
by POSIX.

### Arrays: The Critical Dependency

Crypto operations on multi-word values (AES state, GCM hash, X25519 field
elements, RSA bignums) fundamentally require indexed arrays. Without arrays,
we'd need to use `eval` tricks with dynamically-named variables (e.g.,
`eval "limb_${i}=..."`) which is fragile, slow, and defeats the purpose.

**Bash arrays** provide:
- Indexed arrays: `arr=(1 2 3)`, `${arr[i]}`, `arr[i]=$((...))`
- These map directly to limbs in big-number arithmetic

**POSIX sh / dash** provide:
- No arrays at all
- The only "array-like" feature is positional parameters `$1 $2 ...` via `set --`
- This is too limited for crypto (can't easily index or update elements)

**Verdict**: Arrays are non-negotiable for crypto. **Bash is required.**

### The NUL Byte Problem

Shell variables cannot contain NUL (`\0`) bytes. This means:
- We cannot store arbitrary binary data in variables
- All binary data must be represented as hex strings
- Conversion to/from raw bytes happens only at I/O boundaries
- `printf '\x00'` can output NUL to stdout/files but cannot capture it

This is a fundamental limitation of all shells (bash, dash, zsh alike) and is
why we adopt the **hex-string convention** throughout.

### Final Shell Choice

**Bash (version 3.2+)** is the minimum viable shell because it provides:
1. `/dev/tcp` for network I/O (not available in POSIX sh)
2. Indexed arrays for crypto state (not available in POSIX sh)
3. `${var:offset:length}` substring extraction (not available in POSIX sh)
4. POSIX-compatible `$(( ))` arithmetic with bitwise operators
5. `printf` builtin with `\xHH` hex escapes
6. `local` variables for function scoping
7. `read -n` for reading specific byte counts from network

Bash 3.2 (2006) is the version shipped with macOS and is available on
essentially all Linux/Unix systems. This is a reasonable minimum.

We will **not** be able to pass `shellcheck --shell=sh` but we **can** use
`shellcheck --shell=bash` for validation.


## 4. TLS 1.3 Protocol Details

### Handshake Overview (1-RTT)

```
Client                                           Server

ClientHello
  + key_share (x25519 pub)
  + supported_versions (TLS 1.3)
  + signature_algorithms
  + supported_groups
  + server_name (SNI)         -------->
                                                ServerHello
                                                  + key_share (x25519 pub)
                                                  + supported_versions
                                          {EncryptedExtensions}
                                          {Certificate}
                                          {CertificateVerify}
                              <--------   {Finished}
{Finished}                    -------->
[Application Data]            <------->   [Application Data]
```

`{}` = encrypted with handshake keys
`[]` = encrypted with application keys

### Record Layer

All TLS 1.3 records after ServerHello are encrypted. The outer record type is
always `application_data` (0x17) for middlebox compatibility. The real content
type is the last byte of the decrypted plaintext.

Record format (outer):
```
ContentType (1 byte) = 0x17
ProtocolVersion (2 bytes) = 0x0303  (TLS 1.2 for compat)
Length (2 bytes)
Fragment (encrypted)
```

### Key Schedule

```
             0
             |
             v
   PSK ->  HKDF-Extract = Early Secret
             |
             +-----> Derive-Secret(., "c e traffic", ClientHello)
             |                     = client_early_traffic_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
(EC)DHE -> HKDF-Extract = Handshake Secret
             |
             +-----> Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
             |                     = client_handshake_traffic_secret
             +-----> Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
             |                     = server_handshake_traffic_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
   0 ->    HKDF-Extract = Master Secret
             |
             +-----> Derive-Secret(., "c ap traffic", ClientHello...server Finished)
             |                     = client_application_traffic_secret_0
             +-----> Derive-Secret(., "s ap traffic", ClientHello...server Finished)
                                   = server_application_traffic_secret_0
```

### Per-Record Nonce Construction (AES-GCM)

The nonce for each record is computed as:
```
nonce = write_iv XOR (sequence_number padded to iv_length)
```
Where `write_iv` is derived from the traffic secret and the sequence number
starts at 0 and increments for each record.

### Reference Material

- **RFC 8446**: https://datatracker.ietf.org/doc/html/rfc8446
- **The Illustrated TLS 1.3 Connection**: https://tls13.xargs.org/
- **Kleppmann X25519 Tutorial**: https://martin.kleppmann.com/papers/curve25519.pdf
- **RFC 7748 (X25519)**: https://www.rfc-editor.org/rfc/rfc7748.html
- **NIST SP 800-38D (GCM)**: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
- **RFC 5869 (HKDF)**: https://datatracker.ietf.org/doc/html/rfc5869


## 5. Performance Considerations

Shell arithmetic operates on string-represented integers with conversion
overhead on every operation. Rough estimates for key operations:

- **SHA-256**: The pure-bash SHA-256 gist by Qix- demonstrates feasibility.
  Expect ~seconds per hash of a small message.
- **AES block encrypt**: 10 rounds of SubBytes/ShiftRows/MixColumns/AddRoundKey,
  each involving table lookups and XORs on 16 bytes. Probably ~tens of ms per
  block in bash.
- **X25519**: ~255 iterations of the Montgomery ladder, each requiring several
  field multiplications. Field multiply on 255-bit numbers using 16-bit limbs
  means ~16x16=256 multiply-and-add operations per field multiply. With ~10
  field ops per ladder step, that's ~650K shell arithmetic operations. Could
  take minutes.
- **RSA-2048 verify**: Modular exponentiation with e=65537 requires ~17
  squarings and 1 multiply of 2048-bit numbers. Each 2048-bit multiply with
  32-bit limbs means ~64x64=4096 operations. Total: ~70K operations. Should
  be feasible in seconds.

The TLS handshake is a one-time cost. After key derivation, per-record
AES-GCM encryption/decryption cost is proportional to data size. For small
requests (e.g., HTTP GET + response), total time might be 30-120 seconds.
Acceptable for a proof of concept.
