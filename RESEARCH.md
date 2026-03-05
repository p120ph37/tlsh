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

### Refined Shell Compatibility: bash/ksh93 Intersection

Rather than targeting bash-only, we target the **intersection of bash 3.2+
and ksh93** features. This gives us compatibility with both shells and
potentially others (though see caveats).

| Feature                       | bash 3.2+ | ksh93 | In intersection? |
|-------------------------------|-----------|-------|-----------------|
| `/dev/tcp/host/port`          | Yes       | Yes   | Yes             |
| `arr=(val val val)`           | Yes       | Yes   | Yes             |
| `arr[i]=val` / `${arr[i]}`   | Yes       | Yes   | Yes             |
| `${var:offset:length}`        | Yes       | Yes   | Yes             |
| `$(( ))` with all bitwise ops | Yes       | Yes   | Yes             |
| `(( ))` arithmetic command    | Yes       | Yes   | Yes             |
| C-style `for ((i=0;i<n;i++))` | Yes      | Yes   | Yes             |
| `local` keyword               | Yes      | Yes*  | Yes             |
| `printf` builtin with `\xHH` | Yes       | Yes   | Yes             |
| `read -n N`                   | Yes       | Yes   | Yes             |
| `typeset -i`                  | Yes       | Yes   | Yes             |

*ksh93 prefers `typeset` but `local` is accepted in ksh93u+m.

**Features to avoid** (not in both shells):
- `declare -n` namerefs (bash 4.3+ only; ksh93 has `typeset -n` with
  different semantics)
- `${!prefix*}` indirect expansion (different behavior in ksh93)
- Floating-point arithmetic, compound variables (ksh93-only)

**Other shells — NOT compatible:**

| Shell | `/dev/tcp` | Arrays | Notes                            |
|-------|-----------|--------|----------------------------------|
| zsh   | No        | Yes    | Has `ztcp` module instead        |
| mksh  | No        | Yes    | Missing `/dev/tcp`               |
| dash  | No        | No     | Missing both critical features   |
| fish  | No        | N/A    | Completely different syntax       |

To support zsh in the future, we keep the TCP layer modular: the network
backend is in `src/net/` and can be swapped (e.g., a `ztcp`-based backend).

For shells lacking arrays, `eval`-based indirection could emulate indexed
arrays (e.g., `eval "arr_${i}=\$val"`). A C preprocessor step with `#ifdef`
could conditionally include such fallbacks. This is noted for future work.

### Final Shell Choice

**Bash 3.2+ / ksh93** intersection. This covers:
- macOS (bash 3.2 ships by default)
- All Linux distributions (bash 4.x/5.x)
- Commercial Unix (AIX, Solaris/illumos, HP-UX via ksh93)
- WSL, Git Bash on Windows

We validate with `shellcheck --shell=bash`.


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


## 5. Reference Test Vectors

All test vectors are in hexadecimal. These are used for unit testing each
cryptographic primitive independently.

### SHA-256 (FIPS 180-4 / di-mgt.com.au)

| # | Input (hex)      | Input (ASCII)  | Expected SHA-256 Output                                          |
|---|------------------|----------------|------------------------------------------------------------------|
| 1 | *(empty)*        | ""             | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 2 | `616263`         | "abc"          | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| 3 | 56-byte string   | "abcdbcde..."  | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` |

### HMAC-SHA-256 (RFC 4231)

| # | Key (hex)                                  | Data (hex)                                                           | HMAC-SHA-256                                                      |
|---|--------------------------------------------|----------------------------------------------------------------------|-------------------------------------------------------------------|
| 1 | `0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b`| `4869205468657265`                                                   | `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7` |
| 2 | `4a656665`                                 | `7768617420646f2079612077616e7420666f72206e6f7468696e673f`           | `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843` |
| 3 | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`  | 50 bytes of `0xdd`                                                   | `773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe` |
| 4 | `0102030405060708090a0b0c0d0e0f10111213141516171819` | 50 bytes of `0xcd`                                    | `82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b` |

### HKDF-SHA-256 (RFC 5869)

**Test Case 1:**
- IKM: `0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b` (22 bytes)
- salt: `000102030405060708090a0b0c` (13 bytes)
- info: `f0f1f2f3f4f5f6f7f8f9` (10 bytes)
- L: 42
- PRK: `077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5`
- OKM: `3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865`

**Test Case 2:**
- IKM: 80 bytes (`000102...4f`)
- salt: 80 bytes (`606162...af`)
- info: 80 bytes (`b0b1b2...ff`)
- L: 82
- PRK: `06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244`
- OKM: `b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87`

### AES-128 ECB (FIPS 197 Appendix C)

| Key                                | Plaintext                          | Ciphertext                         |
|------------------------------------|------------------------------------|------------------------------------|
| `000102030405060708090a0b0c0d0e0f` | `00112233445566778899aabbccddeeff` | `69c4e0d86a7b0430d8cdb78070b4c55a` |

Additional (NIST SP 800-38A):

| Key                                | Plaintext                          | Ciphertext                         |
|------------------------------------|------------------------------------|------------------------------------|
| `2b7e151628aed2a6abf7158809cf4f3c` | `6bc1bee22e409f96e93d7e117393172a` | `3ad77bb40d7a3660a89ecaf32466ef97` |
| `2b7e151628aed2a6abf7158809cf4f3c` | `ae2d8a571e03ac9c9eb76fac45af8e51` | `f5d3d58503b9699de785895a96fdbaaf` |

### AES-128-GCM (GCM Spec Appendix B, McGrew & Viega)

Test vectors from the GCM specification. See the full spec PDF for all cases:
https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

**Test Case 1** (empty plaintext, no AAD):
- Key: `00000000000000000000000000000000`
- IV: `000000000000000000000000`
- PT: *(empty)*
- AAD: *(empty)*
- CT: *(empty)*
- Tag: `58e2fccefa7e3061367f1d57a4e7455a`

**Test Case 2** (128-bit plaintext, no AAD):
- Key: `00000000000000000000000000000000`
- IV: `000000000000000000000000`
- PT: `00000000000000000000000000000000`
- AAD: *(empty)*
- CT: `0388dace60b6a392f328c2b971b2fe78`
- Tag: `ab6e47d42cec13bdf53a67b21257bddf`

### X25519 (RFC 7748 Section 5.2 and 6.1)

**Test Vector 1:**
- Scalar: `a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4`
- u-coordinate: `e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c`
- Output: `c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552`

**DH Test (Section 6.1):**
- Alice private: `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a`
- Alice public (X25519(a, 9)): `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a`
- Bob private: `5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb`
- Bob public (X25519(b, 9)): `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f`
- Shared secret: `4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742`

**Iterated Test** (scalar = u = basepoint 9):
- After 1 iteration: `422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079`
- After 1000 iterations: `684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51`

### Test Vector Sources

- SHA-256: https://di-mgt.com.au/sha_testvectors.html
- HMAC-SHA-256: https://www.rfc-editor.org/rfc/rfc4231.html
- HKDF: https://datatracker.ietf.org/doc/html/rfc5869
- AES-128: FIPS 197, NIST SP 800-38A
- AES-GCM: https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
- X25519: https://www.rfc-editor.org/rfc/rfc7748.html


## 6. Performance Considerations

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
