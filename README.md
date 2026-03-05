# tlsh

A pure-shell implementation of modern TLS. Just because.

## Overview

`tlsh` is a proof-of-concept project that implements TLS 1.3 (and the minimum
subset of TLS 1.2 needed for compatibility) entirely in shell script. The
primary API is an `s_client`-compatible function that can establish HTTPS
connections, mimicking `openssl s_client`.

## Design Goals

- **Pure shell**: No external binaries. All cryptographic primitives, protocol
  logic, and data manipulation use only shell built-ins. No `sed`, `awk`,
  `curl`, `grep`, `openssl`, `md5sum`, etc.
- **Network I/O via `/dev/tcp`**: Connections are made using the shell's
  `/dev/tcp/host/port` pseudo-device.
- **Modern TLS**: Targets TLS 1.3 with a minimal cipher suite (e.g.,
  TLS_AES_128_GCM_SHA256). Fallback to TLS 1.2 only if strictly necessary.
- **Simple API**: Exposes an `s_client` function that behaves like
  `openssl s_client -connect host:port`.
- **Monolithic build output**: The published artifact is a single minified
  shell script, built by concatenating the development source files and
  stripping comments.
- **Modular development sources**: During development, the implementation is
  split across multiple files, sourced by a main entry point.
- **Open-license cryptography references**: Crypto primitives are ported from
  small, well-understood, BSD/MIT/public-domain C implementations.
- **Proof of concept**: Performance is not a primary concern. Correctness and
  clarity come first.

## Shell Compatibility Target

The ideal target is POSIX `sh` (e.g., `dash`) with `shellcheck` validation.
However, the `/dev/tcp` pseudo-device and certain byte-manipulation operations
may require `bash`. The exact minimum shell version is documented in
[RESEARCH.md](RESEARCH.md).

## Building

```sh
./build.sh          # produces dist/tlsh.sh
```

The build step concatenates all source modules and applies comment stripping.
Further minification may be added later.

## Usage

```sh
# Equivalent to: openssl s_client -connect example.com:443
./dist/tlsh.sh s_client -connect example.com:443
```

## Project Status

Early research and planning phase. See [PLAN.md](PLAN.md) and
[RESEARCH.md](RESEARCH.md) for details.

## License

MIT
