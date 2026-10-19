# CRISPER

C2 framework. Unit 1 of the build: wire protocol and teamserver session core.

## What is in this tree

    proto/        crisper-proto — frames, AEAD, replay window, handshake,
                  CBOR message bodies. Ships with four unit tests.
    teamserver/   TLS listener, handshake, session registry, task queue,
                  SQLite (sessions, tasks, audit), file chunk assembly.
    docs/         PROTOCOL.md — byte-exact wire format.
    certs/        certificate generation notes.

Not in this tree yet (next units):

    console/      operator TUI/CLI
    api           bearer auth, TOTP, RBAC, REST surface
    implant/      C++20 x64, PEB walk, indirect syscalls, sleep obfuscation
    loader/       encrypted at rest, section mapping, anti-analysis gates
    stager/       Rust / Nim / Go stage-0 variants

The teamserver runs today. It accepts sessions, completes the handshake,
prints check-ins, stores task records, and assembles uploaded chunks.
Nothing can connect until the implant unit lands.

## Build

Needs Rust 1.79 or newer and a C toolchain for `rusqlite`'s bundled SQLite.

    cargo test --workspace
    cargo build --release -p crisper-teamserver

Windows users without `make`: run the two commands above directly.

## Run

    make certs
    # edit teamserver.yaml: psk_hex, bind, paths
    cargo run --release -p crisper-teamserver -- teamserver.yaml

On Windows, run from the repo root so the relative `certs/` paths resolve.

## Configuration

`teamserver.yaml`:

    bind: 0.0.0.0:443
    tls_cert: certs/server.pem
    tls_key: certs/server.key
    psk_hex: "<32 hex chars minimum>"
    db_path: data/crisper.db
    files_dir: data/files

The PSK is shared with the implant build. A mismatch fails the HMAC and
the connection drops before any key is derived.

## Protocol

See `docs/PROTOCOL.md`. Summary:

- TLS 1.3 transport, TCP client is the implant.
- 54-byte HELLO, 92-byte HELLO_ACK, HMAC-SHA256 over the transcript.
- X25519 + HKDF-SHA256 → 32-byte keys per direction.
- Frames: 10-byte header, ChaCha20-Poly1305 body, seq-based nonce.
- 1024-frame replay window, 8 MiB frame ceiling.
- CBOR bodies defined in `proto/src/msg.rs`.
- Rekey carries a fresh X25519 public key; the REKEY frame is the last
  frame on the old keys.

## Layout

    crisper/
      Cargo.toml
      Makefile
      proto/
        Cargo.toml
        src/lib.rs
        src/crypto.rs
        src/frame.rs
        src/handshake.rs
        src/msg.rs
      teamserver/
        Cargo.toml
        teamserver.yaml
        src/main.rs
        src/config.rs
        src/db.rs
        src/session.rs
        src/listener.rs
      docs/PROTOCOL.md
      certs/README.md
