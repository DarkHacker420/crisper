# CRISPER — wire protocol v1

Status: unit 1 (protocol + teamserver session core).
Byte order: big-endian for every integer.

## 1. Transport

TLS 1.3, ALPN `h2` in the HTTPS profile. The TCP profile is the same
handshake and the same frames over a TLS stream with no HTTP layer.

The implant is the TCP client; the teamserver is the TCP server.

## 2. Handshake

The handshake runs before any encrypted frame and is not length-prefixed.

### HELLO (client → server), 54 bytes

| offset | size | field |
|---|---|---|
| 0  | 4  | magic `CRSP` |
| 4  | 2  | version = 1 |
| 6  | 32 | client X25519 public key |
| 38 | 16 | client nonce (random) |

### HELLO_ACK (server → client), 92 bytes

| offset | size | field |
|---|---|---|
| 0  | 32 | server X25519 public key |
| 32 | 16 | server nonce (random) |
| 48 | 12 | handshake nonce, mixed into HKDF info |
| 60 | 32 | HMAC-SHA256 |

HMAC input:

    hello_bytes (54) || ack.public (32) || ack.nonce (16) || ack.gcm_nonce (12)

HMAC key: the pre-shared key (PSK), minimum 16 bytes, delivered out of band.

### Key derivation

    shared = X25519(client_secret, server_public)
    salt   = client_nonce || server_nonce          (32 bytes)
    info   = "crisper-v1" || gcm_nonce             (22 bytes)
    okm    = HKDF-SHA256(ikm = shared, salt, info, 96 bytes)

    k_c2s = okm[0..32]    client → server
    k_s2c = okm[32..64]   server → client
    k_mac = okm[64..96]   reserved for out-of-band MACs

The client MUST verify the HMAC before deriving keys or sending a frame.
A failed HMAC aborts the connection with no further bytes written.

## 3. Frames

    offset size field
    0      1    type
    1      1    flags
    2      4    seq          (per direction, starts at 0, increments by 1)
    6      4    body_len     (ciphertext length, tag included)
    10     N    body

    body = ChaCha20-Poly1305(k_dir, nonce, aad = header[0..10], plaintext)

    nonce = seq as u32 big-endian || 8 zero bytes   (12 bytes total)

`body_len` must be 1..=8 MiB. A frame that violates any rule closes the
connection; no partial state is retained.

Replay window: 1024 sequences. A frame with `seq` more than 1023 behind
the highest accepted sequence, or one already accepted, is dropped and the
session closes.

## 4. Message types

| value | name | direction |
|---|---|---|
| 0x01 | HELLO | c → s |
| 0x02 | HELLO_ACK | s → c |
| 0x03 | CHECKIN | c → s |
| 0x10 | TASK | s → c |
| 0x11 | TASK_RESULT | c → s |
| 0x12 | TASK_CANCEL | s → c |
| 0x20 | PING | both |
| 0x21 | PONG | both |
| 0x22 | REKEY | c → s |
| 0x30 | FILE_CHUNK | c → s |
| 0x31 | FILE_ACK | s → c |
| 0x32 | FILE_END | c → s |
| 0x40 | PIVOT_START | both |
| 0x41 | PIVOT_DATA | both |
| 0x42 | PIVOT_END | both |
| 0xF0 | KILL | s → c |
| 0xFF | ERROR | both |

Bodies are CBOR (RFC 8949), definite lengths, struct field order as
declared in `proto/src/msg.rs`.

### CHECKIN

    hostname, username, domain, pid, ppid, path, integrity, arch,
    os_build, uptime, sid, modules[], keyfp

### TASK

    id (u64), kind (string), args (byte string, command-specific),
    deadline (optional u64, unix seconds)

### TASK_RESULT

    id (u64), status (i32), data (byte string), done (bool)

### REKEY

    public (32-byte X25519 key)

Rekey derivation:

    shared = X25519(server_secret, client_rekey_public)
    salt   = client_rekey_public || server_public   (64 bytes)
    info   = "crisper-v1-rekey"
    okm    = HKDF-SHA256(shared, salt, info, 96 bytes)
    split  = same as §2

The REKEY frame is the last frame on the old keys. Every frame after it,
in both directions, uses the new keys.

### FILE_CHUNK / FILE_ACK / FILE_END

    FILE_CHUNK: xfer (u32), offset (u64), data (bytes), sha256 (32)
    FILE_ACK:   xfer (u32), next (u64)
    FILE_END:   xfer (u32), size (u64), sha256 (32)

The receiver verifies each chunk digest before writing. `next` is
`offset + len(data)`. Resume sends the chunk at `next`.

## 5. Failure rules

- bad magic, version, HMAC → close, no response
- bad AEAD tag → close immediately
- unknown type → close
- body_len 0 or > 8 MiB → close
- replayed or out-of-window seq → close
- chunk digest mismatch → ERROR frame, chunk not written
