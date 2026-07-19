# vaiexia-obfs

Noise-XK encrypted TCP transport for the VAIEXIA ecosystem, with
configurable traffic-mimicry profiles.

## What it is

`vaiexia-obfs` implements an encrypted transport channel over TCP using the
`vaiexia-wire` Noise-XK handshake and session layer, carrying
`vaiexia-core` RPC envelopes. It exposes:

- **`ObfsTransport`** — client-side connection that implements core's
  `Requester`, `Subscriber`, and `Connection` traits.
- **`serve_obfs()`** — server-side listener that accepts TCP connections,
  performs the Noise-XK handshake, gates clients via a `TransportGate`, and
  dispatches requests through a core `Service`.

## Phase 3b — Mimicry profiles

The transport is fully parameterised by a `MimicryProfile` (from
`vaiexia-wire`). Every byte on the wire — preamble, Noise handshake
messages, and transport records — is shaped by the active profile.
Two profiles are shipped:

### `Vanilla` (default, no obfuscation)

Wire format: `[len: u32 BE][ChaCha20Poly1305 ciphertext]`. Identical to the
Phase-2b baseline. No preamble, no padding, no jitter.

```rust
Arc::new(Vanilla::new(MimicryConfig::default()))
```

### `AmneziaJunk` (DPI-resistance)

Inspired by the AmneziaWG approach. Wire format per record:
```text
[magic: 4 bytes][len: u32 BE][record (len bytes)][padding to bucket multiple]
```

A random preamble (`preamble_junk_len` bytes) is written by the client before
the first frame; the server skips exactly that many bytes. Random bucket
padding hides payload sizes. Timing jitter adds inter-write delays.

```rust
Arc::new(AmneziaJunk::new(MimicryConfig {
    magic_header: [0xDE, 0xAD, 0xBE, 0xEF],
    preamble_junk_len: 23,
    pad_bucket: 128,
    jitter_ms: (0, 2),
}))
```

### Profile selection

Profiles are chosen **out-of-band** (same channel as the Noise server key).
There is no in-band negotiation — negotiating the profile would itself be a
fingerprint. Both peers must be configured with the same profile.

**Important:** `AmneziaJunk` improves DPI resistance but real-world
effectiveness requires testing against actual DPI hardware/software.

## Key model (Noise XK)

- The **client** pins the server's static public key before connecting.
  A wrong key causes the handshake to fail at the Diffie-Hellman step —
  connection to a rogue server is not possible.
- The **server** learns the client's static key authenticated and encrypted
  inside handshake message 3 (active-probing resistance).
- Post-handshake messages are encrypted with ChaCha20Poly1305 (BLAKE2s MAC).

## Usage

```rust
use std::sync::Arc;
use vaiexia_obfs::{serve_obfs, AllowAll, ObfsTransport, Vanilla, MimicryConfig};
use vaiexia_wire::keypair::generate_keypair;
use vaiexia_core::server::Service;
use vaiexia_core::transport::{Requester, Subscriber};

let profile = Arc::new(Vanilla::new(MimicryConfig::default()));

// Server
let server_kp = generate_keypair()?;
let svc = Arc::new(Service::builder().verifier(my_verifier).build());
let handle = serve_obfs(
    "0.0.0.0:4433",
    server_kp.private,
    svc,
    Arc::new(AllowAll),
    Arc::clone(&profile),
).await?;

// Client
let client_kp = generate_keypair()?;
let transport = ObfsTransport::connect(
    "127.0.0.1:4433",
    client_kp.private,
    server_kp.public,
    profile,
).await?;
let response = transport.request(req).await?;
```

## Proxy support (Phase 4)

`ObfsTransport::connect` accepts an optional `ProxyConfig` (from
`vaiexia-core`) to route the TCP connection through one or more proxy hops
before the Noise-XK handshake begins.

### Supported protocols

| Kind | RFC | Auth |
|------|-----|------|
| SOCKS5 | RFC 1928 + RFC 1929 | username/password (optional) |
| HTTP CONNECT | RFC 7231 §4.3.6 | `Proxy-Authorization: Basic` (optional) |

### Single-hop SOCKS5

```rust
use vaiexia_core::transport::proxy::{ProxyAuth, ProxyConfig, ProxyKind};

let proxy = ProxyConfig {
    kind: ProxyKind::Socks5,
    addr: "127.0.0.1:1080".to_string(),
    auth: Some(ProxyAuth { user: "alice".into(), pass: "s3cr3t".into() }),
    chain: vec![],
};

let client = ObfsTransport::connect(
    "10.0.0.1:4433",
    client_kp.private,
    server_public,
    profile,
    Some(proxy),
).await?;
```

### Single-hop HTTP CONNECT

```rust
let proxy = ProxyConfig {
    kind: ProxyKind::HttpConnect,
    addr: "proxy.example.com:3128".to_string(),
    auth: None,
    chain: vec![],
};
```

### Multi-hop chain (SOCKS5 → SOCKS5)

```rust
use vaiexia_core::transport::proxy::ProxyHop;

let proxy = ProxyConfig {
    kind: ProxyKind::Socks5,
    addr: "10.0.0.1:1080".to_string(),   // first hop
    auth: None,
    chain: vec![
        ProxyHop {
            kind: ProxyKind::Socks5,
            addr: "10.0.0.2:1080".to_string(),  // second hop
            auth: None,
        },
    ],
};
// Traffic path: client → proxy1 → proxy2 → obfs server
```

`chain` entries can mix kinds freely (e.g. SOCKS5 → HTTP CONNECT).
The Noise-XK handshake and all subsequent traffic are tunnelled through
the full chain — the proxies see only opaque bytes.

## snow 64 KiB limit

The ChaCha20Poly1305 implementation (snow) caps each transport message at
65 535 bytes. v1 RPC payloads are well under this limit.  Chunking large
payloads is a Phase 4 follow-up.

## Path dependencies

This crate requires `../vaiexia-core` and `../vaiexia-wire` as siblings.
CI runs in a multi-repo checkout that provides those paths. Switching to
git deps is a follow-up once the repos are published.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Copyright (c) 2026 VAIEXIA Team
