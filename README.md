# vaiexia-obfs

Noise-XK encrypted TCP transport for the VAIEXIA ecosystem.

## What it is

`vaiexia-obfs` implements an encrypted transport channel over TCP using the
`vaiexia-wire` Noise-XK handshake and session layer, carrying
`vaiexia-core` RPC envelopes. It exposes:

- **`ObfsTransport`** — client-side connection that implements core's
  `Requester`, `Subscriber`, and `Connection` traits.
- **`serve_obfs()`** — server-side listener that accepts TCP connections,
  performs the Noise-XK handshake, gates clients via a `TransportGate`, and
  dispatches requests through a core `Service`.

## Phase 2b — Vanilla

This is the **vanilla** (unobfuscated) profile: each message is framed as
`[len: u32 BE][ChaCha20Poly1305 ciphertext]`. The Noise-XK protocol
authenticates both sides; the server learns the client's static public key
(encrypted inside message 3). Phase 3 adds traffic-mimicry profiles on top
of the same framing.

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
use vaiexia_obfs::{serve_obfs, AllowAll, ObfsTransport};
use vaiexia_wire::keypair::generate_keypair;
use vaiexia_core::server::Service;
use vaiexia_core::transport::{Requester, Subscriber};

// Server
let server_kp = generate_keypair()?;
let svc = Arc::new(Service::builder().verifier(my_verifier).build());
let handle = serve_obfs(svc, "0.0.0.0:4433", server_kp.clone(), Arc::new(AllowAll)).await?;

// Client
let client_kp = generate_keypair()?;
let transport = ObfsTransport::connect("127.0.0.1:4433", server_kp.public, client_kp).await?;
let response = transport.request(req).await?;
```

## snow 64 KiB limit

The ChaCha20Poly1305 implementation (snow) caps each transport message at
65 535 bytes. v1 RPC payloads are well under this limit. `write_frame`
returns `ObfsError::FrameTooLarge` if a payload would exceed the cap.
Chunking large payloads is a Phase 3 follow-up.

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
