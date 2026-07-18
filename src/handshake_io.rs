//! Async I/O driver for the Noise-XK handshake.
//!
//! Wraps the pure state machines in [`vaiexia_wire::handshake::Handshake`] and
//! drives the 3-message exchange over any `AsyncRead + AsyncWrite` stream.
//!
//! # Preamble junk
//! When a [`MimicryProfile`] has a non-zero `preamble_junk_len`, the **sender**
//! (always the client / initiator) writes that many random bytes before the
//! first handshake frame.  The **receiver** (server / responder) reads and
//! discards exactly `profile.preamble_skip()` bytes before parsing frames.
//!
//! Both sides must be configured with the same profile (out-of-band), so the
//! receiver knows exactly how many bytes to skip — there is no in-band length.
//!
//! # Message framing
//! The 3 XK messages are sent / received via `send_raw` / `recv_raw` in
//! [`crate::framing`] so they are shaped by the active profile exactly like
//! transport records, but without session encryption (Noise messages are
//! already cryptographically random).

use crate::{ObfsError, Result};
use crate::framing::{recv_raw, send_raw};
use rand::{SeedableRng, rngs::SmallRng};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vaiexia_wire::{handshake::Handshake, mimicry::MimicryProfile, session::Session};

// ── Profile-aware in-place variants (used by client.rs / server.rs) ──────────

/// Drive the **initiator** (client) side of the Noise-XK handshake **in-place**
/// on a mutable reference, using `profile` for preamble + message framing.
///
/// - Writes `profile.preamble(...)` bytes to the socket first.
/// - Sends all 3 XK messages via `send_raw` / `recv_raw`.
/// - Returns `(Session, leftover_buf)`.  `leftover_buf` holds any bytes already
///   read from the socket beyond msg2.  Pass it as the initial pump read buffer.
pub async fn client_handshake_in_place<S>(
    io: &mut S,
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    profile: &Arc<dyn MimicryProfile>,
) -> Result<(Session, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut rng = SmallRng::from_entropy();
    let mut hs = Handshake::initiator(local_private, remote_public)?;
    let mut buf = Vec::new();

    // Preamble junk (client always sends it).
    let mut preamble = Vec::new();
    profile.preamble(&mut preamble, &mut rng);
    if !preamble.is_empty() {
        io.write_all(&preamble).await?;
        io.flush().await?;
    }

    // msg1: initiator → responder  (e, es)
    let m1 = hs.write_message(b"")?;
    send_raw(io, profile.as_ref(), &mut rng, &m1).await?;

    // msg2: responder → initiator  (e, ee)
    let m2 = recv_raw(io, profile.as_ref(), &mut buf).await?;
    hs.read_message(&m2)?;

    // msg3: initiator → responder  (s, se)
    let m3 = hs.write_message(b"")?;
    send_raw(io, profile.as_ref(), &mut rng, &m3).await?;

    // Return leftover bytes (normally empty; server can't send before msg3 in XK).
    Ok((hs.into_session()?, buf))
}

/// Drive the **responder** (server) side of the Noise-XK handshake **in-place**
/// on a mutable reference, using `profile` for preamble skip + message framing.
///
/// - Reads and discards exactly `profile.preamble_skip()` bytes first.
/// - Receives all 3 XK messages via `send_raw` / `recv_raw`.
/// - Returns `(Session, remote_static, leftover_buf)`.  `leftover_buf` holds
///   any bytes that were read from the socket beyond what the handshake needed.
///   The caller MUST pass this as the initial contents of its read buffer so
///   that frames sent by the peer immediately after the handshake (before the
///   server loop started) are not silently discarded.
pub async fn server_handshake_in_place<S>(
    io: &mut S,
    local_private: &[u8; 32],
    profile: &Arc<dyn MimicryProfile>,
) -> Result<(Session, Option<[u8; 32]>, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut rng = SmallRng::from_entropy();
    let mut hs = Handshake::responder(local_private)?;
    let mut buf = Vec::new();

    // Skip preamble junk the client sent.
    let skip = profile.preamble_skip();
    if skip > 0 {
        let mut discard = vec![0u8; skip];
        match io.read_exact(&mut discard).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(ObfsError::Closed);
            }
            Err(e) => return Err(ObfsError::Io(e)),
        }
    }

    // msg1: initiator → responder  (e, es)
    let m1 = recv_raw(io, profile.as_ref(), &mut buf).await?;
    hs.read_message(&m1)?;

    // msg2: responder → initiator  (e, ee)
    let m2 = hs.write_message(b"")?;
    send_raw(io, profile.as_ref(), &mut rng, &m2).await?;

    // msg3: initiator → responder  (s, se)
    let m3 = recv_raw(io, profile.as_ref(), &mut buf).await?;
    hs.read_message(&m3)?;

    let remote_static = hs.remote_static();
    let session = hs.into_session()?;
    // Return `buf` to the caller — any bytes already read beyond msg3
    // (e.g. the first transport frame sent by the client) must not be lost.
    Ok((session, remote_static, buf))
}

// ── Vanilla (profile-free) variants — kept for unit tests ────────────────────

use vaiexia_wire::mimicry::Vanilla;

/// Drive the **initiator** (client) side of the Noise-XK handshake.
///
/// Takes ownership of `io`; returns the post-handshake [`Session`].
/// Uses Vanilla framing (no preamble, no padding).
///
/// # Note
/// Prefer [`client_handshake_in_place`] in production code so the stream
/// remains available after the handshake.
pub async fn client_handshake<S>(
    mut io: S,
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let profile: Arc<dyn MimicryProfile> = Arc::new(Vanilla::new(Default::default()));
    let (session, _leftover) =
        client_handshake_in_place(&mut io, local_private, remote_public, &profile).await?;
    Ok(session)
}

/// Drive the **responder** (server) side of the Noise-XK handshake.
///
/// Takes ownership of `io`; returns the post-handshake [`Session`].
/// Uses Vanilla framing (no preamble, no padding).
///
/// # Note
/// Prefer [`server_handshake_in_place`] in production code so the stream
/// remains available after the handshake.
pub async fn server_handshake<S>(
    mut io: S,
    local_private: &[u8; 32],
) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let profile: Arc<dyn MimicryProfile> = Arc::new(Vanilla::new(Default::default()));
    let (session, _, _leftover) =
        server_handshake_in_place(&mut io, local_private, &profile).await?;
    Ok(session)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vaiexia_wire::keypair::generate_keypair;
    use vaiexia_wire::mimicry::{AmneziaJunk, MimicryConfig};

    /// A full Noise-XK handshake over a duplex pipe completes on both sides.
    #[tokio::test]
    async fn handshake_completes() {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();

        let (client_io, server_io) = tokio::io::duplex(4096);

        let (client_res, server_res) = tokio::join!(
            client_handshake(client_io, &client_kp.private, &server_kp.public),
            server_handshake(server_io, &server_kp.private),
        );

        assert!(client_res.is_ok(), "client handshake failed");
        assert!(server_res.is_ok(), "server handshake failed");
    }

    /// Sessions produced by a successful handshake can encrypt/decrypt.
    #[tokio::test]
    async fn sessions_interoperate_after_handshake() {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();

        let (client_io, server_io) = tokio::io::duplex(4096);

        let (cs, ss) = tokio::join!(
            client_handshake(client_io, &client_kp.private, &server_kp.public),
            server_handshake(server_io, &server_kp.private),
        );
        let mut cs = cs.unwrap();
        let mut ss = ss.unwrap();

        let ct = cs.encrypt(b"hello").unwrap();
        assert_eq!(ss.decrypt(&ct).unwrap(), b"hello");

        let ct2 = ss.encrypt(b"world").unwrap();
        assert_eq!(cs.decrypt(&ct2).unwrap(), b"world");
    }

    /// Using the wrong server public key causes the handshake to fail.
    #[tokio::test]
    async fn wrong_server_key_fails() {
        let server_kp = generate_keypair().unwrap();
        let attacker_kp = generate_keypair().unwrap(); // wrong key
        let client_kp = generate_keypair().unwrap();

        let (client_io, server_io) = tokio::io::duplex(4096);

        let (client_res, _server_res) = tokio::join!(
            // Client pins the attacker's public key instead of the server's.
            client_handshake(client_io, &client_kp.private, &attacker_kp.public),
            server_handshake(server_io, &server_kp.private),
        );

        assert!(client_res.is_err(), "handshake with wrong key should fail");
    }

    /// In-place variants keep the stream available after the handshake.
    #[tokio::test]
    async fn in_place_variants_complete() {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();

        let (mut client_io, mut server_io) = tokio::io::duplex(4096);
        let profile: Arc<dyn MimicryProfile> = Arc::new(Vanilla::new(Default::default()));

        let (cs, ss_pair) = tokio::join!(
            client_handshake_in_place(&mut client_io, &client_kp.private, &server_kp.public, &profile),
            server_handshake_in_place(&mut server_io, &server_kp.private, &profile),
        );

        let (mut cs, _) = cs.unwrap();
        let (mut ss, remote_key, _leftover) = ss_pair.unwrap();

        assert_eq!(remote_key.unwrap(), client_kp.public);

        let ct = cs.encrypt(b"in-place test").unwrap();
        assert_eq!(ss.decrypt(&ct).unwrap(), b"in-place test");
    }

    /// Preamble junk + profile-shaped handshake with AmneziaJunk, non-zero magic.
    /// Both sides complete and the sessions interop.
    #[tokio::test]
    async fn amnezia_preamble_shaped_handshake() {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();

        let (mut client_io, mut server_io) = tokio::io::duplex(65536);

        let profile: Arc<dyn MimicryProfile> = Arc::new(AmneziaJunk::new(MimicryConfig {
            magic_header: [0xCA, 0xFE, 0xBA, 0xBE],
            preamble_junk_len: 17,
            pad_bucket: 64,
            jitter_ms: (0, 0),
        }));

        let (cs, ss_pair) = tokio::join!(
            client_handshake_in_place(
                &mut client_io,
                &client_kp.private,
                &server_kp.public,
                &profile,
            ),
            server_handshake_in_place(&mut server_io, &server_kp.private, &profile),
        );

        let (mut cs, _) = cs.unwrap();
        let (mut ss, remote_key, _leftover) = ss_pair.unwrap();

        assert_eq!(remote_key.unwrap(), client_kp.public);

        // Sessions can encrypt/decrypt after the profile-shaped handshake.
        let ct = cs.encrypt(b"preamble works").unwrap();
        assert_eq!(ss.decrypt(&ct).unwrap(), b"preamble works");
    }
}
