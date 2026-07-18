//! Profile-driven encrypted framing for the obfuscated TCP transport.
//!
//! Each frame is shaped by the active [`MimicryProfile`]:
//!
//! - [`send_frame`] serialises an [`Envelope`], encrypts it, and uses
//!   `profile.frame_out` to produce the final wire bytes.
//! - [`recv_frame`] accumulates bytes from the TCP stream into a caller-
//!   supplied buffer and calls `profile.frame_in` in a loop until a complete
//!   record arrives, then decrypts and deserialises it.
//!
//! Both functions operate on a single `&mut impl AsyncRead + AsyncWrite` so
//! the caller can keep a single stream object across the whole pump loop, which
//! is the same pattern the original Phase-2b code used and keeps tokio's I/O
//! reactor registration intact.
//!
//! # Handshake framing
//! Before a [`Session`] exists the raw Noise messages also pass through the
//! profile (`send_raw` / `recv_raw`).  The bytes are profile-shaped but not
//! session-encrypted (Noise messages are already random-looking).
//!
//! # Back-compat
//! `Vanilla` produces `[len u32 BE][record]` frames — identical to the old
//! `write_frame` / `read_frame` functions.  The old wrappers are kept below
//! so that existing tests continue to compile unchanged.

use crate::{ObfsError, Result, envelope::Envelope};
use rand::{SeedableRng, rngs::SmallRng};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vaiexia_wire::mimicry::{FrameInResult, MimicryProfile};
use vaiexia_wire::session::Session;

// ── Core framing functions ────────────────────────────────────────────────────

/// Serialise `env`, encrypt with `session`, shape with the profile, and
/// write to `io`.
///
/// Jitter is applied by the caller (before calling this function) to keep
/// this function a pure write operation.
pub async fn send_frame<W>(
    io: &mut W,
    session: &mut Session,
    env: &Envelope,
    profile: &dyn MimicryProfile,
    rng: &mut SmallRng,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let plaintext = serde_json::to_vec(env)?;
    let ciphertext = session.encrypt(&plaintext)?;

    let mut wire = Vec::new();
    profile.frame_out(&ciphertext, &mut wire, rng)?;
    io.write_all(&wire).await?;
    Ok(())
}

/// Accumulate bytes from `io` into `buf` until the profile yields a complete
/// frame, then decrypt and deserialise the payload as an [`Envelope`].
///
/// `buf` must be a caller-owned accumulation buffer that persists across calls
/// (e.g. a local `Vec<u8>` in the pump loop).  Bytes that were read but belong
/// to future frames remain in `buf` for the next call.
///
/// Returns:
/// - `Ok(Envelope)` on success.
/// - `Err(ObfsError::Closed)` on clean EOF with an empty buffer.
/// - `Err(ObfsError::Io(UnexpectedEof))` on EOF mid-frame.
/// - `Err(_)` on framing or decryption errors.
pub async fn recv_frame<R>(
    io: &mut R,
    session: &mut Session,
    profile: &dyn MimicryProfile,
    buf: &mut Vec<u8>,
) -> Result<Envelope>
where
    R: AsyncRead + Unpin,
{
    loop {
        match profile.frame_in(buf) {
            FrameInResult::Record(ciphertext) => {
                let plaintext = session.decrypt(&ciphertext)?;
                let env = serde_json::from_slice(&plaintext)?;
                return Ok(env);
            }
            FrameInResult::NeedMore => {
                let mut tmp = [0u8; 4096];
                let n = match io.read(&mut tmp).await {
                    Ok(0) => {
                        if buf.is_empty() {
                            return Err(ObfsError::Closed);
                        } else {
                            return Err(ObfsError::Io(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "EOF mid-frame",
                            )));
                        }
                    }
                    Ok(n) => n,
                    Err(e) => return Err(ObfsError::Io(e)),
                };
                buf.extend_from_slice(&tmp[..n]);
            }
            FrameInResult::Invalid(_msg) => {
                return Err(ObfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid framing",
                )));
            }
        }
    }
}

// ── Raw (pre-session) helpers — used by handshake_io ─────────────────────────

/// Write a raw pre-session byte message shaped through `profile` to `w`.
pub async fn send_raw<W>(
    w: &mut W,
    profile: &dyn MimicryProfile,
    rng: &mut SmallRng,
    bytes: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut wire = Vec::new();
    profile.frame_out(bytes, &mut wire, rng)?;
    w.write_all(&wire).await?;
    Ok(())
}

/// Read one raw pre-session framed message through `profile` from `r` using
/// an external accumulation buffer `buf`.
pub async fn recv_raw<R>(
    r: &mut R,
    profile: &dyn MimicryProfile,
    buf: &mut Vec<u8>,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    loop {
        match profile.frame_in(buf) {
            FrameInResult::Record(bytes) => return Ok(bytes),
            FrameInResult::NeedMore => {
                let mut tmp = [0u8; 4096];
                let n = match r.read(&mut tmp).await {
                    Ok(0) => {
                        if buf.is_empty() {
                            return Err(ObfsError::Closed);
                        } else {
                            return Err(ObfsError::Io(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "EOF mid-frame",
                            )));
                        }
                    }
                    Ok(n) => n,
                    Err(e) => return Err(ObfsError::Io(e)),
                };
                buf.extend_from_slice(&tmp[..n]);
            }
            FrameInResult::Invalid(_msg) => {
                return Err(ObfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid framing",
                )));
            }
        }
    }
}

// ── Compatibility structs for tests ──────────────────────────────────────────
//
// FramedWriter and FramedReader are kept as simple wrappers so the framing
// unit tests continue to compile.  They ARE used in the framing tests but are
// NOT used by the production pump (which uses send_frame/recv_frame with a
// single &mut TcpStream to keep reactor registration intact).

use vaiexia_wire::mimicry::Vanilla;

/// Writes profile-shaped, session-encrypted envelopes to an async writer.
pub struct FramedWriter<W> {
    w: W,
    profile: Arc<dyn MimicryProfile>,
    rng: SmallRng,
}

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    /// Create a new writer.
    pub fn new(w: W, profile: Arc<dyn MimicryProfile>) -> Self {
        Self { w, profile, rng: SmallRng::from_entropy() }
    }

    /// Send an envelope.
    pub async fn send(&mut self, session: &mut Session, env: &Envelope) -> Result<()> {
        send_frame(&mut self.w, session, env, self.profile.as_ref(), &mut self.rng).await
    }
}

/// Reads profile-shaped, session-encrypted envelopes from an async reader.
pub struct FramedReader<R> {
    r: R,
    profile: Arc<dyn MimicryProfile>,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    /// Create a new reader.
    pub fn new(r: R, profile: Arc<dyn MimicryProfile>) -> Self {
        Self { r, profile, buf: Vec::new() }
    }

    /// Receive one envelope.
    pub async fn recv(&mut self, session: &mut Session) -> Result<Envelope> {
        recv_frame(&mut self.r, session, self.profile.as_ref(), &mut self.buf).await
    }
}

// ── Legacy thin wrappers (kept for existing tests in framing.rs) ─────────────

/// Serialise `envelope`, encrypt it with `session`, and write it as a
/// Vanilla-framed record.  Kept for backwards-compatibility.
pub async fn write_frame<W>(
    io: &mut W,
    session: &mut Session,
    envelope: &Envelope,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut rng = SmallRng::from_entropy();
    send_frame(io, session, envelope, &Vanilla::new(Default::default()), &mut rng).await
}

/// Read one Vanilla-framed record from `io`, decrypt and deserialise it.
/// Kept for backwards-compatibility.
pub async fn read_frame<R>(
    io: &mut R,
    session: &mut Session,
) -> Result<Envelope>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    recv_frame(io, session, &Vanilla::new(Default::default()), &mut buf).await
}

/// Maximum permitted ciphertext size (16 MiB).  Kept for API compat.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake_io::{client_handshake, server_handshake};
    use vaiexia_core::protocol::{Method, Request, RequestId};
    use vaiexia_core::version::ProtoVersion;
    use vaiexia_wire::keypair::generate_keypair;
    use vaiexia_wire::mimicry::{AmneziaJunk, MimicryConfig};

    /// Run a Noise-XK handshake over a duplex pair and return (client_session, server_session).
    async fn make_sessions() -> (Session, Session) {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();

        let (client_io, server_io) = tokio::io::duplex(4096);

        let (cs, ss) = tokio::join!(
            client_handshake(client_io, &client_kp.private, &server_kp.public),
            server_handshake(server_io, &server_kp.private),
        );
        (cs.unwrap(), ss.unwrap())
    }

    // ── Legacy write_frame / read_frame (Vanilla) ─────────────────────────────

    #[tokio::test]
    async fn ping_pong_roundtrip() {
        let (mut cs, mut ss) = make_sessions().await;

        let (mut client_io, mut server_io) = tokio::io::duplex(4096);

        write_frame(&mut client_io, &mut cs, &Envelope::Ping)
            .await
            .unwrap();
        let received = read_frame(&mut server_io, &mut ss).await.unwrap();
        assert!(matches!(received, Envelope::Ping));

        write_frame(&mut server_io, &mut ss, &Envelope::Pong)
            .await
            .unwrap();
        let received2 = read_frame(&mut client_io, &mut cs).await.unwrap();
        assert!(matches!(received2, Envelope::Pong));
    }

    #[tokio::test]
    async fn request_envelope_roundtrip() {
        let (mut cs, mut ss) = make_sessions().await;
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);

        let req = Request {
            id: RequestId::new(),
            version: ProtoVersion::CURRENT,
            method: Method::new("server.ping").unwrap(),
            params: serde_json::json!({"key": "value"}),
            capability: None,
        };
        let env = Envelope::Request(req.clone());

        write_frame(&mut client_io, &mut cs, &env)
            .await
            .unwrap();
        let back = read_frame(&mut server_io, &mut ss).await.unwrap();

        match back {
            Envelope::Request(r) => assert_eq!(r.id.as_str(), req.id.as_str()),
            _ => panic!("expected Request envelope, got: {:?}", back),
        }
    }

    #[tokio::test]
    async fn eof_returns_closed() {
        let (_cs, mut ss) = make_sessions().await;

        let mut empty: &[u8] = &[];
        let err = read_frame(&mut empty, &mut ss).await.unwrap_err();
        assert!(matches!(err, ObfsError::Closed), "expected Closed, got {err:?}");
    }

    // ── FramedWriter / FramedReader with Vanilla ───────────────────────────────

    #[tokio::test]
    async fn framed_writer_reader_vanilla_roundtrip() {
        let (mut cs, mut ss) = make_sessions().await;
        let (client_io, server_io) = tokio::io::duplex(8192);

        let profile: Arc<dyn MimicryProfile> =
            Arc::new(Vanilla::new(MimicryConfig::default()));

        let mut fw = FramedWriter::new(client_io, Arc::clone(&profile));
        let mut fr = FramedReader::new(server_io, Arc::clone(&profile));

        fw.send(&mut cs, &Envelope::Ping).await.unwrap();
        let got = fr.recv(&mut ss).await.unwrap();
        assert!(matches!(got, Envelope::Ping));
    }

    // ── FramedWriter / FramedReader with AmneziaJunk ─────────────────────────

    #[tokio::test]
    async fn framed_writer_reader_amnezia_roundtrip() {
        let (mut cs, mut ss) = make_sessions().await;
        let (client_io, server_io) = tokio::io::duplex(65536);

        let profile: Arc<dyn MimicryProfile> = Arc::new(AmneziaJunk::new(MimicryConfig {
            magic_header: [0xDE, 0xAD, 0xBE, 0xEF],
            preamble_junk_len: 0,
            pad_bucket: 64,
            jitter_ms: (0, 0),
        }));

        let mut fw = FramedWriter::new(client_io, Arc::clone(&profile));
        let mut fr = FramedReader::new(server_io, Arc::clone(&profile));

        fw.send(&mut cs, &Envelope::Ping).await.unwrap();
        let got1 = fr.recv(&mut ss).await.unwrap();
        assert!(matches!(got1, Envelope::Ping));
    }

    // ── Partial / interleaved reads reassemble ────────────────────────────────

    #[tokio::test]
    async fn partial_reads_reassemble_vanilla() {
        let (mut cs, mut ss) = make_sessions().await;

        let profile: Arc<dyn MimicryProfile> =
            Arc::new(Vanilla::new(MimicryConfig::default()));

        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut fw = FramedWriter::new(client_io, Arc::clone(&profile));
        let mut fr = FramedReader::new(server_io, Arc::clone(&profile));

        fw.send(&mut cs, &Envelope::Ping).await.unwrap();
        fw.send(&mut cs, &Envelope::Pong).await.unwrap();

        let g1 = fr.recv(&mut ss).await.unwrap();
        let g2 = fr.recv(&mut ss).await.unwrap();
        assert!(matches!(g1, Envelope::Ping));
        assert!(matches!(g2, Envelope::Pong));
    }
}
