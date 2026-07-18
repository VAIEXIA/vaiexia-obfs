//! Length-prefixed encrypted framing for the obfuscated TCP transport.
//!
//! Wire format for each frame (after the Noise handshake):
//!
//! ```text
//! ┌─────────────────────────┬──────────────────────────────────────┐
//! │  length (4 bytes, BE)   │  Noise ciphertext (length bytes)     │
//! └─────────────────────────┴──────────────────────────────────────┘
//! ```
//!
//! - `length` is a big-endian `u32` encoding the byte length of the
//!   *ciphertext* that follows (not the plaintext).
//! - The plaintext inside is a JSON-encoded [`Envelope`].
//! - Maximum frame size: [`MAX_FRAME`] bytes (ciphertext).
//!
//! # Chunking
//! snow limits each encrypted message to 65535 bytes. Frames whose *plaintext*
//! exceeds `65535 - 16` bytes (the AEAD overhead) must be split by the caller
//! before calling [`write_frame`].  In practice all RPC envelopes are well
//! under that limit.

use crate::{ObfsError, Result, envelope::Envelope};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vaiexia_wire::session::Session;

/// Maximum permitted ciphertext size (16 MiB).  Frames larger than this
/// are rejected on read to prevent memory exhaustion.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Serialise `envelope`, encrypt it with `session`, and write it to `io`
/// as a length-prefixed frame.
pub async fn write_frame<W>(
    io: &mut W,
    session: &mut Session,
    envelope: &Envelope,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let plaintext = serde_json::to_vec(envelope)?;
    let ciphertext = session.encrypt(&plaintext)?;

    let len = ciphertext.len();
    if len > MAX_FRAME {
        return Err(ObfsError::FrameTooLarge(len, MAX_FRAME));
    }

    let len_bytes = (len as u32).to_be_bytes();
    io.write_all(&len_bytes).await?;
    io.write_all(&ciphertext).await?;
    Ok(())
}

/// Read one length-prefixed frame from `io`, decrypt it with `session`,
/// and deserialise the plaintext as an [`Envelope`].
pub async fn read_frame<R>(
    io: &mut R,
    session: &mut Session,
) -> Result<Envelope>
where
    R: AsyncRead + Unpin,
{
    // Read the 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    match io.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ObfsError::Closed);
        }
        Err(e) => return Err(ObfsError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;

    if len == 0 {
        return Err(ObfsError::Closed);
    }
    if len > MAX_FRAME {
        return Err(ObfsError::FrameTooLarge(len, MAX_FRAME));
    }

    // Read the ciphertext.
    let mut ciphertext = vec![0u8; len];
    match io.read_exact(&mut ciphertext).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ObfsError::Closed);
        }
        Err(e) => return Err(ObfsError::Io(e)),
    }

    // Decrypt and parse.
    let plaintext = session.decrypt(&ciphertext)?;
    let envelope = serde_json::from_slice(&plaintext)?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake_io::{client_handshake, server_handshake};
    use vaiexia_core::protocol::{Method, Request, RequestId};
    use vaiexia_core::version::ProtoVersion;
    use vaiexia_wire::keypair::generate_keypair;

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

    #[tokio::test]
    async fn ping_pong_roundtrip() {
        let (mut cs, mut ss) = make_sessions().await;

        let (mut client_io, mut server_io) = tokio::io::duplex(4096);

        // Client writes Ping → server reads it.
        write_frame(&mut client_io, &mut cs, &Envelope::Ping)
            .await
            .unwrap();
        let received = read_frame(&mut server_io, &mut ss).await.unwrap();
        assert!(matches!(received, Envelope::Ping));

        // Server writes Pong → client reads it.
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

        // An empty reader immediately returns EOF.
        let mut empty: &[u8] = &[];
        let err = read_frame(&mut empty, &mut ss).await.unwrap_err();
        assert!(matches!(err, ObfsError::Closed), "expected Closed, got {err:?}");
    }
}
