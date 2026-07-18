//! Async I/O driver for the Noise-XK handshake.
//!
//! Wraps the pure state machines in [`vaiexia_wire::handshake::Handshake`] and
//! drives the 3-message exchange over any `AsyncRead + AsyncWrite` stream.
//!
//! Message framing during the handshake uses a simple 2-byte big-endian length
//! prefix (handshake messages are well under 65535 bytes).

use crate::{ObfsError, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vaiexia_wire::{handshake::Handshake, session::Session};

/// Write a single handshake message with a 2-byte big-endian length prefix.
pub async fn write_hs_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> Result<()> {
    let len = msg.len() as u16;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(msg).await?;
    Ok(())
}

/// Read a single handshake message (2-byte length prefix).
pub async fn read_hs_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ObfsError::Closed);
        }
        Err(e) => return Err(ObfsError::Io(e)),
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    match r.read_exact(&mut buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ObfsError::Closed);
        }
        Err(e) => return Err(ObfsError::Io(e)),
    }
    Ok(buf)
}

/// Drive the **initiator** (client) side of the Noise-XK handshake.
///
/// Sends msg1, receives msg2, sends msg3, then returns the post-handshake
/// [`Session`].
///
/// `remote_public` is the server's known static public key (the "K" in XK).
pub async fn client_handshake<S>(
    mut io: S,
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = Handshake::initiator(local_private, remote_public)?;

    // msg1: initiator → responder  (e, es)
    let m1 = hs.write_message(b"")?;
    write_hs_msg(&mut io, &m1).await?;

    // msg2: responder → initiator  (e, ee)
    let m2 = read_hs_msg(&mut io).await?;
    hs.read_message(&m2)?;

    // msg3: initiator → responder  (s, se)
    let m3 = hs.write_message(b"")?;
    write_hs_msg(&mut io, &m3).await?;

    let session = hs.into_session()?;
    Ok(session)
}

/// Drive the **responder** (server) side of the Noise-XK handshake.
///
/// Receives msg1, sends msg2, receives msg3, then returns the post-handshake
/// [`Session`].
pub async fn server_handshake<S>(
    mut io: S,
    local_private: &[u8; 32],
) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = Handshake::responder(local_private)?;

    // msg1: initiator → responder  (e, es)
    let m1 = read_hs_msg(&mut io).await?;
    hs.read_message(&m1)?;

    // msg2: responder → initiator  (e, ee)
    let m2 = hs.write_message(b"")?;
    write_hs_msg(&mut io, &m2).await?;

    // msg3: initiator → responder  (s, se)
    let m3 = read_hs_msg(&mut io).await?;
    hs.read_message(&m3)?;

    let session = hs.into_session()?;
    Ok(session)
}

/// Drive the **initiator** side of the Noise-XK handshake **in-place** on a
/// mutable reference.
///
/// Unlike [`client_handshake`], this borrows the I/O object so the caller
/// retains ownership for subsequent framed communication.
pub async fn client_handshake_in_place<S>(
    io: &mut S,
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = Handshake::initiator(local_private, remote_public)?;

    let m1 = hs.write_message(b"")?;
    write_hs_msg(io, &m1).await?;

    let m2 = read_hs_msg(io).await?;
    hs.read_message(&m2)?;

    let m3 = hs.write_message(b"")?;
    write_hs_msg(io, &m3).await?;

    Ok(hs.into_session()?)
}

/// Drive the **responder** side of the Noise-XK handshake **in-place** on a
/// mutable reference.
///
/// Unlike [`server_handshake`], this borrows the I/O object so the caller
/// retains ownership for subsequent framed communication.
pub async fn server_handshake_in_place<S>(
    io: &mut S,
    local_private: &[u8; 32],
) -> Result<(Session, Option<[u8; 32]>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = Handshake::responder(local_private)?;

    let m1 = read_hs_msg(io).await?;
    hs.read_message(&m1)?;

    let m2 = hs.write_message(b"")?;
    write_hs_msg(io, &m2).await?;

    let m3 = read_hs_msg(io).await?;
    hs.read_message(&m3)?;

    let remote_static = hs.remote_static();
    let session = hs.into_session()?;
    Ok((session, remote_static))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaiexia_wire::keypair::generate_keypair;

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

        let (cs, ss_pair) = tokio::join!(
            client_handshake_in_place(&mut client_io, &client_kp.private, &server_kp.public),
            server_handshake_in_place(&mut server_io, &server_kp.private),
        );

        let mut cs = cs.unwrap();
        let (mut ss, remote_key) = ss_pair.unwrap();

        assert_eq!(remote_key.unwrap(), client_kp.public);

        let ct = cs.encrypt(b"in-place test").unwrap();
        assert_eq!(ss.decrypt(&ct).unwrap(), b"in-place test");
    }
}
