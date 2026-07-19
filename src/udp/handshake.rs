//! UDP Noise-XK handshake: retransmission, seed-in-msg3, cookie DoS.

use std::net::SocketAddr;
use std::sync::Arc;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use vaiexia_wire::cookie::CookieSecret;
use vaiexia_wire::handshake::Handshake;
use vaiexia_wire::mimicry::DatagramMimicry;
use vaiexia_wire::record::{RecordSealer, RecordOpener};

use crate::udp::wire_dgram::{DgramType, encode_inner, decode_inner};
use crate::udp::keys::derive_record_keys;
use crate::udp::dataplane::DataChannel;
use crate::udp::cookie_gate::LoadGate;
use crate::{ObfsError, Result};

const RETRANSMIT_INTERVAL: Duration = Duration::from_millis(250);
const MAX_HS_TRIES: usize = 12;
const MAX_HANDSHAKE_ATTEMPTS: usize = 3;
const READY_WAIT_TIMEOUT: Duration = Duration::from_millis(2000);
const MAX_DGRAM: usize = 65535;

/// Shape a handshake message into a wire datagram.
fn shape_hs(ty: DgramType, msg: &[u8], mimic: &Arc<dyn DatagramMimicry>, rng: &mut dyn RngCore) -> Vec<u8> {
    let inner = encode_inner(ty, msg);
    let mut out = Vec::new();
    mimic.shape_out(&inner, &mut out, rng);
    out
}

/// Unshape a received datagram, returning (type, body) if it's a valid hs datagram.
fn unshape_hs(datagram: &[u8], mimic: &Arc<dyn DatagramMimicry>) -> Option<(DgramType, Vec<u8>)> {
    let inner = mimic.shape_in(datagram)?;
    let (ty, body) = decode_inner(&inner)?;
    Some((ty, body.to_vec()))
}

/// Encode a cookie reply: [cookie 16 bytes]
fn encode_cookie(cookie: [u8; 16]) -> Vec<u8> {
    cookie.to_vec()
}

/// Decode a cookie from a Cookie datagram body.
fn decode_cookie(body: &[u8]) -> Option<[u8; 16]> {
    if body.len() < 16 { return None; }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&body[..16]);
    Some(arr)
}

/// Get source bytes for cookie (ip:port as bytes)
fn src_bytes(addr: &SocketAddr) -> Vec<u8> {
    addr.to_string().into_bytes()
}

/// Encode msg1 with optional cookie, length-prefixing the msg1 so the responder
/// can split the (variable-length) Noise message from the fixed 16-byte cookie.
fn encode_msg1_framed(msg1: &[u8], cookie: Option<[u8; 16]>) -> Vec<u8> {
    let mut out = Vec::new();
    let len = msg1.len() as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(msg1);
    if let Some(c) = cookie {
        out.extend_from_slice(&c);
    }
    out
}

fn decode_msg1_framed(body: &[u8]) -> Option<(Vec<u8>, Option<[u8; 16]>)> {
    if body.len() < 2 { return None; }
    let msg1_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let rest = &body[2..];
    if rest.len() < msg1_len { return None; }
    let msg1 = rest[..msg1_len].to_vec();
    let remaining = &rest[msg1_len..];
    let cookie = if remaining.len() >= 16 {
        let mut c = [0u8; 16];
        c.copy_from_slice(&remaining[..16]);
        Some(c)
    } else {
        None
    };
    Some((msg1, cookie))
}

/// Client side: perform the XK handshake, obtain a DataChannel.
pub async fn client_udp_handshake(
    sock: Arc<UdpSocket>,
    server_addr: SocketAddr,
    server_pub: [u8; 32],
    client_kp: vaiexia_wire::keypair::StaticKeypair,
    mimic: Arc<dyn DatagramMimicry>,
    rng: &mut dyn RngCore,
) -> Result<DataChannel> {
    for _attempt in 0..MAX_HANDSHAKE_ATTEMPTS {
        // Generate a fresh seed for each attempt
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        // Build initiator
        let mut hs = Handshake::initiator(&client_kp.private, &server_pub)
            .map_err(|e| ObfsError::HandshakeFailed(format!("initiator: {e}")))?;

        // Write msg1
        let msg1 = hs.write_message(&[])
            .map_err(|e| ObfsError::HandshakeFailed(format!("write msg1: {e}")))?;

        let mut current_cookie: Option<[u8; 16]> = None;
        let mut msg2_body: Option<Vec<u8>> = None;

        // Retransmit msg1 loop: send, wait for msg2 or cookie
        'msg1_loop: for _try in 0..MAX_HS_TRIES {
            let framed = encode_msg1_framed(&msg1, current_cookie);
            let wire = shape_hs(DgramType::Hs1, &framed, &mimic, rng);
            sock.send_to(&wire, server_addr).await
                .map_err(ObfsError::Io)?;

            // Wait for response
            let result = timeout(RETRANSMIT_INTERVAL, recv_from_server(&sock, server_addr, MAX_DGRAM)).await;
            match result {
                Err(_) => continue, // timed out, retransmit
                Ok(Err(e)) => return Err(ObfsError::Io(e)),
                Ok(Ok(data)) => {
                    match unshape_hs(&data, &mimic) {
                        Some((DgramType::Hs2, body)) => {
                            msg2_body = Some(body);
                            break 'msg1_loop;
                        }
                        Some((DgramType::Cookie, body)) => {
                            // Server sent us a cookie challenge
                            if let Some(cookie) = decode_cookie(&body) {
                                current_cookie = Some(cookie);
                            }
                            continue;
                        }
                        _ => continue, // ignore other datagrams
                    }
                }
            }
        }

        let msg2 = match msg2_body {
            Some(b) => b,
            None => continue, // didn't get msg2, try fresh handshake
        };

        // Process msg2
        if hs.read_message(&msg2).is_err() {
            continue; // bad msg2 — try fresh
        }

        // Write msg3 with seed as payload
        let msg3 = match hs.write_message(&seed) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let wire3 = shape_hs(DgramType::Hs3, &msg3, &mimic, rng);
        sock.send_to(&wire3, server_addr).await
            .map_err(ObfsError::Io)?;

        // Derive keys
        let (c2s_key, s2c_key) = derive_record_keys(&seed);
        let channel = DataChannel::new(
            RecordSealer::new(c2s_key),
            RecordOpener::new(s2c_key),
            Arc::clone(&mimic),
        );

        // Wait for the server's "ready" record (server sends an initial s2c Data
        // datagram after completing the handshake).
        let wait_result = timeout(READY_WAIT_TIMEOUT, async {
            loop {
                let data = recv_from_server(&sock, server_addr, MAX_DGRAM).await?;
                if let Ok(Some(_)) = channel.open_datagram(&data) {
                    return Ok::<(), std::io::Error>(());
                }
            }
        }).await;

        match wait_result {
            Ok(Ok(())) => return Ok(channel),
            _ => {
                // Resend msg3 a few more times and try waiting again
                for _ in 0..3 {
                    let _ = sock.send_to(&wire3, server_addr).await;
                    let wait = timeout(Duration::from_millis(500), async {
                        loop {
                            match recv_from_server(&sock, server_addr, MAX_DGRAM).await {
                                Ok(data) => {
                                    if let Ok(Some(_)) = channel.open_datagram(&data) {
                                        return Ok::<(), std::io::Error>(());
                                    }
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }).await;
                    if let Ok(Ok(())) = wait {
                        return Ok(channel);
                    }
                }
                // Try fresh handshake
                continue;
            }
        }
    }

    Err(ObfsError::HandshakeFailed("handshake exhausted all attempts".into()))
}

/// Receive a datagram from a specific source address.
async fn recv_from_server(
    sock: &UdpSocket,
    expected_src: SocketAddr,
    max_size: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; max_size];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        if src == expected_src {
            return Ok(buf[..n].to_vec());
        }
    }
}

/// Result of processing an inbound Hs1 datagram from a client.
// Transient value, destructured immediately by the caller — boxing the large
// `Handshake` variant would only add an allocation per accepted Hs1.
#[allow(clippy::large_enum_variant)]
pub enum AcceptResult {
    /// Send this cookie reply to the client, allocate no state.
    CookieReply(Vec<u8>),
    /// Handshake state partially set up, waiting for msg3.
    PartialHandshake {
        responder: Handshake,
        msg2: Vec<u8>,
        client_addr: SocketAddr,
    },
}

/// Process an inbound Hs1: if under load and no valid cookie → CookieReply.
/// Otherwise, run msg1→msg2 and return PartialHandshake.
pub fn process_hs1(
    body: &[u8],
    client_addr: SocketAddr,
    server_private: &[u8; 32],
    cookie_secret: &CookieSecret,
    load_gate: &dyn LoadGate,
    mimic: &Arc<dyn DatagramMimicry>,
    rng: &mut dyn RngCore,
) -> Result<Option<AcceptResult>> {
    let (msg1, supplied_cookie) = match decode_msg1_framed(body) {
        Some(pair) => pair,
        None => return Ok(None), // malformed
    };

    let src = src_bytes(&client_addr);

    // Cookie check under load
    if load_gate.under_load() {
        let cookie_ok = supplied_cookie
            .map(|c| cookie_secret.verify(&src, &c))
            .unwrap_or(false);

        if !cookie_ok {
            // Send cookie reply
            let cookie = cookie_secret.make(&src);
            let encoded = encode_cookie(cookie);
            let wire = shape_hs(DgramType::Cookie, &encoded, mimic, rng);
            return Ok(Some(AcceptResult::CookieReply(wire)));
        }
    }

    // Not under load (or cookie verified) — run responder msg1→msg2
    let mut hs = match Handshake::responder(server_private) {
        Ok(h) => h,
        Err(e) => return Err(ObfsError::HandshakeFailed(format!("responder: {e}"))),
    };

    if hs.read_message(&msg1).is_err() {
        return Ok(None); // malformed msg1
    }

    let msg2 = hs.write_message(&[])
        .map_err(|e| ObfsError::HandshakeFailed(format!("write msg2: {e}")))?;
    let wire_msg2 = shape_hs(DgramType::Hs2, &msg2, mimic, rng);

    Ok(Some(AcceptResult::PartialHandshake {
        responder: hs,
        msg2: wire_msg2,
        client_addr,
    }))
}

/// Complete the handshake on msg3: extract seed, derive keys, return DataChannel + client static key.
pub fn complete_handshake_msg3(
    responder: &mut Handshake,
    msg3_body: &[u8],
    mimic: Arc<dyn DatagramMimicry>,
) -> Result<(DataChannel, [u8; 32])> {
    let payload = responder.read_message(msg3_body)
        .map_err(|e| ObfsError::HandshakeFailed(format!("read msg3: {e}")))?;

    if payload.len() < 32 {
        return Err(ObfsError::HandshakeFailed("msg3 payload too short for seed".into()));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&payload[..32]);

    let client_static = responder.remote_static()
        .ok_or_else(|| ObfsError::HandshakeFailed("no remote static after msg3".into()))?;

    // Server seals s2c / opens c2s (reverse of client)
    let (c2s_key, s2c_key) = derive_record_keys(&seed);
    let channel = DataChannel::new(
        RecordSealer::new(s2c_key),
        RecordOpener::new(c2s_key),
        mimic,
    );

    Ok((channel, client_static))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use rand::{rngs::SmallRng, SeedableRng};
    use tokio::net::UdpSocket;
    use vaiexia_wire::keypair::generate_keypair;
    use vaiexia_wire::mimicry::{Passthrough, MimicryConfig};
    use vaiexia_wire::cookie::CookieSecret;
    use crate::udp::cookie_gate::{AlwaysOpen, AlwaysUnderLoad};
    use crate::envelope::Envelope;

    fn passthrough() -> Arc<dyn DatagramMimicry> {
        Arc::new(Passthrough::new(MimicryConfig::default()))
    }

    #[tokio::test]
    async fn handshake_completes_and_channels_interop() {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();
        let mimic = passthrough();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();

        let server_priv = server_kp.private;
        let mimic2 = Arc::clone(&mimic);
        let server_sock2 = Arc::clone(&server_sock);

        let server_task = tokio::spawn(async move {
            let mut rng = SmallRng::seed_from_u64(0);
            let cookie_secret = CookieSecret::new([0xAB; 32]);
            let load_gate = AlwaysOpen;
            let mut buf = vec![0u8; 65535];

            // Receive Hs1
            let (n, src) = server_sock2.recv_from(&mut buf).await.unwrap();
            let (ty, body) = unshape_hs(&buf[..n], &mimic2).unwrap();
            assert_eq!(ty, DgramType::Hs1);

            let result = process_hs1(&body, src, &server_priv, &cookie_secret, &load_gate, &mimic2, &mut rng).unwrap().unwrap();
            match result {
                AcceptResult::CookieReply(_) => panic!("unexpected cookie"),
                AcceptResult::PartialHandshake { mut responder, msg2, client_addr: _ } => {
                    server_sock2.send_to(&msg2, src).await.unwrap();
                    let (n, _) = server_sock2.recv_from(&mut buf).await.unwrap();
                    let (ty3, body3) = unshape_hs(&buf[..n], &mimic2).unwrap();
                    assert_eq!(ty3, DgramType::Hs3);
                    let (channel, _client_key) = complete_handshake_msg3(&mut responder, &body3, Arc::clone(&mimic2)).unwrap();
                    let wire_ready = channel.seal_envelope(&Envelope::Pong, &mut rng).unwrap();
                    server_sock2.send_to(&wire_ready, src).await.unwrap();
                    let (n, src) = server_sock2.recv_from(&mut buf).await.unwrap();
                    let probe = channel.open_datagram(&buf[..n]).unwrap().unwrap();
                    assert!(matches!(probe, Envelope::Ping));
                    let reply = channel.seal_envelope(&Envelope::Pong, &mut rng).unwrap();
                    server_sock2.send_to(&reply, src).await.unwrap();
                }
            }
        });

        let mut rng = SmallRng::seed_from_u64(1);
        let channel = client_udp_handshake(
            Arc::clone(&client_sock),
            server_addr,
            server_kp.public,
            client_kp,
            mimic,
            &mut rng,
        ).await.unwrap();

        let probe = channel.seal_envelope(&Envelope::Ping, &mut rng).unwrap();
        client_sock.send_to(&probe, server_addr).await.unwrap();

        let mut buf = vec![0u8; 65535];
        let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
        let reply = channel.open_datagram(&buf[..n]).unwrap().unwrap();
        assert!(matches!(reply, Envelope::Pong));

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_task).await;
    }

    #[tokio::test]
    async fn cookie_path_completes() {
        let server_kp = generate_keypair().unwrap();
        let client_kp = generate_keypair().unwrap();
        let mimic = passthrough();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();

        let server_priv = server_kp.private;
        let mimic2 = Arc::clone(&mimic);
        let server_sock2 = Arc::clone(&server_sock);

        let server_task = tokio::spawn(async move {
            let mut rng = SmallRng::seed_from_u64(0);
            let cookie_secret = CookieSecret::new([0xCD; 32]);
            let load_gate = AlwaysUnderLoad; // always under load — triggers cookie path
            let mut buf = vec![0u8; 65535];

            // First Hs1: no cookie → send Cookie reply
            let (n, src) = server_sock2.recv_from(&mut buf).await.unwrap();
            let (ty, body) = unshape_hs(&buf[..n], &mimic2).unwrap();
            assert_eq!(ty, DgramType::Hs1);
            let result = process_hs1(&body, src, &server_priv, &cookie_secret, &load_gate, &mimic2, &mut rng).unwrap().unwrap();
            match result {
                AcceptResult::CookieReply(cookie_wire) => {
                    server_sock2.send_to(&cookie_wire, src).await.unwrap();
                }
                _ => panic!("expected CookieReply"),
            }

            // Second Hs1: has cookie → proceed with handshake
            let (n, src) = server_sock2.recv_from(&mut buf).await.unwrap();
            let (ty, body) = unshape_hs(&buf[..n], &mimic2).unwrap();
            assert_eq!(ty, DgramType::Hs1);
            let result = process_hs1(&body, src, &server_priv, &cookie_secret, &load_gate, &mimic2, &mut rng).unwrap().unwrap();
            match result {
                AcceptResult::PartialHandshake { mut responder, msg2, .. } => {
                    server_sock2.send_to(&msg2, src).await.unwrap();
                    let (n, _) = server_sock2.recv_from(&mut buf).await.unwrap();
                    let (ty3, body3) = unshape_hs(&buf[..n], &mimic2).unwrap();
                    assert_eq!(ty3, DgramType::Hs3);
                    let (channel, _) = complete_handshake_msg3(&mut responder, &body3, Arc::clone(&mimic2)).unwrap();
                    let ready = channel.seal_envelope(&Envelope::Pong, &mut rng).unwrap();
                    server_sock2.send_to(&ready, src).await.unwrap();
                }
                _ => panic!("expected PartialHandshake after cookie verified"),
            }
        });

        let mut rng = SmallRng::seed_from_u64(2);
        let _channel = client_udp_handshake(
            Arc::clone(&client_sock),
            server_addr,
            server_kp.public,
            client_kp,
            mimic,
            &mut rng,
        ).await.expect("handshake with cookie should succeed");

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_task).await;
    }

    #[tokio::test]
    async fn wrong_server_key_fails() {
        let server_kp = generate_keypair().unwrap();
        let wrong_kp = generate_keypair().unwrap(); // attacker key
        let client_kp = generate_keypair().unwrap();
        let mimic = passthrough();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();

        let server_priv = server_kp.private;
        let mimic2 = Arc::clone(&mimic);
        let server_sock2 = Arc::clone(&server_sock);

        let _server_task = tokio::spawn(async move {
            let mut rng = SmallRng::seed_from_u64(0);
            let cookie_secret = CookieSecret::new([0xAB; 32]);
            let load_gate = AlwaysOpen;
            let mut buf = vec![0u8; 65535];
            for _ in 0..20 {
                let res = tokio::time::timeout(
                    Duration::from_millis(200),
                    server_sock2.recv_from(&mut buf)
                ).await;
                if let Ok(Ok((n, src))) = res
                    && let Some((DgramType::Hs1, body)) = unshape_hs(&buf[..n], &mimic2)
                    && let Ok(Some(result)) = process_hs1(&body, src, &server_priv, &cookie_secret, &load_gate, &mimic2, &mut rng)
                {
                    match result {
                        AcceptResult::PartialHandshake { msg2, .. } => {
                            let _ = server_sock2.send_to(&msg2, src).await;
                        }
                        AcceptResult::CookieReply(r) => {
                            let _ = server_sock2.send_to(&r, src).await;
                        }
                    }
                }
            }
        });

        let mut rng = SmallRng::seed_from_u64(1);
        let result = client_udp_handshake(
            Arc::clone(&client_sock),
            server_addr,
            wrong_kp.public, // WRONG key
            client_kp,
            mimic,
            &mut rng,
        ).await;

        assert!(result.is_err(), "handshake with wrong key must fail");
    }
}
