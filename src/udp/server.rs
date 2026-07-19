//! UDP server: per-peer state demux, Service dispatch, cookie-gated handshake.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use rand::{rngs::SmallRng, SeedableRng};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use vaiexia_wire::mimicry::DatagramMimicry;
use vaiexia_core::server::Service;

use crate::envelope::Envelope;
use crate::udp::cookie_gate::{AlwaysOpen, AlwaysUnderLoad, LoadGate};
use crate::udp::dataplane::DataChannel;
use crate::udp::handshake::{
    AcceptResult, process_hs1, complete_handshake_msg3,
};
use crate::udp::wire_dgram::{DgramType, decode_inner};
use crate::verifier::TransportGate;
use crate::Result;
use vaiexia_core::diagnostic::{codes, Diagnostic};
use vaiexia_core::error::CoreError;

const MAX_DGRAM: usize = 65507;
const MAX_PEERS: usize = 1024;
/// Hard ceiling on half-open (pending) handshakes; caps memory under a flood.
const MAX_PENDING: usize = 2048;
/// Once this many handshakes are half-open, force the cookie challenge even if
/// the injected `LoadGate` reports no load — this is the actual line of defence
/// against a spoofed-source Hs1 flood allocating unbounded Noise state.
const PENDING_SOFT_LIMIT: usize = 256;
/// Peers idle longer than this are evicted so the MAX_PEERS budget can't be
/// permanently exhausted by abandoned sessions.
const PEER_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

struct PendingHandshake {
    responder: vaiexia_wire::handshake::Handshake,
    created_at: std::time::Instant,
}

struct PeerState {
    channel: Arc<DataChannel>,
    last_seen: std::time::Instant,
    /// Events to send to this peer (drained by the per-peer sealer task).
    outbound_tx: mpsc::UnboundedSender<Envelope>,
}

/// Handle returned by [`serve_obfs_udp`]; dropping it stops the server loop
/// and the periodic cookie-secret rotation task.
pub struct UdpServeHandle {
    /// Local address the socket is bound to.
    pub local_addr: std::net::SocketAddr,
    recv_task: tokio::task::JoinHandle<()>,
    rotate_task: tokio::task::JoinHandle<()>,
}

impl UdpServeHandle {
    pub fn local_addr(&self) -> std::net::SocketAddr { self.local_addr }

    /// Stop the server: aborts the recv loop and the cookie-rotation task.
    /// Dropping the handle has the same effect.
    pub fn shutdown(&self) {
        self.recv_task.abort();
        self.rotate_task.abort();
    }
}

impl Drop for UdpServeHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Interval between cookie-secret rotations.
///
/// [`CookieSecret::verify`](vaiexia_wire::cookie::CookieSecret::verify) keeps a
/// two-epoch grace (current OR previous), so a cookie minted up to one full
/// interval before a rotation still verifies after it — in-flight `Hs1`
/// retries are never orphaned by a rotation. Cookies older than two rotations
/// are rejected, bounding the replay window to ~2x this interval.
const COOKIE_ROTATE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(120);

/// Spawn the periodic cookie-secret rotation task.
///
/// Returns the `JoinHandle` so the owner can abort it on shutdown. The seed is
/// generated *before* taking the lock, and the lock is never held across an
/// await point.
fn spawn_cookie_rotation(
    cookie_secret: Arc<Mutex<vaiexia_wire::cookie::CookieSecret>>,
    every: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use rand::RngCore;
        let mut rng = SmallRng::from_entropy();
        let mut ticker = tokio::time::interval(every);
        ticker.tick().await; // first tick completes immediately — skip it
        loop {
            ticker.tick().await;
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            cookie_secret.lock().unwrap().rotate(seed);
        }
    })
}

/// Bind a UDP server and start the recv loop.
pub async fn serve_obfs_udp(
    addr: impl tokio::net::ToSocketAddrs,
    server_keypair: vaiexia_wire::keypair::StaticKeypair,
    service: Arc<Service>,
    gate: Arc<dyn TransportGate>,
    load: Arc<dyn LoadGate>,
    profile: Arc<dyn DatagramMimicry>,
) -> Result<UdpServeHandle> {
    let sock = Arc::new(UdpSocket::bind(addr).await?);
    let local_addr = sock.local_addr()?;

    let server_priv = server_keypair.private;
    let cookie_seed: [u8; 32] = {
        use rand::RngCore;
        let mut s = SmallRng::from_entropy();
        let mut b = [0u8; 32];
        s.fill_bytes(&mut b);
        b
    };
    let cookie_secret = Arc::new(Mutex::new(vaiexia_wire::cookie::CookieSecret::new(cookie_seed)));

    // Rotate the cookie secret on a timer so a captured cookie is only
    // replayable for a bounded window (two epochs ≈ 2x the interval).
    let rotate_task = spawn_cookie_rotation(Arc::clone(&cookie_secret), COOKIE_ROTATE_INTERVAL);

    // Central (dst, datagram) outbound channel: per-peer sealer tasks push here,
    // a single send loop drains it and writes to the socket.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();

    let sock2 = Arc::clone(&sock);
    let sock3 = Arc::clone(&sock);

    // Send loop
    tokio::spawn(async move {
        while let Some((dst, data)) = out_rx.recv().await {
            let _ = sock3.send_to(&data, dst).await;
        }
    });

    let recv_task = tokio::spawn(async move {
        let mut rng = SmallRng::from_entropy();
        let mut buf = vec![0u8; MAX_DGRAM];
        let mut pending: HashMap<SocketAddr, PendingHandshake> = HashMap::new();
        let mut peers: HashMap<SocketAddr, PeerState> = HashMap::new();

        loop {
            match sock2.recv_from(&mut buf).await {
                Err(_) => break,
                Ok((n, src)) => {
                    let dgram = buf[..n].to_vec();
                    handle_dgram(
                        dgram, src, &sock2, &out_tx,
                        &server_priv, &service, &gate,
                        load.as_ref(), &profile, &cookie_secret,
                        &mut pending, &mut peers, &mut rng,
                    ).await;
                }
            }
        }
    });

    Ok(UdpServeHandle { local_addr, recv_task, rotate_task })
}

#[allow(clippy::too_many_arguments)]
async fn handle_dgram(
    dgram: Vec<u8>,
    src: SocketAddr,
    sock: &Arc<UdpSocket>,
    out_tx: &mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    server_priv: &[u8; 32],
    service: &Arc<Service>,
    gate: &Arc<dyn TransportGate>,
    load: &dyn LoadGate,
    profile: &Arc<dyn DatagramMimicry>,
    cookie_secret: &Arc<Mutex<vaiexia_wire::cookie::CookieSecret>>,
    pending: &mut HashMap<SocketAddr, PendingHandshake>,
    peers: &mut HashMap<SocketAddr, PeerState>,
    rng: &mut SmallRng,
) {
    // Recover inner
    let inner = match profile.shape_in(&dgram) {
        Some(i) => i,
        None => return,
    };
    let (ty, body) = match decode_inner(&inner) {
        Some(p) => p,
        None => return,
    };
    let body = body.to_vec(); // own it

    match ty {
        DgramType::Hs1 => {
            if peers.len() >= MAX_PEERS { return; }

            // The cookie challenge engages on EITHER the operator override
            // (`LoadGate`, for signals the server can't observe: CPU, fds,
            // admin panic switch) OR internal pending-handshake pressure —
            // the built-in flood defence. A spoofed-source flood then cannot
            // allocate Noise responder state without first echoing a
            // src-bound cookie it can only obtain by actually receiving our
            // reply at that source.
            let effective_under_load =
                load.under_load() || pending.len() >= PENDING_SOFT_LIMIT;
            let eff_gate: &dyn LoadGate =
                if effective_under_load { &AlwaysUnderLoad } else { &AlwaysOpen };

            let result = {
                let cs = cookie_secret.lock().unwrap();
                process_hs1(&body, src, server_priv, &cs, eff_gate, profile, rng)
            };

            match result {
                Ok(Some(AcceptResult::CookieReply(wire))) => {
                    let _ = sock.send_to(&wire, src).await;
                }
                Ok(Some(AcceptResult::PartialHandshake { responder, msg2, .. })) => {
                    // Hard cap: never let the pending map grow without bound,
                    // even under a cookie-verified burst.
                    if pending.len() >= MAX_PENDING && !pending.contains_key(&src) {
                        return;
                    }
                    pending.insert(src, PendingHandshake {
                        responder,
                        created_at: std::time::Instant::now(),
                    });
                    let _ = sock.send_to(&msg2, src).await;
                }
                _ => {}
            }
        }

        DgramType::Hs3 => {
            let Some(ph) = pending.remove(&src) else { return };
            let mut responder = ph.responder;

            if let Ok((channel, client_static)) =
                complete_handshake_msg3(&mut responder, &body, Arc::clone(profile))
            {
                if gate.authenticate(&client_static).is_err() { return; }

                let channel = Arc::new(channel);
                // Send ready record
                if let Ok(wire) = channel.seal_envelope(&Envelope::Pong, rng) {
                    let _ = sock.send_to(&wire, src).await;
                }

                let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<Envelope>();
                let ch2 = Arc::clone(&channel);
                let out_tx2 = out_tx.clone();

                // Event sender task: seals Envelopes and forwards to the send loop.
                tokio::spawn(async move {
                    let mut local_rng = SmallRng::from_entropy();
                    while let Some(env) = ev_rx.recv().await {
                        if let Ok(wire) = ch2.seal_envelope(&env, &mut local_rng) {
                            let _ = out_tx2.send((src, wire));
                        }
                    }
                });

                peers.insert(src, PeerState {
                    channel,
                    last_seen: std::time::Instant::now(),
                    outbound_tx: ev_tx,
                });
            }
        }

        DgramType::Data => {
            let Some(peer) = peers.get_mut(&src) else { return };
            peer.last_seen = std::time::Instant::now();

            let env = match peer.channel.open_datagram(&dgram) {
                Ok(Some(e)) => e,
                _ => return,
            };

            let ev_tx = peer.outbound_tx.clone();
            let ch = Arc::clone(&peer.channel);
            let svc = Arc::clone(service);

            match env {
                Envelope::Ping => {
                    if let Ok(wire) = ch.seal_envelope(&Envelope::Pong, rng) {
                        let _ = sock.send_to(&wire, src).await;
                    }
                }
                Envelope::Request(req) => {
                    let resp = svc.handle(req).await;
                    if let Ok(wire) = ch.seal_envelope(&Envelope::Response(resp), rng) {
                        let _ = sock.send_to(&wire, src).await;
                    }
                }
                Envelope::Subscribe { topic, capability, .. } => {
                    // Gate per-topic access before wiring the event source,
                    // mirroring core's ws_conn behaviour.
                    match svc.verify_topic(capability.as_ref(), &topic) {
                        Err(err) => {
                            let diag = match err {
                                CoreError::Auth(d) => d,
                                _ => Diagnostic::error(
                                    codes::FORBIDDEN,
                                    "subscription denied",
                                ),
                            };
                            // Best-effort: send error back to the peer.
                            let _ = ev_tx.send(Envelope::SubscribeError {
                                topic,
                                error: diag,
                            });
                        }
                        Ok(_subject) => {
                            if let Some(event_src) = svc.event_source(&topic) {
                                let mut rx = event_src.subscribe();
                                let topic_clone = topic.clone();
                                tokio::spawn(async move {
                                    loop {
                                        match rx.recv().await {
                                            Ok(ev) if ev.topic == topic_clone => {
                                                if ev_tx.send(Envelope::Event(ev)).is_err() { break; }
                                            }
                                            Ok(_) => {}
                                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                                            Err(_) => break,
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
                Envelope::Unsubscribe { .. } => {}
                _ => {}
            }
        }

        _ => {}
    }

    // Cleanup stale pending handshakes (>5s)
    let now = std::time::Instant::now();
    pending.retain(|_, ph| now.duration_since(ph.created_at) < std::time::Duration::from_secs(5));
    // Evict idle peers so a finite MAX_PEERS budget can't be permanently wedged
    // by abandoned sessions; dropping PeerState closes its outbound sealer task.
    peers.retain(|_, p| now.duration_since(p.last_seen) < PEER_IDLE_TIMEOUT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;
    use vaiexia_wire::cookie::CookieSecret;

    const SRC: &[u8] = b"203.0.113.7:51820";

    /// A cookie minted just before a rotation must still verify just after it
    /// (two-epoch grace), but a cookie two rotations old must be rejected.
    #[tokio::test(start_paused = true)]
    async fn cookie_survives_one_rotation_but_not_two() {
        let cs = Arc::new(Mutex::new(CookieSecret::new([0x11; 32])));
        let cookie = cs.lock().unwrap().make(SRC);

        let task = spawn_cookie_rotation(Arc::clone(&cs), Duration::from_millis(100));

        // t=150ms: exactly one rotation (at t=100ms) has happened.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            cs.lock().unwrap().verify(SRC, &cookie),
            "cookie in flight across one rotation must still verify (previous epoch)"
        );
        // A cookie minted under the post-rotation current epoch also verifies.
        let fresh = cs.lock().unwrap().make(SRC);
        assert!(cs.lock().unwrap().verify(SRC, &fresh));

        // t=250ms: a second rotation (at t=200ms) evicted the original epoch.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !cs.lock().unwrap().verify(SRC, &cookie),
            "cookie two rotations old must be rejected"
        );

        task.abort();
    }

    /// Aborting the rotation task stops all further rotations.
    #[tokio::test(start_paused = true)]
    async fn aborted_rotation_task_stops_rotating() {
        let cs = Arc::new(Mutex::new(CookieSecret::new([0x22; 32])));
        let task = spawn_cookie_rotation(Arc::clone(&cs), Duration::from_millis(100));
        task.abort();
        let _ = task.await; // wait until the abort has landed

        let cookie = cs.lock().unwrap().make(SRC);
        // Many intervals later the cookie is still current-epoch valid: had the
        // task kept rotating, two rotations would have evicted its epoch.
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert!(cs.lock().unwrap().verify(SRC, &cookie));
    }

    /// `shutdown()` (and drop) abort both background tasks.
    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_aborts_background_tasks() {
        use vaiexia_core::auth::{Capability, ScopeSet, Subject, SubjectId, Verifier};
        use vaiexia_core::protocol::Method;
        use vaiexia_core::server::ServiceBuilder;

        struct AllowAllVerifier;
        impl Verifier for AllowAllVerifier {
            fn verify(
                &self,
                _: Option<&Capability>,
                _: &Method,
            ) -> vaiexia_core::error::Result<Subject> {
                Ok(Subject {
                    id: SubjectId::new("test"),
                    scopes: ScopeSet::from_iter(["*"]),
                })
            }
        }

        let kp = vaiexia_wire::keypair::generate_keypair().unwrap();
        let svc = Arc::new(ServiceBuilder::new().verifier(AllowAllVerifier).build());
        let profile: Arc<dyn DatagramMimicry> = Arc::new(
            vaiexia_wire::mimicry::Passthrough::new(vaiexia_wire::mimicry::MimicryConfig::default()),
        );

        let handle = serve_obfs_udp(
            "127.0.0.1:0",
            kp,
            svc,
            Arc::new(crate::verifier::AllowAll),
            Arc::new(AlwaysOpen),
            profile,
        )
        .await
        .expect("server should bind");

        handle.shutdown();
        // Aborts are asynchronous; poll until both tasks report finished.
        for _ in 0..100 {
            if handle.recv_task.is_finished() && handle.rotate_task.is_finished() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("background tasks still running after shutdown()");
    }
}
