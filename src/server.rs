//! TCP server that accepts Noise-XK connections and dispatches to a
//! vaiexia-core [`Service`].
//!
//! Each accepted connection gets its own task that:
//! 1. Performs the Noise-XK handshake (in-place, keeping the stream).
//! 2. Authenticates the remote static key via the [`TransportGate`].
//! 3. Runs a request/event pump loop over the encrypted framed channel.
//!
//! The `profile` parameter controls byte-stream framing.  Pass
//! `Arc::new(Vanilla::new(Default::default()))` for Vanilla (Phase-2b)
//! behaviour; `AmneziaJunk` for DPI-resistant deployments.

use crate::envelope::Envelope;
use crate::framing::{recv_frame, send_frame};
use crate::handshake_io::server_handshake_in_place;
use crate::verifier::TransportGate;
use rand::{SeedableRng, rngs::SmallRng};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use vaiexia_core::protocol::Topic;
use vaiexia_core::server::Service;
use vaiexia_wire::mimicry::MimicryProfile;

/// Handle returned by [`serve_obfs`]; dropping it signals the listener task to stop.
pub struct ObfsServeHandle {
    _stop: mpsc::Sender<()>,
    /// Local address the listener is bound to.
    pub local_addr: std::net::SocketAddr,
}

impl ObfsServeHandle {
    /// The local address the server is listening on.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }
}

/// Start a Noise-XK TCP server.
///
/// Binds to `addr`, accepts connections, runs the Noise-XK handshake,
/// authenticates via `gate`, and dispatches requests to `service`.
///
/// `profile` controls byte-stream framing for all connections.
///
/// Returns an [`ObfsServeHandle`]; dropping it shuts down the listener.
pub async fn serve_obfs(
    addr: impl tokio::net::ToSocketAddrs,
    server_private: [u8; 32],
    service: Arc<Service>,
    gate: Arc<dyn TransportGate>,
    profile: Arc<dyn MimicryProfile>,
) -> crate::Result<ObfsServeHandle> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.recv() => break,
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _peer)) => {
                            let svc = Arc::clone(&service);
                            let gate = Arc::clone(&gate);
                            let profile = Arc::clone(&profile);
                            let priv_key = server_private;
                            tokio::spawn(handle_connection(stream, priv_key, svc, gate, profile));
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    Ok(ObfsServeHandle {
        _stop: stop_tx,
        local_addr,
    })
}

/// Handle a single accepted connection end-to-end.
async fn handle_connection(
    mut stream: TcpStream,
    server_private: [u8; 32],
    service: Arc<Service>,
    gate: Arc<dyn TransportGate>,
    profile: Arc<dyn MimicryProfile>,
) {
    // ── handshake (in-place — stream stays available) ───────────────────────
    // Note: `leftover` holds any bytes read past msg3 during the handshake
    // (e.g. the first transport frame sent by the client).  We use it as the
    // pump's initial read buffer so those bytes are not discarded.
    let (mut session, remote_key, leftover) =
        match server_handshake_in_place(&mut stream, &server_private, &profile).await {
            Ok(triple) => triple,
            Err(_) => return,
        };

    // ── transport gate ───────────────────────────────────────────────────────
    if let Some(key) = &remote_key {
        if gate.authenticate(key).is_err() {
            return;
        }
    }

    // ── post-handshake pump ──────────────────────────────────────────────────
    let mut rng = SmallRng::from_entropy();
    let mut buf = leftover; // seed with any bytes already read beyond the handshake

    // Outbound channel: subscription tasks push events here; the pump loop
    // drains it and encrypts/writes to the stream.
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Envelope>();

    loop {
        tokio::select! {
            biased;

            // ── outbound event (subscription push) ───────────────────────
            Some(env) = event_rx.recv() => {
                let delay = profile.jitter(&mut rng);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if send_frame(&mut stream, &mut session, &env, profile.as_ref(), &mut rng)
                    .await
                    .is_err()
                {
                    break;
                }
            }

            // ── inbound frame from client ─────────────────────────────────
            result = recv_frame(&mut stream, &mut session, profile.as_ref(), &mut buf) => {
                match result {
                    Err(_) => break,
                    Ok(Envelope::Ping) => {
                        let delay = profile.jitter(&mut rng);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        if send_frame(
                            &mut stream,
                            &mut session,
                            &Envelope::Pong,
                            profile.as_ref(),
                            &mut rng,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Envelope::Request(req)) => {
                        let svc = Arc::clone(&service);
                        let resp = svc.handle(req).await;
                        let delay = profile.jitter(&mut rng);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        if send_frame(
                            &mut stream,
                            &mut session,
                            &Envelope::Response(resp),
                            profile.as_ref(),
                            &mut rng,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Envelope::Subscribe { topic, .. }) => {
                        handle_subscribe(&service, topic, event_tx.clone());
                    }
                    Ok(Envelope::Unsubscribe { .. }) => {
                        // Full unsubscribe tracking is future work.
                    }
                    Ok(_) => {} // ignore unexpected client-side envelopes
                }
            }
        }
    }
}

/// Spawn a task that forwards events from the service's broadcast channel to
/// the connection's outbound mpsc.
fn handle_subscribe(
    service: &Arc<Service>,
    topic: Topic,
    event_tx: mpsc::UnboundedSender<Envelope>,
) {
    let maybe_src = service.event_source(&topic);
    if let Some(src) = maybe_src {
        let mut rx = src.subscribe();
        let topic_clone = topic.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) if ev.topic == topic_clone => {
                        if event_tx.send(Envelope::Event(ev)).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
    } else {
        let _ = event_tx.send(Envelope::SubscribeError {
            topic,
            error: vaiexia_core::diagnostic::Diagnostic::error(
                vaiexia_core::diagnostic::codes::METHOD_NOT_FOUND,
                "no event source for topic",
            ),
        });
    }
}
