//! [`ObfsTransport`]: a vaiexia-core [`Transport`] over Noise-XK encrypted TCP.
//!
//! # Architecture
//!
//! A background pump task owns both the [`TcpStream`] and the [`Session`].
//! It communicates with the transport handle via channels:
//!
//! - **Outbound**: the transport sends [`Envelope`]s to the pump via an
//!   unbounded mpsc channel.
//! - **Pending requests**: before sending a [`Request`], the transport
//!   inserts a `(request_id_string, oneshot::Sender<Response>)` entry into a
//!   shared `PendingMap`; the pump resolves it when the matching
//!   [`Response`] arrives.
//! - **Events**: the pump broadcasts every received [`Event`] via a
//!   `broadcast::Sender<Event>`; subscribers wrap a receiver in
//!   `dedup_by_seq` to filter and deduplicate.

use crate::envelope::Envelope;
use crate::framing::{read_frame, write_frame};
use crate::handshake_io::client_handshake_in_place;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};
use vaiexia_core::error::{CoreError, Result};
use vaiexia_core::protocol::{Event, Request, Response, Topic};
use vaiexia_core::transport::{Connection, ConnectionState, EventStream, Requester, Subscriber};

type PendingMap = Mutex<HashMap<String, oneshot::Sender<Response>>>;

/// A full-duplex RPC transport over Noise-XK encrypted TCP.
///
/// Implements [`Transport`][vaiexia_core::transport::Transport] (i.e., all of
/// [`Requester`], [`Subscriber`], and [`Connection`]).
pub struct ObfsTransport {
    /// Outbound envelope sender → pump task.
    tx: mpsc::UnboundedSender<Envelope>,
    /// Pending unary requests awaiting their response.
    pending: Arc<PendingMap>,
    /// Broadcast sender; subscribers call `.subscribe()` on it.
    events: broadcast::Sender<Event>,
    /// Live connection state.
    state: Arc<Mutex<ConnectionState>>,
}

impl ObfsTransport {
    /// Connect to a Noise-XK server and perform the handshake.
    ///
    /// `server_public` is the server's known static public key.
    pub async fn connect(
        addr: impl tokio::net::ToSocketAddrs,
        local_private: [u8; 32],
        server_public: [u8; 32],
    ) -> crate::Result<Self> {
        let mut stream = TcpStream::connect(addr).await?;

        let session =
            client_handshake_in_place(&mut stream, &local_private, &server_public).await?;

        let (ev_tx, _) = broadcast::channel::<Event>(256);
        let pending: Arc<PendingMap> = Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(Mutex::new(ConnectionState::Connected));

        let (tx, rx) = mpsc::unbounded_channel::<Envelope>();

        // Spawn the pump task.
        let ev_tx2 = ev_tx.clone();
        let pending2 = Arc::clone(&pending);
        let state2 = Arc::clone(&state);
        tokio::spawn(pump(stream, session, rx, ev_tx2, pending2, state2));

        Ok(Self {
            tx,
            pending,
            events: ev_tx,
            state,
        })
    }
}

/// The background pump task.
///
/// Owns the `TcpStream` and `Session` for their lifetimes. On any I/O error
/// it marks the state as `Down`, drains pending requests (causing their
/// receivers to see a disconnection error), and exits.
async fn pump(
    mut stream: TcpStream,
    mut session: vaiexia_wire::session::Session,
    mut outbound: mpsc::UnboundedReceiver<Envelope>,
    events: broadcast::Sender<Event>,
    pending: Arc<PendingMap>,
    state: Arc<Mutex<ConnectionState>>,
) {
    loop {
        tokio::select! {
            biased;

            // ── outbound frame ────────────────────────────────────────────────
            Some(env) = outbound.recv() => {
                if write_frame(&mut stream, &mut session, &env).await.is_err() {
                    break;
                }
            }

            // ── inbound frame from server ─────────────────────────────────────
            result = read_frame(&mut stream, &mut session) => {
                match result {
                    Err(_) => break,
                    Ok(Envelope::Response(resp)) => {
                        let key = resp.id.as_str().to_owned();
                        let tx = pending.lock().unwrap().remove(&key);
                        if let Some(tx) = tx {
                            let _ = tx.send(resp);
                        }
                    }
                    Ok(Envelope::Event(ev)) => {
                        let _ = events.send(ev);
                    }
                    Ok(Envelope::Ping) => {
                        // Server-initiated ping; reply with pong.
                        let _ = write_frame(&mut stream, &mut session, &Envelope::Pong).await;
                    }
                    Ok(Envelope::Pong) => {} // response to our ping
                    Ok(_) => {}              // ignore unexpected envelopes
                }
            }

            // ── outbound channel closed ───────────────────────────────────────
            else => break,
        }
    }

    // Mark as down and fail all pending requests.
    *state.lock().unwrap() = ConnectionState::Down;
    let drained: Vec<_> = {
        let mut map = pending.lock().unwrap();
        map.drain().map(|(_, tx)| tx).collect()
    };
    // Dropping senders causes receivers to get `RecvError`, which we map to Disconnected.
    drop(drained);
}

// ── Trait implementations ─────────────────────────────────────────────────────

#[async_trait]
impl Requester for ObfsTransport {
    async fn request(&self, req: Request) -> Result<Response> {
        let (tx, rx) = oneshot::channel::<Response>();
        let id = req.id.as_str().to_owned();

        // Insert before sending to avoid a race.
        self.pending.lock().unwrap().insert(id.clone(), tx);

        if self.tx.send(Envelope::Request(req)).is_err() {
            // Pump is gone; remove the pending entry and return an error.
            self.pending.lock().unwrap().remove(&id);
            return Err(CoreError::Disconnected);
        }

        rx.await.map_err(|_| CoreError::Disconnected)
    }
}

#[async_trait]
impl Subscriber for ObfsTransport {
    async fn subscribe(&self, topic: &Topic) -> Result<EventStream> {
        // Send the Subscribe control message to the server.
        self.tx
            .send(Envelope::Subscribe {
                topic: topic.clone(),
                filter: None,
            })
            .map_err(|_| CoreError::Disconnected)?;

        let mut rx = self.events.subscribe();
        let topic_clone = topic.clone();

        // Adapt the broadcast receiver into a deduplicated stream.
        let raw = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(ev) => yield Ok(ev),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => {
                        yield Err(CoreError::Disconnected);
                        break;
                    }
                }
            }
        };

        let stream = vaiexia_core::transport::dedup::dedup_by_seq(raw, topic_clone);
        Ok(Box::pin(stream))
    }
}

impl Connection for ObfsTransport {
    fn state(&self) -> ConnectionState {
        *self.state.lock().unwrap()
    }
}
