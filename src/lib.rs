pub mod client;
pub mod envelope;
pub mod framing;
pub mod handshake_io;
pub mod server;
pub mod verifier;

pub use client::ObfsTransport;
pub use envelope::Envelope;
pub use server::{serve_obfs, ObfsServeHandle};
pub use verifier::{AllowAll, TransportGate};

#[derive(Debug, thiserror::Error)]
pub enum ObfsError {
    #[error("connection closed")]
    Closed,
    #[error("frame too large: {0} bytes (max {1})")]
    FrameTooLarge(usize, usize),
    #[error("wire error: {0}")]
    Wire(#[from] vaiexia_wire::error::WireError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("core error: {0}")]
    Core(#[from] vaiexia_core::error::CoreError),
}

pub type Result<T> = std::result::Result<T, ObfsError>;
