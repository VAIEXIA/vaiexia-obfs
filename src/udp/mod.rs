//! UDP substrate for the obfuscated transport.
//!
//! Provides a datagram-oriented alternative to the TCP path: a Noise-XK
//! handshake with retransmission and DoS-cookie gating, a record-layer data
//! channel, and a `Requester`/`Subscriber`/`Connection` client transport.

pub mod dataplane;
pub mod keys;
pub mod wire_dgram;
