//! `LoadGate` — operator override for DoS-cookie gating.
//!
//! # What actually drives the cookie challenge
//!
//! The UDP server **self-triggers** the stateless cookie challenge whenever
//! its half-open handshake map reaches `PENDING_SOFT_LIMIT` (see
//! `udp::server`). That internal signal is the real flood defence: a
//! spoofed-source `Hs1` flood fills the pending map, the challenge engages,
//! and no Noise responder state is allocated for sources that cannot echo a
//! src-bound cookie. It needs no external wiring.
//!
//! # What `LoadGate` is for
//!
//! The gate passed to `serve_obfs_udp` is an *additional*, operator-supplied
//! override for load signals the server cannot observe itself — CPU
//! pressure, fd exhaustion, or an admin "panic switch" during an active
//! attack. The effective condition on each first-contact `Hs1` is:
//!
//! ```text
//! challenge = gate.under_load() || pending.len() >= PENDING_SOFT_LIMIT
//! ```
//!
//! Use [`AlwaysOpen`] when you have no external signal (the internal trigger
//! still protects you) and [`AlwaysUnderLoad`] to force-challenge every new
//! handshake.

/// Operator-supplied override that can force the DoS-cookie challenge.
///
/// Returning `true` forces the cookie challenge for new handshakes regardless
/// of internal pending-handshake pressure; returning `false` defers entirely
/// to the server's built-in pending-pressure trigger.
pub trait LoadGate: Send + Sync {
    fn under_load(&self) -> bool;
}

/// No operator override (default): the cookie challenge engages only on the
/// server's internal pending-handshake pressure.
pub struct AlwaysOpen;

impl LoadGate for AlwaysOpen {
    fn under_load(&self) -> bool { false }
}

/// Force-cookie mode: every first `Hs1` is challenged. Useful as an operator
/// "panic switch" during an active flood, and for testing the cookie path.
pub struct AlwaysUnderLoad;

impl LoadGate for AlwaysUnderLoad {
    fn under_load(&self) -> bool { true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_open_not_under_load() {
        assert!(!AlwaysOpen.under_load());
    }

    #[test]
    fn always_under_load() {
        assert!(AlwaysUnderLoad.under_load());
    }
}
