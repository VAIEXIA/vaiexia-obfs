//! LoadGate trait for DoS-cookie gating.

use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

/// Controls whether the responder is under load.
pub trait LoadGate: Send + Sync {
    fn under_load(&self) -> bool;
}

/// Never under load (default — always allocate handshake state).
pub struct AlwaysOpen;

impl LoadGate for AlwaysOpen {
    fn under_load(&self) -> bool { false }
}

/// Always under load (for testing the cookie path).
pub struct AlwaysUnderLoad;

impl LoadGate for AlwaysUnderLoad {
    fn under_load(&self) -> bool { true }
}

/// Under load when in-flight handshakes exceed max_inflight.
pub struct Threshold {
    pub max_inflight: usize,
    pub counter: Arc<AtomicUsize>,
}

impl Threshold {
    pub fn new(max_inflight: usize) -> (Self, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        (Self { max_inflight, counter: Arc::clone(&counter) }, counter)
    }

    pub fn increment(&self) {
        self.counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

impl LoadGate for Threshold {
    fn under_load(&self) -> bool {
        self.counter.load(Ordering::Relaxed) >= self.max_inflight
    }
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

    #[test]
    fn threshold_under_load_when_exceeded() {
        let (gate, counter) = Threshold::new(2);
        assert!(!gate.under_load());
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(!gate.under_load());
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(gate.under_load());
    }

    #[test]
    fn threshold_not_under_load_after_decrement() {
        let (gate, _) = Threshold::new(1);
        gate.increment();
        assert!(gate.under_load());
        gate.decrement();
        assert!(!gate.under_load());
    }
}
