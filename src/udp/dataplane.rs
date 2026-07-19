//! UDP data-plane: seal/open Envelopes using the record layer + mimicry.

use std::sync::{Arc, Mutex};
use rand::RngCore;
use vaiexia_wire::record::{RecordSealer, RecordOpener};
use vaiexia_wire::mimicry::DatagramMimicry;
use crate::envelope::Envelope;
use crate::udp::wire_dgram::{DgramType, encode_inner, decode_inner};
use crate::Result;

/// Bidirectional UDP data channel using the record layer.
///
/// RecordOpener::open internally enforces replay via ReplayWindow
/// (authenticate-before-replay, as per Phase-1 design).
pub struct DataChannel {
    sealer: Mutex<RecordSealer>,
    opener: Mutex<RecordOpener>,
    mimic: Arc<dyn DatagramMimicry>,
}

impl DataChannel {
    pub fn new(sealer: RecordSealer, opener: RecordOpener, mimic: Arc<dyn DatagramMimicry>) -> Self {
        Self {
            sealer: Mutex::new(sealer),
            opener: Mutex::new(opener),
            mimic,
        }
    }

    /// Seal an Envelope into a wire datagram (inner framed + mimicry shaped).
    pub fn seal_envelope(&self, env: &Envelope, rng: &mut dyn RngCore) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(env)?;
        let record = self.sealer.lock().unwrap().seal(&json, &[])?;
        let inner = encode_inner(DgramType::Data, &record);
        let mut out = Vec::new();
        self.mimic.shape_out(&inner, &mut out, rng);
        Ok(out)
    }

    /// Open a wire datagram into an Envelope.
    /// Returns Ok(None) for non-Data datagrams, replay-rejected, auth-failed, or malformed.
    /// Never panics on adversarial input.
    pub fn open_datagram(&self, datagram: &[u8]) -> Result<Option<Envelope>> {
        // shape_in recovers the inner from mimicry
        let inner = match self.mimic.shape_in(datagram) {
            Some(i) => i,
            None => return Ok(None),
        };
        // decode type tag
        let (ty, record) = match decode_inner(&inner) {
            Some(pair) => pair,
            None => return Ok(None),
        };
        if ty != DgramType::Data {
            return Ok(None);
        }
        // open record (authenticate + replay-check internally)
        let plaintext = match self.opener.lock().unwrap().open(record, &[]) {
            Ok(pt) => pt,
            Err(_) => return Ok(None), // auth failed or replay — drop silently
        };
        // deserialize
        let env = serde_json::from_slice(&plaintext)?;
        Ok(Some(env))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use rand::{rngs::SmallRng, SeedableRng};
    use vaiexia_wire::mimicry::{Passthrough, MimicryConfig};
    use vaiexia_wire::record::{RecordSealer, RecordOpener};
    use crate::udp::keys::derive_record_keys;
    use crate::envelope::Envelope;

    fn make_channels(seed: &[u8; 32]) -> (DataChannel, DataChannel) {
        let (c2s_key, s2c_key) = derive_record_keys(seed);
        let mimic: Arc<dyn DatagramMimicry> = Arc::new(Passthrough::new(MimicryConfig::default()));
        let client = DataChannel::new(
            RecordSealer::new(c2s_key.clone()),
            RecordOpener::new(s2c_key.clone()),
            Arc::clone(&mimic),
        );
        let server = DataChannel::new(
            RecordSealer::new(s2c_key),
            RecordOpener::new(c2s_key),
            mimic,
        );
        (client, server)
    }

    fn rng() -> SmallRng { SmallRng::seed_from_u64(42) }

    #[test]
    fn seal_open_roundtrip() {
        let seed = [0x55u8; 32];
        let (client, server) = make_channels(&seed);
        let mut rng = rng();
        let env = Envelope::Ping;
        let wire = client.seal_envelope(&env, &mut rng).unwrap();
        let recovered = server.open_datagram(&wire).unwrap();
        assert!(matches!(recovered, Some(Envelope::Ping)));
    }

    #[test]
    fn out_of_order_delivery() {
        let seed = [0x66u8; 32];
        let (client, server) = make_channels(&seed);
        let mut rng = rng();
        let w0 = client.seal_envelope(&Envelope::Ping, &mut rng).unwrap();
        let w1 = client.seal_envelope(&Envelope::Pong, &mut rng).unwrap();
        let w2 = client.seal_envelope(&Envelope::Ping, &mut rng).unwrap();
        // Open in order 2, 0, 1 — all should succeed (window tolerates reorder)
        assert!(server.open_datagram(&w2).unwrap().is_some(), "record 2 should open");
        assert!(server.open_datagram(&w0).unwrap().is_some(), "record 0 should open");
        assert!(server.open_datagram(&w1).unwrap().is_some(), "record 1 should open");
    }

    #[test]
    fn replay_rejected() {
        let seed = [0x77u8; 32];
        let (client, server) = make_channels(&seed);
        let mut rng = rng();
        let wire = client.seal_envelope(&Envelope::Ping, &mut rng).unwrap();
        // First open succeeds
        assert!(server.open_datagram(&wire).unwrap().is_some());
        // Second open of same datagram → replay rejected → Ok(None)
        assert!(server.open_datagram(&wire).unwrap().is_none(), "replay must be rejected");
    }

    #[test]
    fn corrupted_datagram_returns_none() {
        let seed = [0x88u8; 32];
        let (client, server) = make_channels(&seed);
        let mut rng = rng();
        let mut wire = client.seal_envelope(&Envelope::Ping, &mut rng).unwrap();
        *wire.last_mut().unwrap() ^= 0xFF;
        assert!(server.open_datagram(&wire).unwrap().is_none(), "corrupted must return None");
    }

    #[test]
    fn junk_datagram_returns_none() {
        let seed = [0x99u8; 32];
        let (_client, server) = make_channels(&seed);
        assert!(server.open_datagram(&[]).unwrap().is_none());
        assert!(server.open_datagram(&[0x42; 7]).unwrap().is_none());
    }
}
