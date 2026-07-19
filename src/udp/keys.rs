//! BLAKE2s key derivation from handshake seed.

use vaiexia_wire::record::RecordKey;

/// Derive two directional RecordKeys from a 32-byte handshake seed.
/// c2s = BLAKE2s(seed, "vaiexia-udp-c2s")[..32]
/// s2c = BLAKE2s(seed, "vaiexia-udp-s2c")[..32]
pub fn derive_record_keys(seed: &[u8; 32]) -> (RecordKey, RecordKey) {
    let c2s = derive_key(seed, b"vaiexia-udp-c2s");
    let s2c = derive_key(seed, b"vaiexia-udp-s2c");
    (RecordKey::from_bytes(c2s), RecordKey::from_bytes(s2c))
}

fn derive_key(seed: &[u8; 32], label: &[u8]) -> [u8; 32] {
    use blake2::digest::Mac;
    use blake2::Blake2sMac256;
    // Use BLAKE2s in MAC mode: key=seed, data=label
    let mut mac = <Blake2sMac256 as Mac>::new_from_slice(seed)
        .expect("seed length 32 always valid");
    Mac::update(&mut mac, label);
    let result = Mac::finalize(mac).into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let seed = [0x42u8; 32];
        let (c2s_a, s2c_a) = derive_record_keys(&seed);
        let (c2s_c, s2c_c) = derive_record_keys(&seed);
        // Indirect: seal with c2s_a, open with c2s_c — should work
        use vaiexia_wire::record::{RecordSealer, RecordOpener};
        let mut s = RecordSealer::new(c2s_a);
        let mut o = RecordOpener::new(c2s_c);
        let ct = s.seal(b"probe", b"").unwrap();
        assert_eq!(o.open(&ct, b"").unwrap(), b"probe");
        // s2c same
        let mut s2 = RecordSealer::new(s2c_a);
        let mut o2 = RecordOpener::new(s2c_c);
        let ct2 = s2.seal(b"probe2", b"").unwrap();
        assert_eq!(o2.open(&ct2, b"").unwrap(), b"probe2");
    }

    #[test]
    fn c2s_differs_from_s2c() {
        let seed = [0x11u8; 32];
        let (c2s, s2c) = derive_record_keys(&seed);
        // Seal with c2s, open with s2c — should FAIL (auth error)
        use vaiexia_wire::record::{RecordSealer, RecordOpener};
        let mut s = RecordSealer::new(c2s);
        let mut o = RecordOpener::new(s2c);
        let ct = s.seal(b"asymmetric", b"").unwrap();
        assert!(o.open(&ct, b"").is_err(), "c2s key must differ from s2c key");
    }

    #[test]
    fn same_seed_both_sides() {
        // Simulate client sealing with c2s, server opening with c2s (same seed)
        let seed = [0xABu8; 32];
        let (client_c2s, _client_s2c) = derive_record_keys(&seed);
        let (server_c2s, _server_s2c) = derive_record_keys(&seed);
        use vaiexia_wire::record::{RecordSealer, RecordOpener};
        let mut sealer = RecordSealer::new(client_c2s);
        let mut opener = RecordOpener::new(server_c2s);
        let ct = sealer.seal(b"hello server", b"").unwrap();
        assert_eq!(opener.open(&ct, b"").unwrap(), b"hello server");
    }
}
