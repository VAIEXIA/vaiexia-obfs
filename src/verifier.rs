//! Transport-layer authentication gate.
//!
//! [`TransportGate`] is the bridge between the Noise-XK layer (which
//! authenticates the *connection* by its static public key) and the
//! vaiexia-core [`Verifier`] layer (which authorises individual *requests*
//! by [`Capability`]).
//!
//! [`AllowAll`] is a permissive implementation suitable for integration tests
//! and trusted-network deployments.

use vaiexia_core::auth::{Capability, ScopeSet, Subject, SubjectId, Verifier};
use vaiexia_core::error::Result;
use vaiexia_core::protocol::Method;

/// Authenticate an incoming TCP connection by its Noise remote static key.
///
/// Called once per accepted connection, after the handshake completes.
/// Returns `Ok(())` to allow the connection, `Err(_)` to reject it.
pub trait TransportGate: Send + Sync + 'static {
    fn authenticate(&self, remote_static: &[u8; 32]) -> std::result::Result<(), String>;
}

/// A [`TransportGate`] that accepts all connections regardless of key.
pub struct AllowAll;

impl TransportGate for AllowAll {
    fn authenticate(&self, _remote_static: &[u8; 32]) -> std::result::Result<(), String> {
        Ok(())
    }
}

/// A [`Verifier`] that grants every request the full set of scopes.
///
/// Useful for integration tests and single-tenant deployments where all
/// connected clients are trusted by virtue of holding the server's public key.
impl Verifier for AllowAll {
    fn verify(&self, _capability: Option<&Capability>, _method: &Method) -> Result<Subject> {
        Ok(Subject {
            id: SubjectId::new("obfs-client"),
            scopes: ScopeSet::from_iter(["*"]),
        })
    }
}

/// A [`TransportGate`] built from a fixed allow-list of public keys.
pub struct KeyAllowList {
    allowed: Vec<[u8; 32]>,
}

impl KeyAllowList {
    /// Create a gate that allows only the given public keys.
    pub fn new(keys: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            allowed: keys.into_iter().collect(),
        }
    }
}

impl TransportGate for KeyAllowList {
    fn authenticate(&self, remote_static: &[u8; 32]) -> std::result::Result<(), String> {
        if self.allowed.contains(remote_static) {
            Ok(())
        } else {
            Err(format!(
                "public key not in allow-list: {}",
                hex_key(remote_static)
            ))
        }
    }
}

fn hex_key(k: &[u8; 32]) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_accepts_any_key() {
        let gate = AllowAll;
        let key = [0xab_u8; 32];
        assert!(gate.authenticate(&key).is_ok());
    }

    #[test]
    fn key_allow_list_accepts_known_key() {
        let key = [0x01_u8; 32];
        let gate = KeyAllowList::new([key]);
        assert!(gate.authenticate(&key).is_ok());
    }

    #[test]
    fn key_allow_list_rejects_unknown_key() {
        let allowed = [0x01_u8; 32];
        let unknown = [0x02_u8; 32];
        let gate = KeyAllowList::new([allowed]);
        assert!(gate.authenticate(&unknown).is_err());
    }
}
