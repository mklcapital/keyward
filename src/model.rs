//! Shared, provider-agnostic types.
use std::collections::BTreeMap;

/// A credential pair plus any provider-specific metadata (endpoint, capabilities…).
#[derive(Debug, Clone)]
pub struct Credential {
    pub key_id: String,
    pub secret: String,
    pub extra: BTreeMap<String, String>,
}

impl Credential {
    pub fn new(key_id: impl Into<String>, secret: impl Into<String>) -> Self {
        Self { key_id: key_id.into(), secret: secret.into(), extra: BTreeMap::new() }
    }
}

/// Metadata about an existing key, used to preserve scope when minting a replacement.
#[derive(Debug, Clone, Default)]
pub struct KeyInfo {
    pub key_id: String,
    pub name: Option<String>,
    pub capabilities: Vec<String>,
    pub bucket_id: Option<String>,
}

/// Result of a rotation, for reporting/auditing.
#[derive(Debug)]
pub struct RotationOutcome {
    pub target: String,
    pub provider: String,
    pub new_key_id: String,
    pub old_key_id: Option<String>,
    pub revoked_old: bool,
    pub dry_run: bool,
    /// If the target configured a `recipe_recipient`, the sealed (zero-knowledge)
    /// recreation recipe for the newly minted key. `None` otherwise. Contains no
    /// plaintext secret — only an age ciphertext of the recreation metadata.
    pub sealed_recipe: Option<crate::crypto::Envelope>,
}
