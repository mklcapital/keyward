//! Provider abstraction. Each cloud service implements `Provider`; adding a new
//! service is one file + one match arm, nothing else in the codebase changes.
use crate::model::{Credential, KeyInfo};
use anyhow::Result;
use async_trait::async_trait;

pub mod aws;
pub mod backblaze;
pub mod cloudflare;

#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &'static str;

    /// List existing keys, so the orchestrator can find the one being replaced
    /// and copy its scope (least-privilege preservation).
    async fn list_keys(&self, mgmt: &Credential) -> Result<Vec<KeyInfo>>;

    /// Mint a new credential. If `like` is given, match its capabilities/scope.
    async fn create_key(&self, mgmt: &Credential, name: &str, like: Option<&KeyInfo>) -> Result<Credential>;

    /// Prove a credential works with a cheap read call, before we rely on it.
    async fn verify_key(&self, cred: &Credential) -> Result<()>;

    /// Revoke/delete an old key by id.
    async fn revoke_key(&self, mgmt: &Credential, key_id: &str) -> Result<()>;
}

pub fn get(name: &str) -> Result<Box<dyn Provider>> {
    match name {
        "backblaze" | "b2" => Ok(Box::new(backblaze::Backblaze::new())),
        "cloudflare" | "r2" => Ok(Box::new(cloudflare::Cloudflare::new())),
        "aws" => Ok(Box::new(aws::Aws::new())),
        other => anyhow::bail!("unknown provider: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_aliases_resolve_to_the_implementation_id() {
        for (name, id) in [
            ("backblaze", "backblaze"),
            ("b2", "backblaze"),
            ("cloudflare", "cloudflare"),
            ("r2", "cloudflare"),
            ("aws", "aws"),
        ] {
            assert_eq!(get(name).unwrap().id(), id, "{name}");
        }
    }

    #[test]
    fn unknown_provider_is_rejected() {
        let err = get("dropbox").err().expect("dropbox should be rejected");
        assert!(err.to_string().contains("unknown provider: dropbox"), "{err}");
    }
}
