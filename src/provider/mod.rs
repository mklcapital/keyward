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
    fn provider_names_are_case_sensitive() {
        // Config typos must fail closed. Folding case would rotate a different
        // provider than the one named in the file.
        for name in ["AWS", "R2", "B2", "Cloudflare", "Backblaze"] {
            let err = get(name).err().unwrap_or_else(|| panic!("{name} was accepted"));
            let msg = err.to_string();
            assert!(msg.contains("unknown provider"), "{name}: {msg}");
            assert!(msg.contains(name), "{name}: {msg}");
            assert!(!msg.contains("id="), "{name}: {msg}");
        }
    }
}
