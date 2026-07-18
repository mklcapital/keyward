//! Secret-store abstraction. 1Password today; Vault / Infisical / env are just
//! more implementations of this trait.
use crate::model::Credential;
use anyhow::Result;
use async_trait::async_trait;

pub mod onepassword;

#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn read(&self, vault: &str, item: &str, field_key_id: &str, field_secret: &str) -> Result<Credential>;

    /// Persist a rotated credential. When `keep_previous`, the current value is
    /// copied into `previous_*` fields first, giving a one-step rollback.
    async fn write(
        &self,
        vault: &str,
        item: &str,
        field_key_id: &str,
        field_secret: &str,
        cred: &Credential,
        keep_previous: bool,
    ) -> Result<()>;
}
