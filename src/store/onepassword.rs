//! 1Password store via the `op` CLI (uses the desktop-app biometric integration,
//! so no service-account token is required for a single-operator setup).
//!
//! SECURITY NOTE (v0.1): `op item edit` takes field values as process arguments,
//! which are briefly visible in the process table. Acceptable for a single-user
//! workstation; for the hosted/daemon version, switch to the 1Password SDK
//! (`onepassword` crate) or 1Password Connect, which pass secrets over a socket.
use super::SecretStore;
use crate::model::Credential;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::process::Command;

pub struct OnePassword;

impl OnePassword {
    pub fn new() -> Self {
        Self
    }

    async fn read_field(&self, reference: &str) -> Result<String> {
        let out = Command::new("op")
            .args(["read", reference])
            .output()
            .await
            .context("failed to run `op` (is the 1Password CLI installed and unlocked?)")?;
        if !out.status.success() {
            return Err(anyhow!("op read {reference}: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

#[async_trait]
impl SecretStore for OnePassword {
    async fn read(&self, vault: &str, item: &str, field_key_id: &str, field_secret: &str) -> Result<Credential> {
        let key_id = self.read_field(&format!("op://{vault}/{item}/{field_key_id}")).await?;
        let secret = self.read_field(&format!("op://{vault}/{item}/{field_secret}")).await?;
        Ok(Credential::new(key_id, secret))
    }

    async fn write(
        &self,
        vault: &str,
        item: &str,
        field_key_id: &str,
        field_secret: &str,
        cred: &Credential,
        keep_previous: bool,
    ) -> Result<()> {
        let mut assignments: Vec<String> = Vec::new();
        if keep_previous {
            if let Ok(old) = self.read_field(&format!("op://{vault}/{item}/{field_key_id}")).await {
                assignments.push(format!("previous_{field_key_id}[text]={old}"));
            }
            if let Ok(old) = self.read_field(&format!("op://{vault}/{item}/{field_secret}")).await {
                assignments.push(format!("previous_{field_secret}[password]={old}"));
            }
        }
        assignments.push(format!("{field_key_id}[text]={}", cred.key_id));
        assignments.push(format!("{field_secret}[password]={}", cred.secret));
        assignments.push(format!("rotated_at[text]={}", chrono::Utc::now().to_rfc3339()));

        let mut cmd = Command::new("op");
        cmd.args(["item", "edit", item, "--vault", vault]);
        for a in &assignments {
            cmd.arg(a);
        }
        let out = cmd.output().await.context("failed to run `op item edit`")?;
        if !out.status.success() {
            return Err(anyhow!("op item edit: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(())
    }
}
