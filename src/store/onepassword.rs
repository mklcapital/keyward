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

/// Field assignments for `op item edit`.
///
/// Key ids are `[text]` and secrets are `[password]`. A previous value is included
/// only when that read succeeded, so the first rotation of an item (no `previous_*`
/// field yet) still writes the new credential. `rotated_at` is supplied by the
/// caller so the stamp can be checked without freezing the clock.
fn edit_assignments(
    field_key_id: &str,
    field_secret: &str,
    cred: &Credential,
    previous_key_id: Option<&str>,
    previous_secret: Option<&str>,
    rotated_at: &str,
) -> Vec<String> {
    let mut assignments = Vec::new();
    if let Some(old) = previous_key_id {
        assignments.push(format!("previous_{field_key_id}[text]={old}"));
    }
    if let Some(old) = previous_secret {
        assignments.push(format!("previous_{field_secret}[password]={old}"));
    }
    assignments.push(format!("{field_key_id}[text]={}", cred.key_id));
    assignments.push(format!("{field_secret}[password]={}", cred.secret));
    assignments.push(format!("rotated_at[text]={rotated_at}"));
    assignments
}

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
        let previous_key_id = if keep_previous {
            self.read_field(&format!("op://{vault}/{item}/{field_key_id}")).await.ok()
        } else {
            None
        };
        let previous_secret = if keep_previous {
            self.read_field(&format!("op://{vault}/{item}/{field_secret}")).await.ok()
        } else {
            None
        };
        let rotated_at = chrono::Utc::now().to_rfc3339();
        let assignments = edit_assignments(
            field_key_id,
            field_secret,
            cred,
            previous_key_id.as_deref(),
            previous_secret.as_deref(),
            &rotated_at,
        );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_keep_previous_and_tag_secrets_as_passwords() {
        let cred = Credential::new("new-id", "new-secret");
        let lines = edit_assignments(
            "keyID",
            "applicationKey",
            &cred,
            Some("old-id"),
            Some("old-secret"),
            "2026-10-11T10:00:00+00:00",
        );
        assert_eq!(
            lines,
            vec![
                "previous_keyID[text]=old-id",
                "previous_applicationKey[password]=old-secret",
                "keyID[text]=new-id",
                "applicationKey[password]=new-secret",
                "rotated_at[text]=2026-10-11T10:00:00+00:00",
            ]
        );
    }

    #[test]
    fn missing_previous_fields_are_skipped_so_the_first_rotation_still_writes() {
        let cred = Credential::new("new-id", "new-secret");
        let lines = edit_assignments("access_key_id", "secret_access_key", &cred, None, None, "t0");
        assert_eq!(
            lines,
            vec![
                "access_key_id[text]=new-id",
                "secret_access_key[password]=new-secret",
                "rotated_at[text]=t0",
            ]
        );
        // A secret that failed to read must not be written as a key-id text field.
        let only_id = edit_assignments("keyID", "applicationKey", &cred, Some("old-id"), None, "t0");
        assert!(only_id.iter().any(|l| l == "previous_keyID[text]=old-id"));
        assert!(only_id.iter().all(|l| !l.contains("previous_applicationKey")));
    }
}
