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
/// caller so the stamp can be checked without freezing the clock. Credential
/// extras (session tokens, raw Cloudflare token values) are not assignments.
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
    fn assignments_keep_secret_bytes_and_omit_credential_extras() {
        // A secret is one argv element. Splitting on `=` or newlines, or trimming,
        // would store a different secret (or smuggle `--vault` as its own argument).
        // Extras such as a raw Cloudflare token must not be written beside it.
        let mut cred = Credential::new("AKIA=NEW", "--vault\nProduction = pwned  ");
        cred.extra.insert("cf_token_value".into(), "RAW-CF-TOKEN".into());
        cred.extra.insert("session_token".into(), "FwoG-SESSION".into());
        let lines = edit_assignments(
            "keyID",
            "applicationKey",
            &cred,
            Some(""),
            Some("old=secret\n"),
            "2026-11-11T10:00:00Z",
        );
        assert_eq!(
            lines,
            vec![
                "previous_keyID[text]=".to_string(),
                "previous_applicationKey[password]=old=secret\n".to_string(),
                "keyID[text]=AKIA=NEW".to_string(),
                "applicationKey[password]=--vault\nProduction = pwned  ".to_string(),
                "rotated_at[text]=2026-11-11T10:00:00Z".to_string(),
            ]
        );
        let flat = lines.join("\0");
        assert!(!flat.contains("RAW-CF-TOKEN"));
        assert!(!flat.contains("FwoG-SESSION"));

        // An empty new secret is still assigned. Dropping it would update the key
        // id and leave the previous password in place.
        let empty = Credential::new("AKIAEMPTY", "");
        let lines = edit_assignments("keyID", "applicationKey", &empty, None, None, "t0");
        assert_eq!(
            lines,
            vec![
                "keyID[text]=AKIAEMPTY".to_string(),
                "applicationKey[password]=".to_string(),
                "rotated_at[text]=t0".to_string(),
            ]
        );
    }
}
