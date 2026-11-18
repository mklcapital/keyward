//! The rotation orchestrator — the safety-critical core.
//!
//! Order is chosen so the system is never without a working credential:
//!   1. read management credential (least-privilege key manager)
//!   2. read current service credential; find its scope
//!   3. mint a NEW key matching that scope
//!   4. VERIFY the new key works
//!   5. store the new key (old kept as `previous_*` for rollback)
//!   6. only now revoke the old key
//! If any step before (6) fails, nothing has been broken. If (6) fails, the new
//! key is already live and stored — safe, with a stale old key to clean up.
use crate::config::Target;
use crate::crypto::{Envelope, RecreationRecipe};
use crate::model::{KeyInfo, RotationOutcome};
use crate::provider;
use crate::store::SecretStore;
use anyhow::{Context, Result};

/// Build the (plaintext) recreation recipe for a freshly minted key, from the
/// target config and the scope discovered on the old key. Contains no secret.
fn build_recipe(t: &Target, like: Option<&KeyInfo>) -> RecreationRecipe {
    let mut restrictions = Vec::new();
    if let Some(b) = like.and_then(|k| k.bucket_id.as_ref()) {
        restrictions.push(format!("bucketId:{b}"));
    }
    RecreationRecipe {
        provider: t.provider.clone(),
        console_url: t.console_url.clone(),
        login_reference: Some(format!("op://{}/{}", t.vault, t.item)),
        capabilities: like.map(|k| k.capabilities.clone()).unwrap_or_default(),
        resource_restrictions: restrictions,
        notes: None,
    }
}

pub struct Options {
    pub dry_run: bool,
    pub revoke: bool,
}

pub async fn rotate(t: &Target, store: &dyn SecretStore, opts: &Options) -> Result<RotationOutcome> {
    let prov = provider::get(&t.provider)?;

    let mgmt = store
        .read(&t.vault, &t.management_item, &t.mgmt_field_key_id, &t.mgmt_field_secret)
        .await
        .context("reading management credential from store")?;

    let current = store
        .read(&t.vault, &t.item, &t.field_key_id, &t.field_secret)
        .await
        .ok();
    let old_key_id = current.as_ref().map(|c| c.key_id.clone());

    // Preserve scope: find the old key's capabilities so the replacement is no broader.
    let like = if let Some(cur) = &current {
        prov.list_keys(&mgmt)
            .await
            .ok()
            .and_then(|ks| ks.into_iter().find(|k| k.key_id == cur.key_id))
    } else {
        None
    };

    if opts.dry_run {
        return Ok(RotationOutcome {
            target: t.name.clone(),
            provider: t.provider.clone(),
            new_key_id: "(dry-run)".into(),
            old_key_id,
            revoked_old: false,
            dry_run: true,
            sealed_recipe: None,
        });
    }

    let name = format!("{}-{}", t.key_name_prefix, chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let new = prov.create_key(&mgmt, &name, like.as_ref()).await.context("minting new key")?;
    prov.verify_key(&new).await.context("verifying new key before use")?;
    store
        .write(&t.vault, &t.item, &t.field_key_id, &t.field_secret, &new, true)
        .await
        .context("writing new key to store")?;

    // Seal a zero-knowledge recreation recipe if the target opted in. This never
    // contains the secret — only how to re-mint an identical key — and is encrypted
    // so even the store (or a SaaS control plane) can't read it.
    let sealed_recipe = match &t.recipe_recipient {
        Some(recipient) => {
            let recipe = build_recipe(t, like.as_ref());
            let env = Envelope::seal_json_to_recipient(
                format!("{}/recipe", t.name),
                recipient,
                &recipe,
            )
            .context("sealing recreation recipe")?;
            Some(env)
        }
        None => None,
    };

    let mut revoked_old = false;
    if opts.revoke {
        if let Some(oid) = &old_key_id {
            prov.revoke_key(&mgmt, oid).await.context("revoking old key")?;
            revoked_old = true;
        }
    }

    Ok(RotationOutcome {
        target: t.name.clone(),
        provider: t.provider.clone(),
        new_key_id: new.key_id,
        old_key_id,
        revoked_old,
        dry_run: false,
        sealed_recipe,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::KeyInfo;

    fn target() -> Target {
        Target {
            name: "b2-prod".into(),
            provider: "backblaze".into(),
            vault: "Production/admin".into(),
            item: "svc key".into(),
            field_key_id: "keyID".into(),
            field_secret: "applicationKey".into(),
            management_item: "mgmt-ADMIN-ITEM".into(),
            mgmt_field_key_id: "keyID".into(),
            mgmt_field_secret: "applicationKey".into(),
            key_name_prefix: "kw".into(),
            schedule: None,
            recipe_recipient: Some("age1SECRET-RECIPIENT-DO-NOT-COPY".into()),
            console_url: None,
        }
    }

    #[test]
    fn recipe_bucket_and_login_reference_stay_literal() {
        // A bucket id is not parsed. One that already looks like a restriction,
        // or is only whitespace, must stay a single restriction — dropping or
        // trimming it would record an account-wide recipe. The login reference
        // is raw concatenation, so a slash in the vault is not re-split.
        let t = target();
        let prefixed = KeyInfo {
            key_id: "key-1".into(),
            name: Some("old".into()),
            capabilities: vec!["readFiles".into()],
            bucket_id: Some("bucketId:admin&id=root".into()),
        };
        let recipe = build_recipe(&t, Some(&prefixed));
        assert_eq!(recipe.provider, "backblaze");
        assert!(recipe.console_url.is_none());
        assert_eq!(
            recipe.login_reference.as_deref(),
            Some("op://Production/admin/svc key")
        );
        assert_eq!(recipe.capabilities, vec!["readFiles".to_string()]);
        assert_eq!(
            recipe.resource_restrictions,
            vec!["bucketId:bucketId:admin&id=root".to_string()]
        );
        assert_eq!(recipe.resource_restrictions.len(), 1);
        assert!(recipe.notes.is_none());

        let blank = KeyInfo {
            key_id: "key-blank".into(),
            name: None,
            capabilities: vec!["readFiles".into()],
            bucket_id: Some(" ".into()),
        };
        let blank_recipe = build_recipe(&t, Some(&blank));
        assert_eq!(blank_recipe.resource_restrictions, vec!["bucketId: ".to_string()]);
        assert_eq!(blank_recipe.capabilities, vec!["readFiles".to_string()]);
        assert!(!blank_recipe.capabilities.iter().any(|c| c == "listBuckets" || c == "listFiles"));

        let json = serde_json::to_string(&recipe).unwrap();
        assert!(!json.contains("mgmt-ADMIN-ITEM"));
        assert!(!json.contains("age1SECRET"));
        assert!(!json.contains("listBuckets"));
        assert!(!json.contains("listFiles"));
        assert_eq!(json.matches("bucketId:").count(), 2);
        assert!(json.contains("op://Production/admin/svc key"));
        assert!(json.contains("\"console_url\":null"));
    }
}
