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
    rotate_with(t, store, opts, prov.as_ref()).await
}

/// Same flow as [`rotate`], with the provider injected so tests can prove which
/// credential each step uses without a live cloud account. Production always
/// resolves the provider from the target name via [`rotate`].
async fn rotate_with(
    t: &Target,
    store: &dyn SecretStore,
    opts: &Options,
    prov: &dyn provider::Provider,
) -> Result<RotationOutcome> {
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
    use crate::model::{Credential, KeyInfo};
    use crate::provider::Provider;
    use async_trait::async_trait;
    use std::sync::Mutex;

    fn target() -> Target {
        Target {
            name: "b2-service".into(),
            provider: "backblaze".into(),
            vault: "Personal".into(),
            item: "svc".into(),
            field_key_id: "svcKey".into(),
            field_secret: "svcSecret".into(),
            management_item: "mgmt".into(),
            mgmt_field_key_id: "mgmtKey".into(),
            mgmt_field_secret: "mgmtSecret".into(),
            key_name_prefix: "cust-prefix".into(),
            schedule: None,
            recipe_recipient: None,
            console_url: None,
        }
    }

    struct ReadCall {
        vault: String,
        item: String,
        field_key_id: String,
        field_secret: String,
    }

    struct WriteCall {
        vault: String,
        item: String,
        field_key_id: String,
        field_secret: String,
        key_id: String,
        secret: String,
        keep_previous: bool,
    }

    struct SeenCred {
        step: &'static str,
        key_id: String,
        secret: String,
    }

    struct SeenCreate {
        name: String,
        like_caps: Option<Vec<String>>,
        like_bucket: Option<String>,
    }

    struct MemStore {
        mgmt: Credential,
        service: Credential,
        reads: Mutex<Vec<ReadCall>>,
        written: Mutex<Option<WriteCall>>,
    }

    struct FakeProv {
        keys: Vec<KeyInfo>,
        seen: Mutex<Vec<SeenCred>>,
        verified: Mutex<Option<(String, String)>>,
        revoked_id: Mutex<Option<String>>,
        seen_create: Mutex<Option<SeenCreate>>,
    }

    #[async_trait]
    impl SecretStore for MemStore {
        async fn read(
            &self,
            vault: &str,
            item: &str,
            field_key_id: &str,
            field_secret: &str,
        ) -> Result<Credential> {
            self.reads.lock().unwrap().push(ReadCall {
                vault: vault.to_string(),
                item: item.to_string(),
                field_key_id: field_key_id.to_string(),
                field_secret: field_secret.to_string(),
            });
            if item == "mgmt" {
                return Ok(self.mgmt.clone());
            }
            Ok(self.service.clone())
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
            *self.written.lock().unwrap() = Some(WriteCall {
                vault: vault.to_string(),
                item: item.to_string(),
                field_key_id: field_key_id.to_string(),
                field_secret: field_secret.to_string(),
                key_id: cred.key_id.clone(),
                secret: cred.secret.clone(),
                keep_previous,
            });
            Ok(())
        }
    }

    #[async_trait]
    impl Provider for FakeProv {
        fn id(&self) -> &'static str {
            "fake"
        }

        async fn list_keys(&self, mgmt: &Credential) -> Result<Vec<KeyInfo>> {
            self.seen.lock().unwrap().push(SeenCred {
                step: "list",
                key_id: mgmt.key_id.clone(),
                secret: mgmt.secret.clone(),
            });
            Ok(self.keys.clone())
        }

        async fn create_key(
            &self,
            mgmt: &Credential,
            name: &str,
            like: Option<&KeyInfo>,
        ) -> Result<Credential> {
            self.seen.lock().unwrap().push(SeenCred {
                step: "create",
                key_id: mgmt.key_id.clone(),
                secret: mgmt.secret.clone(),
            });
            *self.seen_create.lock().unwrap() = Some(SeenCreate {
                name: name.to_string(),
                like_caps: like.map(|k| k.capabilities.clone()),
                like_bucket: like.and_then(|k| k.bucket_id.clone()),
            });
            Ok(Credential::new("new-key", "new-secret-DO-NOT-LEAK"))
        }

        async fn verify_key(&self, cred: &Credential) -> Result<()> {
            *self.verified.lock().unwrap() = Some((cred.key_id.clone(), cred.secret.clone()));
            Ok(())
        }

        async fn revoke_key(&self, mgmt: &Credential, key_id: &str) -> Result<()> {
            self.seen.lock().unwrap().push(SeenCred {
                step: "revoke",
                key_id: mgmt.key_id.clone(),
                secret: mgmt.secret.clone(),
            });
            *self.revoked_id.lock().unwrap() = Some(key_id.to_string());
            Ok(())
        }
    }

    fn harness(keys: Vec<KeyInfo>) -> (Target, MemStore, FakeProv) {
        let store = MemStore {
            mgmt: Credential::new("mgmt-id", "mgmt-secret-DO-NOT-LEAK"),
            service: Credential::new("old-key", "old-secret-DO-NOT-LEAK"),
            reads: Mutex::new(Vec::new()),
            written: Mutex::new(None),
        };
        let prov = FakeProv {
            keys,
            seen: Mutex::new(Vec::new()),
            verified: Mutex::new(None),
            revoked_id: Mutex::new(None),
            seen_create: Mutex::new(None),
        };
        (target(), store, prov)
    }

    fn scoped(id: &str, caps: &[&str], bucket: &str) -> KeyInfo {
        KeyInfo {
            key_id: id.into(),
            name: Some("service".into()),
            capabilities: caps.iter().map(|c| (*c).to_string()).collect(),
            bucket_id: Some(bucket.into()),
        }
    }

    #[tokio::test]
    async fn live_rotation_uses_management_creds_and_writes_the_service_item() {
        // The management principal mints and revokes. The new secret is verified
        // and stored on the service item only — never sent back as a management
        // secret, and never written onto the management item.
        let (t, store, prov) = harness(vec![
            scoped("other", &["writeFiles", "deleteFiles"], "wide-open"),
            scoped("old-key", &["listFiles", "readFiles"], "bucket-abc"),
        ]);
        let out = rotate_with(
            &t,
            &store,
            &Options { dry_run: false, revoke: true },
            &prov,
        )
        .await
        .unwrap();

        assert_eq!(out.new_key_id, "new-key");
        assert_eq!(out.old_key_id.as_deref(), Some("old-key"));
        assert!(out.revoked_old);

        let reads = store.reads.lock().unwrap();
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0].vault, "Personal");
        assert_eq!(reads[0].item, "mgmt");
        assert_eq!(reads[0].field_key_id, "mgmtKey");
        assert_eq!(reads[0].field_secret, "mgmtSecret");
        assert_eq!(reads[1].vault, "Personal");
        assert_eq!(reads[1].item, "svc");
        assert_eq!(reads[1].field_key_id, "svcKey");
        assert_eq!(reads[1].field_secret, "svcSecret");

        let seen = prov.seen.lock().unwrap();
        assert_eq!(
            seen.iter().map(|s| s.step).collect::<Vec<_>>(),
            vec!["list", "create", "revoke"]
        );
        for call in seen.iter() {
            assert_eq!(call.key_id, "mgmt-id", "{}", call.step);
            assert_eq!(call.secret, "mgmt-secret-DO-NOT-LEAK", "{}", call.step);
            assert_ne!(call.secret, "old-secret-DO-NOT-LEAK");
            assert_ne!(call.secret, "new-secret-DO-NOT-LEAK");
        }
        assert_eq!(prov.revoked_id.lock().unwrap().as_deref(), Some("old-key"));

        let (verified_id, verified_secret) = prov.verified.lock().unwrap().clone().unwrap();
        assert_eq!(verified_id, "new-key");
        assert_eq!(verified_secret, "new-secret-DO-NOT-LEAK");
        assert_ne!(verified_secret, "mgmt-secret-DO-NOT-LEAK");
        assert_ne!(verified_secret, "old-secret-DO-NOT-LEAK");

        let written = store.written.lock().unwrap().take().unwrap();
        assert_eq!(written.vault, "Personal");
        assert_eq!(written.item, "svc");
        assert_ne!(written.item, "mgmt");
        assert_eq!(written.field_key_id, "svcKey");
        assert_eq!(written.field_secret, "svcSecret");
        assert_eq!(written.key_id, "new-key");
        assert_eq!(written.secret, "new-secret-DO-NOT-LEAK");
        assert_ne!(written.secret, "mgmt-secret-DO-NOT-LEAK");
        assert!(written.keep_previous);

        let created = prov.seen_create.lock().unwrap().take().unwrap();
        assert!(created.name.starts_with("cust-prefix-"), "{}", created.name);
        assert!(!created.name.contains("keyward-"));
        assert!(!created.name.contains("DO-NOT-LEAK"));
        let date = created.name.trim_start_matches("cust-prefix-");
        assert_eq!(date.len(), 15, "{date}");
        assert_eq!(date.as_bytes()[8], b'-');
        assert!(date.as_bytes().iter().enumerate().all(|(i, b)| i == 8 || b.is_ascii_digit()));
        assert_eq!(created.like_caps.unwrap(), vec!["listFiles", "readFiles"]);
        assert_eq!(created.like_bucket.as_deref(), Some("bucket-abc"));
    }

    #[tokio::test]
    async fn duplicate_key_id_keeps_the_first_listed_scope() {
        // Two listed keys can share an id. The first match is the scope that
        // gets copied. A later, broader row must not widen the replacement.
        let (t, store, prov) = harness(vec![
            scoped("old-key", &["readFiles"], "bucket-tight"),
            scoped("old-key", &["deleteFiles", "writeFiles"], "wide-open"),
        ]);
        rotate_with(
            &t,
            &store,
            &Options { dry_run: false, revoke: true },
            &prov,
        )
        .await
        .unwrap();

        let created = prov.seen_create.lock().unwrap().take().unwrap();
        let caps = created.like_caps.unwrap();
        assert_eq!(caps, vec!["readFiles"]);
        assert!(!caps.iter().any(|c| c == "deleteFiles" || c == "writeFiles"));
        assert_eq!(created.like_bucket.as_deref(), Some("bucket-tight"));
        assert_ne!(created.like_bucket.as_deref(), Some("wide-open"));
    }
}
