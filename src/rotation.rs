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

/// Same flow as [`rotate`], with the provider injected so tests can prove the
/// safety order without a live cloud account. Production always resolves the
/// provider from the target name via [`rotate`].
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
    use crate::crypto::KeyPair;
    use crate::model::{Credential, KeyInfo};
    use crate::provider::Provider;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    fn target() -> Target {
        Target {
            name: "b2-service".into(),
            provider: "backblaze".into(),
            vault: "Personal".into(),
            item: "svc".into(),
            field_key_id: "keyID".into(),
            field_secret: "applicationKey".into(),
            management_item: "mgmt".into(),
            mgmt_field_key_id: "keyID".into(),
            mgmt_field_secret: "applicationKey".into(),
            key_name_prefix: "keyward".into(),
            schedule: None,
            recipe_recipient: None,
            console_url: Some("https://secure.backblaze.com/app_keys.htm".into()),
        }
    }

    #[derive(Clone)]
    struct Written {
        key_id: String,
        secret: String,
        keep_previous: bool,
    }

    #[derive(Clone)]
    struct SeenCreate {
        name: String,
        like_key_id: Option<String>,
        like_caps: Option<Vec<String>>,
        like_bucket: Option<String>,
    }

    struct MemStore {
        log: Arc<Mutex<Vec<String>>>,
        mgmt: Credential,
        service: Option<Credential>,
        fail_mgmt: bool,
        fail_write: bool,
        written: Mutex<Option<Written>>,
    }

    impl MemStore {
        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    struct FakeProv {
        log: Arc<Mutex<Vec<String>>>,
        keys: Vec<KeyInfo>,
        fail_list: bool,
        fail_create: bool,
        fail_verify: bool,
        fail_revoke: bool,
        seen_create: Mutex<Option<SeenCreate>>,
        revoked: Mutex<Option<String>>,
    }

    fn note(log: &Mutex<Vec<String>>, step: &str) {
        log.lock().unwrap().push(step.to_string());
    }

    fn harness() -> (Target, MemStore, FakeProv) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let store = MemStore {
            log: log.clone(),
            mgmt: Credential::new("mgmt-id", "mgmt-secret-DO-NOT-LEAK"),
            service: Some(Credential::new("old-key", "old-secret-DO-NOT-LEAK")),
            fail_mgmt: false,
            fail_write: false,
            written: Mutex::new(None),
        };
        let prov = FakeProv {
            log,
            keys: vec![
                KeyInfo {
                    key_id: "other".into(),
                    name: Some("wider".into()),
                    capabilities: vec!["writeFiles".into(), "deleteFiles".into()],
                    bucket_id: Some("wide-open".into()),
                },
                KeyInfo {
                    key_id: "old-key".into(),
                    name: Some("service".into()),
                    capabilities: vec!["listFiles".into(), "readFiles".into()],
                    bucket_id: Some("bucket-abc".into()),
                },
            ],
            fail_list: false,
            fail_create: false,
            fail_verify: false,
            fail_revoke: false,
            seen_create: Mutex::new(None),
            revoked: Mutex::new(None),
        };
        (target(), store, prov)
    }

    #[async_trait]
    impl SecretStore for MemStore {
        async fn read(&self, _vault: &str, item: &str, _field_key_id: &str, _field_secret: &str) -> Result<Credential> {
            note(&self.log, &format!("read:{item}"));
            if item == "mgmt" {
                if self.fail_mgmt {
                    anyhow::bail!("management store down");
                }
                return Ok(self.mgmt.clone());
            }
            self.service.clone().ok_or_else(|| anyhow::anyhow!("no service credential"))
        }

        async fn write(
            &self,
            _vault: &str,
            _item: &str,
            _field_key_id: &str,
            _field_secret: &str,
            cred: &Credential,
            keep_previous: bool,
        ) -> Result<()> {
            note(&self.log, "write");
            if self.fail_write {
                anyhow::bail!("store write failed");
            }
            *self.written.lock().unwrap() = Some(Written {
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

        async fn list_keys(&self, _mgmt: &Credential) -> Result<Vec<KeyInfo>> {
            note(&self.log, "list");
            if self.fail_list {
                anyhow::bail!("list failed");
            }
            Ok(self.keys.clone())
        }

        async fn create_key(&self, _mgmt: &Credential, name: &str, like: Option<&KeyInfo>) -> Result<Credential> {
            note(&self.log, "create");
            *self.seen_create.lock().unwrap() = Some(SeenCreate {
                name: name.to_string(),
                like_key_id: like.map(|k| k.key_id.clone()),
                like_caps: like.map(|k| k.capabilities.clone()),
                like_bucket: like.and_then(|k| k.bucket_id.clone()),
            });
            if self.fail_create {
                anyhow::bail!("create failed");
            }
            Ok(Credential::new("new-key", "new-secret-DO-NOT-LEAK"))
        }

        async fn verify_key(&self, _cred: &Credential) -> Result<()> {
            note(&self.log, "verify");
            if self.fail_verify {
                anyhow::bail!("verify failed");
            }
            Ok(())
        }

        async fn revoke_key(&self, _mgmt: &Credential, key_id: &str) -> Result<()> {
            note(&self.log, "revoke");
            *self.revoked.lock().unwrap() = Some(key_id.to_string());
            if self.fail_revoke {
                anyhow::bail!("revoke failed");
            }
            Ok(())
        }
    }

    fn live() -> Options {
        Options { dry_run: false, revoke: true }
    }

    fn expect(steps: &[&str]) -> Vec<String> {
        steps.iter().map(|s| (*s).to_string()).collect()
    }

    #[tokio::test]
    async fn live_rotation_copies_matching_scope_and_revokes_only_after_store() {
        let (t, store, prov) = harness();
        let out = rotate_with(&t, &store, &live(), &prov).await.unwrap();

        assert!(!out.dry_run);
        assert!(out.sealed_recipe.is_none());
        assert_eq!(out.old_key_id.as_deref(), Some("old-key"));
        assert_eq!(out.new_key_id, "new-key");
        assert!(out.revoked_old);
        assert_eq!(
            store.log(),
            expect(&["read:mgmt", "read:svc", "list", "create", "verify", "write", "revoke"])
        );

        let seen = prov.seen_create.lock().unwrap().clone().unwrap();
        assert!(seen.name.starts_with("keyward-"), "minted name {}", seen.name);
        // The wider sibling key must not be the scope template.
        assert_eq!(seen.like_key_id.as_deref(), Some("old-key"));
        assert_eq!(seen.like_caps.unwrap(), vec!["listFiles", "readFiles"]);
        assert_eq!(seen.like_bucket.as_deref(), Some("bucket-abc"));

        let written = store.written.lock().unwrap().clone().unwrap();
        assert!(written.keep_previous, "previous_* rollback fields must be kept");
        assert_eq!(written.key_id, "new-key");
        assert_eq!(written.secret, "new-secret-DO-NOT-LEAK");
        assert_eq!(prov.revoked.lock().unwrap().as_deref(), Some("old-key"));
    }

    #[tokio::test]
    async fn dry_run_reads_scope_but_does_not_mint_store_revoke_or_seal() {
        let (mut t, store, prov) = harness();
        t.recipe_recipient = Some("not-a-valid-recipient".into());
        let out = rotate_with(&t, &store, &Options { dry_run: true, revoke: true }, &prov)
            .await
            .unwrap();

        assert!(out.dry_run);
        assert!(out.sealed_recipe.is_none());
        assert!(!out.revoked_old);
        assert_eq!(out.new_key_id, "(dry-run)");
        assert_eq!(out.old_key_id.as_deref(), Some("old-key"));
        assert_eq!(store.log(), expect(&["read:mgmt", "read:svc", "list"]));
        assert!(prov.seen_create.lock().unwrap().is_none());
        assert!(store.written.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn verify_failure_does_not_store_or_revoke() {
        let (t, store, mut prov) = harness();
        prov.fail_verify = true;
        let err = rotate_with(&t, &store, &live(), &prov).await.unwrap_err();
        assert!(format!("{err:#}").contains("verifying"), "{err:#}");
        assert_eq!(store.log(), expect(&["read:mgmt", "read:svc", "list", "create", "verify"]));
        assert!(store.written.lock().unwrap().is_none());
        assert!(prov.revoked.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn store_failure_does_not_revoke_the_old_key() {
        let (t, mut store, prov) = harness();
        store.fail_write = true;
        let err = rotate_with(&t, &store, &live(), &prov).await.unwrap_err();
        assert!(format!("{err:#}").contains("writing new key"), "{err:#}");
        assert_eq!(store.log(), expect(&["read:mgmt", "read:svc", "list", "create", "verify", "write"]));
        assert!(prov.revoked.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn create_failure_stops_before_verify_store_and_revoke() {
        let (t, store, mut prov) = harness();
        prov.fail_create = true;
        let err = rotate_with(&t, &store, &live(), &prov).await.unwrap_err();
        assert!(format!("{err:#}").contains("minting"), "{err:#}");
        assert_eq!(store.log(), expect(&["read:mgmt", "read:svc", "list", "create"]));
        assert!(store.written.lock().unwrap().is_none());
        assert!(prov.revoked.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn management_read_failure_touches_nothing_else() {
        let (t, mut store, prov) = harness();
        store.fail_mgmt = true;
        let err = rotate_with(&t, &store, &live(), &prov).await.unwrap_err();
        assert!(format!("{err:#}").contains("management credential"), "{err:#}");
        assert_eq!(store.log(), expect(&["read:mgmt"]));
    }

    #[tokio::test]
    async fn missing_service_credential_skips_scope_lookup_and_revoke() {
        let (t, mut store, prov) = harness();
        store.service = None;
        let out = rotate_with(&t, &store, &live(), &prov).await.unwrap();
        assert_eq!(out.old_key_id, None);
        assert!(!out.revoked_old);
        assert_eq!(store.log(), expect(&["read:mgmt", "read:svc", "create", "verify", "write"]));
        let seen = prov.seen_create.lock().unwrap().clone().unwrap();
        assert!(seen.like_caps.is_none(), "no current key means no scope to copy");
        assert!(prov.revoked.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn list_failure_still_rotates_but_without_a_scope_template() {
        let (t, store, mut prov) = harness();
        prov.fail_list = true;
        let out = rotate_with(&t, &store, &live(), &prov).await.unwrap();
        assert!(out.revoked_old);
        let seen = prov.seen_create.lock().unwrap().clone().unwrap();
        assert!(seen.like_caps.is_none());
        assert_eq!(
            store.log(),
            expect(&["read:mgmt", "read:svc", "list", "create", "verify", "write", "revoke"])
        );
    }

    #[tokio::test]
    async fn unmatched_current_key_does_not_borrow_a_sibling_scope() {
        let (t, store, mut prov) = harness();
        prov.keys.retain(|k| k.key_id != "old-key");
        rotate_with(&t, &store, &live(), &prov).await.unwrap();
        let seen = prov.seen_create.lock().unwrap().clone().unwrap();
        assert!(seen.like_key_id.is_none());
        assert!(seen.like_caps.is_none());
    }

    #[tokio::test]
    async fn no_revoke_keeps_the_old_key() {
        let (t, store, prov) = harness();
        let out = rotate_with(&t, &store, &Options { dry_run: false, revoke: false }, &prov)
            .await
            .unwrap();
        assert!(!out.revoked_old);
        assert_eq!(out.new_key_id, "new-key");
        assert!(!store.log().contains(&"revoke".to_string()));
        assert!(prov.revoked.lock().unwrap().is_none());
        assert!(store.written.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_failure_reports_error_after_the_new_key_is_stored() {
        let (t, store, mut prov) = harness();
        prov.fail_revoke = true;
        let err = rotate_with(&t, &store, &live(), &prov).await.unwrap_err();
        assert!(format!("{err:#}").contains("revoking old key"), "{err:#}");
        let log = store.log();
        let write_at = log.iter().position(|s| s == "write").unwrap();
        let revoke_at = log.iter().position(|s| s == "revoke").unwrap();
        assert!(write_at < revoke_at);
        assert!(store.written.lock().unwrap().is_some());
        assert_eq!(prov.revoked.lock().unwrap().as_deref(), Some("old-key"));
    }

    #[tokio::test]
    async fn sealed_recipe_copies_scope_and_does_not_contain_secrets() {
        let kp = KeyPair::generate();
        let (mut t, store, prov) = harness();
        t.recipe_recipient = Some(kp.recipient_str());
        let out = rotate_with(&t, &store, &live(), &prov).await.unwrap();
        let env = out.sealed_recipe.expect("recipe sealed");
        assert_eq!(env.label, "b2-service/recipe");
        let blob = format!("{} {}", env.label, env.ciphertext_b64);
        for secret in ["new-secret-DO-NOT-LEAK", "old-secret-DO-NOT-LEAK", "mgmt-secret-DO-NOT-LEAK"] {
            assert!(!blob.contains(secret), "recipe envelope leaked {secret}");
        }
        let recipe: RecreationRecipe = env.open_json(&kp).unwrap();
        assert_eq!(recipe.provider, "backblaze");
        assert_eq!(recipe.console_url.as_deref(), Some("https://secure.backblaze.com/app_keys.htm"));
        assert_eq!(recipe.login_reference.as_deref(), Some("op://Personal/svc"));
        assert_eq!(recipe.capabilities, vec!["listFiles", "readFiles"]);
        assert_eq!(recipe.resource_restrictions, vec!["bucketId:bucket-abc"]);
        assert_eq!(recipe.notes, None);
        assert!(env.open_json::<RecreationRecipe>(&KeyPair::generate()).is_err());
    }

    #[tokio::test]
    async fn bad_recipe_recipient_fails_after_store_and_does_not_revoke() {
        let (mut t, store, prov) = harness();
        t.recipe_recipient = Some("not-an-age-recipient".into());
        let err = rotate_with(&t, &store, &live(), &prov).await.unwrap_err();
        assert!(format!("{err:#}").contains("sealing recreation recipe"), "{err:#}");
        assert!(store.written.lock().unwrap().is_some());
        assert!(prov.revoked.lock().unwrap().is_none());
        assert!(!store.log().contains(&"revoke".to_string()));
    }

    #[tokio::test]
    async fn unknown_provider_fails_before_any_store_read() {
        let (mut t, store, _prov) = harness();
        t.provider = "dropbox".into();
        let err = rotate(&t, &store, &live()).await.unwrap_err();
        assert!(err.to_string().contains("unknown provider"), "{err}");
        assert!(store.log().is_empty());
    }
}
