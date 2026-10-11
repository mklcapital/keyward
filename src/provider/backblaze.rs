//! Backblaze B2 provider (fully implemented).
//!
//! Rotation preserves the old key's capabilities and bucket restriction, so the
//! new key is never broader than the one it replaces.
use super::Provider;
use crate::model::{Credential, KeyInfo};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use serde_json::json;

const AUTH_URL: &str = "https://api.backblazeb2.com/b2api/v3/b2_authorize_account";

pub struct Backblaze {
    http: reqwest::Client,
}

struct Auth {
    token: String,
    api_url: String,
    account_id: String,
}

/// Capabilities copied from the key being replaced. An empty or missing scope
/// falls back to read-only B2 permissions — never to a write/admin default.
fn capabilities_for(like: Option<&KeyInfo>) -> Vec<String> {
    like.map(|k| k.capabilities.clone())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| vec!["listBuckets".into(), "listFiles".into(), "readFiles".into()])
}

/// Request body for `b2_create_key`, plus the capability list stamped onto the
/// stored credential. `bucketId` is included only when the old key was restricted.
fn create_key_body(account_id: &str, name: &str, like: Option<&KeyInfo>) -> (serde_json::Value, Vec<String>) {
    let caps = capabilities_for(like);
    let mut body = json!({ "accountId": account_id, "capabilities": &caps, "keyName": name });
    if let Some(b) = like.and_then(|k| k.bucket_id.as_ref()) {
        body["bucketId"] = json!(b);
    }
    (body, caps)
}

fn parse_listed_keys(v: &serde_json::Value) -> Vec<KeyInfo> {
    v["keys"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|k| KeyInfo {
            key_id: k["applicationKeyId"].as_str().unwrap_or_default().to_string(),
            name: k["keyName"].as_str().map(String::from),
            capabilities: k["capabilities"]
                .as_array()
                .map(|c| c.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            bucket_id: k["bucketId"].as_str().map(String::from),
        })
        .collect()
}

fn credential_from_create_response(v: &serde_json::Value, caps: &[String]) -> Result<Credential> {
    let mut cred = Credential::new(
        v["applicationKeyId"].as_str().ok_or_else(|| anyhow!("no applicationKeyId"))?,
        v["applicationKey"].as_str().ok_or_else(|| anyhow!("no applicationKey"))?,
    );
    cred.extra.insert("capabilities".into(), caps.join(","));
    Ok(cred)
}

impl Backblaze {
    pub fn new() -> Self {
        Self { http: reqwest::Client::new() }
    }

    async fn authorize(&self, cred: &Credential) -> Result<Auth> {
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", cred.key_id, cred.secret));
        let v: serde_json::Value = self
            .http
            .get(AUTH_URL)
            .header("Authorization", format!("Basic {basic}"))
            .send()
            .await?
            .error_for_status()
            .context("B2 authorize failed")?
            .json()
            .await?;
        Ok(Auth {
            token: v["authorizationToken"].as_str().unwrap_or_default().to_string(),
            api_url: v["apiInfo"]["storageApi"]["apiUrl"]
                .as_str()
                .ok_or_else(|| anyhow!("B2 authorize: no storage apiUrl"))?
                .to_string(),
            account_id: v["accountId"].as_str().unwrap_or_default().to_string(),
        })
    }
}

#[async_trait]
impl Provider for Backblaze {
    fn id(&self) -> &'static str {
        "backblaze"
    }

    async fn list_keys(&self, mgmt: &Credential) -> Result<Vec<KeyInfo>> {
        let a = self.authorize(mgmt).await?;
        let v: serde_json::Value = self
            .http
            .post(format!("{}/b2api/v3/b2_list_keys", a.api_url))
            .header("Authorization", &a.token)
            .json(&json!({ "accountId": a.account_id, "maxKeyCount": 1000 }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(parse_listed_keys(&v))
    }

    async fn create_key(&self, mgmt: &Credential, name: &str, like: Option<&KeyInfo>) -> Result<Credential> {
        let a = self.authorize(mgmt).await?;
        let (body, caps) = create_key_body(&a.account_id, name, like);
        let v: serde_json::Value = self
            .http
            .post(format!("{}/b2api/v3/b2_create_key", a.api_url))
            .header("Authorization", &a.token)
            .json(&body)
            .send()
            .await?
            .error_for_status()
            .context("B2 create_key failed")?
            .json()
            .await?;
        credential_from_create_response(&v, &caps)
    }

    async fn verify_key(&self, cred: &Credential) -> Result<()> {
        self.authorize(cred)
            .await
            .map(|_| ())
            .context("new B2 key failed verification (could not authorize)")
    }

    async fn revoke_key(&self, mgmt: &Credential, key_id: &str) -> Result<()> {
        let a = self.authorize(mgmt).await?;
        self.http
            .post(format!("{}/b2api/v3/b2_delete_key", a.api_url))
            .header("Authorization", &a.token)
            .json(&json!({ "applicationKeyId": key_id }))
            .send()
            .await?
            .error_for_status()
            .context("B2 delete_key failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn like(caps: &[&str], bucket: Option<&str>) -> KeyInfo {
        KeyInfo {
            key_id: "k".into(),
            name: Some("n".into()),
            capabilities: caps.iter().map(|s| (*s).to_string()).collect(),
            bucket_id: bucket.map(str::to_string),
        }
    }

    #[test]
    fn missing_or_empty_scope_falls_back_to_read_only() {
        for template in [None, Some(like(&[], None))] {
            let (body, caps) = create_key_body("acct", "keyward-b2", template.as_ref());
            assert_eq!(caps, vec!["listBuckets", "listFiles", "readFiles"]);
            assert_eq!(body["accountId"], "acct");
            assert_eq!(body["keyName"], "keyward-b2");
            assert_eq!(body["capabilities"], json!(["listBuckets", "listFiles", "readFiles"]));
            assert!(body.get("bucketId").is_none(), "unrestricted fallback must not invent a bucket");
        }
    }

    #[test]
    fn create_body_copies_capabilities_and_bucket_restriction() {
        let info = like(&["listFiles", "readFiles"], Some("bucket-abc"));
        let (body, caps) = create_key_body("acct", "named", Some(&info));
        assert_eq!(caps, vec!["listFiles", "readFiles"]);
        assert_eq!(body["capabilities"], json!(["listFiles", "readFiles"]));
        assert_eq!(body["bucketId"], "bucket-abc");
        // Capabilities without a bucket restriction omit the field entirely.
        let open = like(&["writeFiles"], None);
        let (body, _) = create_key_body("acct", "named", Some(&open));
        assert_eq!(body["capabilities"], json!(["writeFiles"]));
        assert!(body.get("bucketId").is_none());
    }

    #[test]
    fn listed_keys_keep_scope_and_drop_malformed_entries() {
        let parsed = parse_listed_keys(&json!({
            "keys": [
                {
                    "applicationKeyId": "old-key",
                    "keyName": "service",
                    "capabilities": ["readFiles", 3, "listFiles"],
                    "bucketId": "bucket-abc"
                },
                { "applicationKeyId": "bare" }
            ]
        }));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].key_id, "old-key");
        assert_eq!(parsed[0].name.as_deref(), Some("service"));
        assert_eq!(parsed[0].capabilities, vec!["readFiles", "listFiles"]);
        assert_eq!(parsed[0].bucket_id.as_deref(), Some("bucket-abc"));
        assert_eq!(parsed[1].key_id, "bare");
        assert_eq!(parsed[1].name, None);
        assert!(parsed[1].capabilities.is_empty());
        assert_eq!(parsed[1].bucket_id, None);

        assert!(parse_listed_keys(&json!({})).is_empty());
        assert!(parse_listed_keys(&json!({ "keys": "nope" })).is_empty());
    }

    #[test]
    fn create_response_requires_both_halves_of_the_credential() {
        let ok = credential_from_create_response(
            &json!({ "applicationKeyId": "id-1", "applicationKey": "secret-1" }),
            &["listFiles".into(), "readFiles".into()],
        )
        .unwrap();
        assert_eq!(ok.key_id, "id-1");
        assert_eq!(ok.secret, "secret-1");
        assert_eq!(ok.extra.get("capabilities").map(String::as_str), Some("listFiles,readFiles"));

        assert!(credential_from_create_response(&json!({ "applicationKey": "s" }), &[]).is_err());
        assert!(credential_from_create_response(&json!({ "applicationKeyId": "i" }), &[]).is_err());
    }
}
