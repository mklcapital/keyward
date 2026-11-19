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
        let keys = v["keys"]
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
            .collect();
        Ok(keys)
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
            name: None,
            capabilities: caps.iter().map(|s| (*s).to_string()).collect(),
            bucket_id: bucket.map(str::to_string),
        }
    }

    #[test]
    fn bucket_restriction_survives_empty_scope_and_blank_id() {
        // An empty capability list falls back to read-only, but the old key's
        // bucket restriction still has to be copied. Dropping it would mint a
        // key that can see every bucket. A hostile id must stay one JSON string.
        let hostile = "bucket\"},\"capabilities\":[\"deleteFiles\"]";
        let (body, caps) = create_key_body("acct-1", "kw-new", Some(&like(&[], Some(hostile))));
        assert_eq!(caps, vec!["listBuckets", "listFiles", "readFiles"]);
        assert_eq!(body["accountId"], "acct-1");
        assert_eq!(body["keyName"], "kw-new");
        assert_eq!(body["capabilities"], json!(["listBuckets", "listFiles", "readFiles"]));
        assert_eq!(body["bucketId"], hostile);
        assert_eq!(body.as_object().unwrap().len(), 4);
        assert!(!body["capabilities"].to_string().contains("deleteFiles"));
        assert!(!body["capabilities"].to_string().contains("bucket"));
        let cred = credential_from_create_response(
            &json!({ "applicationKeyId": "id-1", "applicationKey": "secret-1" }),
            &caps,
        )
        .unwrap();
        assert_eq!(cred.extra.get("capabilities").map(String::as_str), Some("listBuckets,listFiles,readFiles"));
        assert!(!cred.secret.is_empty());

        // A copied readFiles key with a blank bucket id must not lose the field.
        // Omitting bucketId would make the replacement broader than the original.
        let (blank, caps) = create_key_body("acct-1", "kw-blank", Some(&like(&["readFiles"], Some(""))));
        assert_eq!(caps, vec!["readFiles"]);
        assert_eq!(blank["capabilities"], json!(["readFiles"]));
        assert_eq!(blank["bucketId"], "");
        assert!(blank.get("bucketId").is_some());
        assert!(!blank["capabilities"].to_string().contains("listBuckets"));

        let (spaced, caps) = create_key_body("acct-1", "kw-space", Some(&like(&["readFiles"], Some(" "))));
        assert_eq!(caps, vec!["readFiles"]);
        assert_eq!(spaced["bucketId"], " ");
        assert_ne!(spaced["bucketId"], "");
    }

    #[test]
    fn create_response_rejects_a_non_string_id_without_echoing_the_secret() {
        let err = credential_from_create_response(
            &json!({ "applicationKeyId": 7, "applicationKey": "SECRET-MARKER-b2" }),
            &["readFiles".into()],
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no applicationKeyId"), "{msg}");
        assert!(!msg.contains("SECRET-MARKER-b2"), "{msg}");
        assert!(!msg.contains("readFiles"), "{msg}");
        assert!(!msg.contains('7'), "{msg}");
    }
}
