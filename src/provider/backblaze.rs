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

/// JSON body for `b2_create_key`, plus the capability list stored on the
/// minted credential. `keyName` and `bucketId` stay single JSON strings so a
/// quote in either field cannot add a capability.
fn create_key_body(account_id: &str, name: &str, like: Option<&KeyInfo>) -> (serde_json::Value, Vec<String>) {
    let caps: Vec<String> = like
        .map(|k| k.capabilities.clone())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| vec!["listBuckets".into(), "listFiles".into(), "readFiles".into()]);
    let mut body = json!({ "accountId": account_id, "capabilities": caps, "keyName": name });
    if let Some(b) = like.and_then(|k| k.bucket_id.as_ref()) {
        body["bucketId"] = json!(b);
    }
    (body, caps)
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
        let mut cred = Credential::new(
            v["applicationKeyId"].as_str().ok_or_else(|| anyhow!("no applicationKeyId"))?,
            v["applicationKey"].as_str().ok_or_else(|| anyhow!("no applicationKey"))?,
        );
        cred.extra.insert("capabilities".into(), caps.join(","));
        Ok(cred)
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

    #[test]
    fn hostile_key_name_stays_one_json_string() {
        let name = "kw\",\"capabilities\":[\"deleteFiles\"],\"keyName\":\"pwned";
        let like = KeyInfo {
            key_id: "old".into(),
            name: None,
            capabilities: vec!["readFiles".into()],
            bucket_id: Some("bucket\",\"capabilities\":[\"deleteFiles\"]".into()),
        };
        let (body, caps) = create_key_body("acct-1", name, Some(&like));

        assert_eq!(caps, vec!["readFiles".to_string()]);
        assert_eq!(body["keyName"], name);
        assert_eq!(body["bucketId"], "bucket\",\"capabilities\":[\"deleteFiles\"]");
        assert_eq!(body["accountId"], "acct-1");
        assert_eq!(body["capabilities"], json!(["readFiles"]));
        assert_eq!(body.as_object().unwrap().len(), 4);

        let raw = serde_json::to_string(&body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, body);
        let parsed_caps = parsed["capabilities"].as_array().unwrap();
        assert_eq!(parsed_caps.len(), 1);
        assert_eq!(parsed_caps[0], "readFiles");
        assert!(!parsed_caps.iter().any(|c| c == "deleteFiles"));
        assert!(!raw.contains("listBuckets"));
        assert!(!raw.contains("listFiles"));
    }
}
