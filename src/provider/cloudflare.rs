//! Cloudflare R2 provider (implemented).
//!
//! # How R2 credentials work
//! R2 is accessed with **S3-compatible** access keys, but Cloudflare does not
//! mint an `{access_key_id, secret_access_key}` pair directly. Instead you mint a
//! Cloudflare **account-owned API token** and *derive* the S3 pair from it
//! (per <https://developers.cloudflare.com/r2/api/tokens/>):
//!
//!   * `access_key_id`     = the token's `id`
//!   * `secret_access_key` = `hex(sha256(token.value))`
//!
//! So one Cloudflare token == one S3 access-key pair. Rotating an R2 credential is
//! therefore: mint a new token, derive its S3 pair, verify it, then delete the old
//! token. There is no separate `/r2/api-tokens` resource — R2 rides the standard
//! account-tokens API.
//!
//! # API surface (base: `https://api.cloudflare.com/client/v4`)
//!   * mint:   `POST /accounts/{account_id}/tokens` with body
//!     `{ name, policies: [{ effect, resources, permission_groups }] }` -> `result.id` + `result.value`
//!   * list:   `GET /accounts/{account_id}/tokens` -> `result[] { id, name, policies }`
//!   * verify: `GET /accounts/{account_id}/tokens/verify` (Bearer = the token's `value`)
//!   * revoke: `DELETE /accounts/{account_id}/tokens/{id}`
//!
//! # The management credential
//! The `mgmt` [`Credential`] carries the Cloudflare account-owned API token used to
//! *manage* R2 tokens, scoped to **Account -> R2 -> Edit** only (least privilege).
//! `mgmt.key_id` is the Cloudflare **account id** and `mgmt.secret` is the
//! management API **token value** (sent as `Bearer`). This mirrors how
//! `backblaze.rs` treats its `mgmt` credential as `keyID:appKey`.
//!
//! # Scope preservation
//! A minted token inherits the *old* token's `policies` verbatim (never broader),
//! exactly like B2 inherits `capabilities` + `bucketId`. If the old token's policy
//! can't be discovered, we fall back to a **read-only** R2 policy — fail closed to
//! least privilege, never to admin.
//!
//! # Assumptions (documented, since the Cloudflare API has fiddly corners)
//!  * The mgmt token's `value` is a bearer secret we already hold; we do not
//!    re-derive it. `mgmt.key_id` holding the *account id* is a keyward convention.
//!  * The read-only fallback policy uses the well-known **"Workers R2 Storage
//!    Bucket Item Read"** permission-group id (`6a018a9f2fc74eb6b293b0c548f38b39`,
//!    from the R2 docs) over all buckets in the account. In production the
//!    orchestrator passes `like`, so the fallback is only a safety net.
use super::Provider;
use crate::model::{Credential, KeyInfo};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Permission-group id for "Workers R2 Storage Bucket Item Read" (from the R2
/// tokens docs). Used only for the least-privilege fallback policy.
const R2_READ_PERMISSION_GROUP: &str = "6a018a9f2fc74eb6b293b0c548f38b39";

/// An HTTP request the provider wants to make. Kept transport-agnostic so the
/// provider can be unit-tested against fixtures with no network — the same
/// dependency-injection style the scheduler uses for `RotateHook`.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    /// Bearer token value (the API token's `value`), if the call is authenticated.
    pub bearer: Option<String>,
    /// JSON body for POST/PUT; `None` for GET/DELETE.
    pub body: Option<Value>,
}

/// The raw HTTP result the transport hands back.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub json: Value,
}

/// Injectable HTTP transport. Production uses [`ReqwestTransport`]; tests use an
/// in-memory fake. This is the seam that keeps the provider unit-testable without
/// touching Cloudflare.
#[async_trait]
pub trait R2Transport: Send + Sync {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse>;
}

/// The real transport: `reqwest` over HTTPS.
pub struct ReqwestTransport {
    http: reqwest::Client,
}

impl ReqwestTransport {
    pub fn new() -> Self {
        Self { http: reqwest::Client::new() }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl R2Transport for ReqwestTransport {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse> {
        let mut builder = match req.method {
            "GET" => self.http.get(&req.url),
            "POST" => self.http.post(&req.url),
            "DELETE" => self.http.delete(&req.url),
            other => bail!("unsupported HTTP method: {other}"),
        };
        if let Some(bearer) = &req.bearer {
            builder = builder.bearer_auth(bearer);
        }
        if let Some(body) = &req.body {
            builder = builder.json(body);
        }
        let resp = builder.send().await.context("cloudflare API request failed")?;
        let status = resp.status().as_u16();
        // Cloudflare always returns JSON (even for errors); tolerate an empty body.
        let json: Value = resp.json().await.unwrap_or(Value::Null);
        Ok(HttpResponse { status, json })
    }
}

/// Cloudflare R2 provider, generic over its HTTP transport so it can be exercised
/// with a fake in tests. `Cloudflare::new()` yields the production instance.
pub struct Cloudflare<T: R2Transport = ReqwestTransport> {
    transport: T,
}

impl Cloudflare<ReqwestTransport> {
    pub fn new() -> Self {
        Self { transport: ReqwestTransport::new() }
    }
}

impl<T: R2Transport> Cloudflare<T> {
    /// Construct with an explicit transport. Used by tests to inject a fake; also
    /// the seam a hosted build would use to swap in an instrumented client.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_transport(transport: T) -> Self {
        Self { transport }
    }

    /// Derive the S3 secret access key from a Cloudflare token `value`:
    /// `hex(sha256(value))`.  See the module docs / Cloudflare R2 token page.
    fn derive_secret_access_key(token_value: &str) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, token_value.as_bytes());
        let mut hex = String::with_capacity(digest.as_ref().len() * 2);
        for byte in digest.as_ref() {
            use std::fmt::Write;
            // infallible: writing to a String never errors.
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

    /// The least-privilege fallback policy: read-only over all R2 buckets in the
    /// account. Only used when the old token's own policy can't be discovered.
    fn fallback_read_policy(account_id: &str) -> Value {
        json!([{
            "effect": "allow",
            "resources": {
                format!("com.cloudflare.api.account.{account_id}"): {
                    "com.cloudflare.edge.r2.bucket.*": "*"
                }
            },
            "permission_groups": [{ "id": R2_READ_PERMISSION_GROUP }]
        }])
    }

    /// Unwrap a Cloudflare API envelope: `{ success, errors, result }`. Cloudflare
    /// returns 200 with `success:false` for logical errors, so we check both.
    fn unwrap_result(resp: HttpResponse, ctx: &str) -> Result<Value> {
        if resp.status >= 400 {
            return Err(anyhow!("{ctx}: HTTP {} — {}", resp.status, summarize_errors(&resp.json)));
        }
        if !resp.json["success"].as_bool().unwrap_or(false) {
            return Err(anyhow!("{ctx}: {}", summarize_errors(&resp.json)));
        }
        Ok(resp.json["result"].clone())
    }
}

impl Default for Cloudflare<ReqwestTransport> {
    fn default() -> Self {
        Self::new()
    }
}

/// Render Cloudflare's `errors: [{ code, message }]` into a one-line string for
/// error context. Never includes secrets — the API never echoes token values here.
fn summarize_errors(v: &Value) -> String {
    match v["errors"].as_array() {
        Some(errs) if !errs.is_empty() => errs
            .iter()
            .map(|e| {
                let code = e["code"].as_i64().unwrap_or_default();
                let msg = e["message"].as_str().unwrap_or("unknown error");
                format!("[{code}] {msg}")
            })
            .collect::<Vec<_>>()
            .join("; "),
        _ => "no error detail from Cloudflare".to_string(),
    }
}

#[async_trait]
impl<T: R2Transport> Provider for Cloudflare<T> {
    fn id(&self) -> &'static str {
        "cloudflare"
    }

    async fn list_keys(&self, mgmt: &Credential) -> Result<Vec<KeyInfo>> {
        let account_id = &mgmt.key_id;
        let resp = self
            .transport
            .send(HttpRequest {
                method: "GET",
                url: format!("{API_BASE}/accounts/{account_id}/tokens"),
                bearer: Some(mgmt.secret.clone()),
                body: None,
            })
            .await?;
        let result = Self::unwrap_result(resp, "cloudflare list tokens")?;
        let keys = result
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|t| KeyInfo {
                key_id: t["id"].as_str().unwrap_or_default().to_string(),
                name: t["name"].as_str().map(String::from),
                // We stash the token's policies (JSON) as a single capability entry
                // so `create_key(like)` can preserve scope verbatim. KeyInfo has no
                // structured policy field; encoding it here keeps the model generic.
                capabilities: match t.get("policies") {
                    Some(p) if !p.is_null() => vec![p.to_string()],
                    _ => Vec::new(),
                },
                bucket_id: None,
            })
            .collect();
        Ok(keys)
    }

    async fn create_key(&self, mgmt: &Credential, name: &str, like: Option<&KeyInfo>) -> Result<Credential> {
        let account_id = &mgmt.key_id;

        // Preserve the old token's policies verbatim; else fall back to read-only.
        let policies: Value = like
            .and_then(|k| k.capabilities.first())
            .and_then(|p| serde_json::from_str::<Value>(p).ok())
            .filter(|p| p.as_array().map(|a| !a.is_empty()).unwrap_or(false))
            .unwrap_or_else(|| Self::fallback_read_policy(account_id));

        let body = json!({ "name": name, "policies": policies });
        let resp = self
            .transport
            .send(HttpRequest {
                method: "POST",
                url: format!("{API_BASE}/accounts/{account_id}/tokens"),
                bearer: Some(mgmt.secret.clone()),
                body: Some(body),
            })
            .await?;
        let result = Self::unwrap_result(resp, "cloudflare create token")?;

        let token_id = result["id"]
            .as_str()
            .ok_or_else(|| anyhow!("cloudflare create token: no `id` in result"))?;
        let token_value = result["value"]
            .as_str()
            .ok_or_else(|| anyhow!("cloudflare create token: no `value` in result"))?;

        // Derive the S3-compatible access-key pair. `key_id` is the S3 Access Key
        // ID (the token id); `secret` is the S3 Secret Access Key.
        let mut cred = Credential::new(token_id, Self::derive_secret_access_key(token_value));
        // Keep the raw token value so `verify_key` can hit the tokens/verify
        // endpoint; and the S3 endpoint so consumers know where to point clients.
        cred.extra.insert("cf_token_value".into(), token_value.to_string());
        cred.extra.insert("account_id".into(), account_id.clone());
        cred.extra.insert(
            "s3_endpoint".into(),
            format!("https://{account_id}.r2.cloudflarestorage.com"),
        );
        cred.extra.insert("policies".into(), policies.to_string());
        Ok(cred)
    }

    async fn verify_key(&self, cred: &Credential) -> Result<()> {
        // Verify the underlying Cloudflare token via the account tokens/verify
        // endpoint (Bearer = the token value). A `success:true` + status "active"
        // proves the freshly minted credential is live before we rely on it.
        let account_id = cred
            .extra
            .get("account_id")
            .ok_or_else(|| anyhow!("cannot verify R2 key: missing account_id in credential extras"))?;
        let token_value = cred
            .extra
            .get("cf_token_value")
            .ok_or_else(|| anyhow!("cannot verify R2 key: missing cf_token_value in credential extras"))?;

        let resp = self
            .transport
            .send(HttpRequest {
                method: "GET",
                url: format!("{API_BASE}/accounts/{account_id}/tokens/verify"),
                bearer: Some(token_value.clone()),
                body: None,
            })
            .await
            .context("new R2 token failed verification (request error)")?;
        let result = Self::unwrap_result(resp, "cloudflare verify token")
            .context("new R2 token failed verification")?;
        match result["status"].as_str() {
            Some("active") => Ok(()),
            Some(other) => bail!("new R2 token is not active (status: {other})"),
            None => Ok(()), // verify succeeded (success:true) but no status echoed — accept.
        }
    }

    async fn revoke_key(&self, mgmt: &Credential, key_id: &str) -> Result<()> {
        let account_id = &mgmt.key_id;
        let resp = self
            .transport
            .send(HttpRequest {
                method: "DELETE",
                url: format!("{API_BASE}/accounts/{account_id}/tokens/{key_id}"),
                bearer: Some(mgmt.secret.clone()),
                body: None,
            })
            .await?;
        Self::unwrap_result(resp, "cloudflare revoke token")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A scripted fake transport: hand it a queue of `(expected_method, response)`
    /// and it pops one per call, recording the requests it saw. No network, no
    /// real secrets — mirrors the in-memory hooks the scheduler tests use.
    struct FakeTransport {
        responses: Mutex<VecDeque<Result<HttpResponse, String>>>,
        seen: Mutex<Vec<HttpRequest>>,
    }

    impl FakeTransport {
        fn new(responses: Vec<Result<HttpResponse, String>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn ok(status: u16, json: Value) -> Result<HttpResponse, String> {
            Ok(HttpResponse { status, json })
        }

        fn last(&self) -> HttpRequest {
            self.seen.lock().unwrap().last().cloned().expect("a request was made")
        }
    }

    #[async_trait]
    impl R2Transport for FakeTransport {
        async fn send(&self, req: HttpRequest) -> Result<HttpResponse> {
            self.seen.lock().unwrap().push(req.clone());
            match self.responses.lock().unwrap().pop_front() {
                Some(Ok(r)) => Ok(r),
                Some(Err(e)) => Err(anyhow!(e)),
                None => panic!("FakeTransport: no scripted response for {} {}", req.method, req.url),
            }
        }
    }

    fn mgmt() -> Credential {
        // account_id in key_id, mgmt token value in secret (a fake, not a real secret).
        Credential::new("acct-123", "mgmt-token-value")
    }

    fn envelope(result: Value) -> Value {
        json!({ "success": true, "errors": [], "messages": [], "result": result })
    }

    #[test]
    fn secret_access_key_is_sha256_hex_of_token_value() {
        // Known-answer test: sha256("") = e3b0c442...  (NIST empty-string vector).
        let empty = Cloudflare::<ReqwestTransport>::derive_secret_access_key("");
        assert_eq!(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // sha256("abc") = ba7816bf...
        let abc = Cloudflare::<ReqwestTransport>::derive_secret_access_key("abc");
        assert_eq!(
            abc,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn create_key_mints_derives_and_scopes() {
        let fake = FakeTransport::new(vec![FakeTransport::ok(
            200,
            envelope(json!({ "id": "tok-new", "value": "raw-token-secret", "name": "kw-2026" })),
        )]);
        let prov = Cloudflare::with_transport(fake);

        // Provide an old token's policies to preserve.
        let old_policies = json!([{ "effect": "allow", "resources": { "x": "*" }, "permission_groups": [{ "id": "pg-1" }] }]);
        let like = KeyInfo {
            key_id: "tok-old".into(),
            name: Some("kw-old".into()),
            capabilities: vec![old_policies.to_string()],
            bucket_id: None,
        };

        let cred = prov.create_key(&mgmt(), "kw-2026", Some(&like)).await.unwrap();

        // S3 access key id = token id; secret = sha256(value) hex.
        assert_eq!(cred.key_id, "tok-new");
        assert_eq!(
            cred.secret,
            Cloudflare::<ReqwestTransport>::derive_secret_access_key("raw-token-secret")
        );
        assert_ne!(cred.secret, "raw-token-secret", "secret must be hashed, not raw");
        assert_eq!(cred.extra.get("account_id").unwrap(), "acct-123");
        assert_eq!(
            cred.extra.get("s3_endpoint").unwrap(),
            "https://acct-123.r2.cloudflarestorage.com"
        );

        // The POST preserved the old policies verbatim (never broadened).
        let req = prov.transport.last();
        assert_eq!(req.method, "POST");
        assert!(req.url.ends_with("/accounts/acct-123/tokens"));
        let sent_policies = &req.body.unwrap()["policies"];
        assert_eq!(sent_policies, &old_policies);
    }

    #[tokio::test]
    async fn create_key_falls_back_to_read_only_policy() {
        let fake = FakeTransport::new(vec![FakeTransport::ok(
            200,
            envelope(json!({ "id": "tok-new", "value": "v", "name": "kw" })),
        )]);
        let prov = Cloudflare::with_transport(fake);

        // No `like` → must fall back to the least-privilege read policy.
        let _ = prov.create_key(&mgmt(), "kw", None).await.unwrap();

        let sent = prov.transport.last().body.unwrap();
        let pg = &sent["policies"][0]["permission_groups"][0]["id"];
        assert_eq!(pg, R2_READ_PERMISSION_GROUP, "fallback must be read-only, not admin");
    }

    #[tokio::test]
    async fn list_keys_parses_tokens_and_policies() {
        let fake = FakeTransport::new(vec![FakeTransport::ok(
            200,
            envelope(json!([
                { "id": "tok-a", "name": "alpha", "policies": [{ "effect": "allow" }] },
                { "id": "tok-b", "name": "beta" },
            ])),
        )]);
        let prov = Cloudflare::with_transport(fake);

        let keys = prov.list_keys(&mgmt()).await.unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key_id, "tok-a");
        assert_eq!(keys[0].name.as_deref(), Some("alpha"));
        assert_eq!(keys[0].capabilities.len(), 1, "policies captured for scope preservation");
        assert!(keys[1].capabilities.is_empty(), "missing policies → empty caps");

        // Request was an authenticated GET to the tokens endpoint.
        let req = prov.transport.last();
        assert_eq!(req.method, "GET");
        assert_eq!(req.bearer.as_deref(), Some("mgmt-token-value"));
    }

    #[tokio::test]
    async fn verify_key_accepts_active_token() {
        let fake = FakeTransport::new(vec![FakeTransport::ok(
            200,
            envelope(json!({ "id": "tok", "status": "active" })),
        )]);
        let prov = Cloudflare::with_transport(fake);

        let mut cred = Credential::new("tok", "s3-secret");
        cred.extra.insert("account_id".into(), "acct-123".into());
        cred.extra.insert("cf_token_value".into(), "raw-token-secret".into());

        prov.verify_key(&cred).await.unwrap();

        // Verify hit the tokens/verify endpoint bearing the *token value*, not the secret.
        let req = prov.transport.last();
        assert!(req.url.ends_with("/accounts/acct-123/tokens/verify"));
        assert_eq!(req.bearer.as_deref(), Some("raw-token-secret"));
    }

    #[tokio::test]
    async fn verify_key_rejects_disabled_token() {
        let fake = FakeTransport::new(vec![FakeTransport::ok(
            200,
            envelope(json!({ "id": "tok", "status": "disabled" })),
        )]);
        let prov = Cloudflare::with_transport(fake);

        let mut cred = Credential::new("tok", "s3-secret");
        cred.extra.insert("account_id".into(), "acct-123".into());
        cred.extra.insert("cf_token_value".into(), "raw-token-secret".into());

        let err = prov.verify_key(&cred).await.unwrap_err();
        assert!(err.to_string().contains("not active"), "got: {err}");
    }

    #[tokio::test]
    async fn verify_key_errors_without_required_extras() {
        let fake = FakeTransport::new(vec![]); // no request should be made
        let prov = Cloudflare::with_transport(fake);
        // Missing account_id / cf_token_value → cannot verify.
        let err = prov.verify_key(&Credential::new("tok", "s3-secret")).await.unwrap_err();
        assert!(err.to_string().contains("account_id"), "got: {err}");
    }

    #[tokio::test]
    async fn revoke_key_deletes_by_id() {
        let fake = FakeTransport::new(vec![FakeTransport::ok(
            200,
            envelope(json!({ "id": "tok-old" })),
        )]);
        let prov = Cloudflare::with_transport(fake);

        prov.revoke_key(&mgmt(), "tok-old").await.unwrap();

        let req = prov.transport.last();
        assert_eq!(req.method, "DELETE");
        assert!(req.url.ends_with("/accounts/acct-123/tokens/tok-old"));
        assert_eq!(req.bearer.as_deref(), Some("mgmt-token-value"));
    }

    #[tokio::test]
    async fn api_error_envelope_is_surfaced() {
        // Cloudflare returns 200 with success:false for logical errors.
        let fake = FakeTransport::new(vec![FakeTransport::ok(
            200,
            json!({ "success": false, "errors": [{ "code": 1001, "message": "invalid policy" }], "result": null }),
        )]);
        let prov = Cloudflare::with_transport(fake);

        let err = prov.create_key(&mgmt(), "kw", None).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("1001") && msg.contains("invalid policy"), "got: {msg}");
    }

    #[tokio::test]
    async fn http_error_status_is_surfaced() {
        let fake = FakeTransport::new(vec![FakeTransport::ok(
            403,
            json!({ "success": false, "errors": [{ "code": 9109, "message": "Unauthorized to access requested resource" }] }),
        )]);
        let prov = Cloudflare::with_transport(fake);

        let err = prov.list_keys(&mgmt()).await.unwrap_err();
        assert!(err.to_string().contains("HTTP 403"), "got: {err}");
    }

    #[tokio::test]
    async fn transport_failure_propagates() {
        let fake = FakeTransport::new(vec![Err("connection reset".into())]);
        let prov = Cloudflare::with_transport(fake);
        let err = prov.revoke_key(&mgmt(), "tok").await.unwrap_err();
        assert!(err.to_string().contains("connection reset"), "got: {err}");
    }

    #[tokio::test]
    async fn create_key_accepts_http_399_and_rejects_http_400() {
        // Cloudflare's error line is 400, not 300. A 399 with success:true
        // still mints. A 400 with success:true must not, and must not echo
        // the token value sitting in `result`.
        let minted = "cf-value-minted-once";
        let rejected = "cf-value-must-not-echo";
        let rejected_digest = Cloudflare::<ReqwestTransport>::derive_secret_access_key(rejected);

        let fake = FakeTransport::new(vec![FakeTransport::ok(
            399,
            envelope(json!({ "id": "tok-399", "value": minted })),
        )]);
        let prov = Cloudflare::with_transport(fake);
        let cred = prov.create_key(&mgmt(), "kw", None).await.unwrap();
        assert_eq!(cred.key_id, "tok-399");
        assert_eq!(
            cred.secret,
            Cloudflare::<ReqwestTransport>::derive_secret_access_key(minted)
        );
        assert_ne!(cred.secret, minted);

        let fake = FakeTransport::new(vec![FakeTransport::ok(
            400,
            json!({
                "success": true,
                "errors": [{ "code": 1000, "message": "bad request" }],
                "result": { "id": "tok-400", "value": rejected }
            }),
        )]);
        let prov = Cloudflare::with_transport(fake);
        let err = prov.create_key(&mgmt(), "kw", None).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("HTTP 400"), "{msg}");
        assert!(!msg.contains(rejected), "{msg}");
        assert!(!msg.contains(&rejected_digest), "{msg}");
        assert!(!msg.contains("tok-400"), "{msg}");
        assert!(!msg.contains("mgmt-token-value"), "{msg}");
        assert_eq!(prov.transport.last().method, "POST");
    }
}
