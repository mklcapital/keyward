//! TOML configuration: which credentials to rotate, and where they live.
use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub target: Vec<Target>,
}

/// One rotatable credential.
///
/// `item` is the *service* credential that gets rotated. `management_item` is a
/// separate, least-privilege credential whose only power is to create/delete keys
/// for this provider — never full account admin.
#[derive(Debug, Deserialize, Clone)]
pub struct Target {
    pub name: String,
    pub provider: String,
    pub vault: String,
    pub item: String,
    #[serde(default = "d_keyid")]
    pub field_key_id: String,
    #[serde(default = "d_secret")]
    pub field_secret: String,

    pub management_item: String,
    #[serde(default = "d_keyid")]
    pub mgmt_field_key_id: String,
    #[serde(default = "d_secret")]
    pub mgmt_field_secret: String,

    #[serde(default = "d_prefix")]
    pub key_name_prefix: String,

    /// Optional rotation schedule. Absent = this target is rotated only on demand.
    #[serde(default)]
    pub schedule: Option<Schedule>,

    /// Optional age recipient (`age1...` public key) to envelope-encrypt this
    /// target's *recreation recipe* at rotation time. When set, keyward seals a
    /// zero-knowledge recipe (how the key was minted) that only the matching age
    /// identity can open. The console URL for re-minting, if any.
    #[serde(default)]
    pub recipe_recipient: Option<String>,
    #[serde(default)]
    pub console_url: Option<String>,
}

/// Scheduled-rotation policy for one target.
///
/// Rotations fire every `interval`, plus a uniformly-random offset in
/// `[-jitter, +jitter]` so a fleet's rotations don't all fire predictably at the
/// same instant (PRODUCT-VISION requirement 4). Both are written in humantime
/// notation, e.g. `interval = "30d"`, `jitter = "36h"`, `jitter = "90min"`.
#[derive(Debug, Deserialize, Clone)]
pub struct Schedule {
    /// Base rotation period, e.g. "30d", "12h", "1week".
    #[serde(with = "humantime_serde")]
    pub interval: std::time::Duration,
    /// Max random +/- offset applied to each interval, e.g. "36h", "90min".
    /// Defaults to zero (no jitter).
    #[serde(with = "humantime_serde", default = "d_zero")]
    pub jitter: std::time::Duration,
}

fn d_keyid() -> String { "keyID".into() }
fn d_secret() -> String { "applicationKey".into() }
fn d_prefix() -> String { "keyward".into() }
fn d_zero() -> std::time::Duration { std::time::Duration::ZERO }

pub fn load(path: &str) -> Result<Config> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
    toml::from_str(&s).context("parsing config TOML")
}
