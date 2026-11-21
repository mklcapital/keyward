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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Result<Config> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyward.toml");
        std::fs::write(&path, src).unwrap();
        load(path.to_str().unwrap())
    }

    #[test]
    fn duplicate_target_names_stay_distinct_rows() {
        // `[[target]]` is a list, not a map. Two rows can share a name and still
        // rotate different items. Collapsing them at load would drop one credential.
        let cfg = parse(
            r#"
            [[target]]
            name = "shared"
            provider = "aws"
            vault = "Work"
            item = "svc-aws"
            management_item = "mgmt-aws"

            [target.schedule]
            interval = "1d"

            [[target]]
            name = "shared"
            provider = "b2"
            vault = "Personal"
            item = "svc-b2"
            management_item = "mgmt-b2"
            "#,
        )
        .unwrap();

        assert_eq!(cfg.target.len(), 2);
        let first = &cfg.target[0];
        let second = &cfg.target[1];
        assert_eq!(first.name, "shared");
        assert_eq!(second.name, "shared");
        assert_eq!(first.provider, "aws");
        assert_eq!(second.provider, "b2");
        assert_eq!(first.vault, "Work");
        assert_eq!(second.vault, "Personal");
        assert_eq!(first.item, "svc-aws");
        assert_eq!(second.item, "svc-b2");
        assert_eq!(first.management_item, "mgmt-aws");
        assert_eq!(second.management_item, "mgmt-b2");
        assert_ne!(first.item, second.item);
        assert_ne!(first.management_item, second.management_item);

        let schedule = first.schedule.as_ref().unwrap();
        assert_eq!(schedule.interval, std::time::Duration::from_secs(24 * 3600));
        assert_eq!(schedule.jitter, std::time::Duration::ZERO);
        assert!(second.schedule.is_none());
        assert!(first.recipe_recipient.is_none());
        assert!(second.console_url.is_none());
    }
}
