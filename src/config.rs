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
    fn defaults_fill_field_names_prefix_and_absent_schedule() {
        let cfg = parse(
            r#"
            [[target]]
            name = "b2-service"
            provider = "backblaze"
            vault = "Personal"
            item = "B2 Service Key"
            management_item = "B2 Key Manager"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.target.len(), 1);
        let t = &cfg.target[0];
        assert_eq!(t.field_key_id, "keyID");
        assert_eq!(t.field_secret, "applicationKey");
        assert_eq!(t.mgmt_field_key_id, "keyID");
        assert_eq!(t.mgmt_field_secret, "applicationKey");
        assert_eq!(t.key_name_prefix, "keyward");
        assert!(t.schedule.is_none());
        assert!(t.recipe_recipient.is_none());
        assert!(t.console_url.is_none());
    }

    #[test]
    fn schedule_parses_humantime_and_defaults_jitter_to_zero() {
        let cfg = parse(
            r#"
            [[target]]
            name = "scheduled"
            provider = "aws"
            vault = "Work"
            item = "svc"
            management_item = "mgmt"
            field_key_id = "access_key_id"
            field_secret = "secret_access_key"
            key_name_prefix = "keyward-aws"
            recipe_recipient = "age1example"
            console_url = "https://console.aws.amazon.com/iam"

            [target.schedule]
            interval = "30d"
            jitter = "36h"

            [[target]]
            name = "no-jitter"
            provider = "b2"
            vault = "Work"
            item = "other"
            management_item = "mgmt"

            [target.schedule]
            interval = "12h"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.target.len(), 2);
        let scheduled = &cfg.target[0];
        let s = scheduled.schedule.as_ref().unwrap();
        assert_eq!(s.interval, std::time::Duration::from_secs(30 * 24 * 3600));
        assert_eq!(s.jitter, std::time::Duration::from_secs(36 * 3600));
        assert_eq!(scheduled.field_key_id, "access_key_id");
        assert_eq!(scheduled.recipe_recipient.as_deref(), Some("age1example"));
        assert_eq!(scheduled.console_url.as_deref(), Some("https://console.aws.amazon.com/iam"));

        let on_demand = cfg.target[1].schedule.as_ref().unwrap();
        assert_eq!(on_demand.interval, std::time::Duration::from_secs(12 * 3600));
        assert_eq!(on_demand.jitter, std::time::Duration::ZERO);
    }

    #[test]
    fn empty_config_has_no_targets() {
        let cfg = parse("").unwrap();
        assert!(cfg.target.is_empty());
    }

    #[test]
    fn missing_required_target_fields_and_bad_durations_error() {
        let missing = parse(
            r#"
            [[target]]
            name = "incomplete"
            provider = "aws"
            "#,
        );
        assert!(missing.is_err());

        let bad_interval = parse(
            r#"
            [[target]]
            name = "t"
            provider = "aws"
            vault = "v"
            item = "i"
            management_item = "m"

            [target.schedule]
            interval = "fortnight"
            "#,
        );
        assert!(bad_interval.is_err());
    }

    #[test]
    fn missing_config_file_errors() {
        let err = load("/tmp/keyward-does-not-exist-5a92.toml").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("reading config"), "{msg}");
    }
}
