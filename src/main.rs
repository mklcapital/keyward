//! keyward — rotate cloud provider credentials into your secret store.
mod config;
// The crypto module is a deliberate, fully-tested API surface. Only its
// zero-knowledge recipe-sealing path is wired into the CLI today; the passphrase
// mode and identity/key management are the interface the forthcoming native
// encrypted-DB store will use, so they are intentionally kept even where the
// binary doesn't yet call them.
#[allow(dead_code)]
mod crypto;
mod model;
mod provider;
mod rotation;
mod scheduler;
mod store;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use store::onepassword::OnePassword;

#[derive(Parser)]
#[command(name = "keyward", version, about = "Rotate cloud credentials across providers into 1Password")]
struct Cli {
    /// Path to the config file.
    #[arg(long, default_value = "keyward.toml")]
    config: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List configured targets.
    List,
    /// Rotate a named target, or every target with --all.
    Rotate {
        /// Target name (omit and pass --all to rotate everything).
        name: Option<String>,
        #[arg(long)]
        all: bool,
        /// Show what would happen without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Mint + store the new key but do NOT revoke the old one yet.
        #[arg(long)]
        no_revoke: bool,
    },
    /// Scheduled rotation with jitter (per-target `[schedule]` in the config).
    Schedule {
        /// Compute and print the schedule, then exit — rotate nothing.
        #[arg(long)]
        once: bool,
        /// Actually rotate when a target comes due. Default is dry-run (safe):
        /// the loop prints what it *would* rotate but touches no live provider.
        #[arg(long)]
        live: bool,
        /// Path to the persistent next-run state file.
        /// Defaults to $KEYWARD_STATE or <state_dir>/keyward/schedule.json.
        #[arg(long)]
        state: Option<String>,
    },
}

/// Choose which configured targets `rotate` will touch.
///
/// `--all` is every target, in config order. A name must match exactly: a prefix
/// or a differently-cased sibling is a different credential and must not rotate.
fn select_targets<'a>(
    targets: &'a [config::Target],
    name: Option<&str>,
    all: bool,
) -> Result<Vec<&'a config::Target>> {
    let chosen: Vec<&config::Target> = if all {
        targets.iter().collect()
    } else {
        let n = name.ok_or_else(|| anyhow::anyhow!("pass a target name, or --all"))?;
        targets.iter().filter(|t| t.name == n).collect()
    };
    if chosen.is_empty() {
        bail!("no matching target");
    }
    Ok(chosen)
}

/// Scheduler hook: on fire, run the rotation flow. `live` decides whether it's a
/// real rotation or a dry-run. Default wiring is dry-run so `keyward schedule`
/// never touches a live provider unless the operator passes --live.
struct RotateRunner<'a> {
    store: &'a OnePassword,
    live: bool,
}

#[async_trait::async_trait]
impl scheduler::RotateHook for RotateRunner<'_> {
    async fn fire(&self, target: &config::Target) -> Result<()> {
        let opts = rotation::Options { dry_run: !self.live, revoke: true };
        let outcome = rotation::rotate(target, self.store, &opts).await?;
        if outcome.dry_run {
            println!(
                "[{}] schedule fired: DRY-RUN would rotate {} (old={})",
                chrono::Utc::now().to_rfc3339(),
                target.name,
                outcome.old_key_id.as_deref().unwrap_or("-"),
            );
        } else {
            println!(
                "[{}] schedule fired: rotated {} new={} revoked_old={}",
                chrono::Utc::now().to_rfc3339(),
                target.name,
                outcome.new_key_id,
                outcome.revoked_old,
            );
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;
    let store = OnePassword::new();

    match cli.cmd {
        Cmd::List => {
            if cfg.target.is_empty() {
                println!("(no targets configured in {})", cli.config);
            }
            for t in &cfg.target {
                println!("{:18} provider={:11} item=op://{}/{}", t.name, t.provider, t.vault, t.item);
            }
        }
        Cmd::Rotate { name, all, dry_run, no_revoke } => {
            let opts = rotation::Options { dry_run, revoke: !no_revoke };
            let targets = select_targets(&cfg.target, name.as_deref(), all)?;
            let mut failures = 0;
            for t in targets {
                print!("rotating {:18} ({:10}) ... ", t.name, t.provider);
                match rotation::rotate(t, &store, &opts).await {
                    Ok(o) if o.dry_run => {
                        println!("DRY-RUN: would mint new key and revoke {:?}", o.old_key_id)
                    }
                    Ok(o) => println!(
                        "OK  new={}  old={}  revoked_old={}{}",
                        o.new_key_id,
                        o.old_key_id.as_deref().unwrap_or("-"),
                        o.revoked_old,
                        if o.sealed_recipe.is_some() { "  recipe=sealed" } else { "" }
                    ),
                    Err(e) => {
                        failures += 1;
                        println!("FAILED: {e:#}");
                    }
                }
            }
            if failures > 0 {
                bail!("{failures} target(s) failed");
            }
        }
        Cmd::Schedule { once, live, state } => {
            let state_path = state
                .map(std::path::PathBuf::from)
                .unwrap_or_else(scheduler::default_state_path);

            if once {
                // Dry: compute + print the plan, persist it, rotate nothing.
                let mut st = scheduler::State::load(&state_path)?;
                let mut rng = rand::thread_rng();
                let plan = scheduler::plan(&cfg, &mut st, chrono::Utc::now(), &mut rng);
                st.save(&state_path)?;
                print!("{}", scheduler::format_plan(&plan, chrono::Utc::now()));
                println!("(state: {})", state_path.display());
                return Ok(());
            }

            if !live {
                println!("keyward schedule: DRY-RUN mode (pass --live to perform real rotations)");
            }
            let hook = RotateRunner { store: &store, live };
            println!("keyward schedule: running (state: {})", state_path.display());
            let n = scheduler::run(&cfg, &state_path, &hook, None).await?;
            println!("scheduler exited after {n} rotation(s)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::select_targets;
    use crate::config::Target;

    fn target(name: &str) -> Target {
        Target {
            name: name.into(),
            provider: "aws".into(),
            vault: format!("vault-{name}"),
            item: format!("item-{name}"),
            field_key_id: "keyID".into(),
            field_secret: "secret".into(),
            management_item: format!("mgmt-{name}"),
            mgmt_field_key_id: "keyID".into(),
            mgmt_field_secret: "secret".into(),
            key_name_prefix: "keyward".into(),
            schedule: None,
            recipe_recipient: None,
            console_url: None,
        }
    }

    #[test]
    fn named_rotation_is_an_exact_match() {
        let targets = vec![
            target("prod"),
            target("prod-backup"),
            target("my-prod"),
            target("Prod"),
            target("prod"),
        ];
        let chosen = select_targets(&targets, Some("prod"), false).unwrap();
        let names: Vec<_> = chosen.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["prod", "prod"]);
        assert!(chosen.iter().all(|t| t.item == "item-prod"));

        let err = select_targets(&targets, Some("prod-"), false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no matching target"));
        assert!(!msg.contains("vault-"));
        assert!(!msg.contains("item-"));
    }

    #[test]
    fn all_keeps_config_order_and_empty_selection_fails_closed() {
        let targets = vec![target("on-demand"), target("scheduled")];
        let chosen = select_targets(&targets, None, true).unwrap();
        let names: Vec<_> = chosen.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["on-demand", "scheduled"]);

        let err = select_targets(&targets, None, false).unwrap_err();
        assert!(format!("{err:#}").contains("pass a target name, or --all"));

        let err = select_targets(&[], Some("prod"), true).unwrap_err();
        assert!(format!("{err:#}").contains("no matching target"));

        let err = select_targets(&targets, Some(""), false).unwrap_err();
        assert!(format!("{err:#}").contains("no matching target"));
    }
}
