//! Scheduled rotation with jitter (`keyward schedule`).
//!
//! Implements PRODUCT-VISION requirements 4 & 5: scheduled auto-rotation with a
//! configurable **interval** and **customizable randomized jitter**, driven off
//! the same rotation code path whether triggered by schedule or TTL.
//!
//! ## Jitter
//! Each rotation is scheduled at `last_run + interval + U(-jitter, +jitter)`, a
//! uniform random offset, so a fleet of credentials does not all rotate at the
//! same predictable instant (which would create a thundering-herd on providers
//! and a nice pattern for an attacker to exploit). Jitter never pushes the next
//! run into the past — the effective delay is clamped at zero.
//!
//! ## Durable next-run state
//! Next-run times are persisted to a small JSON state file (default:
//! `~/.local/state/keyward/schedule.json`, or `$KEYWARD_STATE`). Restarting the
//! scheduler resumes from the persisted plan instead of re-randomizing, so a
//! restart can't be used to dodge or repeatedly re-roll a rotation.
//!
//! ## Safety
//! This is a **scheduler**, not a live-rotation driver. `plan_once` only computes
//! and prints the schedule — it performs no rotation at all. `run` executes the
//! loop but defers each due rotation to `rotation::rotate`, which itself honors
//! the dry-run flag; keyward's CLI wires the scheduler to **dry-run by default**
//! so no real provider is ever touched unless an operator explicitly opts in.

use crate::config::{Config, Schedule, Target};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Persisted schedule state, keyed by target name. Survives restarts.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// target name -> its next scheduled run (UTC).
    pub next_run: BTreeMap<String, DateTime<Utc>>,
    /// target name -> its last actual run (UTC), for auditing / next interval base.
    #[serde(default)]
    pub last_run: BTreeMap<String, DateTime<Utc>>,
}

impl State {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("parsing state {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e).with_context(|| format!("reading state {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating state dir {}", dir.display()))?;
        }
        let json = serde_json::to_string_pretty(self).context("serializing state")?;
        std::fs::write(path, json).with_context(|| format!("writing state {}", path.display()))
    }
}

/// Default on-disk location for the schedule state file.
/// Honors `$KEYWARD_STATE`, else `<state_dir>/keyward/schedule.json`.
pub fn default_state_path() -> PathBuf {
    if let Ok(p) = std::env::var("KEYWARD_STATE") {
        return PathBuf::from(p);
    }
    let base = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("keyward").join("schedule.json")
}

/// Compute the next run for a schedule, from a base time, applying jitter.
///
/// `next = base + interval + U(-jitter, +jitter)`, clamped so it is never before
/// `base` (jitter can shorten, but not make the delay negative).
pub fn next_run_from(base: DateTime<Utc>, sched: &Schedule, rng: &mut impl Rng) -> DateTime<Utc> {
    let interval_s = sched.interval.as_secs_f64();
    let jitter_s = sched.jitter.as_secs_f64();
    let offset = if jitter_s > 0.0 {
        rng.gen_range(-jitter_s..=jitter_s)
    } else {
        0.0
    };
    // Effective delay from `base`; never negative.
    let delay = (interval_s + offset).max(0.0);
    base + chrono::Duration::milliseconds((delay * 1000.0) as i64)
}

/// One line of a computed plan (for `--once` / dry printing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntry {
    pub target: String,
    pub next_run: DateTime<Utc>,
    /// True if this next_run was freshly computed (vs. loaded from persisted state).
    pub freshly_scheduled: bool,
}

/// Build (and persist) the schedule for every target that has a `[schedule]`,
/// without rotating anything. Targets already present in `state` keep their
/// persisted next_run (so restarts don't re-roll jitter); new targets get one.
///
/// Returns the plan sorted by next_run. Deterministic given `rng` and `now`.
pub fn plan(cfg: &Config, state: &mut State, now: DateTime<Utc>, rng: &mut impl Rng) -> Vec<PlanEntry> {
    let mut plan = Vec::new();
    for t in &cfg.target {
        let Some(sched) = &t.schedule else { continue };
        let (next, fresh) = match state.next_run.get(&t.name) {
            Some(existing) => (*existing, false),
            None => {
                let n = next_run_from(now, sched, rng);
                state.next_run.insert(t.name.clone(), n);
                (n, true)
            }
        };
        plan.push(PlanEntry { target: t.name.clone(), next_run: next, freshly_scheduled: fresh });
    }
    plan.sort_by_key(|p| p.next_run);
    plan
}

/// Render a plan as human-readable lines. No secrets — target names + times only.
pub fn format_plan(plan: &[PlanEntry], now: DateTime<Utc>) -> String {
    if plan.is_empty() {
        return "(no targets have a [schedule] block)".into();
    }
    let mut out = String::new();
    for e in plan {
        let delta = e.next_run - now;
        let mins = delta.num_minutes();
        let human = if mins < 0 {
            "due now".to_string()
        } else if mins < 60 {
            format!("in {mins}m")
        } else if mins < 60 * 24 {
            format!("in {}h{}m", mins / 60, mins % 60)
        } else {
            format!("in {}d{}h", mins / (60 * 24), (mins % (60 * 24)) / 60)
        };
        let tag = if e.freshly_scheduled { "new" } else { "persisted" };
        out.push_str(&format!(
            "{:20} next {} ({human}) [{tag}]\n",
            e.target,
            e.next_run.to_rfc3339(),
        ));
    }
    out
}

/// A rotation trigger — abstracted so the loop is testable without live providers.
#[async_trait::async_trait]
pub trait RotateHook: Send + Sync {
    /// Rotate the named target. Implementations decide dry-run vs. live.
    async fn fire(&self, target: &Target) -> Result<()>;
}

/// Run the scheduler loop until `max_iters` due-rotations have fired (test-bounded)
/// or, with `None`, forever. Each iteration:
///   1. find the soonest due target
///   2. sleep until it's due (real wall clock via tokio)
///   3. fire the rotation via `hook`
///   4. reschedule it (last_run = now, next_run = now + interval ± jitter)
///   5. persist state
///
/// The loop never rotates on its own — it calls `hook.fire`, which the CLI wires
/// to a dry-run by default. Returns the number of rotations fired.
pub async fn run(
    cfg: &Config,
    state_path: &Path,
    hook: &dyn RotateHook,
    max_iters: Option<usize>,
) -> Result<usize> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut state = State::load(state_path)?;

    // Seed any unscheduled targets.
    let _ = plan(cfg, &mut state, Utc::now(), &mut rng);
    state.save(state_path)?;

    let scheds: BTreeMap<&str, (&Target, &Schedule)> = cfg
        .target
        .iter()
        .filter_map(|t| t.schedule.as_ref().map(|s| (t.name.as_str(), (t, s))))
        .collect();
    if scheds.is_empty() {
        return Ok(0);
    }

    let mut fired = 0usize;
    loop {
        if let Some(m) = max_iters {
            if fired >= m {
                break;
            }
        }
        // Soonest due target among scheduled ones.
        let Some((name, next)) = state
            .next_run
            .iter()
            .filter(|(n, _)| scheds.contains_key(n.as_str()))
            .min_by_key(|(_, t)| **t)
            .map(|(n, t)| (n.clone(), *t))
        else {
            break;
        };

        let now = Utc::now();
        let wait = (next - now).to_std().unwrap_or(Duration::ZERO);
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }

        let (target, sched) = scheds[name.as_str()];
        // Fire (hook decides dry-run vs live). Errors are logged but don't abort
        // the whole loop — one failing target shouldn't stop the fleet.
        if let Err(e) = hook.fire(target).await {
            eprintln!("schedule: rotation of {name} failed: {e:#}");
        }
        fired += 1;

        // Reschedule from now.
        let fire_time = Utc::now();
        state.last_run.insert(name.clone(), fire_time);
        let next = next_run_from(fire_time, sched, &mut rng);
        state.next_run.insert(name.clone(), next);
        state.save(state_path)?;
    }
    Ok(fired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn sched(interval: &str, jitter: &str) -> Schedule {
        Schedule {
            interval: humantime::parse_duration(interval).unwrap(),
            jitter: humantime::parse_duration(jitter).unwrap(),
        }
    }

    fn cfg_with(targets: Vec<(&str, Option<Schedule>)>) -> Config {
        Config {
            target: targets
                .into_iter()
                .map(|(name, schedule)| Target {
                    name: name.into(),
                    provider: "backblaze".into(),
                    vault: "v".into(),
                    item: "i".into(),
                    field_key_id: "keyID".into(),
                    field_secret: "applicationKey".into(),
                    management_item: "m".into(),
                    mgmt_field_key_id: "keyID".into(),
                    mgmt_field_secret: "applicationKey".into(),
                    key_name_prefix: "kw".into(),
                    schedule,
                    recipe_recipient: None,
                    console_url: None,
                })
                .collect(),
        }
    }

    #[test]
    fn next_run_respects_interval_with_no_jitter() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let base = Utc::now();
        let s = sched("30d", "0s");
        let next = next_run_from(base, &s, &mut rng);
        let delta = (next - base).num_seconds();
        // 30 days, exact (no jitter).
        assert_eq!(delta, 30 * 24 * 3600);
    }

    #[test]
    fn jitter_stays_within_bounds_and_varies() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let base = Utc::now();
        let s = sched("10d", "1d"); // +/- 1 day
        let lo = 10 * 24 * 3600 - 24 * 3600;
        let hi = 10 * 24 * 3600 + 24 * 3600;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let d = (next_run_from(base, &s, &mut rng) - base).num_seconds();
            assert!(d >= lo && d <= hi, "jittered delay {d} out of [{lo},{hi}]");
            seen.insert(d);
        }
        // With random jitter we should see many distinct values, not a constant.
        assert!(seen.len() > 50, "jitter should vary, only saw {} values", seen.len());
    }

    #[test]
    fn jitter_never_schedules_in_the_past() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let base = Utc::now();
        // Jitter larger than interval: could go negative if unclamped.
        let s = sched("1h", "10h");
        for _ in 0..500 {
            let next = next_run_from(base, &s, &mut rng);
            assert!(next >= base, "next_run must never be before base");
        }
    }

    #[test]
    fn plan_skips_unscheduled_targets() {
        let cfg = cfg_with(vec![
            ("scheduled", Some(sched("7d", "1d"))),
            ("on-demand", None),
        ]);
        let mut state = State::default();
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let plan = plan(&cfg, &mut state, Utc::now(), &mut rng);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].target, "scheduled");
        assert!(plan[0].freshly_scheduled);
    }

    #[test]
    fn plan_is_sorted_by_next_run() {
        let cfg = cfg_with(vec![
            ("a", Some(sched("30d", "0s"))),
            ("b", Some(sched("1d", "0s"))),
            ("c", Some(sched("7d", "0s"))),
        ]);
        let mut state = State::default();
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let plan = plan(&cfg, &mut state, Utc::now(), &mut rng);
        let names: Vec<_> = plan.iter().map(|p| p.target.as_str()).collect();
        assert_eq!(names, vec!["b", "c", "a"]);
    }

    #[test]
    fn persisted_next_run_survives_and_is_not_rerolled() {
        let cfg = cfg_with(vec![("t", Some(sched("30d", "10d")))]);
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let now = Utc::now();

        let mut state = State::default();
        let plan1 = plan(&cfg, &mut state, now, &mut rng);
        let first = plan1[0].next_run;
        assert!(plan1[0].freshly_scheduled);

        // Re-plan with the same (now-populated) state: must reuse, not re-roll.
        let plan2 = plan(&cfg, &mut state, now, &mut rng);
        assert_eq!(plan2[0].next_run, first);
        assert!(!plan2[0].freshly_scheduled, "second plan must be persisted, not new");
    }

    #[test]
    fn state_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("schedule.json");
        let mut state = State::default();
        state.next_run.insert("t".into(), Utc::now());
        state.save(&path).unwrap();
        let loaded = State::load(&path).unwrap();
        assert_eq!(state, loaded);
    }

    #[test]
    fn load_missing_state_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let s = State::load(&path).unwrap();
        assert_eq!(s, State::default());
    }

    // A hook that just counts fires and records which targets fired — never touches
    // a real provider. This is how we test the loop without live rotations.
    struct CountingHook {
        count: Arc<AtomicUsize>,
        fired: Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl RotateHook for CountingHook {
        async fn fire(&self, target: &Target) -> Result<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.fired.lock().unwrap().push(target.name.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_loop_fires_due_target_and_reschedules() {
        // Interval far in the future, but we pre-seed state with a due next_run so
        // the loop fires immediately without waiting real wall-clock time.
        let cfg = cfg_with(vec![("t", Some(sched("30d", "0s")))]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schedule.json");

        let mut state = State::default();
        state.next_run.insert("t".into(), Utc::now() - chrono::Duration::seconds(1)); // due
        state.save(&path).unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let fired = Arc::new(std::sync::Mutex::new(Vec::new()));
        let hook = CountingHook { count: count.clone(), fired: fired.clone() };

        let n = run(&cfg, &path, &hook, Some(1)).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(&*fired.lock().unwrap(), &vec!["t".to_string()]);

        // After firing, next_run must be pushed ~30d out and last_run recorded.
        let after = State::load(&path).unwrap();
        assert!(after.last_run.contains_key("t"));
        assert!(after.next_run["t"] > Utc::now() + chrono::Duration::days(29));
    }

    #[tokio::test]
    async fn run_loop_no_scheduled_targets_is_noop() {
        let cfg = cfg_with(vec![("t", None)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schedule.json");
        let hook = CountingHook {
            count: Arc::new(AtomicUsize::new(0)),
            fired: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let n = run(&cfg, &path, &hook, None).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn run_refuses_an_unreadable_state_file_instead_of_rescheduling() {
        // A permissions error is not a first run. Treating it as an empty
        // schedule would drop the persisted next_run and could fire a rotation
        // the operator had already planned.
        use std::os::unix::fs::PermissionsExt;

        let cfg = cfg_with(vec![("t", Some(sched("30d", "0s")))]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schedule.json");
        let planned = Utc::now() + chrono::Duration::days(10);
        let mut state = State::default();
        state.next_run.insert("t".into(), planned);
        state.save(&path).unwrap();

        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&path, perms).unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let hook = CountingHook {
            count: count.clone(),
            fired: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let err = run(&cfg, &path, &hook, Some(1)).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("reading state"), "{msg}");
        assert!(!msg.contains("parsing state"), "unreadable must not be treated as JSON: {msg}");
        assert_eq!(count.load(Ordering::SeqCst), 0, "hook must not fire");

        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).unwrap();
        let loaded = State::load(&path).unwrap();
        assert_eq!(loaded.next_run.get("t"), Some(&planned));
    }
}
