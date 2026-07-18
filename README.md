# keyward

Rotate cloud provider credentials — mint a new key, verify it, store it, revoke the old — across providers, into your secret store. One command instead of a tour of every provider's website. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Why

I run a real-estate operation and I'm building my own AI/data infrastructure around it — backups, document search, automation. That meant accumulating API keys for half a dozen cloud providers, and rotating them the honest way (routinely, and immediately after any scare) was a manual slog through every provider's console. keyward is the tool I wanted: one audited code path that mints a new key at the same scope, proves it works, stores it in my password manager, and only then revokes the old one. It's also the seed of something bigger — see [PRODUCT-VISION.md](PRODUCT-VISION.md) for where this goes as an open-core product.

**Status:** in-progress, shared to show the approach. v0.2 — Backblaze B2, Cloudflare R2, and AWS IAM providers + 1Password store, safe rotation, **scheduled rotation with jitter** (`keyward schedule`), and **envelope encryption** (`age`) for zero-knowledge recreation recipes.

## Build
```sh
cargo build --release      # -> target/release/keyward (single static binary)
```

## Use
```sh
keyward --config keyward.toml list
keyward rotate b2-service --dry-run    # see what would happen, change nothing
keyward rotate b2-service              # mint → verify → store → revoke old
keyward rotate --all                   # rotate everything (incident break-glass)
keyward rotate b2-service --no-revoke  # keep the old key alive during overlap

keyward schedule --once                # compute + print the jittered schedule, rotate nothing
keyward schedule                       # run the scheduler loop (DRY-RUN by default; safe)
keyward schedule --live                # run the loop and perform real rotations when due
```

### Scheduled rotation with jitter
Add a `[schedule]` block to any target to have it rotate on an interval with
randomized jitter (so a fleet doesn't all rotate at the same predictable moment):
```toml
[target.schedule]
interval = "30d"      # humantime notation: 30d, 12h, 1week, 90min …
jitter   = "36h"      # each run fires at interval ± up-to-this, uniform random
```
`keyward schedule --once` prints the plan and persists next-run times to a small
JSON state file (`$KEYWARD_STATE`, else `<state_dir>/keyward/schedule.json`) so it
survives restarts. The scheduler loop is **dry-run by default** — it never touches
a live provider unless you pass `--live`.

### Zero-knowledge recreation recipes
Set `recipe_recipient` on a target (an `age1…` public key) and each rotation seals
a *recreation recipe* — how to re-mint an identical key (provider, console URL,
scope, a password-manager reference; **never the secret**) — encrypted so only the
holder of the matching age identity can read it. See `crypto.rs` for the threat model.

## Setup (one-time, per provider)
1. In the provider console, create a **least-privilege management credential** — permission to *create/delete keys only*, never account admin:
   - **Backblaze B2:** an Application Key with `listKeys`, `writeKeys`, `deleteKeys` capabilities.
   - **Cloudflare R2:** an API token scoped to *Account → R2 → Edit*.
   - **AWS:** an IAM principal allowed only `iam:{Create,List,Update,Delete}AccessKey` on the target user.
2. Store it in 1Password (its own item, e.g. `B2 Key Manager`).
3. Add a `[[target]]` in `keyward.toml` (see `keyward.example.toml`) pointing at the service credential to rotate and its management item.
4. `keyward rotate <name> --dry-run` to sanity-check, then for real.

Rotations preserve the old key's scope, stamp `rotated_at`, and keep the prior key in `previous_*` fields for rollback.

## License

MIT — see [LICENSE](LICENSE).
