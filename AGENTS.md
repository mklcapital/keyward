# AGENTS.md

## Cursor Cloud specific instructions

`keyward` is a Rust CLI that rotates cloud-provider credentials into a secret
store. Standard build/run commands are in `README.md`; test with `cargo test`.

Non-obvious notes for this environment:

- **Rust toolchain must be ≥ 1.85.** A transitive dependency requires the
  `edition2024` cargo feature, so the stock 1.83 toolchain fails to build. The
  environment's default toolchain is set to `stable` (currently 1.9x) via
  `rustup default stable`; keep it there.
- **`cargo build` / `cargo test` need no external services.** All 45 unit tests
  (`crypto`, `scheduler`, `provider::{aws,cloudflare}`) run offline.
- **`keyward rotate` cannot run end-to-end here.** It shells out to the
  1Password CLI (`op`) and talks to live provider APIs; without an installed +
  unlocked `op` and real credentials it fails at "reading management credential
  from store". To verify the app without live secrets, use `keyward list` and
  `keyward schedule --once` (both read only the TOML config) plus `cargo test`.
- `keyward.toml` is gitignored; copy `keyward.example.toml` to `keyward.toml`
  for local runs.

### Project direction (per maintainer)

- **These are Linux server apps and must be Rust only.** `keyward` is already the
  reference Rust implementation; keep new functionality in Rust. The Python
  sibling repos (`ltm-mcp`, `mission-control`) are prototypes to be reimplemented
  in Rust.
- **Swift is only for genuinely native Apple client apps** (macOS / iPhone /
  iPad / Apple Silicon viewers) that talk to these servers — never for the
  servers themselves. All heavy lifting, including GUI, stays server-side and is
  exposed over web tech (and optional Apple-native viewers/browsers).
- **Prefer latest stable tooling** (e.g. current Rust stable, latest stable
  PostgreSQL where a datastore is involved) — no pinning to stale majors without
  a concrete reason.
