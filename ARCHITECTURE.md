# keyward — architecture & product vision

*A credential-rotation tool: mint a new key, verify it, store it, revoke the old — across any provider, into any secret store. Built in Rust for a single memory-safe static binary that runs on-prem, on a server, or in a scratch Docker image.*

## The problem it solves
Credentials sprawl across providers (Backblaze, Cloudflare, AWS, Dropbox, …), each with its own console and key format. Rotating them — routinely for hygiene, or *immediately* during an incident — means a manual slog through every provider's website. keyward makes it one command: `keyward rotate --all`.

## Design principles
1. **Never be without a working credential.** The rotation order guarantees this (below).
2. **Least privilege everywhere.** The tool's own power is a per-provider *management* credential scoped to key create/delete only — never account admin. New keys inherit the *old key's* scope, never broader.
3. **Two orthogonal abstractions.** `Provider` (how a service mints/revokes keys) and `SecretStore` (where credentials live). Adding a provider or a store is one new file — nothing else changes.
4. **Verify before you trust.** A freshly minted key is proven with a live read call *before* it's stored and *before* the old one dies.
5. **Auditable & reversible.** Every rotation stamps `rotated_at` and preserves the prior key in `previous_*` fields for one-step rollback.

## The safety-critical flow (`src/rotation.rs`)
```
1. read management credential   (least-privilege key manager)
2. read current service key     → discover its scope
3. mint NEW key                 (matching that scope)
4. VERIFY new key works         (live call; abort if not)
5. store NEW key                (old copied to previous_* for rollback)
6. revoke OLD key               (only now)
```
Fail before step 6 → nothing is broken. Fail *at* step 6 → the new key is already live and stored; you're left only with a stale old key to clean up. There is no ordering that leaves you credential-less.

### AWS IAM's variation: disable-then-delete (a grace window)
Most providers let step 6 *delete* the old key outright. **AWS IAM caps each user at two access keys**, so keyward cannot rely on being able to mint an overlapping third. The AWS provider therefore treats "revoke" as **deactivate, not delete**: step 6 calls `UpdateAccessKey → Status=Inactive`, keeping the old key as a disabled rollback anchor. The actual `DeleteAccessKey` happens lazily on the *next* rotation's "make room" step, which deletes the oldest **Inactive** key to free a slot before minting. It never deletes an `Active` key to make room; if a user somehow holds two Active keys it refuses rather than sever a live credential. This preserves the same one-step rollback promise while respecting the 2-key limit.

## Module map
```
src/
  main.rs            CLI (clap): list · rotate [name|--all] [--dry-run] [--no-revoke]
                                 · schedule [--once] [--live] [--state <path>]
  config.rs          TOML targets (+ optional [schedule] and recipe_recipient)
  rotation.rs        the orchestrator (the flow above); seals recreation recipe
  scheduler.rs       ✅ scheduled rotation with jitter + durable next-run state
  crypto.rs          ✅ envelope encryption (age) for metadata / recreation recipe
  model.rs           Credential, KeyInfo, RotationOutcome
  provider/
    mod.rs           trait Provider + registry
    backblaze.rs     ✅ implemented (B2 API v3)
    cloudflare.rs    ✅ implemented (R2 via Cloudflare account-tokens API; injectable transport, mock-tested)
    aws.rs           ✅ implemented (IAM access keys; SigV4-signed IAM/STS Query API; disable-then-delete grace window; injectable transport, mock-tested)
  store/
    mod.rs           trait SecretStore
    onepassword.rs   ✅ implemented (op CLI)
```

## Scheduler (`src/scheduler.rs`) — PRODUCT-VISION reqs 4 & 5
`keyward schedule` rotates each target on a per-credential **interval** with
uniform **jitter**, so a fleet's rotations don't all fire at the same predictable
instant. Config is a `[schedule]` block per target: `interval = "30d"`,
`jitter = "36h"` (humantime notation, ± in sec/min/hr/day).

- **Next-run formula:** `next = base + interval + U(-jitter, +jitter)`, clamped so
  jitter can shorten but never schedule in the past.
- **Durable state:** next-run + last-run times persist to a small JSON file
  (`$KEYWARD_STATE`, else `<state_dir>/keyward/schedule.json`). A restart resumes
  the persisted plan instead of re-rolling jitter — a restart can't dodge or
  re-randomize a due rotation. State holds **only** target names + timestamps, never secrets.
- **`--once`** computes, persists, and prints the plan, then exits — rotates nothing.
- **Safety:** the loop is a scheduler, not a rotation driver. It defers each due
  rotation to `rotation::rotate` through a `RotateHook`, and the CLI wires it to
  **dry-run by default** — no live provider is touched unless `--live` is passed.
  The loop is unit-tested with an in-memory counting hook (no live calls).

## Crypto (`src/crypto.rs`) — PRODUCT-VISION req 6 (zero-knowledge)
Envelope encryption of stored **metadata** and the **recreation recipe** (the
record of how a key was minted, so it can be re-minted) via the vetted
[`age`](https://age-encryption.org/v1) format: an ephemeral X25519 key agreement
wraps a random per-message data key that encrypts the payload under
ChaCha20-Poly1305 (AEAD → tamper-evident). Two modes:
- **X25519 recipient/identity** (asymmetric). `seal_to_recipient` encrypts to a
  public `age1…` recipient *without* the private key — the **zero-knowledge path**:
  a control plane (or the rotation flow) can seal a recipe it can never open; only
  the matching identity (held by the self-hosted worker / the user) decrypts. This
  maps directly to PRODUCT-VISION tension-A resolution #1 (self-hosted worker).
- **scrypt passphrase** (symmetric). Key derived from a user secret; no keypair to
  store, strength = the passphrase.

**Threat model** (full version in the module docs):
- *Protected:* payload confidentiality at rest + integrity/tamper-detection
  (decryption fails **closed** on any bit-flip; never returns wrong-but-plausible
  plaintext). A stolen store / backup / compromised control plane sees only opaque
  ciphertext.
- *Not protected:* the private identity is the crown jewel (whoever holds it can
  decrypt — where it lives is the deployment choice above); metadata left *outside*
  the envelope (sizes, row counts, existence); and a decryptor that is compromised
  *while running*. Envelope-at-rest defends the store, not a live-owned worker.
- *A compromised store reveals:* nothing beyond ciphertext length and whatever the
  caller deliberately left in cleartext (the non-secret `label`).

The rotation flow uses this today: when a target sets `recipe_recipient` (an
`age1…` public key), a successful rotation seals a `RecreationRecipe` — provider,
console URL, capabilities, resource restrictions, a password-manager *reference*
(never the secret) — into a `RotationOutcome::sealed_recipe` envelope.

## Extending it
- **New provider:** implement `Provider` (list / create / verify / revoke), add one match arm in `provider::get`. ~120 lines like `backblaze.rs`.
- **New store:** implement `SecretStore` (read / write). Vault, Infisical, AWS Secrets Manager, env, or a KMS-encrypted file are all just this trait.

## Security model & known edges
- **Management credentials are the crown jewels.** You trade many scattered keys for a few tightly-scoped, heavily-guarded ones (MFA on the account, stored in 1Password/Vault). This is a strict improvement, but must be done deliberately.
- **v0.1 caveat:** the `op` CLI takes field values as process args (briefly visible in `ps`). Fine on a single-operator workstation; the hosted/daemon build must move to the 1Password SDK / Connect (socket transport) or Vault.
- **No secrets in logs.** Outcomes print key *ids*, never secrets.

## Roadmap → product
- **v0.1:** single-operator CLI · 1Password store · B2 provider · safe rotation · dry-run.
- **v0.2 (now):** ✅ provider set complete — Cloudflare R2 + AWS IAM providers landed (AWS: disable-then-delete with a grace window, respecting the 2-key limit; both mock-tested via an injectable HTTP transport) · ✅ scheduled rotation with jitter + durable state (`keyward schedule`) · ✅ envelope-encryption crypto module (`age`) for zero-knowledge metadata / recreation recipes.
- **v0.3:** daemon + audit log (append-only, hash-chained) · notifications on rotate (Slack/email) · `rotate --all` **break-glass** mode for incident response.
- **v1.0 (the product):** a "Supabase for secret rotation" — open-source core, hosted SaaS on top.
  - **Store plugins:** 1Password, Vault, Infisical, AWS/GCP/Azure secret managers, env.
  - **Provider plugins:** B2, R2, AWS, GCP, Azure, Dropbox, GitHub, Stripe, database creds, TLS certs.
  - **Consumer hooks:** after rotation, push the new key to the things that use it (CI secrets, k8s secrets, redeploys) via webhooks — closing the loop that makes rotation *actually* painless.
  - **Policy engine:** rotate every N days · on-intrusion rotate-all · approvals · break-glass.
  - **Compliance:** immutable audit trail + SOC2/PCI-friendly rotation reports (auditors love provable rotation).
  - **RBAC + SSO** for teams.

## Why this can be a business
- The **provider integration library** is the hard, defensible part — each provider's key API is fiddly and undocumented in the corners. Owning a correct, well-tested set of them is the moat.
- **Self-hostable** is non-negotiable for a *security* tool — teams won't hand their rotation keys to an opaque SaaS. Open-source core earns trust; hosted tier sells convenience (managed, audit, alerting, support) and enterprise (SSO, on-prem support) — exactly the Supabase / GitLab / HashiCorp open-core model.
- **Timing:** short-lived/dynamic credentials are the industry direction; a tool that both rotates static keys *and* bridges toward dynamic ones (Vault-style) rides that trend.
