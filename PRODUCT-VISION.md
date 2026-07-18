# keyward — product vision (v1 requirements)

Captured 2026-07-06 from Marc's direction. This is the *product*, beyond the v0.1 CLI. Honest engineering notes included, because two of these requirements are in genuine tension and pretending otherwise would bite us later.

## Requirements (as stated)
1. **Pluggable secret stores** from day one — 1Password, Bitwarden, Vault, Infisical, cloud secret managers, *and* keyward's own encrypted DB. **Interface with the user's existing password manager; don't try to replace 30 years of 1Password.** (Already designed: the `SecretStore` trait — this is exactly it.)
2. **Web interface** to manually input **admin tokens**, then keyward goes to each SaaS and mints **scoped** keys — with heavy in-product **documentation and hand-holding** on how to choose scope.
3. **Admin keys are allowed, not just scoped** — because for many providers, *admin is required to mint the lesser-privileged keys*. keyward uses admin to create least-privilege children (and can then avoid keeping admin online).
4. **Scheduled auto-rotation** with **customizable randomized jitter** (± in sec/min/hr/day notation) so rotations don't all fire predictably.
5. **Rotate by schedule OR by TTL** — same code path either way.
6. **Zero-knowledge, quantum-safe storage** — even Marc as the SaaS operator cannot read or recover anyone's keys.
7. **Consumer awareness** — software relying on a key must be **securely notified** when its key changes or dies, and be able to fetch the new one. New key doesn't instantly displace old (overlap window). **Panic button** = rotate all.
8. **Rich metadata beside every key** — not just key/secret, but endpoint(s), scope/capabilities, resource restrictions (buckets/paths), TTL, notes, per-field "obscured" flags, and the **recreation recipe** (how to re-mint an identical key). Providers name things inconsistently (secret / password / token / key) — normalize but preserve.
9. **Metadata harvesting** — pull the extra info from providers automatically: from one-time-view pages, expiring pages, and whatever API/transmission formats each uses.
10. **Interfaces**: built-in **MCP server**, a well-designed **REST API**, optional **SDKs**. Orgs pull/create/rotate keys programmatically.
11. **Auth for the web UI**: password, +MFA/2FA, SSO (SAML/OIDC), FIDO2/WebAuthn, passkeys, biometrics, social logins (Google/Apple/etc.). **Enterprise identity cooperation: Okta, SCIM provisioning, directory sync.**
12. **Secure database** backing it all.

## The two hard tensions (be honest)

### A. "We can't read your keys" **and** "automatic scheduled rotation" pull against each other.
Pure zero-knowledge means only the user's client can decrypt the vault. But scheduled rotation needs *something* to wake up while the user is offline, decrypt the management credential, call the provider, and re-encrypt. That something can decrypt — which is the opposite of zero-knowledge. Three ways to resolve, pick per-credential:
1. **Self-hosted rotation worker (recommended default).** The SaaS is *control-plane only* — scheduling, UI, audit, notifications. The actual rotation runs on a worker the customer controls (their server / a Docker container / a home box / a small always-on agent) that holds the decrypt capability. The SaaS never sees plaintext. **This is how you truthfully say "even we can't read your keys," and it maps perfectly to the open-core model: the worker IS open-source keyward; the SaaS is the managed control plane.**
2. **Enrolled envelope encryption + HSM/KMS custody.** Only creds explicitly enrolled for hands-off cloud rotation are wrapped so a hardened rotation service (HSM-held keys, per-op audit) can unwrap *just those*. This is a **consented, documented** reduction of zero-knowledge for the enrolled subset — market it truthfully, not as "we can never read them."
3. **Client/edge scheduling.** Rotation fires only when the user's agent is online. Strongest privacy; "automatic while offline" becomes best-effort.
**Plan:** default to (1); offer (2) as explicit, clearly-disclosed opt-in.

### B. "Quantum-safe" — what's actually real (don't invent crypto).
- **At rest (the vault):** AES-256-GCM or XChaCha20-Poly1305, keyed from the user secret via **Argon2id**. 256-bit symmetric is already quantum-resistant (Grover only halves it → ~128-bit). No exotic primitives needed to call storage quantum-safe.
- **Public-key steps** (device enrollment, sharing, key exchange) are where quantum bites → use **NIST PQC hybrid**: ML-KEM (Kyber) for KEM + ML-DSA (Dilithium) for signatures, run *alongside* classical so you're safe if either breaks. TLS 1.3 hybrid PQC is available today.
- **Rule:** compose vetted symmetric + hybrid-PQC transport; **get a third-party crypto audit before anyone trusts it with real keys.** For a security product this is table stakes, not optional.

## Data model (the metadata problem most tools get wrong)
A credential is a typed record, not a pair:
`provider · key_id · secret(obscured) · endpoints · region · scope/capabilities · resource_restrictions · ttl · created/rotated_at · recreation_recipe · notes · per_field_obscure_flags`.
The **recreation recipe** is the differentiator: enough to re-mint an identical key (console URL, login reference in the user's password manager, exact scope, capabilities, resource limits) so a forgotten dead key isn't an archaeology project. Harvest it at creation time.

## Consumer-awareness mechanisms
- **Reference, not value:** consumers fetch the *current* key by a stable reference at use-time (SDK/agent), so rotation is transparent.
- **Signed rotation events:** webhooks / pub-sub notify subscribed services ("key X rotated → fetch new") with a signed payload; the SDK surfaces both "your key stopped working" *and* the reason + replacement.
- **Overlap window:** new key verified + live before old is revoked (already the v0.1 invariant).

## How this extends the v0.1 code
- `SecretStore` trait → add Bitwarden, Vault, Infisical, cloud managers, and a native encrypted-DB store.
- `Provider` trait → the metadata-harvesting + recreation-recipe fields hang off `create_key`/`list_keys`.
- New crates: control-plane API (axum), MCP server, scheduler (with jitter), notifier, and the crypto/vault module (audited).
- The CLI + self-hosted worker stay the open-source core; the web UI + control plane become the SaaS.
