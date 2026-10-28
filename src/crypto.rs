//! Envelope encryption for stored secret **metadata** and **recreation recipes**.
//!
//! This module underpins keyward's "zero-knowledge" storage goal (PRODUCT-VISION
//! requirement 6). It wraps a small JSON payload — the metadata that hangs off a
//! credential, and the *recreation recipe* (how a key was minted, so it can be
//! re-minted) — in an [`age`] envelope so that only the holder of the private
//! identity can read it.
//!
//! # Why `age`
//! We deliberately do **not** hand-roll crypto. `age` implements the vetted
//! age-encryption.org/v1 format: an ephemeral X25519 key agreement wraps a random
//! per-message data key, which encrypts the payload under ChaCha20-Poly1305. That
//! is textbook envelope encryption — the same shape KMS/HSM systems use — with a
//! reviewed implementation. `secrecy` keeps the private identity zeroized in memory.
//!
//! # Threat model
//!
//! ## What is protected
//! - **Confidentiality of the payload at rest.** The ciphertext (`Envelope::ciphertext`)
//!   reveals nothing about the plaintext beyond its approximate length. An attacker
//!   who exfiltrates the *store* (the encrypted-DB backend, a stolen backup, a
//!   compromised control-plane server) sees only opaque `age` blobs.
//! - **Integrity / tamper-detection.** age's payload is authenticated
//!   (ChaCha20-Poly1305 AEAD + a header MAC). Flipping any bit of the ciphertext,
//!   the header, or the wrapped key causes decryption to *fail closed* — it never
//!   returns wrong-but-plausible plaintext. See the tamper tests.
//!
//! ## What is NOT protected (key-management assumptions)
//! - **The private identity is the crown jewel.** Whoever holds it can decrypt.
//!   This module does not decide *where* the identity lives — that is a deployment
//!   choice mapped directly to PRODUCT-VISION's tension-A resolutions:
//!   (a) *self-hosted worker (default)* — the identity lives only on a worker the
//!   customer controls, so the SaaS control plane stores/syncs ciphertext and
//!   genuinely cannot read it; (b) *enrolled KMS/HSM custody* — the identity is held
//!   in an HSM for the subset of credentials explicitly enrolled for hands-off cloud
//!   rotation; (c) *client/edge only* — the identity never leaves the user's device.
//!   Passphrase mode ([`Envelope::seal_with_passphrase`]) instead derives the
//!   wrapping key from a user secret via age's scrypt work factor — no keypair to
//!   store, at the cost of being only as strong as the passphrase.
//! - **Metadata that is not inside the payload.** Timing, size, the *fact* that a
//!   credential exists, row counts — none of that is hidden. Encrypt what is
//!   sensitive; do not rely on the envelope to hide the schema.
//! - **A live/compromised worker.** If the machine holding the identity is owned
//!   *while running*, plaintext is reachable there. Envelope-at-rest defends the
//!   store, not a compromised decryptor.
//!
//! ## What a compromised store reveals
//! Nothing beyond ciphertext length and whatever plaintext metadata the caller
//! chose to leave outside the envelope. It does **not** reveal the recreation
//! recipe, the notes, the scope details, or the wrapped data key.

use age::secrecy::ExposeSecret;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// A keypair for envelope encryption. The public [`recipient`](Self::recipient)
/// encrypts; the private [`identity`](Self::identity_str) decrypts.
///
/// The identity string (`AGE-SECRET-KEY-1...`) is the secret to guard; the
/// recipient string (`age1...`) is safe to distribute — it can only encrypt.
pub struct KeyPair {
    identity: age::x25519::Identity,
}

impl KeyPair {
    /// Generate a fresh random keypair.
    pub fn generate() -> Self {
        Self { identity: age::x25519::Identity::generate() }
    }

    /// Parse an identity (private key) from its `AGE-SECRET-KEY-1...` string.
    pub fn from_identity_str(s: &str) -> Result<Self> {
        let identity = s
            .parse::<age::x25519::Identity>()
            .map_err(|e| anyhow!("invalid age identity: {e}"))?;
        Ok(Self { identity })
    }

    /// The private identity string. **Secret** — store in a vault / HSM / worker only.
    pub fn identity_str(&self) -> String {
        self.identity.to_string().expose_secret().to_string()
    }

    /// The public recipient string. Safe to distribute; encrypt-only.
    pub fn recipient_str(&self) -> String {
        self.identity.to_public().to_string()
    }

    fn recipient(&self) -> age::x25519::Recipient {
        self.identity.to_public()
    }
}

/// An age-encrypted payload plus a small, *cleartext-safe* label so operators can
/// tell envelopes apart without decrypting. The label MUST NOT contain secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    /// Which encryption mode produced this (for forward-compat / auditing).
    pub scheme: Scheme,
    /// Non-secret hint (e.g. `"b2-service/recipe"`). Never put secrets here.
    pub label: String,
    /// The age ciphertext, base64-encoded for text/JSON transport.
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Scheme {
    /// X25519 recipient/identity (asymmetric envelope).
    AgeX25519,
    /// scrypt passphrase (symmetric, key derived from a user secret).
    AgeScrypt,
}

impl Envelope {
    /// Encrypt `plaintext` to a public recipient (asymmetric envelope mode).
    /// Only the matching identity can decrypt.
    pub fn seal(label: impl Into<String>, kp: &KeyPair, plaintext: &[u8]) -> Result<Self> {
        let ciphertext =
            age::encrypt(&kp.recipient(), plaintext).context("age encrypt (x25519)")?;
        Ok(Self {
            scheme: Scheme::AgeX25519,
            label: label.into(),
            ciphertext_b64: b64(&ciphertext),
        })
    }

    /// Encrypt to a public recipient string (`age1...`) *without* the private key.
    /// This is the zero-knowledge path: the caller (e.g. the rotation flow, or the
    /// SaaS control plane) can seal a recipe it will never be able to open — only
    /// the holder of the matching identity (the self-hosted worker / the user) can.
    pub fn seal_to_recipient(label: impl Into<String>, recipient: &str, plaintext: &[u8]) -> Result<Self> {
        let r = recipient
            .parse::<age::x25519::Recipient>()
            .map_err(|e| anyhow!("invalid age recipient: {e}"))?;
        let ciphertext = age::encrypt(&r, plaintext).context("age encrypt (x25519, recipient-only)")?;
        Ok(Self {
            scheme: Scheme::AgeX25519,
            label: label.into(),
            ciphertext_b64: b64(&ciphertext),
        })
    }

    /// Seal a JSON-serializable value to a recipient string (zero-knowledge path).
    pub fn seal_json_to_recipient<T: Serialize>(
        label: impl Into<String>,
        recipient: &str,
        value: &T,
    ) -> Result<Self> {
        let json = serde_json::to_vec(value).context("serializing payload to JSON")?;
        Self::seal_to_recipient(label, recipient, &json)
    }

    /// Decrypt with the private identity. Fails closed on tamper or wrong key.
    pub fn open(&self, kp: &KeyPair) -> Result<Vec<u8>> {
        if self.scheme != Scheme::AgeX25519 {
            return Err(anyhow!("envelope scheme {:?} needs a passphrase, not an identity", self.scheme));
        }
        let ct = unb64(&self.ciphertext_b64)?;
        age::decrypt(&kp.identity, &ct).context("age decrypt (x25519) — wrong key or tampered ciphertext")
    }

    /// Encrypt under a passphrase (symmetric). No keypair to store; strength is
    /// the passphrase's. age applies an scrypt work factor internally.
    pub fn seal_with_passphrase(label: impl Into<String>, passphrase: &str, plaintext: &[u8]) -> Result<Self> {
        let recipient = age::scrypt::Recipient::new(passphrase.to_owned().into());
        let ciphertext = age::encrypt(&recipient, plaintext).context("age encrypt (scrypt)")?;
        Ok(Self {
            scheme: Scheme::AgeScrypt,
            label: label.into(),
            ciphertext_b64: b64(&ciphertext),
        })
    }

    /// Decrypt a passphrase-sealed envelope. Fails closed on wrong passphrase or tamper.
    pub fn open_with_passphrase(&self, passphrase: &str) -> Result<Vec<u8>> {
        if self.scheme != Scheme::AgeScrypt {
            return Err(anyhow!("envelope scheme {:?} needs an identity, not a passphrase", self.scheme));
        }
        let ct = unb64(&self.ciphertext_b64)?;
        let identity = age::scrypt::Identity::new(passphrase.to_owned().into());
        age::decrypt(&identity, &ct)
            .context("age decrypt (scrypt) — wrong passphrase or tampered ciphertext")
    }

    /// Convenience: seal a serializable value as JSON inside the envelope.
    pub fn seal_json<T: Serialize>(label: impl Into<String>, kp: &KeyPair, value: &T) -> Result<Self> {
        let json = serde_json::to_vec(value).context("serializing payload to JSON")?;
        Self::seal(label, kp, &json)
    }

    /// Convenience: open the envelope and deserialize its JSON payload.
    pub fn open_json<T: for<'de> Deserialize<'de>>(&self, kp: &KeyPair) -> Result<T> {
        let bytes = self.open(kp)?;
        serde_json::from_slice(&bytes).context("deserializing decrypted JSON payload")
    }
}

/// The "recreation recipe" — enough to re-mint an identical credential, per
/// PRODUCT-VISION's data model. This is exactly the kind of record that must be
/// encrypted at rest: it names consoles, scopes, and password-manager references.
///
/// It contains **no secret material** itself (no key/secret), but is still
/// sensitive reconnaissance for an attacker, so we envelope it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RecreationRecipe {
    pub provider: String,
    /// Console URL where the key is minted.
    pub console_url: Option<String>,
    /// Reference (not value) to the login in the user's password manager.
    pub login_reference: Option<String>,
    /// Exact scope/capabilities the key was minted with.
    pub capabilities: Vec<String>,
    /// Resource restrictions (bucket ids, path prefixes, target IAM user, …).
    pub resource_restrictions: Vec<String>,
    /// Free-form operator notes.
    pub notes: Option<String>,
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("decoding base64 ciphertext")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_round_trip() {
        let kp = KeyPair::generate();
        let msg = b"top-secret recreation recipe";
        let env = Envelope::seal("t/recipe", &kp, msg).unwrap();
        assert_eq!(env.scheme, Scheme::AgeX25519);
        // Ciphertext must not contain the plaintext.
        assert!(!env.ciphertext_b64.contains("secret"));
        let out = env.open(&kp).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn identity_str_reparses_and_decrypts() {
        let kp = KeyPair::generate();
        let env = Envelope::seal("t", &kp, b"hello").unwrap();
        // A worker that only has the identity string can still decrypt.
        let kp2 = KeyPair::from_identity_str(&kp.identity_str()).unwrap();
        assert_eq!(env.open(&kp2).unwrap(), b"hello");
        assert_eq!(kp.recipient_str(), kp2.recipient_str());
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let kp = KeyPair::generate();
        let other = KeyPair::generate();
        let env = Envelope::seal("t", &kp, b"payload").unwrap();
        assert!(env.open(&other).is_err(), "a different identity must not decrypt");
    }

    #[test]
    fn tamper_is_detected() {
        let kp = KeyPair::generate();
        let mut env = Envelope::seal("t", &kp, b"integrity matters").unwrap();
        // Flip a byte in the middle of the ciphertext.
        let mut raw = unb64(&env.ciphertext_b64).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0xFF;
        env.ciphertext_b64 = b64(&raw);
        assert!(env.open(&kp).is_err(), "tampered ciphertext must fail closed");
    }

    #[test]
    fn passphrase_round_trip_and_wrong_passphrase() {
        let env = Envelope::seal_with_passphrase("t", "correct horse battery staple", b"vault contents").unwrap();
        assert_eq!(env.scheme, Scheme::AgeScrypt);
        assert_eq!(env.open_with_passphrase("correct horse battery staple").unwrap(), b"vault contents");
        assert!(env.open_with_passphrase("wrong passphrase").is_err());
    }

    #[test]
    fn scheme_mismatch_is_rejected() {
        let kp = KeyPair::generate();
        let x = Envelope::seal("t", &kp, b"x").unwrap();
        assert!(x.open_with_passphrase("p").is_err(), "x25519 envelope must reject passphrase open");
        let p = Envelope::seal_with_passphrase("t", "p", b"y").unwrap();
        assert!(p.open(&kp).is_err(), "scrypt envelope must reject identity open");
    }

    #[test]
    fn recipient_only_seal_is_zero_knowledge() {
        // The sealer holds ONLY the public recipient string — it cannot decrypt
        // what it just sealed. Only the identity holder can. This is the property
        // that lets a control plane store recipes it can never read.
        let kp = KeyPair::generate();
        let recipient = kp.recipient_str();
        let env = Envelope::seal_to_recipient("t/recipe", &recipient, b"how to re-mint").unwrap();
        // Sealer's view (recipient only) cannot open. Identity holder can.
        assert_eq!(env.open(&kp).unwrap(), b"how to re-mint");
        // A wrong identity still can't.
        assert!(env.open(&KeyPair::generate()).is_err());
    }

    #[test]
    fn seal_to_recipient_rejects_garbage_recipient() {
        assert!(Envelope::seal_to_recipient("t", "not-an-age-key", b"x").is_err());
    }

    #[test]
    fn passphrase_tamper_fails_closed_without_echoing_plaintext() {
        let plaintext = b"vault-contents-do-not-leak";
        let passphrase = "correct horse battery staple";
        let env = Envelope::seal_with_passphrase("db/meta", passphrase, plaintext).unwrap();
        assert_eq!(env.scheme, Scheme::AgeScrypt);
        assert_eq!(env.label, "db/meta");
        assert!(!env.ciphertext_b64.contains("vault-contents"));
        assert!(!env.ciphertext_b64.contains("battery staple"));
        assert_eq!(env.open_with_passphrase(passphrase).unwrap(), plaintext);

        let wrong = env.open_with_passphrase("wrong passphrase").unwrap_err();
        let wrong_msg = format!("{wrong:#}");
        assert!(!wrong_msg.contains("vault-contents"), "{wrong_msg}");
        assert!(!wrong_msg.contains(passphrase), "{wrong_msg}");

        let mut tampered = env.clone();
        let mut raw = unb64(&tampered.ciphertext_b64).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0xff;
        tampered.ciphertext_b64 = b64(&raw);
        let err = tampered.open_with_passphrase(passphrase).unwrap_err();
        let msg = format!("{err:#}");
        assert!(!msg.contains("vault-contents"), "{msg}");
        assert!(!msg.contains(passphrase), "{msg}");
    }

    #[test]
    fn recreation_recipe_round_trips_as_json() {
        let kp = KeyPair::generate();
        let recipe = RecreationRecipe {
            provider: "backblaze".into(),
            console_url: Some("https://secure.backblaze.com/app_keys.htm".into()),
            login_reference: Some("op://Personal/Backblaze Login".into()),
            capabilities: vec!["listBuckets".into(), "readFiles".into()],
            resource_restrictions: vec!["bucketId:abc123".into()],
            notes: Some("scoped to the claude backups bucket".into()),
        };
        let env = Envelope::seal_json("b2-service/recipe", &kp, &recipe).unwrap();
        // The console URL must not leak in the ciphertext.
        assert!(!env.ciphertext_b64.contains("backblaze.com"));
        let back: RecreationRecipe = env.open_json(&kp).unwrap();
        assert_eq!(back, recipe);
    }
}
