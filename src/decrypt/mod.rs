//! Encrypted-database decryption: keychain secrets → profile → cipher → plaintext.
//!
//! Defines: the decryption module surface and its three decoupled layers, plus a
//! shim (added in a later milestone) that the search engine calls to turn an
//! encrypted entry's bytes into plaintext before searching/inspecting them.
//! Used by: `engine` (the content shim) and `run` (builds the context from a
//! keychain dump + the profile registry).
//! Uses: the three submodules below.
//!
//! ── The three layers ────────────────────────────────────────────────────────
//!   1. [`keyfile`] — secret-store *providers* for the `--keyfile` dump(s). Each
//!      loader normalises one dump format (iLEAPP, Cellebrite, Android Keystore, …)
//!      into a [`SecretStore`] of [`Secret`]s. Adding a source is one [`KeyfileProvider`].
//!   2. [`profile`] — the external [`ProfileRegistry`]: per-app YAML describing
//!      which database to decrypt, how to locate its key in the store, and the
//!      cipher parameters. Adding a target is adding one YAML file.
//!   3. [`cipher`] — the [`DbDecryptor`]s. One per scheme (SQLCipher first); the
//!      engine dispatches via [`cipher::decrypt`].
//!
//! The design is scheme-agnostic on purpose: the profile is data, the key source
//! is a provider, the cipher is a trait. iOS (keychain + SQLCipher) is the first
//! concrete path; Android (Keystore + app ciphers like WhatsApp crypt14/15) drops
//! in by adding a provider and a decryptor, without touching this surface.
//!
//! Scope reminder: this only works on acquisitions whose keychain/keystore has
//! *already been decrypted* by the acquisition tool. A raw on-device `keychain-2.db`
//! cannot be decrypted offline — its keys are wrapped by the Secure Enclave/UID key.

pub mod cipher;
pub mod context;
pub mod keyfile;
pub mod profile;

pub use cipher::{DbDecryptor, DecryptedDb};
pub use context::{DecryptionContext, DecryptionOutcome, DecryptionRecord, TryOutcome};
pub use keyfile::{KeyfileProvider, Secret, SecretStore, load_dump, load_if_dump};
pub use profile::{CipherSpec, KeyEncoding, KeyMaterial, Platform, Profile, ProfileRegistry};
