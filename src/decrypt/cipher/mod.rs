//! Database decryptors: turn ciphertext + key material into plaintext bytes.
//!
//! Defines: [`DecryptedDb`] (the decryption result, with a `verified` flag), the
//! [`DbDecryptor`] trait (one implementor per scheme), and [`decrypt`] (the
//! dispatch that routes a profile's [`CipherSpec`] to its decryptor).
//! Used by: the engine shim (M4), which decrypts a matched entry's bytes before
//! handing the plaintext to the search/inspect pipeline.
//! Uses: `crate::decrypt::profile::{CipherSpec, KeyMaterial}` and `anyhow`.
//!
//! One implementor per scheme — SQLCipher and WhatsApp crypt12/14 so far. Adding a
//! scheme is adding a `DbDecryptor` and one [`decrypt`] dispatch arm.

pub(crate) mod sqlcipher;
mod whatsapp;

use anyhow::Result;

pub use sqlcipher::SqlCipher;
pub use whatsapp::WhatsappCrypt;

use crate::decrypt::profile::{CipherSpec, KeyMaterial};

/// The outcome of decrypting a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedDb {
    /// The decrypted file bytes (a plaintext SQLite image for SQLCipher).
    pub plaintext: Vec<u8>,
    /// Whether the cipher could *cryptographically confirm* the key was correct
    /// (e.g. SQLCipher's page-1 HMAC verified). `false` means "decrypted, but the
    /// key could not be authenticated" — the caller decides whether to trust it.
    pub verified: bool,
}

/// A cipher that decrypts an encrypted database in memory.
///
/// One implementor per scheme (SQLCipher, WhatsApp crypt14/15, …). The engine
/// never names a concrete decryptor; it calls [`decrypt`], which dispatches on the
/// profile's [`CipherSpec`].
pub trait DbDecryptor: Sync {
    /// The `algorithm` tag this decryptor handles (e.g. `"sqlcipher"`).
    fn algorithm(&self) -> &'static str;
    /// Decrypt `ciphertext` with `key` under `spec`.
    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &KeyMaterial,
        spec: &CipherSpec,
    ) -> Result<DecryptedDb>;
}

/// Decrypt `ciphertext` using the decryptor selected by `spec`.
///
/// Central dispatch point: a profile names its scheme in `spec`, and this routes
/// to the matching [`DbDecryptor`]. A failed decryption (e.g. an unverifiable key)
/// is an error, never a silent pass-through of the ciphertext.
pub fn decrypt(ciphertext: &[u8], key: &KeyMaterial, spec: &CipherSpec) -> Result<DecryptedDb> {
    match spec {
        CipherSpec::Sqlcipher(_) => SqlCipher.decrypt(ciphertext, key, spec),
        CipherSpec::WhatsappCrypt(_) => WhatsappCrypt.decrypt(ciphertext, key, spec),
    }
}
