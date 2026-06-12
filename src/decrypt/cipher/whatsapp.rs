//! WhatsApp crypt12/14 decryptor (AES-256-GCM over a zlib-compressed database).
//!
//! Defines: [`WhatsappCrypt`], the [`DbDecryptor`] for WhatsApp `.crypt12`/`.crypt14`
//! message-store backups.
//! Used by: `decrypt::cipher::decrypt` (dispatch).
//! Uses: `aes-gcm` (AES-256-GCM), `hmac`+`sha2` (the backup-key KDF), `flate2`
//! (zlib) — all on the project's single RustCrypto line.
//!
//! ── Format (what this implements) ────────────────────────────────────────────
//! A `.crypt14` file is: a variable-length header, then a 16-byte GCM **IV**, then
//! the AES-256-GCM **ciphertext** (a zlib-compressed SQLite database), ending in
//! the 16-byte GCM **tag**. The plaintext database is `inflate(zlib)` of the
//! decrypted bytes.
//!
//! Key derivation (the WhatsApp "backup encryption" KDF, an HKDF-SHA256):
//!   intermediate = HMAC-SHA256(key = 0×32, msg = key_material)
//!   aes_key      = HMAC-SHA256(key = intermediate, msg = "backup encryption" ‖ 0x01)
//! where `key_material` is the raw `key` file (crypt14) or the 32-byte backup key.
//!
//! Header offset: crypt14's header is a variable-length protobuf, so the IV/data
//! offsets are not fixed. Rather than parse the protobuf, we **try candidate IV
//! offsets** and rely on the GCM authentication tag to confirm the right one —
//! only the correct offset+key produces a verifying tag (a false accept is ~2⁻¹²⁸).
//! That GCM verification doubles as the decryptor's `verified` flag.
//!
//! ⚠ Validation status: assembled from the documented format (sourced from the
//! open-source wa-crypt-tools project) and covered by an encrypt↔decrypt round-trip
//! plus a wrong-key test, but **not** verified against a real WhatsApp backup here.
//! A known-answer test against a genuine `.crypt14` + `key` file is required before
//! relying on it. Also note: on Android the `key` file lives in the acquisition
//! filesystem (`/data/data/com.whatsapp/files/key`), not a keystore dump — wiring
//! that into the keychain model is a separate follow-up (see docs/decryption.md).

use std::io::Read;

use aes_gcm::AesGcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::generic_array::typenum::U16;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use anyhow::{Result, bail};
use flate2::read::ZlibDecoder;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::decrypt::cipher::{DbDecryptor, DecryptedDb};
use crate::decrypt::profile::{CipherSpec, KeyMaterial, WhatsappCryptParams};

/// AES-256-GCM with WhatsApp's 16-byte IV (a non-96-bit nonce, handled via GHASH).
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// GCM IV length, in bytes (WhatsApp uses 16, not the usual 12).
const IV_LEN: usize = 16;
/// GCM authentication tag length, in bytes.
const TAG_LEN: usize = 16;
/// HKDF `info` string for the WhatsApp backup-key derivation.
const KDF_INFO: &[u8] = b"backup encryption\x01";

/// Hard ceiling on the inflated output from a WhatsApp backup database.
///
/// WHY: `inflate_zlib` previously called `read_to_end` with no output bound —
/// a crafted (but GCM-authenticated) payload could expand without limit and
/// exhaust RAM.  This cap is intentionally generous: the largest known real
/// WhatsApp message database fits well within 2 GiB even for heavy users, and
/// our ZIP inflater uses a similar absolute ceiling (`zip.rs`: INFLATE_HINT_CAP
/// + 1-byte trip-wire via `.take(expected_size + 1)`).
///
/// Hitting the cap is an error, not a silent truncation — a database larger
/// than this limit would produce a corrupt SQLite file and confuse downstream
/// parsing anyway.
const INFLATE_WHATSAPP_CAP: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// The WhatsApp crypt12/14 decryptor.
pub struct WhatsappCrypt;

impl DbDecryptor for WhatsappCrypt {
    fn algorithm(&self) -> &'static str {
        "whatsapp-crypt"
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &KeyMaterial,
        spec: &CipherSpec,
    ) -> Result<DecryptedDb> {
        match spec {
            CipherSpec::WhatsappCrypt(params) => decrypt_crypt(ciphertext, key, params),
            _ => bail!("whatsapp-crypt decryptor invoked with a non-whatsapp cipher spec"),
        }
    }
}

/// Decrypt a `.crypt12`/`.crypt14` file.
fn decrypt_crypt(file: &[u8], key: &KeyMaterial, p: &WhatsappCryptParams) -> Result<DecryptedDb> {
    let key_material = match key {
        // Both forms are byte material fed to the backup-key KDF (the raw `key`
        // file for crypt14, or a 32-byte backup key).
        KeyMaterial::Raw(bytes) | KeyMaterial::Passphrase(bytes) => bytes,
    };
    let aes_key = derive_key(key_material);
    let cipher = Aes256Gcm16::new_from_slice(&aes_key).expect("32-byte AES key");

    // Try each candidate IV offset; GCM authentication tells us which is correct.
    let mut last_offset = 0usize;
    for &iv_off in &p.iv_offsets {
        // Need room for the IV plus at least an (empty-plaintext) tag.
        if iv_off + IV_LEN + TAG_LEN > file.len() {
            continue;
        }
        last_offset = iv_off;
        let nonce = GenericArray::<u8, U16>::from_slice(&file[iv_off..iv_off + IV_LEN]);
        // The ciphertext+tag is everything after the IV (GCM expects `ct‖tag`).
        let ct_and_tag = &file[iv_off + IV_LEN..];
        let Ok(decrypted) = cipher.decrypt(nonce, ct_and_tag) else {
            continue; // wrong offset (or wrong key): tag did not verify
        };

        // GCM verified: the bytes are authentic. Inflate the zlib-compressed DB.
        let plaintext = if p.zlib {
            inflate_zlib(&decrypted)?
        } else {
            decrypted
        };
        return Ok(DecryptedDb {
            plaintext,
            verified: true,
        });
    }

    bail!(
        "WhatsApp crypt: no candidate IV offset {:?} produced a verifying GCM tag \
         (wrong key, wrong offsets, or not a crypt12/14 file; last tried {last_offset})",
        p.iv_offsets
    )
}

/// The WhatsApp "backup encryption" key derivation (HKDF-SHA256 over `key_material`).
fn derive_key(key_material: &[u8]) -> [u8; 32] {
    let intermediate = hmac_sha256(&[0u8; 32], key_material);
    hmac_sha256(&intermediate, KDF_INFO)
}

/// `HMAC-SHA256(key, msg)` as a 32-byte array.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    // Qualified as `Mac`: both `hmac::Mac` and `aes_gcm`'s `KeyInit` (in scope for
    // the cipher) provide `new_from_slice`, so the call would otherwise be ambiguous.
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut array = [0u8; 32];
    array.copy_from_slice(&out);
    array
}

/// Inflate a zlib stream into the plaintext database.
///
/// The output is bounded by [`INFLATE_WHATSAPP_CAP`]: reading more than that
/// limit returns an error rather than silently truncating.  A legitimate
/// WhatsApp database is far smaller than the cap; exceeding it indicates a
/// zip-bomb or a corrupt / adversarially crafted backup.
fn inflate_zlib(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(compressed.len() * 4);
    // `.take(cap)` caps the reader at `cap` bytes, so `read_to_end` inflates at most
    // that many and returns the count `n` actually produced. WHY this bounds RAM:
    // the decoder physically cannot grow `out` past `cap`, so a zip-bomb stops there
    // instead of exhausting memory.
    let cap = INFLATE_WHATSAPP_CAP;
    let n = ZlibDecoder::new(compressed)
        .take(cap)
        .read_to_end(&mut out)
        .map_err(|e| {
            anyhow::anyhow!("GCM verified but the plaintext is not a valid zlib stream: {e}")
        })?;
    // `n == cap` means inflation was truncated AT the cap: the real database is at
    // least `cap` bytes, so we conservatively reject rather than hand back a silently
    // truncated (corrupt) SQLite file. WHY reject rather than probe for more: there is
    // no need to confirm bytes remain — a legitimate database is far below 2 GiB, so a
    // database whose inflated size lands *exactly* on the cap (an astronomically
    // unlikely 2 GiB-exact edge) is rejected too, which is acceptable.
    if n as u64 == cap {
        return Err(anyhow::anyhow!(
            "inflated WhatsApp database exceeds the {} byte safety cap; \
             refusing to decompress further (zip-bomb or corrupt backup)",
            cap
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    /// Build a crypt14-style file: `[header pad][IV(16)][AES-GCM(zlib(plaintext))‖tag]`,
    /// placing the IV at `iv_off`. Independent of production code's offset logic.
    fn encrypt_crypt(
        plaintext: &[u8],
        key_material: &[u8],
        iv_off: usize,
        iv: &[u8; 16],
    ) -> Vec<u8> {
        // zlib-compress the plaintext database.
        let mut zenc = ZlibEncoder::new(Vec::new(), Compression::default());
        zenc.write_all(plaintext).unwrap();
        let compressed = zenc.finish().unwrap();

        // AES-256-GCM encrypt with the derived key.
        let aes_key = derive_key(key_material);
        let cipher = Aes256Gcm16::new_from_slice(&aes_key).unwrap();
        let nonce = GenericArray::<u8, U16>::from_slice(iv);
        let ct_and_tag = cipher.encrypt(nonce, compressed.as_slice()).unwrap();

        // Assemble: header padding, then IV, then ciphertext+tag.
        let mut file = vec![0xABu8; iv_off];
        file.extend_from_slice(iv);
        file.extend_from_slice(&ct_and_tag);
        file
    }

    fn params() -> WhatsappCryptParams {
        WhatsappCryptParams {
            iv_offsets: vec![8, 51, 67, 191],
            zlib: true,
        }
    }

    #[test]
    fn round_trip_finds_offset_and_verifies() {
        let key_file = b"a-whatsapp-key-file-of-some-length...";
        let plaintext = b"SQLite format 3\x00 ... WHATSAPP-needle-xyz ... rest of db";
        // IV placed at offset 67 (one of the candidates).
        let blob = encrypt_crypt(plaintext, key_file, 67, &[0x22u8; 16]);

        let out = decrypt_crypt(&blob, &KeyMaterial::Raw(key_file.to_vec()), &params()).unwrap();
        assert!(out.verified);
        assert_eq!(out.plaintext, plaintext);
        assert!(
            out.plaintext
                .windows(19)
                .any(|w| w == b"WHATSAPP-needle-xyz")
        );
    }

    #[test]
    fn wrong_key_fails_to_verify() {
        let blob = encrypt_crypt(b"secret db", b"correct-key", 67, &[0x22u8; 16]);
        let err = decrypt_crypt(&blob, &KeyMaterial::Raw(b"wrong-key".to_vec()), &params());
        assert!(err.is_err()); // no offset's GCM tag verifies with the wrong key
    }

    #[test]
    fn offset_not_in_candidates_is_not_found() {
        // IV at offset 100, which is not in the candidate list → reported as failure
        // (never a silent wrong decrypt, thanks to GCM auth).
        let blob = encrypt_crypt(b"db", b"key", 100, &[0x22u8; 16]);
        assert!(decrypt_crypt(&blob, &KeyMaterial::Raw(b"key".to_vec()), &params()).is_err());
    }
}
