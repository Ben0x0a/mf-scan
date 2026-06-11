//! SQLCipher page decryptor (AES-256-CBC + per-page HMAC, PBKDF2 key derivation).
//!
//! Defines: [`SqlCipher`], the [`DbDecryptor`] implementation for SQLCipher
//! databases, plus the key-derivation / page helpers it uses.
//! Used by: `decrypt::cipher::decrypt` (dispatch) — and, in M4, the engine shim.
//! Uses: RustCrypto crates `aes`/`cbc` (AES-256-CBC), `hmac` + `sha1`/`sha2`
//! (page authentication), `pbkdf2` (key derivation) — all pure-Rust, on the same
//! `digest 0.11` line as the rest of the project.
//!
//! ── SQLCipher on-disk format (what this implements) ──────────────────────────
//! A SQLCipher database is a sequence of fixed-size pages (`page_size`, default
//! 4096). The first 16 bytes of the file are a random **salt**. Each page ends in
//! a `reserve` area holding the page's random **IV** (16 bytes) and its **HMAC**;
//! `reserve = roundup16(IV + hmac_len)` (48/48/80 for SHA1/256/512). The cipher
//! text occupies the page up to that reserve; on page 1 it starts *after* the
//! 16-byte salt (whose slot holds the SQLite "SQLite format 3\0" header in a
//! plaintext database).
//!
//! Key derivation (parameterised by the profile):
//!   • passphrase → `key = PBKDF2-HMAC-<kdf>(passphrase, salt, kdf_iter, 32)`.
//!   • raw key → used directly (32 bytes); a 48-byte raw key is `key(32)||salt(16)`
//!     and its embedded salt overrides the file salt (the Signal keyspec form).
//!   • `hmac_key = PBKDF2-HMAC-<kdf>(key, salt⊕0x3a, 2, 32)`.
//!
//! Per page: the HMAC is computed over `page[0 .. cipher+IV] || pgno_le32` and
//! compared to the stored HMAC; the cipher region is then AES-256-CBC decrypted
//! with the page IV. Page 1's output is prefixed with the fixed SQLite header.
//!
//! ⚠ Validation status: this is assembled from the documented algorithm and is
//! covered by an encrypt↔decrypt round-trip plus tamper/wrong-key tests, but it
//! has **not** yet been checked against a database produced by the real
//! `sqlcipher` tool (none is available in this environment). A known-answer test
//! against a real DB is required before relying on it forensically — see the test
//! module for the exact `sqlcipher` commands to generate the fixture. The page
//! number is HMAC'd little-endian (the de-facto SQLCipher convention); a real
//! fixture would confirm that.

use aes::Aes256;
use anyhow::{Result, bail, ensure};
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::decrypt::cipher::{DbDecryptor, DecryptedDb};
use crate::decrypt::profile::{CipherSpec, HashAlgorithm, KeyMaterial, SqlCipherParams};

/// AES-256 key length, in bytes.
const KEY_SZ: usize = 32;
/// AES block / CBC IV size, in bytes.
const IV_SZ: usize = 16;
/// AES block size, in bytes (regions must be a multiple of this).
const BLOCK_SZ: usize = 16;
/// SQLCipher salt size at the head of the database, in bytes.
const SALT_SZ: usize = 16;
/// XOR mask applied to the salt to derive the HMAC-key salt (SQLCipher constant).
const HMAC_SALT_MASK: u8 = 0x3a;
/// PBKDF2 iteration count for the (fast) HMAC-key derivation (SQLCipher constant).
const FAST_KDF_ITER: u32 = 2;
/// The 16-byte header every plaintext SQLite database starts with.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\x00";

/// The SQLCipher decryptor.
pub struct SqlCipher;

impl DbDecryptor for SqlCipher {
    fn algorithm(&self) -> &'static str {
        "sqlcipher"
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &KeyMaterial,
        spec: &CipherSpec,
    ) -> Result<DecryptedDb> {
        match spec {
            CipherSpec::Sqlcipher(params) => decrypt_db(ciphertext, key, params),
            _ => bail!("sqlcipher decryptor invoked with a non-sqlcipher cipher spec"),
        }
    }
}

/// Decrypt a whole SQLCipher database image.
///
/// Returns the plaintext page image and whether every page's HMAC verified.
/// A page-1 HMAC mismatch is treated as a *wrong key* and returned as an error so
/// a caller trying several candidate keys can move on; a mismatch on a later page
/// is treated as corruption (the key was right) and only lowers `verified`.
fn decrypt_db(db: &[u8], key_material: &KeyMaterial, p: &SqlCipherParams) -> Result<DecryptedDb> {
    // A cleartext header before the cipher data is rare and changes page indexing;
    // reject it explicitly rather than silently decrypt the wrong bytes.
    ensure!(
        p.plaintext_header_size == 0,
        "sqlcipher plaintext_header_size > 0 is not yet supported"
    );

    let page_size = p.page_size;
    ensure!(
        page_size >= 512 && page_size.is_power_of_two(),
        "invalid sqlcipher page_size {page_size}"
    );
    ensure!(db.len() >= page_size, "database smaller than one page");
    ensure!(
        db.len().is_multiple_of(page_size),
        "database length {} is not a multiple of page_size {page_size}",
        db.len()
    );

    let reserve = reserve_size(p);
    ensure!(
        page_size > reserve + SALT_SZ,
        "page_size {page_size} too small for reserve {reserve}"
    );
    // `size` is the cipher-region length (also where the IV sits). It and the
    // page-1 region (minus the salt) must be block-aligned or the params are wrong.
    let size = page_size - reserve;
    ensure!(
        size.is_multiple_of(BLOCK_SZ) && (size - SALT_SZ).is_multiple_of(BLOCK_SZ),
        "sqlcipher cipher region is not block-aligned (page_size/hmac mismatch?)"
    );

    // Derive the encryption key (and the effective salt: a 48-byte raw keyspec
    // carries its own).
    let (enc_key, salt) = derive_key(key_material, &db[..SALT_SZ], p)?;
    let hmac_key = p.use_hmac.then(|| derive_hmac_key(&enc_key, &salt, p));
    let hlen = hmac_len(p.hmac);

    let num_pages = db.len() / page_size;
    let mut out = Vec::with_capacity(db.len());
    let mut all_verified = p.use_hmac;

    for page_idx in 0..num_pages {
        let pgno = (page_idx + 1) as u32;
        let page = &db[page_idx * page_size..(page_idx + 1) * page_size];
        let iv = &page[size..size + IV_SZ];

        if let Some(hk) = &hmac_key {
            // HMAC covers the cipher region + IV (page[0..size+IV], salt included on
            // page 1), then the little-endian page number.
            let mac_end = size + IV_SZ;
            let stored = &page[mac_end..mac_end + hlen];
            let ok = hmac_ok(p.hmac, hk, &page[..mac_end], pgno, stored);
            if !ok {
                if pgno == 1 {
                    bail!(
                        "SQLCipher key verification failed: page 1 HMAC mismatch \
                         (wrong key or cipher parameters)"
                    );
                }
                all_verified = false;
            }
        }

        // Cipher region: the whole `size` for later pages; after the salt on page 1.
        let cipher_off = if pgno == 1 { SALT_SZ } else { 0 };
        let mut buf = page[cipher_off..size].to_vec();
        aes_cbc_decrypt(&enc_key, iv, &mut buf)?;

        // Reassemble the plaintext page: [SQLite header on pg 1] + decrypted region
        // + the original reserve area (IV/HMAC bytes SQLite treats as reserved).
        if pgno == 1 {
            out.extend_from_slice(SQLITE_HEADER);
        }
        out.extend_from_slice(&buf);
        out.extend_from_slice(&page[size..page_size]);
    }

    debug_assert_eq!(out.len(), db.len());
    Ok(DecryptedDb {
        plaintext: out,
        verified: all_verified,
    })
}

/// Derive the 32-byte encryption key and the effective salt.
///
/// A raw key is used directly (32 bytes), or split as `key(32)||salt(16)` for the
/// 48-byte keyspec form (Signal), whose embedded salt overrides the file salt. A
/// passphrase is stretched with PBKDF2 over the file salt.
fn derive_key(
    key_material: &KeyMaterial,
    file_salt: &[u8],
    p: &SqlCipherParams,
) -> Result<([u8; KEY_SZ], Vec<u8>)> {
    match key_material {
        KeyMaterial::Raw(bytes) if bytes.len() == KEY_SZ => {
            let mut key = [0u8; KEY_SZ];
            key.copy_from_slice(bytes);
            Ok((key, file_salt.to_vec()))
        }
        KeyMaterial::Raw(bytes) if bytes.len() == KEY_SZ + SALT_SZ => {
            let mut key = [0u8; KEY_SZ];
            key.copy_from_slice(&bytes[..KEY_SZ]);
            Ok((key, bytes[KEY_SZ..].to_vec()))
        }
        KeyMaterial::Raw(bytes) => bail!(
            "raw SQLCipher key must be {KEY_SZ} bytes (or {} with an embedded salt), got {}",
            KEY_SZ + SALT_SZ,
            bytes.len()
        ),
        KeyMaterial::Passphrase(pass) => {
            let mut key = [0u8; KEY_SZ];
            pbkdf2(p.kdf, pass, file_salt, p.kdf_iter, &mut key);
            Ok((key, file_salt.to_vec()))
        }
    }
}

/// Derive the HMAC key: `PBKDF2(enc_key, salt⊕0x3a, 2, 32)`.
fn derive_hmac_key(enc_key: &[u8; KEY_SZ], salt: &[u8], p: &SqlCipherParams) -> [u8; KEY_SZ] {
    let hmac_salt: Vec<u8> = salt.iter().map(|b| b ^ HMAC_SALT_MASK).collect();
    let mut hmac_key = [0u8; KEY_SZ];
    pbkdf2(p.kdf, enc_key, &hmac_salt, FAST_KDF_ITER, &mut hmac_key);
    hmac_key
}

/// Per-page reserve size: `roundup16(IV + hmac_len)`, or just the IV when HMAC is
/// disabled.
fn reserve_size(p: &SqlCipherParams) -> usize {
    let raw = if p.use_hmac {
        IV_SZ + hmac_len(p.hmac)
    } else {
        IV_SZ
    };
    round_up(raw, BLOCK_SZ)
}

/// HMAC output length for an algorithm, in bytes.
fn hmac_len(algo: HashAlgorithm) -> usize {
    match algo {
        HashAlgorithm::Sha1 => 20,
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha512 => 64,
    }
}

/// Round `n` up to the next multiple of `m`.
fn round_up(n: usize, m: usize) -> usize {
    n.div_ceil(m) * m
}

/// PBKDF2-HMAC over the chosen hash, writing the derived key into `out`.
fn pbkdf2(algo: HashAlgorithm, password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    use pbkdf2::pbkdf2_hmac;
    match algo {
        HashAlgorithm::Sha1 => pbkdf2_hmac::<Sha1>(password, salt, rounds, out),
        HashAlgorithm::Sha256 => pbkdf2_hmac::<Sha256>(password, salt, rounds, out),
        HashAlgorithm::Sha512 => pbkdf2_hmac::<Sha512>(password, salt, rounds, out),
    }
}

/// Verify a page HMAC over `data || pgno_le32` against `expected` (constant-time).
///
/// Monomorphised per hash via a local macro rather than a generic helper: the
/// RustCrypto trait bounds needed to write one generic `Hmac<D>` function are
/// verbose and brittle, whereas three concrete instantiations are trivial. HMAC
/// accepts a key of any length, so `new_from_slice` cannot actually fail.
fn hmac_ok(algo: HashAlgorithm, key: &[u8], data: &[u8], pgno: u32, expected: &[u8]) -> bool {
    let pgno_le = pgno.to_le_bytes();
    macro_rules! verify_with {
        ($hash:ty) => {{
            let mut mac =
                Hmac::<$hash>::new_from_slice(key).expect("HMAC accepts a key of any length");
            mac.update(data);
            mac.update(&pgno_le);
            mac.verify_slice(expected).is_ok()
        }};
    }
    match algo {
        HashAlgorithm::Sha1 => verify_with!(Sha1),
        HashAlgorithm::Sha256 => verify_with!(Sha256),
        HashAlgorithm::Sha512 => verify_with!(Sha512),
    }
}

/// AES-256-CBC decrypt `buf` in place (no padding; `buf` must be block-aligned).
fn aes_cbc_decrypt(key: &[u8; KEY_SZ], iv: &[u8], buf: &mut [u8]) -> Result<()> {
    ensure!(
        buf.len().is_multiple_of(BLOCK_SZ),
        "cipher region is not block-aligned"
    );
    let decryptor = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| anyhow::anyhow!("invalid AES key/IV length"))?;
    decryptor
        .decrypt_padded_mut::<NoPadding>(buf)
        .map_err(|_| anyhow::anyhow!("AES-CBC decryption failed"))?;
    Ok(())
}

// ── Independent SQLCipher encryptor (test-only) ─────────────────────────────
// Builds a SQLCipher-format image from plaintext pages so the production
// decryptor can be round-tripped — and so other modules' tests (the context and
// engine end-to-end tests) can fabricate an encrypted database. Kept separate
// from production code (its own AES/HMAC calls) so a bug there does not hide in
// both directions.
//
// ⚠ This proves internal consistency and tamper/wrong-key detection — NOT that it
// matches the real `sqlcipher` tool. To add a known-answer test against a genuine
// database:
//   sqlcipher real.db "PRAGMA key='x''<64-hex>''';
//     PRAGMA cipher_page_size=1024; CREATE TABLE t(x); INSERT INTO t VALUES('needle');"
// then commit `real.db` + the hex key and assert this decryptor recovers it.

#[cfg(test)]
fn aes_cbc_encrypt(key: &[u8; KEY_SZ], iv: &[u8; IV_SZ], data: &[u8]) -> Vec<u8> {
    use cbc::Encryptor;
    use cbc::cipher::BlockEncryptMut;
    let mut buf = data.to_vec();
    let len = buf.len();
    Encryptor::<Aes256>::new_from_slices(key, iv)
        .unwrap()
        .encrypt_padded_mut::<NoPadding>(&mut buf, len)
        .unwrap()
        .to_vec()
}

#[cfg(test)]
fn hmac_compute(algo: HashAlgorithm, key: &[u8], data: &[u8], pgno: u32) -> Vec<u8> {
    let pg = pgno.to_le_bytes();
    macro_rules! mac_with {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.update(&pg);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match algo {
        HashAlgorithm::Sha1 => mac_with!(Sha1),
        HashAlgorithm::Sha256 => mac_with!(Sha256),
        HashAlgorithm::Sha512 => mac_with!(Sha512),
    }
}

/// Encrypt logical plaintext pages into a SQLCipher image with a raw key.
/// `pages[0]` must start with the SQLite header. Test-only; `pub(crate)` so the
/// context/engine end-to-end tests can build an encrypted database.
#[cfg(test)]
pub(crate) fn encrypt_db(
    pages: &[Vec<u8>],
    key: &[u8; KEY_SZ],
    salt: &[u8; SALT_SZ],
    p: &SqlCipherParams,
) -> Vec<u8> {
    let page_size = p.page_size;
    let reserve = reserve_size(p);
    let size = page_size - reserve;
    let hlen = hmac_len(p.hmac);
    let hmac_key = derive_hmac_key(key, salt, p);
    let mut out = Vec::new();
    for (i, page) in pages.iter().enumerate() {
        assert_eq!(page.len(), page_size);
        let pgno = (i + 1) as u32;
        let iv = [0x11u8 ^ (i as u8); IV_SZ]; // deterministic per page for the test
        let cipher_off = if pgno == 1 { SALT_SZ } else { 0 };
        let ct = aes_cbc_encrypt(key, &iv, &page[cipher_off..size]);

        let mut pb = vec![0u8; page_size];
        if pgno == 1 {
            pb[..SALT_SZ].copy_from_slice(salt);
        }
        pb[cipher_off..size].copy_from_slice(&ct);
        pb[size..size + IV_SZ].copy_from_slice(&iv);
        if p.use_hmac {
            let mac = hmac_compute(p.hmac, &hmac_key, &pb[..size + IV_SZ], pgno);
            pb[size + IV_SZ..size + IV_SZ + hlen].copy_from_slice(&mac[..hlen]);
        }
        out.extend_from_slice(&pb);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(
        use_hmac: bool,
        hmac: HashAlgorithm,
        kdf: HashAlgorithm,
        kdf_iter: u32,
    ) -> SqlCipherParams {
        SqlCipherParams {
            page_size: 1024,
            kdf_iter,
            hmac,
            kdf,
            use_hmac,
            plaintext_header_size: 0,
        }
    }

    /// Two logical plaintext pages (1024 bytes each) with searchable needles.
    fn plaintext_pages(page_size: usize) -> Vec<Vec<u8>> {
        let mut p1 = vec![0u8; page_size];
        p1[..SQLITE_HEADER.len()].copy_from_slice(SQLITE_HEADER);
        p1[100..118].copy_from_slice(b"PAGE1-SECRET-token");
        let mut p2 = vec![0u8; page_size];
        p2[..16].copy_from_slice(b"PAGE2-needle-xyz");
        vec![p1, p2]
    }

    #[test]
    fn reserve_sizes_match_sqlcipher() {
        assert_eq!(
            reserve_size(&params(true, HashAlgorithm::Sha1, HashAlgorithm::Sha1, 1)),
            48
        );
        assert_eq!(
            reserve_size(&params(
                true,
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha256,
                1
            )),
            48
        );
        assert_eq!(
            reserve_size(&params(
                true,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha512,
                1
            )),
            80
        );
        assert_eq!(
            reserve_size(&params(
                false,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha512,
                1
            )),
            16
        );
    }

    #[test]
    fn round_trip_raw_key_v4() {
        let p = params(true, HashAlgorithm::Sha512, HashAlgorithm::Sha512, 256_000);
        let key = [0x42u8; KEY_SZ];
        let salt = [0x7bu8; SALT_SZ];
        let pages = plaintext_pages(p.page_size);
        let blob = encrypt_db(&pages, &key, &salt, &p);

        let out = decrypt_db(&blob, &KeyMaterial::Raw(key.to_vec()), &p).unwrap();
        assert!(out.verified);
        // Compare the content region of each page (the reserve area legitimately
        // differs: it holds IV/HMAC, which SQLite treats as reserved bytes).
        let size = p.page_size - reserve_size(&p);
        for (i, page) in pages.iter().enumerate() {
            let got = &out.plaintext[i * p.page_size..i * p.page_size + size];
            assert_eq!(got, &page[..size], "page {} content mismatch", i + 1);
        }
        // The plaintext is searchable.
        assert!(
            out.plaintext
                .windows(18)
                .any(|w| w == b"PAGE1-SECRET-token")
        );
        assert!(out.plaintext.windows(16).any(|w| w == b"PAGE2-needle-xyz"));
    }

    #[test]
    fn round_trip_48_byte_keyspec_uses_embedded_salt() {
        let p = params(true, HashAlgorithm::Sha512, HashAlgorithm::Sha512, 256_000);
        let key = [0x42u8; KEY_SZ];
        let salt = [0x99u8; SALT_SZ]; // embedded salt differs from a default
        let pages = plaintext_pages(p.page_size);
        let blob = encrypt_db(&pages, &key, &salt, &p);

        // Pass key||salt (48 bytes); the decryptor must use the embedded salt.
        let mut keyspec = key.to_vec();
        keyspec.extend_from_slice(&salt);
        let out = decrypt_db(&blob, &KeyMaterial::Raw(keyspec), &p).unwrap();
        assert!(out.verified);
        assert!(out.plaintext.windows(16).any(|w| w == b"PAGE2-needle-xyz"));
    }

    #[test]
    fn round_trip_passphrase() {
        let p = params(true, HashAlgorithm::Sha512, HashAlgorithm::Sha512, 4096);
        let salt = [0x10u8; SALT_SZ];
        // Derive the same key the decryptor will, to build the fixture.
        let mut key = [0u8; KEY_SZ];
        pbkdf2(p.kdf, b"correct horse", &salt, p.kdf_iter, &mut key);
        let pages = plaintext_pages(p.page_size);
        let blob = encrypt_db(&pages, &key, &salt, &p);

        let out = decrypt_db(
            &blob,
            &KeyMaterial::Passphrase(b"correct horse".to_vec()),
            &p,
        )
        .unwrap();
        assert!(out.verified);
        assert!(
            out.plaintext
                .windows(18)
                .any(|w| w == b"PAGE1-SECRET-token")
        );
    }

    #[test]
    fn wrong_key_fails_page1_hmac() {
        let p = params(true, HashAlgorithm::Sha512, HashAlgorithm::Sha512, 256_000);
        let salt = [0x7bu8; SALT_SZ];
        let blob = encrypt_db(&plaintext_pages(p.page_size), &[0x42u8; KEY_SZ], &salt, &p);
        // A different key must be rejected, not silently produce garbage.
        let err = decrypt_db(&blob, &KeyMaterial::Raw(vec![0x43u8; KEY_SZ]), &p);
        assert!(err.is_err());
    }

    #[test]
    fn tampered_page_is_detected() {
        let p = params(true, HashAlgorithm::Sha512, HashAlgorithm::Sha512, 256_000);
        let key = [0x42u8; KEY_SZ];
        let salt = [0x7bu8; SALT_SZ];
        let mut blob = encrypt_db(&plaintext_pages(p.page_size), &key, &salt, &p);
        // Flip a byte in page 1's cipher region → page-1 HMAC must fail.
        blob[200] ^= 0xff;
        assert!(decrypt_db(&blob, &KeyMaterial::Raw(key.to_vec()), &p).is_err());
    }

    #[test]
    fn no_hmac_round_trips_but_unverified() {
        let p = params(false, HashAlgorithm::Sha512, HashAlgorithm::Sha512, 256_000);
        let key = [0x42u8; KEY_SZ];
        let salt = [0x7bu8; SALT_SZ];
        let blob = encrypt_db(&plaintext_pages(p.page_size), &key, &salt, &p);
        let out = decrypt_db(&blob, &KeyMaterial::Raw(key.to_vec()), &p).unwrap();
        assert!(!out.verified); // no HMAC ⇒ key cannot be authenticated
        assert!(out.plaintext.windows(16).any(|w| w == b"PAGE2-needle-xyz"));
    }
}
