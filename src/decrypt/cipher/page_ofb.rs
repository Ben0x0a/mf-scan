//! Page-level AES-256-OFB decryptor, the scheme Apple's Find My daemons use.
//!
//! Defines: [`PageAesOfb`], the [`DbDecryptor`] for SQLite databases whose pages are each
//! encrypted with AES-256 in OFB mode, under a nonce kept in the page's reserved bytes.
//! Used by: `decrypt::cipher::decrypt` (dispatch).
//! Uses: `aes` (one AES-256 block encryption per 16 bytes; OFB is built on it here).
//!
//! ── Format (what this implements) ────────────────────────────────────────────
//! Worked out on a real iPhone full-filesystem extraction (December 2025), from the
//! databases of `searchpartyd`, `findmylocated` and `findmybeaconingd`, and checked by
//! decrypting them and running SQLite's `PRAGMA integrity_check` (result: ok):
//!   • the SQLite header's page size (bytes 16-17) and reserved-byte count (byte 20, 12)
//!     are stored in the clear: bytes 16 to 23 are not encrypted;
//!   • each page's last 12 bytes are a nonce, stored in the clear;
//!   • the rest of the page is AES-256-OFB, with IV = page number (little-endian u32)
//!     followed by the 12-byte nonce;
//!   • the key is the raw 32-byte value of a keychain item in the daemon's access group.
//!
//! Verification: nothing authenticates the pages. The key is checked instead by page 1,
//! whose first 16 bytes must decrypt to the SQLite magic `SQLite format 3\0`. A wrong key
//! passes that test with a probability of 2⁻¹²⁸, so the key is verified. A damaged page
//! elsewhere would still decrypt to wrong bytes without an error.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use anyhow::{Result, bail};

use crate::decrypt::cipher::{DbDecryptor, DecryptedDb};
use crate::decrypt::profile::{CipherSpec, KeyMaterial};

/// The SQLite file magic, the first 16 bytes of a plaintext database.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// The header bytes stored in the clear: page size, file format versions, reserve.
const CLEAR_HEADER: std::ops::Range<usize> = 16..24;
/// Length of the per-page nonce, which is also the page's reserved-byte count.
const NONCE_LEN: usize = 12;
/// AES block length.
const BLOCK: usize = 16;
/// AES-256 key length.
const KEY_LEN: usize = 32;

/// The page-level AES-256-OFB decryptor.
pub struct PageAesOfb;

impl DbDecryptor for PageAesOfb {
    fn algorithm(&self) -> &'static str {
        "page-aes-ofb"
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &KeyMaterial,
        spec: &CipherSpec,
    ) -> Result<DecryptedDb> {
        match spec {
            CipherSpec::PageAesOfb(_) => decrypt_db(ciphertext, key),
            _ => bail!("page-aes-ofb decryptor invoked with another cipher spec"),
        }
    }
}

/// Decrypt every page of `db`, checking the key on page 1.
fn decrypt_db(db: &[u8], key: &KeyMaterial) -> Result<DecryptedDb> {
    let KeyMaterial::Raw(key) = key else {
        bail!("page-aes-ofb needs a raw 32-byte key, not a passphrase");
    };
    if key.len() != KEY_LEN {
        bail!("page-aes-ofb needs a 32-byte key, got {} bytes", key.len());
    }
    let page_size = page_size(db)?;
    let reserve = usize::from(db[20]);
    if reserve != NONCE_LEN {
        bail!(
            "page-aes-ofb expects {NONCE_LEN} reserved bytes per page, the header says {reserve}"
        );
    }
    if !db.len().is_multiple_of(page_size) {
        bail!(
            "file length {} is not a whole number of {page_size}-byte pages",
            db.len()
        );
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut plaintext = Vec::with_capacity(db.len());
    for (index, page) in db.chunks_exact(page_size).enumerate() {
        let page_no = u32::try_from(index + 1)?;
        let (body, nonce) = page.split_at(page_size - NONCE_LEN);
        let start = plaintext.len();
        plaintext.extend_from_slice(body);
        apply_ofb(&cipher, page_no, nonce, &mut plaintext[start..]);
        plaintext.extend_from_slice(nonce);

        if index == 0 {
            if plaintext[..SQLITE_MAGIC.len()] != SQLITE_MAGIC[..] {
                bail!("page 1 did not decrypt to the SQLite magic: wrong key");
            }
            plaintext[CLEAR_HEADER].copy_from_slice(&page[CLEAR_HEADER]);
        }
    }
    Ok(DecryptedDb {
        plaintext,
        verified: true,
    })
}

/// The page size from the clear header (bytes 16-17, big-endian; 1 means 65536).
fn page_size(db: &[u8]) -> Result<usize> {
    let Some(raw) = db.get(16..18) else {
        bail!("file too short for a SQLite header");
    };
    let size = match u16::from_be_bytes([raw[0], raw[1]]) {
        1 => 65_536,
        n => usize::from(n),
    };
    if !(512..=65_536).contains(&size) || !size.is_power_of_two() {
        bail!("header page size {size} is not a valid SQLite page size");
    }
    Ok(size)
}

/// XOR `data` with the OFB keystream for `page_no` and `nonce`, in place.
///
/// HOW: OFB encrypts the IV, then encrypts each output again; the outputs are the
/// keystream. Encryption and decryption are the same operation.
fn apply_ofb(cipher: &Aes256, page_no: u32, nonce: &[u8], data: &mut [u8]) {
    let mut block = GenericArray::from([0u8; BLOCK]);
    block[..4].copy_from_slice(&page_no.to_le_bytes());
    block[4..].copy_from_slice(nonce);
    for chunk in data.chunks_mut(BLOCK) {
        cipher.encrypt_block(&mut block);
        for (byte, ks) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= ks;
        }
    }
}

/// Encrypt a plaintext SQLite image the way the Find My daemons do (test helper).
#[cfg(test)]
pub(crate) fn encrypt_db(plain: &[u8], key: &[u8], page_size: usize) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(plain.len());
    for (index, page) in plain.chunks_exact(page_size).enumerate() {
        let page_no = u32::try_from(index + 1).unwrap();
        let (body, nonce) = page.split_at(page_size - NONCE_LEN);
        let start = out.len();
        out.extend_from_slice(body);
        apply_ofb(&cipher, page_no, nonce, &mut out[start..]);
        out.extend_from_slice(nonce);
        if index == 0 {
            out[CLEAR_HEADER].copy_from_slice(&page[CLEAR_HEADER]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::profile::PageAesOfbParams;

    const PAGE: usize = 512;

    /// A two-page plaintext image with a SQLite header, 12 reserved bytes and a
    /// distinct nonce in each page's reserved area.
    fn plain_db() -> Vec<u8> {
        let mut db = vec![0u8; PAGE * 2];
        db[..16].copy_from_slice(SQLITE_MAGIC);
        db[16..18].copy_from_slice(&(PAGE as u16).to_be_bytes());
        db[18] = 1;
        db[19] = 1;
        db[20] = NONCE_LEN as u8;
        db[100] = 0x0d;
        db[PAGE] = 0x0d;
        for (i, b) in db.iter_mut().enumerate().skip(101) {
            if i % PAGE < PAGE - NONCE_LEN && i != PAGE {
                *b = (i % 251) as u8;
            }
        }
        db[PAGE - NONCE_LEN..PAGE].copy_from_slice(&[7; NONCE_LEN]);
        db[2 * PAGE - NONCE_LEN..].copy_from_slice(&[9; NONCE_LEN]);
        db
    }

    fn spec() -> CipherSpec {
        CipherSpec::PageAesOfb(PageAesOfbParams {})
    }

    #[test]
    fn round_trips_and_verifies() {
        let key = [0x42u8; KEY_LEN];
        let plain = plain_db();
        let enc = encrypt_db(&plain, &key, PAGE);
        assert_ne!(&enc[..16], SQLITE_MAGIC, "the magic must be encrypted");
        assert_eq!(enc[16..24], plain[16..24], "bytes 16-23 stay in the clear");

        let out = PageAesOfb
            .decrypt(&enc, &KeyMaterial::Raw(key.to_vec()), &spec())
            .unwrap();
        assert!(out.verified);
        assert_eq!(out.plaintext, plain);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let enc = encrypt_db(&plain_db(), &[1u8; KEY_LEN], PAGE);
        let err = PageAesOfb
            .decrypt(&enc, &KeyMaterial::Raw(vec![2u8; KEY_LEN]), &spec())
            .unwrap_err();
        assert!(err.to_string().contains("wrong key"), "{err}");
    }

    #[test]
    fn short_key_and_wrong_reserve_are_rejected() {
        let enc = encrypt_db(&plain_db(), &[1u8; KEY_LEN], PAGE);
        assert!(
            PageAesOfb
                .decrypt(&enc, &KeyMaterial::Raw(vec![1u8; 16]), &spec())
                .is_err()
        );
        let mut other = enc.clone();
        other[20] = 80;
        assert!(
            PageAesOfb
                .decrypt(&other, &KeyMaterial::Raw(vec![1u8; KEY_LEN]), &spec())
                .is_err()
        );
    }
}
