//! Encrypted ZIP entries: ZipCrypto (PKWARE's traditional encryption) and WinZip AES.
//!
//! Defines: [`ZipPassword`] (what a ZIP reader knows of the password), [`decrypt`]
//! (an entry's raw data to its still-compressed plain data).
//! Used by: `zip` (`decode`, shared by the mapped, ranged and nested ZIP readers).
//! Uses: `crate::core::models::Encryption`, `aes` (AES-128/192/256 blocks), `hmac` +
//! `sha1` + `pbkdf2` (the AES key derivation and authentication code).
//!
//! ZipCrypto (APPNOTE.TXT 6.1): three 32-bit keys, set from the password, update with
//! each plain byte; each cipher byte is the plain byte XOR a byte drawn from the third
//! key. The data starts with a 12-byte header whose last byte, decrypted, must be the
//! entry's check byte. That is one byte of check: the caller verifies the CRC-32 of the
//! decoded data too.
//!
//! WinZip AES (AE-1 / AE-2, compression method 99): the data is a salt (8, 12 or 16
//! bytes), a 2-byte password check value, the ciphertext, and a 10-byte HMAC-SHA1 of
//! the ciphertext. PBKDF2-HMAC-SHA1 (1000 rounds) over the salt gives the AES key, the
//! HMAC key and the check value; the cipher is AES in counter mode, the counter a
//! 16-byte little-endian integer from 1.
//!
//! WHY by hand, not a ZIP crate: the ZIP reader is hand-made (see `zip`) for bounds
//! control on evidence, and both schemes are small on top of the audited block
//! cipher, HMAC and PBKDF2 already in the build for backups.
//!
//! The password is taken as its UTF-8 bytes, which is what 7-Zip and Info-ZIP write
//! on macOS and Linux. A ZipCrypto archive made on Windows with a non-ASCII password
//! used the system code page instead, and does not open.

use aes::cipher::consts::U16;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use anyhow::{Result, anyhow, bail, ensure};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

use crate::core::models::Encryption;

/// ZipCrypto's encryption header, before the data.
const ZIPCRYPTO_HEADER: usize = 12;
/// WinZip AES: the password check value, after the salt.
const AES_CHECK: usize = 2;
/// WinZip AES: the truncated HMAC-SHA1, after the ciphertext.
const AES_MAC: usize = 10;
/// WinZip AES: PBKDF2 rounds, fixed by the format.
const AES_ROUNDS: u32 = 1000;
/// An AES block, and the counter's size.
const BLOCK: usize = 16;

/// What a ZIP reader knows of the password, for its error messages.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ZipPassword<'a> {
    /// The password given (asked for with `--archive-password`, or
    /// `MFSCAN_ARCHIVE_PASSWORD`).
    Given(&'a str),
    /// No password was given.
    Missing,
    /// A ZIP inside another container: those are not decrypted.
    Nested,
}

/// The plain bytes of an entry's raw `data`, still compressed by its method.
///
/// Fails, naming the cause, without a password, with a wrong one (the check value,
/// or for AES the authentication code), on data too short to hold the scheme's
/// header, and for an encryption this tool does not read.
pub(crate) fn decrypt(
    data: &[u8],
    encryption: Encryption,
    password: ZipPassword,
) -> Result<Vec<u8>> {
    let password = match (encryption, password) {
        (Encryption::None, _) => return Ok(data.to_vec()),
        (Encryption::Unsupported, _) => bail!(
            "it uses an encryption mf-scan does not read (PKWARE strong encryption, or a \
             malformed AES field)"
        ),
        (_, ZipPassword::Given(password)) => password.as_bytes(),
        (_, ZipPassword::Missing) => bail!(
            "it is encrypted: pass --archive-password to be asked for the archive's \
             password (or set MFSCAN_ARCHIVE_PASSWORD)"
        ),
        (_, ZipPassword::Nested) => {
            bail!("it is encrypted, inside a nested archive: those are not decrypted")
        }
    };
    match encryption {
        Encryption::ZipCrypto { check, .. } => zipcrypto(data, check, password),
        Encryption::Aes { strength } => winzip_aes(data, strength, password),
        Encryption::None | Encryption::Unsupported => unreachable!("handled above"),
    }
}

/// The CRC-32 table (reflected polynomial 0xEDB88320), as ZipCrypto's key update uses it.
const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
};

/// One CRC-32 step, without the pre- and post-inversion of a whole-message CRC.
fn crc_step(crc: u32, byte: u8) -> u32 {
    CRC_TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8)
}

/// ZipCrypto's three keys (APPNOTE 6.1.5).
struct Keys([u32; 3]);

impl Keys {
    fn new(password: &[u8]) -> Self {
        let mut keys = Self([0x1234_5678, 0x2345_6789, 0x3456_7890]);
        for &byte in password {
            keys.update(byte);
        }
        keys
    }

    fn update(&mut self, plain: u8) {
        let [k0, k1, k2] = &mut self.0;
        *k0 = crc_step(*k0, plain);
        *k1 = k1
            .wrapping_add(*k0 & 0xFF)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        *k2 = crc_step(*k2, (*k1 >> 24) as u8);
    }

    fn decrypt(&mut self, cipher: u8) -> u8 {
        let temp = (self.0[2] | 2) & 0xFFFF;
        let plain = cipher ^ ((temp * (temp ^ 1)) >> 8) as u8;
        self.update(plain);
        plain
    }
}

fn zipcrypto(data: &[u8], check: u8, password: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        data.len() >= ZIPCRYPTO_HEADER,
        "its data is shorter than the 12-byte encryption header"
    );
    let mut keys = Keys::new(password);
    let mut last = 0;
    for &byte in &data[..ZIPCRYPTO_HEADER] {
        last = keys.decrypt(byte);
    }
    ensure!(
        last == check,
        "the password does not open it (the check byte differs)"
    );
    Ok(data[ZIPCRYPTO_HEADER..]
        .iter()
        .map(|&byte| keys.decrypt(byte))
        .collect())
}

fn winzip_aes(data: &[u8], strength: u8, password: &[u8]) -> Result<Vec<u8>> {
    let (key_len, salt_len) = match strength {
        1 => (16, 8),
        2 => (24, 12),
        3 => (32, 16),
        other => bail!("it declares an unknown AES strength ({other})"),
    };
    ensure!(
        data.len() >= salt_len + AES_CHECK + AES_MAC,
        "its data is shorter than the AES salt, check value and authentication code"
    );
    let (salt, rest) = data.split_at(salt_len);
    let (stored_check, rest) = rest.split_at(AES_CHECK);
    let (ciphertext, stored_mac) = rest.split_at(rest.len() - AES_MAC);

    // AES key, then HMAC key, then the check value.
    let mut derived = vec![0u8; 2 * key_len + AES_CHECK];
    pbkdf2_hmac::<Sha1>(password, salt, AES_ROUNDS, &mut derived);
    let (aes_key, rest) = derived.split_at(key_len);
    let (mac_key, check) = rest.split_at(key_len);
    ensure!(
        check == stored_check,
        "the password does not open it (the AES check value differs)"
    );

    let mut mac = <Hmac<Sha1> as hmac::KeyInit>::new_from_slice(mac_key)
        .map_err(|_| anyhow!("HMAC accepts a key of any length"))?;
    mac.update(ciphertext);
    let computed = mac.finalize().into_bytes();
    // A matching check value is 1 in 65,536 for a wrong password; the code is
    // the real test, of the password and of the data.
    ensure!(
        computed[..AES_MAC] == *stored_mac,
        "its AES authentication code does not match (a wrong password, or damaged data)"
    );

    let mut plain = ciphertext.to_vec();
    match strength {
        1 => counter_mode(&Aes128::new_from_slice(aes_key)?, &mut plain),
        2 => counter_mode(&Aes192::new_from_slice(aes_key)?, &mut plain),
        _ => counter_mode(&Aes256::new_from_slice(aes_key)?, &mut plain),
    }
    Ok(plain)
}

/// XOR `data` with AES-CTR keystream, the counter little-endian from 1 (WinZip's).
fn counter_mode(cipher: &impl BlockCipherEncrypt<BlockSize = U16>, data: &mut [u8]) {
    let mut counter: u128 = 1;
    for chunk in data.chunks_mut(BLOCK) {
        let mut block = counter.to_le_bytes();
        cipher.encrypt_block((&mut block).into());
        for (byte, key) in chunk.iter_mut().zip(block) {
            *byte ^= key;
        }
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crc_table_is_the_standard_one() {
        // CRC-32 of "123456789" is 0xCBF43926 (the check value of the standard).
        let crc = b"123456789".iter().fold(!0u32, |c, &b| crc_step(c, b));
        assert_eq!(!crc, 0xCBF4_3926);
    }

    #[test]
    fn without_a_password_or_nested_it_says_why() {
        let aes = Encryption::Aes { strength: 3 };
        let e = decrypt(&[0; 64], aes, ZipPassword::Missing).unwrap_err();
        assert!(e.to_string().contains("--archive-password"), "{e}");
        let e = decrypt(&[0; 64], aes, ZipPassword::Nested).unwrap_err();
        assert!(e.to_string().contains("nested"), "{e}");
        assert!(decrypt(&[0; 64], Encryption::Unsupported, ZipPassword::Given("x")).is_err());
    }
}
