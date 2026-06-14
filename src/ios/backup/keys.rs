//! Key derivation, AES key-unwrap and AES-CBC for encrypted iOS backups.
//!
//! Defines: the backup-password KDF ([`derive_keybag_key`]), the RFC 3394 AES
//! key-unwrap ([`aes_unwrap`]), the per-class key recovery built on top of them
//! ([`unwrap_class_keys`]), and an AES-256-CBC-NoPadding decrypt helper
//! ([`aes_cbc_decrypt`]) for the per-file blobs.
//! Used by: the next sub-stage (`BackupSource`), which derives the class keys
//! once and then unwraps + CBC-decrypts each file named in `Manifest.db`.
//! Uses: `aes::Aes256` single-block ECB decrypt (RFC 3394), `cbc` (CBC mode),
//! `pbkdf2` + `sha1`/`sha2` (the KDF) — the same RustCrypto crates the
//! `sqlcipher` decryptor uses, no new dependency.
//!
//! ⚠ See `ios::backup` (mod.rs) for the validation-status note: [`aes_unwrap`]
//! is KAT-validated against RFC 3394 §4.6, but the KDF / class-selection / file
//! decryption path still needs a real-backup known-answer test.

use std::collections::BTreeMap;

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use anyhow::{Result, ensure};
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use sha1::Sha1;
use sha2::Sha256;

use crate::ios::backup::keybag::Keybag;

/// AES-256 key length, in bytes.
const KEY_SZ: usize = 32;
/// AES block / CBC IV size, in bytes.
const BLOCK_SZ: usize = 16;
/// RFC 3394 semi-block size, in bytes (the algorithm works on 64-bit halves).
const HALF_SZ: usize = 8;
/// RFC 3394 number of wrapping rounds (the spec's fixed 6 passes).
const KW_ROUNDS: u64 = 6;
/// RFC 3394 default integrity-check IV (the "A6" constant), one per semi-block.
const KW_DEFAULT_IV: [u8; HALF_SZ] = [0xA6; HALF_SZ];
/// `WRAP` bit meaning "wrapped by the passcode/keybag-derived key" — the only
/// class keys recoverable offline (bit 1, `0x1`, is device-key-wrapped).
const WRAP_PASSCODE: u32 = 2;

/// AES key unwrap, RFC 3394, with a 256-bit KEK.
///
/// Recovers the key data wrapped by `aes_wrap`-style AES key wrapping. The
/// algorithm runs the 6 rounds in reverse, AES-256-ECB *decrypting* each
/// `(A ⊕ t) ‖ R[i]` block; after the rounds the accumulator `A` must equal the
/// default IV `0xA6A6A6A6A6A6A6A6` or the integrity check has failed (wrong
/// password / corrupt keybag), which we surface as an `Err` so a caller trying
/// candidate passwords can move on.
///
/// WHY a hand-rolled single-block loop: RFC 3394 key wrap is not CBC/ECB of the
/// whole buffer — it interleaves the semi-blocks with a per-step counter, so we
/// drive `aes::Aes256` one 16-byte block at a time rather than using a mode.
pub fn aes_unwrap(kek: &[u8; KEY_SZ], wrapped: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        wrapped.len().is_multiple_of(HALF_SZ),
        "AES key unwrap: wrapped length {} is not a multiple of {HALF_SZ}",
        wrapped.len()
    );
    // n = number of 8-byte data semi-blocks (the first semi-block is the IV/A).
    let n = wrapped.len() / HALF_SZ;
    ensure!(
        n >= 2,
        "AES key unwrap: need at least one data block plus the IV, got {} bytes",
        wrapped.len()
    );
    let n = n - 1;

    let cipher = Aes256::new(GenericArray::from_slice(kek));

    // A = first semi-block; R[1..=n] = the rest, kept as a flat Vec (R[i] lives
    // at r[(i-1)*8 .. i*8]).
    let mut a = [0u8; HALF_SZ];
    a.copy_from_slice(&wrapped[..HALF_SZ]);
    let mut r = wrapped[HALF_SZ..].to_vec();

    let n_u64 = n as u64;
    // for j in 5..=0, for i in n..=1 — the reverse of the wrap schedule.
    for j in (0..KW_ROUNDS).rev() {
        for i in (1..=n).rev() {
            let t = n_u64 * j + (i as u64);
            // B = AES-decrypt( (A ⊕ t_be64) ‖ R[i] ).
            let mut block = [0u8; BLOCK_SZ];
            let t_be = t.to_be_bytes();
            for k in 0..HALF_SZ {
                block[k] = a[k] ^ t_be[k];
            }
            let ri = &r[(i - 1) * HALF_SZ..i * HALF_SZ];
            block[HALF_SZ..].copy_from_slice(ri);

            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));

            // A = B[0..8]; R[i] = B[8..16].
            a.copy_from_slice(&block[..HALF_SZ]);
            r[(i - 1) * HALF_SZ..i * HALF_SZ].copy_from_slice(&block[HALF_SZ..]);
        }
    }

    // Integrity check: A must equal the default IV. Mismatch ⇒ wrong key.
    ensure!(
        a == KW_DEFAULT_IV,
        "AES key unwrap integrity check failed (wrong password or corrupt keybag)"
    );
    Ok(r)
}

/// Derive the 32-byte keybag key from the backup password.
///
/// Two forms, selected by whether the keybag carries the iOS 10.2+ double-
/// protection fields:
///   • `DPSL` + `DPIC` present: `t = PBKDF2-HMAC-SHA256(password, DPSL, DPIC)`
///     then `key = PBKDF2-HMAC-SHA1(t, SALT, ITER)`.
///   • otherwise: `key = PBKDF2-HMAC-SHA1(password, SALT, ITER)`.
///
/// WHY the double PBKDF2: from iOS 10.2 Apple prepends a high-iteration
/// SHA-256 PBKDF2 pass ("double protection") before the legacy SHA-1 pass. The
/// SHA-256 pre-hash raises the per-guess cost on modern (GPU/ASIC) crackers far
/// more than adding SHA-1 rounds would, while the trailing SHA-1 pass keeps the
/// derived value compatible with the older keybag-key consumer. Both passes must
/// run, in this order, or the resulting key is wrong.
pub fn derive_keybag_key(password: &[u8], kb: &Keybag) -> [u8; KEY_SZ] {
    use pbkdf2::pbkdf2_hmac;
    match (&kb.dpsl, kb.dpic) {
        (Some(dpsl), Some(dpic)) => {
            let mut t = [0u8; KEY_SZ];
            pbkdf2_hmac::<Sha256>(password, dpsl, dpic, &mut t);
            let mut key = [0u8; KEY_SZ];
            pbkdf2_hmac::<Sha1>(&t, &kb.salt, kb.iter, &mut key);
            key
        }
        _ => {
            let mut key = [0u8; KEY_SZ];
            pbkdf2_hmac::<Sha1>(password, &kb.salt, kb.iter, &mut key);
            key
        }
    }
}

/// Derive the keybag key and unwrap every passcode-wrapped class key.
///
/// Only classes whose `WRAP` has the passcode bit (`& 2 != 0`) can be unwrapped
/// offline; classes that are device-key-wrapped only (`& 1`) need the device's
/// hardware key and are skipped. Returns a map of class number → 32-byte class
/// key. Partial success is fine (some classes are legitimately device-only), but
/// if *no* class unwraps — every integrity check fails — the password is wrong,
/// which we report as an `Err` so the caller can say so cleanly rather than hand
/// back an empty, silently-useless map.
pub fn unwrap_class_keys(password: &[u8], kb: &Keybag) -> Result<BTreeMap<u32, [u8; KEY_SZ]>> {
    let kek = derive_keybag_key(password, kb);
    let mut keys = BTreeMap::new();
    // Track whether any passcode-wrapped class existed at all, to distinguish
    // "wrong password" from "nothing to unwrap".
    let mut had_passcode_class = false;

    for entry in &kb.classes {
        if entry.wrap & WRAP_PASSCODE == 0 {
            continue; // device-key-wrapped only — cannot unwrap offline.
        }
        had_passcode_class = true;
        // A single class failing its integrity check does not condemn the whole
        // password — keep going and decide at the end. (Some keybags carry a
        // class whose wrapped key is malformed; that should not block the rest.)
        if let Ok(unwrapped) = aes_unwrap(&kek, &entry.wrapped_key)
            && unwrapped.len() == KEY_SZ
        {
            let mut k = [0u8; KEY_SZ];
            k.copy_from_slice(&unwrapped);
            keys.insert(entry.class, k);
        }
    }

    ensure!(
        !(had_passcode_class && keys.is_empty()),
        "no protection-class key could be unwrapped (wrong backup password?)"
    );
    Ok(keys)
}

/// AES-256-CBC decrypt `data` with NoPadding, returning the plaintext.
///
/// Operates on an owned copy and requires `data.len() % 16 == 0`. Padding is
/// deliberately NOT stripped: callers (next sub-stage) decrypt per-file blobs
/// with a zero IV and truncate to the manifest-recorded real size themselves, so
/// stripping a PKCS#7-looking tail here would corrupt files whose true length is
/// already known.
pub fn aes_cbc_decrypt(key: &[u8; KEY_SZ], iv: &[u8; BLOCK_SZ], data: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        data.len().is_multiple_of(BLOCK_SZ),
        "AES-CBC: data length {} is not a multiple of {BLOCK_SZ}",
        data.len()
    );
    let mut buf = data.to_vec();
    let decryptor = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| anyhow::anyhow!("invalid AES key/IV length"))?;
    decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| anyhow::anyhow!("AES-CBC decryption failed"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ios::backup::keybag::ClassEntry;
    // `encrypt_block` (used only by the test-only RFC 3394 wrapper) lives on the
    // `BlockEncrypt` trait, which production code does not need.
    use aes::cipher::BlockEncrypt;

    /// Decode a hex string into bytes (test helper).
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc3394_aes256_kat() {
        // RFC 3394 §4.6 — "Wrap 256 bits of Key Data with a 256-bit KEK".
        let kek_v = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let ct =
            hex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");
        let expected = hex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

        let mut kek = [0u8; KEY_SZ];
        kek.copy_from_slice(&kek_v);
        let got = aes_unwrap(&kek, &ct).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn corrupted_ciphertext_fails_integrity_check() {
        let kek_v = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let mut ct =
            hex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");
        // Flip a byte: the trailing A6-IV check must fail rather than return junk.
        ct[0] ^= 0xff;
        let mut kek = [0u8; KEY_SZ];
        kek.copy_from_slice(&kek_v);
        assert!(aes_unwrap(&kek, &ct).is_err());
    }

    #[test]
    fn unwrap_rejects_misaligned_input() {
        let kek = [0u8; KEY_SZ];
        assert!(aes_unwrap(&kek, &[0u8; 7]).is_err()); // not a multiple of 8
        assert!(aes_unwrap(&kek, &[0u8; 8]).is_err()); // only the IV, no data
    }

    #[test]
    fn derive_single_vs_double_pbkdf2_differ() {
        // Same password + SALT/ITER, but adding DPSL/DPIC must change the key —
        // proving the double-PBKDF2 branch is actually taken.
        let base = Keybag {
            type_: 1,
            salt: vec![0x11; 20],
            iter: 1_000,
            dpsl: None,
            dpic: None,
            classes: vec![],
        };
        let single = derive_keybag_key(b"open sesame", &base);

        let double_kb = Keybag {
            dpsl: Some(vec![0x22; 32]),
            dpic: Some(1_000),
            ..base.clone()
        };
        let double = derive_keybag_key(b"open sesame", &double_kb);
        assert_ne!(single, double);

        // And the single branch is deterministic.
        assert_eq!(single, derive_keybag_key(b"open sesame", &base));
    }

    #[test]
    fn unwrap_class_keys_skips_device_only_and_uses_passcode_class() {
        // Build a keybag where one passcode-wrapped class carries a class key we
        // can verify by unwrapping with the derived keybag key. We obtain a valid
        // wrapped key by round-tripping through a local RFC 3394 wrap.
        let kb_meta = Keybag {
            type_: 1,
            salt: vec![0x11; 20],
            iter: 1_000,
            dpsl: None,
            dpic: None,
            classes: vec![],
        };
        let kek = derive_keybag_key(b"pw", &kb_meta);
        let class_key = [0x5Au8; KEY_SZ];
        let wrapped = aes_wrap_for_test(&kek, &class_key);

        let kb = Keybag {
            classes: vec![
                // Device-only class — must be skipped (no entry in the map).
                ClassEntry {
                    class: 1,
                    wrap: 1,
                    wrapped_key: vec![0u8; 40],
                },
                // Passcode-wrapped class — must unwrap to `class_key`.
                ClassEntry {
                    class: 3,
                    wrap: 3, // bits 1 and 2 both set; bit 2 ⇒ passcode-wrapped
                    wrapped_key: wrapped,
                },
            ],
            ..kb_meta
        };

        let keys = unwrap_class_keys(b"pw", &kb).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.get(&3), Some(&class_key));
        assert!(!keys.contains_key(&1));
    }

    #[test]
    fn unwrap_class_keys_all_fail_is_err() {
        // A passcode-wrapped class with a bogus wrapped key (right length, wrong
        // contents) must make the whole call fail as a wrong-password signal.
        let kb = Keybag {
            type_: 1,
            salt: vec![0x11; 20],
            iter: 1_000,
            dpsl: None,
            dpic: None,
            classes: vec![ClassEntry {
                class: 3,
                wrap: 2,
                wrapped_key: vec![0u8; 40],
            }],
        };
        assert!(unwrap_class_keys(b"pw", &kb).is_err());
    }

    #[test]
    fn unwrap_class_keys_no_passcode_class_is_ok_empty() {
        // Only device-only classes: nothing to unwrap, but that is not a wrong
        // password — return an empty map, not an error.
        let kb = Keybag {
            type_: 1,
            salt: vec![0x11; 20],
            iter: 1_000,
            dpsl: None,
            dpic: None,
            classes: vec![ClassEntry {
                class: 1,
                wrap: 1,
                wrapped_key: vec![0u8; 40],
            }],
        };
        let keys = unwrap_class_keys(b"pw", &kb).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn aes_cbc_decrypt_round_trips() {
        use cbc::Encryptor;
        use cbc::cipher::BlockEncryptMut;
        let key = [0x42u8; KEY_SZ];
        let iv = [0u8; BLOCK_SZ];
        let plain = b"sixteen byte msg"; // exactly one block
        let mut buf = plain.to_vec();
        let len = buf.len();
        let ct = Encryptor::<Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_mut::<NoPadding>(&mut buf, len)
            .unwrap()
            .to_vec();
        let got = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(got, plain);
    }

    #[test]
    fn aes_cbc_decrypt_rejects_misaligned() {
        let key = [0u8; KEY_SZ];
        let iv = [0u8; BLOCK_SZ];
        assert!(aes_cbc_decrypt(&key, &iv, &[0u8; 15]).is_err());
    }

    /// RFC 3394 AES key *wrap* — test-only inverse of [`aes_unwrap`], used to
    /// fabricate a valid wrapped class key for the unwrap tests. Kept separate
    /// from production code so a bug here cannot mask one in the unwrapper.
    fn aes_wrap_for_test(kek: &[u8; KEY_SZ], key_data: &[u8]) -> Vec<u8> {
        assert!(key_data.len().is_multiple_of(HALF_SZ));
        let n = key_data.len() / HALF_SZ;
        let cipher = Aes256::new(GenericArray::from_slice(kek));
        let mut a = KW_DEFAULT_IV;
        let mut r = key_data.to_vec();
        let n_u64 = n as u64;
        for j in 0..KW_ROUNDS {
            for i in 1..=n {
                let mut block = [0u8; BLOCK_SZ];
                block[..HALF_SZ].copy_from_slice(&a);
                block[HALF_SZ..].copy_from_slice(&r[(i - 1) * HALF_SZ..i * HALF_SZ]);
                cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
                let t = n_u64 * j + (i as u64);
                let t_be = t.to_be_bytes();
                a.copy_from_slice(&block[..HALF_SZ]);
                for k in 0..HALF_SZ {
                    a[k] ^= t_be[k];
                }
                r[(i - 1) * HALF_SZ..i * HALF_SZ].copy_from_slice(&block[HALF_SZ..]);
            }
        }
        let mut out = a.to_vec();
        out.extend_from_slice(&r);
        out
    }
}
