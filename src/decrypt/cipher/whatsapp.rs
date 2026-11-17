//! WhatsApp crypt14 decryptor (AES-256-GCM over a zlib-compressed database).
//!
//! Defines: [`WhatsappCrypt`], the [`DbDecryptor`] for WhatsApp `.crypt14` backups,
//! and [`cipher_key_from_key_file`] (the AES key inside the app's `key` file).
//! Used by: `decrypt::cipher::decrypt` (dispatch).
//! Uses: `aes-gcm` (AES-256-GCM with a 16-byte nonce) and `flate2` (zlib).
//!
//! ── Format (what this implements) ────────────────────────────────────────────
//! Written from the format as wa-crypt-tools documents it (its key and database
//! modules and its `.proto` schemas; GPL-3.0, so only the facts are used, not code),
//! and validated against a real Google Pixel 9a extraction (December 2025): every
//! `.db.crypt14` backup decrypted with a verifying tag and inflated to SQLite.
//!
//! The key file (`/data/data/com.whatsapp/files/key`) is a Java-serialised `byte[]`
//! of 131 bytes: cipher version (2 bytes, `00 01`), key version (1), server salt (32),
//! Google-ID salt (16), its SHA-256 (32), an unused IV (16), then the 32-byte AES key.
//! The key is used as it is: crypt14 applies no key derivation.
//!
//! A `.crypt14` file is:
//!   • a protobuf varint, the size of the header that follows;
//!   • the header, a protobuf `BackupPrefix`. Its field 2 (`wa_provided_key_data`)
//!     holds the 16-byte GCM nonce in its own field 5 (`encryption_iv`). Field 3 is
//!     set instead for crypt15, which this module does not decrypt;
//!   • the AES-256-GCM ciphertext of the zlib-compressed database, then the 16-byte
//!     tag, then, in a single-file backup, an MD5 of everything before it (16 bytes).
//!     A multi-file backup has no MD5, so the tag is last. Both layouts are tried; the
//!     GCM tag only verifies on the right one, which doubles as the key check.

use std::io::Read;

use aes_gcm::AesGcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::generic_array::typenum::U16;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use anyhow::{Result, bail, ensure};
use flate2::read::ZlibDecoder;

use crate::decrypt::cipher::{DbDecryptor, DecryptedDb};
use crate::decrypt::profile::{CipherSpec, KeyMaterial, WhatsappCryptParams};

/// AES-256-GCM with WhatsApp's 16-byte nonce (a non-96-bit nonce, handled via GHASH).
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// GCM nonce length, in bytes (WhatsApp uses 16, not the usual 12).
const IV_LEN: usize = 16;
/// GCM tag length, and the MD5 checksum's, in bytes.
const TAG_LEN: usize = 16;
const MD5_LEN: usize = 16;
/// AES-256 key length.
const KEY_LEN: usize = 32;

/// Java serialisation's stream magic and version (`ObjectOutputStream`).
const JAVA_STREAM_MAGIC: &[u8] = &[0xac, 0xed, 0x00, 0x05];
/// Java serialisation's end-of-class-description marker then null superclass, the two
/// bytes just before an array's length.
const JAVA_CLASS_DESC_END: &[u8] = &[0x78, 0x70];
/// The key file's payload length, and the AES key's offset in it.
const KEY_PAYLOAD_LEN: usize = 131;
const CIPHER_KEY_OFFSET: usize = 99;
/// The only cipher version the payload is known to carry.
const KEY_CIPHER_VERSION: &[u8] = &[0x00, 0x01];

/// Protobuf field numbers in the `BackupPrefix` header.
const FIELD_C14_KEY_DATA: u64 = 2;
const FIELD_C15_KEY_DATA: u64 = 3;
const FIELD_ENCRYPTION_IV: u64 = 5;

/// Hard ceiling on the inflated output from a WhatsApp backup database.
///
/// WHY: an unbounded `read_to_end` would let a crafted (but GCM-authenticated)
/// payload expand without limit and exhaust RAM. The cap is generous: the largest
/// known real WhatsApp message database fits well within 2 GiB even for heavy users.
/// Hitting it is an error, not a silent truncation, which would produce a corrupt
/// SQLite file.
const INFLATE_WHATSAPP_CAP: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// The WhatsApp crypt14 decryptor.
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
            CipherSpec::WhatsappCrypt(params) => decrypt_crypt14(ciphertext, key, params),
            _ => bail!("whatsapp-crypt decryptor invoked with a non-whatsapp cipher spec"),
        }
    }
}

/// The 32-byte AES key inside a WhatsApp `key` file.
///
/// Accepts the file as the app writes it (a Java-serialised `byte[]`), its 131-byte
/// payload alone, or a bare 32-byte key, so a key exported by another tool works too.
pub fn cipher_key_from_key_file(file: &[u8]) -> Result<[u8; KEY_LEN]> {
    let payload = if file.starts_with(JAVA_STREAM_MAGIC) {
        java_byte_array(file)?
    } else {
        file
    };
    let key = match payload.len() {
        KEY_LEN => payload,
        KEY_PAYLOAD_LEN => {
            ensure!(
                payload.starts_with(KEY_CIPHER_VERSION),
                "WhatsApp key file: unsupported cipher version {:02x?}",
                &payload[..2]
            );
            &payload[CIPHER_KEY_OFFSET..]
        }
        n => bail!("WhatsApp key file: a {n}-byte payload is neither a key file nor a key"),
    };
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(key);
    Ok(out)
}

/// The contents of the single `byte[]` a Java-serialised stream holds.
///
/// HOW: the array's class description ends with `78 70`, then comes its length as a
/// big-endian `u32`, then the bytes, which must run to the end of the stream.
fn java_byte_array(stream: &[u8]) -> Result<&[u8]> {
    let Some(end) = find(stream, JAVA_CLASS_DESC_END) else {
        bail!("WhatsApp key file: no byte array in the Java-serialised stream");
    };
    let len_at = end + JAVA_CLASS_DESC_END.len();
    let Some(len) = stream.get(len_at..len_at + 4) else {
        bail!("WhatsApp key file: the byte array's length is cut off");
    };
    let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    let data = &stream[len_at + 4..];
    ensure!(
        data.len() == len,
        "WhatsApp key file: the array says {len} bytes but {} follow",
        data.len()
    );
    Ok(data)
}

/// Decrypt a `.crypt14` file.
fn decrypt_crypt14(file: &[u8], key: &KeyMaterial, p: &WhatsappCryptParams) -> Result<DecryptedDb> {
    let key_bytes = match key {
        KeyMaterial::Raw(bytes) | KeyMaterial::Passphrase(bytes) => bytes,
    };
    let aes_key = cipher_key_from_key_file(key_bytes)?;
    let (iv, body) = parse_header(file)?;
    let cipher = Aes256Gcm16::new_from_slice(&aes_key).expect("a 32-byte AES-256 key");
    let nonce = GenericArray::<u8, U16>::from_slice(iv);

    // Single-file backup (tag then MD5) first, then multi-file (tag last).
    let layouts = [body.len().checked_sub(MD5_LEN), Some(body.len())];
    for end in layouts.into_iter().flatten() {
        if end < TAG_LEN {
            continue;
        }
        let Ok(compressed) = cipher.decrypt(nonce, &body[..end]) else {
            continue;
        };
        let plaintext = if p.zlib {
            inflate_zlib(&compressed)?
        } else {
            compressed
        };
        return Ok(DecryptedDb {
            plaintext,
            verified: true,
        });
    }
    bail!("WhatsApp crypt14: the GCM tag did not verify (wrong key, or not a crypt14 file)")
}

/// Split a `.crypt14` file into its 16-byte nonce and the encrypted body after the
/// header.
fn parse_header(file: &[u8]) -> Result<(&[u8], &[u8])> {
    let (header_len, used) = read_varint(file)
        .ok_or_else(|| anyhow::anyhow!("WhatsApp crypt14: the header size is cut off"))?;
    let header_end = usize::try_from(header_len)
        .ok()
        .and_then(|n| used.checked_add(n))
        .filter(|&end| end <= file.len())
        .ok_or_else(|| anyhow::anyhow!("WhatsApp crypt14: the header runs past the file"))?;
    let header = &file[used..header_end];

    let mut iv = None;
    for (field, value) in protobuf_fields(header)? {
        match (field, value) {
            (FIELD_C15_KEY_DATA, Some(_)) => {
                bail!("this is a crypt15 backup, which is not supported (only crypt14)")
            }
            (FIELD_C14_KEY_DATA, Some(key_data)) => {
                for (inner, inner_value) in protobuf_fields(key_data)? {
                    if inner == FIELD_ENCRYPTION_IV {
                        iv = inner_value;
                    }
                }
            }
            _ => {}
        }
    }
    let Some(iv) = iv else {
        bail!("WhatsApp crypt14: the header holds no encryption IV (not a crypt14 file)");
    };
    ensure!(
        iv.len() == IV_LEN,
        "WhatsApp crypt14: the IV is {} bytes, not {IV_LEN}",
        iv.len()
    );
    Ok((iv, &file[header_end..]))
}

/// One protobuf field: its number, and its bytes when it is length-delimited (`None`
/// for the other wire types, whose values are skipped).
type Field<'a> = (u64, Option<&'a [u8]>);

/// Every top-level field of a protobuf message.
fn protobuf_fields(message: &[u8]) -> Result<Vec<Field<'_>>> {
    let cut = || anyhow::anyhow!("WhatsApp crypt14: the header is not a valid protobuf message");
    let mut fields = Vec::new();
    let mut at = 0;
    while at < message.len() {
        let (tag, used) = read_varint(&message[at..]).ok_or_else(cut)?;
        at += used;
        let value = match tag & 0x7 {
            0 => {
                let (_, used) = read_varint(&message[at..]).ok_or_else(cut)?;
                at += used;
                None
            }
            1 => {
                at = at
                    .checked_add(8)
                    .filter(|&e| e <= message.len())
                    .ok_or_else(cut)?;
                None
            }
            2 => {
                let (len, used) = read_varint(&message[at..]).ok_or_else(cut)?;
                let start = at + used;
                let end = usize::try_from(len)
                    .ok()
                    .and_then(|n| start.checked_add(n))
                    .filter(|&e| e <= message.len())
                    .ok_or_else(cut)?;
                at = end;
                Some(&message[start..end])
            }
            5 => {
                at = at
                    .checked_add(4)
                    .filter(|&e| e <= message.len())
                    .ok_or_else(cut)?;
                None
            }
            _ => return Err(cut()),
        };
        fields.push((tag >> 3, value));
    }
    Ok(fields)
}

/// A protobuf varint at the start of `data`, and how many bytes it took.
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &byte) in data.iter().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// The first position of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
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
    // truncated (corrupt) SQLite file.
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
    use std::io::Write;

    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    const AES_KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const IV: [u8; IV_LEN] = [0x07; IV_LEN];
    const PLAIN: &[u8] = b"SQLite format 3\0 a WhatsApp message store";

    /// A key file as the app writes it: the Java `byte[]` header, then the payload.
    fn key_file() -> Vec<u8> {
        let mut payload = vec![0x00, 0x01, 0x02];
        payload.extend_from_slice(&[0x11; 32 + 16 + 32 + 16]);
        payload.extend_from_slice(&AES_KEY);
        assert_eq!(payload.len(), KEY_PAYLOAD_LEN);
        let mut file = JAVA_STREAM_MAGIC.to_vec();
        file.extend_from_slice(&[0x75, 0x72, 0x00, 0x02, b'[', b'B']);
        file.extend_from_slice(&[
            0xac, 0xf3, 0x17, 0xf8, 0x06, 0x08, 0x54, 0xe0, 0x02, 0x00, 0x00,
        ]);
        file.extend_from_slice(JAVA_CLASS_DESC_END);
        file.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        file.extend_from_slice(&payload);
        file
    }

    /// A `.crypt14` file; `with_md5` appends the single-file trailer (any 16 bytes:
    /// the decryptor finds the tag by the GCM check, not by the MD5).
    fn crypt14(with_md5: bool) -> Vec<u8> {
        let mut key_data = vec![0x0a, 0x02, 0x00, 0x01]; // field 1: cipher header
        key_data.extend_from_slice(&[0x2a, IV_LEN as u8]); // field 5: the IV
        key_data.extend_from_slice(&IV);
        let mut header = vec![0x08, 0x00]; // field 1: a varint
        header.push(0x12); // field 2: the crypt14 key data
        header.push(key_data.len() as u8);
        header.extend_from_slice(&key_data);

        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(PLAIN).unwrap();
        let compressed = zlib.finish().unwrap();
        let cipher = Aes256Gcm16::new_from_slice(&AES_KEY).unwrap();
        let sealed = cipher
            .encrypt(
                GenericArray::<u8, U16>::from_slice(&IV),
                compressed.as_slice(),
            )
            .unwrap();

        let mut file = vec![header.len() as u8];
        file.extend_from_slice(&header);
        file.extend_from_slice(&sealed);
        if with_md5 {
            file.extend_from_slice(&[0x5a; MD5_LEN]);
        }
        file
    }

    fn params() -> WhatsappCryptParams {
        WhatsappCryptParams { zlib: true }
    }

    #[test]
    fn the_key_is_the_last_32_bytes_of_the_payload() {
        assert_eq!(cipher_key_from_key_file(&key_file()).unwrap(), AES_KEY);
        assert_eq!(cipher_key_from_key_file(&AES_KEY).unwrap(), AES_KEY);
        assert!(cipher_key_from_key_file(&[0u8; 50]).is_err());
    }

    #[test]
    fn decrypts_single_and_multi_file_layouts() {
        for with_md5 in [true, false] {
            let out = decrypt_crypt14(&crypt14(with_md5), &KeyMaterial::Raw(key_file()), &params())
                .unwrap();
            assert!(out.verified);
            assert_eq!(out.plaintext, PLAIN);
        }
    }

    #[test]
    fn a_wrong_key_fails_the_tag() {
        let err = decrypt_crypt14(
            &crypt14(true),
            &KeyMaterial::Raw(vec![9; KEY_LEN]),
            &params(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("did not verify"), "{err}");
    }

    #[test]
    fn a_crypt15_header_is_refused_by_name() {
        let header = [0x1a, 0x00]; // field 3, empty
        let mut file = vec![header.len() as u8];
        file.extend_from_slice(&header);
        file.extend_from_slice(&[0u8; 40]);
        let err = parse_header(&file).unwrap_err();
        assert!(err.to_string().contains("crypt15"), "{err}");
    }

    #[test]
    fn a_header_running_past_the_file_is_an_error() {
        assert!(parse_header(&[0x7f, 0x12]).is_err());
        assert!(parse_header(&[]).is_err());
    }
}
