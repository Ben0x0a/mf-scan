//! `BackupKeyBag` TLV parser for encrypted iOS backups.
//!
//! Defines: [`Keybag`] / [`ClassEntry`] and [`parse`], which walk the binary
//! keybag blob found in `Manifest.plist` and extract the global KDF parameters
//! plus the per-protection-class wrapped keys.
//! Used by: `ios::backup::keys` (derives the keybag key from the global fields,
//! then AES-key-unwraps each class entry's wrapped key).
//! Uses: nothing beyond `anyhow` for typed errors — a pure, bounds-checked
//! byte-walk so a malformed blob degrades to `Err`, never a panic.
//!
//! ── Keybag blob format (what `parse` implements) ────────────────────────────
//! The keybag is a flat sequence of TLV records. Each record is:
//!   • a 4-byte ASCII tag (e.g. `b"SALT"`),
//!   • a 4-byte BIG-ENDIAN u32 length,
//!   • that many value bytes.
//! WHY big-endian: the keybag format is Apple's and stores its TLV lengths
//! big-endian (network byte order) — unlike the ZIP fields parsed elsewhere in
//! this crate, which are little-endian. Mixing the two up silently misreads
//! every length, so the endianness is called out here deliberately.
//!
//! The leading records are global: `TYPE` (u32), `UUID` (16 bytes), `HMCK`,
//! `WRAP` (u32), `SALT`, `ITER` (u32), and the iOS 10.2+ double-protection pair
//! `DPSL` (a second salt) and `DPIC` (a second iteration count). After the
//! header come the protection classes: a new class starts at each `CLAS` tag
//! (the u32 class number); within a class, `WRAP` (u32) flags how the class key
//! is wrapped and `WPKY` holds the wrapped class key (40 bytes for an
//! AES-256-wrapped 32-byte key). Other per-class tags (`KTYP`, `PBKY`, `UUID`)
//! are not needed for offline unwrap and are skipped — but skipped *by their
//! length*, so the walk stays aligned.

use anyhow::{Result, bail, ensure};

/// TLV tag length, in bytes (4-byte ASCII tag).
const TAG_SZ: usize = 4;
/// TLV length-field size, in bytes (a big-endian u32).
const LEN_SZ: usize = 4;
/// Size of a `UUID` value, in bytes.
const UUID_SZ: usize = 16;

/// One protection-class entry from the keybag.
///
/// `class` is the data-protection class number, `wrap` the wrapping flags (bit 1
/// = device-key-wrapped, bit 2 = passcode/keybag-key-wrapped), and
/// `wrapped_key` the RFC 3394 wrapped class key (40 bytes for a 32-byte key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassEntry {
    pub class: u32,
    pub wrap: u32,
    pub wrapped_key: Vec<u8>,
}

/// The parsed `BackupKeyBag`.
///
/// Holds the global KDF parameters and the list of per-class entries. `dpsl` /
/// `dpic` are present only on iOS 10.2+ keybags (the double-PBKDF2 form); they
/// are `None` on older backups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keybag {
    pub type_: u32,
    pub salt: Vec<u8>,
    pub iter: u32,
    pub dpsl: Option<Vec<u8>>,
    pub dpic: Option<u32>,
    pub classes: Vec<ClassEntry>,
}

/// Read a big-endian u32 from a TLV value, erroring if it is not exactly 4 bytes.
///
/// WHY strict: a `TYPE`/`WRAP`/`ITER`/`DPIC`/`CLAS` record whose value is not a
/// clean 4-byte integer means the blob is malformed or we are mis-aligned;
/// silently zero-padding would mask that and derive a wrong key.
fn read_u32(tag: &[u8], value: &[u8]) -> Result<u32> {
    ensure!(
        value.len() == 4,
        "keybag tag {:?} expected a 4-byte u32 value, got {} bytes",
        String::from_utf8_lossy(tag),
        value.len()
    );
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

/// Parse a `BackupKeyBag` blob into its global fields and per-class entries.
///
/// The blob is untrusted evidence, so every read is bounds-checked: a truncated
/// or malformed blob returns `Err` and never panics. Records appear in document
/// order; the per-class section begins at the first `CLAS` tag and each `CLAS`
/// opens a fresh [`ClassEntry`].
pub fn parse(blob: &[u8]) -> Result<Keybag> {
    let mut type_: Option<u32> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut iter: Option<u32> = None;
    let mut dpsl: Option<Vec<u8>> = None;
    let mut dpic: Option<u32> = None;
    let mut classes: Vec<ClassEntry> = Vec::new();
    // The class currently being assembled; flushed when the next `CLAS` opens or
    // at end-of-blob. `None` until the first `CLAS` is seen.
    let mut current: Option<ClassEntry> = None;

    let mut pos = 0usize;
    while pos < blob.len() {
        // Each record needs at least a tag + a length header; a trailing stub
        // shorter than that is a truncated blob, not a valid record.
        ensure!(
            pos + TAG_SZ + LEN_SZ <= blob.len(),
            "keybag truncated: {} bytes left at offset {pos}, need {} for a TLV header",
            blob.len() - pos,
            TAG_SZ + LEN_SZ
        );
        let tag = &blob[pos..pos + TAG_SZ];
        // Big-endian length — see the module-level WHY note.
        let len = u32::from_be_bytes([
            blob[pos + TAG_SZ],
            blob[pos + TAG_SZ + 1],
            blob[pos + TAG_SZ + 2],
            blob[pos + TAG_SZ + 3],
        ]) as usize;
        let val_start = pos + TAG_SZ + LEN_SZ;
        // A length that runs past the blob end is corruption: refuse it rather
        // than slice out of bounds (this is the panic-vs-Err boundary).
        ensure!(
            val_start + len <= blob.len(),
            "keybag record {:?} at offset {pos} claims {len} bytes but only {} remain",
            String::from_utf8_lossy(tag),
            blob.len() - val_start
        );
        let value = &blob[val_start..val_start + len];

        match tag {
            b"TYPE" => type_ = Some(read_u32(tag, value)?),
            b"SALT" => salt = Some(value.to_vec()),
            b"ITER" => iter = Some(read_u32(tag, value)?),
            b"DPSL" => dpsl = Some(value.to_vec()),
            b"DPIC" => dpic = Some(read_u32(tag, value)?),
            // The header UUID is 16 bytes; a per-class UUID also appears but is
            // not needed. We validate the length only for the global UUID (no
            // class open yet) and otherwise skip it past its length.
            b"UUID" if current.is_none() => {
                ensure!(
                    value.len() == UUID_SZ,
                    "keybag global UUID expected {UUID_SZ} bytes, got {}",
                    value.len()
                );
            }
            b"CLAS" => {
                // A new protection class begins: flush the one in progress.
                if let Some(entry) = current.take() {
                    classes.push(entry);
                }
                current = Some(ClassEntry {
                    class: read_u32(tag, value)?,
                    wrap: 0,
                    wrapped_key: Vec::new(),
                });
            }
            b"WRAP" => {
                let w = read_u32(tag, value)?;
                // `WRAP` appears once globally (before any `CLAS`) and once per
                // class. The per-class value is the one that drives unwrap; the
                // global one is informational and deliberately ignored here.
                if let Some(entry) = current.as_mut() {
                    entry.wrap = w;
                }
            }
            b"WPKY" => {
                if let Some(entry) = current.as_mut() {
                    entry.wrapped_key = value.to_vec();
                } else {
                    // A wrapped key with no open class means the section order is
                    // wrong — treat as malformed rather than drop it silently.
                    bail!("keybag WPKY record at offset {pos} appears before any CLAS");
                }
            }
            // KTYP, PBKY, HMCK and any unknown tag: not needed for offline
            // unwrap. Skip the value (we already advanced past it by `len`).
            _ => {}
        }

        pos = val_start + len;
    }

    // Flush the final class.
    if let Some(entry) = current.take() {
        classes.push(entry);
    }

    let type_ = type_.ok_or_else(|| anyhow::anyhow!("keybag missing TYPE field"))?;
    let salt = salt.ok_or_else(|| anyhow::anyhow!("keybag missing SALT field"))?;
    let iter = iter.ok_or_else(|| anyhow::anyhow!("keybag missing ITER field"))?;

    Ok(Keybag {
        type_,
        salt,
        iter,
        dpsl,
        dpic,
        classes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append one TLV record (4-byte tag, 4-byte big-endian length, value).
    fn push_tlv(out: &mut Vec<u8>, tag: &[u8; 4], value: &[u8]) {
        out.extend_from_slice(tag);
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }

    /// Build a small synthetic keybag with two protection classes.
    fn synthetic_keybag() -> Vec<u8> {
        let mut b = Vec::new();
        push_tlv(&mut b, b"VERS", &2u32.to_be_bytes());
        push_tlv(&mut b, b"TYPE", &1u32.to_be_bytes());
        push_tlv(&mut b, b"UUID", &[0xAA; 16]);
        push_tlv(&mut b, b"HMCK", &[0xBB; 40]);
        push_tlv(&mut b, b"WRAP", &0u32.to_be_bytes()); // global WRAP, ignored
        push_tlv(&mut b, b"SALT", &[0x11; 20]);
        push_tlv(&mut b, b"ITER", &10_000u32.to_be_bytes());
        push_tlv(&mut b, b"DPSL", &[0x22; 32]);
        push_tlv(&mut b, b"DPIC", &50_000u32.to_be_bytes());

        // Class 1: passcode-wrapped (wrap = 2), with a per-class UUID and KTYP
        // interleaved to prove they are skipped by length.
        push_tlv(&mut b, b"CLAS", &1u32.to_be_bytes());
        push_tlv(&mut b, b"WRAP", &2u32.to_be_bytes());
        push_tlv(&mut b, b"KTYP", &0u32.to_be_bytes());
        push_tlv(&mut b, b"WPKY", &[0x33; 40]);
        push_tlv(&mut b, b"UUID", &[0xCC; 16]); // per-class UUID, skipped

        // Class 3: device-key-wrapped only (wrap = 1).
        push_tlv(&mut b, b"CLAS", &3u32.to_be_bytes());
        push_tlv(&mut b, b"WRAP", &1u32.to_be_bytes());
        push_tlv(&mut b, b"WPKY", &[0x44; 40]);
        b
    }

    #[test]
    fn parses_global_fields_and_classes() {
        let kb = parse(&synthetic_keybag()).unwrap();
        assert_eq!(kb.type_, 1);
        assert_eq!(kb.salt, vec![0x11; 20]);
        assert_eq!(kb.iter, 10_000);
        assert_eq!(kb.dpsl, Some(vec![0x22; 32]));
        assert_eq!(kb.dpic, Some(50_000));
        assert_eq!(kb.classes.len(), 2);

        assert_eq!(
            kb.classes[0],
            ClassEntry {
                class: 1,
                wrap: 2,
                wrapped_key: vec![0x33; 40],
            }
        );
        assert_eq!(
            kb.classes[1],
            ClassEntry {
                class: 3,
                wrap: 1,
                wrapped_key: vec![0x44; 40],
            }
        );
    }

    #[test]
    fn absent_double_protection_fields_are_none() {
        let mut b = Vec::new();
        push_tlv(&mut b, b"TYPE", &1u32.to_be_bytes());
        push_tlv(&mut b, b"SALT", &[0x11; 20]);
        push_tlv(&mut b, b"ITER", &10_000u32.to_be_bytes());
        let kb = parse(&b).unwrap();
        assert_eq!(kb.dpsl, None);
        assert_eq!(kb.dpic, None);
        assert!(kb.classes.is_empty());
    }

    #[test]
    fn truncated_header_errors() {
        // Tag + only 2 of the 4 length bytes: not a full TLV header.
        let blob = b"SALT\x00\x00";
        assert!(parse(blob).is_err());
    }

    #[test]
    fn length_past_end_errors() {
        // SALT claims 100 bytes but none follow.
        let mut b = Vec::new();
        b.extend_from_slice(b"SALT");
        b.extend_from_slice(&100u32.to_be_bytes());
        assert!(parse(&b).is_err());
    }

    #[test]
    fn wrong_u32_length_errors() {
        // ITER with a 3-byte value must be rejected, not silently padded.
        let mut b = Vec::new();
        push_tlv(&mut b, b"TYPE", &1u32.to_be_bytes());
        push_tlv(&mut b, b"SALT", &[0x11; 20]);
        b.extend_from_slice(b"ITER");
        b.extend_from_slice(&3u32.to_be_bytes());
        b.extend_from_slice(&[0, 0, 1]);
        assert!(parse(&b).is_err());
    }

    #[test]
    fn missing_required_field_errors() {
        // No SALT.
        let mut b = Vec::new();
        push_tlv(&mut b, b"TYPE", &1u32.to_be_bytes());
        push_tlv(&mut b, b"ITER", &10_000u32.to_be_bytes());
        assert!(parse(&b).is_err());
    }
}
