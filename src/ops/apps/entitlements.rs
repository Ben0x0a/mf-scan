//! Mach-O code-signature entitlements reader (iOS app binaries).
//!
//! Defines: [`application_groups`] — extract the
//! `com.apple.security.application-groups` array from an iOS app executable's
//! embedded code-signature entitlements. This is the *authoritative* declaration
//! of which App Groups an app may write to, used by the `apps` module to attribute
//! shared-container data to the owning app (a name heuristic cannot — e.g.
//! Instagram declares `group.com.facebook.family`).
//! Used by: `crate::ops::apps::ios_ffs` (resolves an app's groups for `app paths` /
//! `app export`).
//! Uses: the `plist` crate (already a dependency) to parse the entitlements XML
//! plist; everything else is manual, bounds-checked byte parsing of the Mach-O
//! and Code-Signing structures — no new dependency.
//!
//! ── What is parsed, and why this layering ───────────────────────────────────
//! An iOS app's entitlements (including its application-groups) are embedded in
//! the main executable's code signature, NOT in `Info.plist` or a sidecar file
//! (verified on a real FFS: App Store apps ship no `embedded.mobileprovision` and
//! no `application-groups` in `Info.plist`). The path to them is:
//!
//! ```text
//! Mach-O file ─► (fat? pick a slice) ─► mach_header ─► load commands
//!   ─► LC_CODE_SIGNATURE ─► Code-Signing SuperBlob
//!     ─► slot CSSLOT_ENTITLEMENTS (0x5) ─► embedded-entitlements blob (0xfade7171)
//!       ─► XML plist ─► com.apple.security.application-groups
//! ```
//!
//! Mach-O headers/load commands are host-endian (little for arm64; the byte-swapped
//! `CIGAM` magics are handled). The Code-Signing structures are ALWAYS big-endian.
//!
//! Degrade-don't-die: any malformed/short/absent structure yields `None`, and the
//! caller falls back to the reverse-DNS vendor-token heuristic. We never panic on a
//! crafted or truncated binary — every read is bounds-checked.

use std::io::Cursor;

use plist::Value;

/// 64-bit Mach-O magic (`MH_MAGIC_64`) and its byte-swapped form (`MH_CIGAM_64`).
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
/// 32-bit Mach-O magic (`MH_MAGIC`) and its byte-swapped form (`MH_CIGAM`).
const MH_MAGIC_32: u32 = 0xFEED_FACE;
const MH_CIGAM_32: u32 = 0xCEFA_EDFE;
/// Universal ("fat") binary magics, stored big-endian on disk. `FAT_MAGIC_64`
/// uses 64-bit offsets/sizes in its arch table.
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
/// `cputype` of an arm64 slice (`CPU_ARCH_ABI64 | CPU_TYPE_ARM`); the slice we
/// prefer in a fat binary (modern iOS devices are arm64/arm64e).
const CPU_TYPE_ARM64: u32 = 0x0100_000C;

/// `LC_CODE_SIGNATURE` load command — points at the Code-Signing SuperBlob.
const LC_CODE_SIGNATURE: u32 = 0x1D;

/// Code-Signing SuperBlob magic (`CSMAGIC_EMBEDDED_SIGNATURE`).
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
/// SuperBlob slot index holding the XML entitlements (`CSSLOT_ENTITLEMENTS`).
const CSSLOT_ENTITLEMENTS: u32 = 0x5;
/// Magic of the embedded XML-entitlements blob (`CSMAGIC_EMBEDDED_ENTITLEMENTS`).
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xFADE_7171;

/// The entitlements key whose array lists the app's App Groups.
const APPLICATION_GROUPS_KEY: &str = "com.apple.security.application-groups";

/// Extract the `com.apple.security.application-groups` identifiers from a Mach-O
/// executable's embedded code-signature entitlements.
///
/// Returns `None` when `bytes` is not a parseable Mach-O, carries no code
/// signature, has no XML entitlements blob, or declares no application-groups —
/// each a normal "no authoritative answer" outcome the caller handles by falling
/// back to the vendor-token heuristic.
pub fn application_groups(bytes: &[u8]) -> Option<Vec<String>> {
    let superblob = code_signature(bytes)?;
    let xml = entitlements_xml(superblob)?;
    parse_application_groups(xml)
}

/// Locate the Code-Signing SuperBlob within a Mach-O (resolving a fat slice
/// first), returned as the byte slice starting at the SuperBlob magic.
fn code_signature(bytes: &[u8]) -> Option<&[u8]> {
    // A fat/universal binary wraps several thin Mach-Os; pick a slice (arm64 if
    // present, else the first) and recurse into it.
    let magic_be = read_u32_be(bytes, 0)?;
    if magic_be == FAT_MAGIC || magic_be == FAT_MAGIC_64 {
        let slice = fat_slice(bytes, magic_be == FAT_MAGIC_64)?;
        return code_signature(slice);
    }

    // Thin Mach-O: determine bit-ness and endianness from the magic, then walk the
    // load commands for LC_CODE_SIGNATURE.
    let raw = read_u32_ne(bytes, 0)?;
    let (le, header_len) = match raw {
        MH_MAGIC_64 => (cfg!(target_endian = "little"), 32),
        MH_CIGAM_64 => (!cfg!(target_endian = "little"), 32),
        MH_MAGIC_32 => (cfg!(target_endian = "little"), 28),
        MH_CIGAM_32 => (!cfg!(target_endian = "little"), 28),
        _ => return None,
    };
    // mach_header(_64): magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, …
    // ncmds is the 5th u32 (offset 16).
    let ncmds = read_u32(bytes, 16, le)?;

    let mut off = header_len;
    for _ in 0..ncmds {
        let cmd = read_u32(bytes, off, le)?;
        let cmdsize = read_u32(bytes, off + 4, le)? as usize;
        // cmdsize must advance us (a zero/short size would loop forever) and stay
        // within the file — guard both, since a crafted binary could violate them.
        if cmdsize < 8 || off.checked_add(cmdsize)? > bytes.len() {
            return None;
        }
        if cmd == LC_CODE_SIGNATURE {
            // linkedit_data_command: cmd, cmdsize, dataoff, datasize.
            let dataoff = read_u32(bytes, off + 8, le)? as usize;
            let datasize = read_u32(bytes, off + 12, le)? as usize;
            let end = dataoff.checked_add(datasize)?;
            return bytes.get(dataoff..end);
        }
        off += cmdsize;
    }
    None
}

/// Pick a thin Mach-O slice out of a fat binary: the arm64 slice if present, else
/// the first. Returns the slice bytes.
fn fat_slice(bytes: &[u8], is_64: bool) -> Option<&[u8]> {
    // fat_header (big-endian): magic, nfat_arch.
    let nfat = read_u32_be(bytes, 4)?;
    // fat_arch is 20 bytes (32-bit offsets) or fat_arch_64 is 32 bytes.
    let arch_size = if is_64 { 32 } else { 20 };
    let mut first: Option<&[u8]> = None;
    for i in 0..nfat as usize {
        let base = 8 + i.checked_mul(arch_size)?;
        let cputype = read_u32_be(bytes, base)?;
        // offset/size are u32 at base+8/+12 (fat_arch) or u64 at base+8/+16
        // (fat_arch_64). We only handle reachable (<=4 GiB) offsets.
        let (offset, size) = if is_64 {
            (
                read_u64_be(bytes, base + 8)? as usize,
                read_u64_be(bytes, base + 16)? as usize,
            )
        } else {
            (
                read_u32_be(bytes, base + 8)? as usize,
                read_u32_be(bytes, base + 12)? as usize,
            )
        };
        let slice = bytes.get(offset..offset.checked_add(size)?)?;
        if cputype == CPU_TYPE_ARM64 {
            return Some(slice);
        }
        first.get_or_insert(slice);
    }
    first
}

/// Walk the Code-Signing SuperBlob index for the entitlements slot and return the
/// XML plist payload of its embedded-entitlements blob.
///
/// The SuperBlob and all its structures are big-endian. Blob offsets in the index
/// are relative to the start of the SuperBlob (`superblob[0]`).
fn entitlements_xml(superblob: &[u8]) -> Option<&[u8]> {
    if read_u32_be(superblob, 0)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return None;
    }
    let count = read_u32_be(superblob, 8)?;
    // Index entries follow the 12-byte header: each is (type u32, offset u32).
    for i in 0..count as usize {
        let entry = 12 + i.checked_mul(8)?;
        let slot_type = read_u32_be(superblob, entry)?;
        let blob_off = read_u32_be(superblob, entry + 4)? as usize;
        if slot_type != CSSLOT_ENTITLEMENTS {
            continue;
        }
        // The entitlements blob: magic, length, then (length-8) bytes of XML.
        if read_u32_be(superblob, blob_off)? != CSMAGIC_EMBEDDED_ENTITLEMENTS {
            return None;
        }
        let length = read_u32_be(superblob, blob_off + 4)? as usize;
        let start = blob_off + 8;
        let end = blob_off.checked_add(length)?;
        return superblob.get(start..end);
    }
    None
}

/// Parse the entitlements XML plist and return the application-groups array.
fn parse_application_groups(xml: &[u8]) -> Option<Vec<String>> {
    let value = Value::from_reader(Cursor::new(xml)).ok()?;
    let dict = value.as_dictionary()?;
    let array = dict.get(APPLICATION_GROUPS_KEY)?.as_array()?;
    let groups: Vec<String> = array
        .iter()
        .filter_map(|v| v.as_string().map(str::to_string))
        .collect();
    // An empty array carries no information — treat it as "no answer" so the
    // caller can still try the heuristic.
    if groups.is_empty() {
        None
    } else {
        Some(groups)
    }
}

/// Read a `u32` at `offset` with the given endianness (`le = true` ⇒ little).
fn read_u32(bytes: &[u8], offset: usize, le: bool) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

/// Read a `u32` at `offset` in big-endian (Code-Signing / fat structures).
fn read_u32_be(bytes: &[u8], offset: usize) -> Option<u32> {
    read_u32(bytes, offset, false)
}

/// Read a `u32` at `offset` in native byte order (for magic detection).
fn read_u32_ne(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(raw))
}

/// Read a `u64` at `offset` in big-endian (fat_arch_64 offsets/sizes).
fn read_u64_be(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_be_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal thin arm64 Mach-O (little-endian) with a single
    /// `LC_CODE_SIGNATURE` load command pointing at a Code-Signing SuperBlob that
    /// carries one entitlements slot holding the given XML. This is a SYNTHETIC
    /// binary — no bytes from any real app — modelled on the documented Mach-O and
    /// Code-Signing layouts the parser walks.
    fn synthetic_macho(entitlements_xml: &[u8]) -> Vec<u8> {
        // Build the SuperBlob first so we know its size, then place it after the
        // header + one load command.
        let ent_blob = {
            let mut b = Vec::new();
            b.extend_from_slice(&CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
            b.extend_from_slice(&((8 + entitlements_xml.len()) as u32).to_be_bytes());
            b.extend_from_slice(entitlements_xml);
            b
        };
        // SuperBlob: magic, length, count, then index (type, offset), then blobs.
        let index_len = 12 + 8; // header + one index entry
        let superblob = {
            let mut b = Vec::new();
            b.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
            b.extend_from_slice(&((index_len + ent_blob.len()) as u32).to_be_bytes());
            b.extend_from_slice(&1u32.to_be_bytes()); // count
            b.extend_from_slice(&CSSLOT_ENTITLEMENTS.to_be_bytes());
            b.extend_from_slice(&(index_len as u32).to_be_bytes()); // blob offset
            b.extend_from_slice(&ent_blob);
            b
        };

        let header_len = 32usize;
        let cmd_len = 16usize; // linkedit_data_command
        let sig_off = header_len + cmd_len;

        let mut out = Vec::new();
        // mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds,
        // flags, reserved.
        out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        out.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        out.extend_from_slice(&2u32.to_le_bytes()); // filetype MH_EXECUTE
        out.extend_from_slice(&1u32.to_le_bytes()); // ncmds
        out.extend_from_slice(&(cmd_len as u32).to_le_bytes()); // sizeofcmds
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        // LC_CODE_SIGNATURE: cmd, cmdsize, dataoff, datasize.
        out.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&(cmd_len as u32).to_le_bytes());
        out.extend_from_slice(&(sig_off as u32).to_le_bytes());
        out.extend_from_slice(&(superblob.len() as u32).to_le_bytes());
        // The SuperBlob payload.
        out.extend_from_slice(&superblob);
        out
    }

    const SAMPLE_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.application-groups</key>
<array><string>group.com.burbn.instagram</string><string>group.com.facebook.family</string></array>
</dict></plist>"#;

    #[test]
    fn extracts_application_groups_from_synthetic_macho() {
        let macho = synthetic_macho(SAMPLE_PLIST);
        let groups = application_groups(&macho).expect("groups parsed");
        assert_eq!(
            groups,
            vec![
                "group.com.burbn.instagram".to_string(),
                "group.com.facebook.family".to_string()
            ]
        );
    }

    #[test]
    fn non_macho_returns_none() {
        assert!(application_groups(b"not a mach-o binary at all").is_none());
    }

    #[test]
    fn macho_without_groups_key_returns_none() {
        let plist = br#"<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>application-identifier</key><string>X.com.app</string></dict></plist>"#;
        let macho = synthetic_macho(plist);
        assert!(application_groups(&macho).is_none());
    }

    #[test]
    fn truncated_after_load_command_returns_none() {
        let macho = synthetic_macho(SAMPLE_PLIST);
        // Chop off the SuperBlob payload entirely — the LC points past EOF.
        let truncated = &macho[..40];
        assert!(application_groups(truncated).is_none());
    }
}
