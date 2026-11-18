//! Identify-only executable and bytecode formats.
//!
//! Defines: [`Elf`], [`MachO`], [`Dex`], [`Hermes`].
//! Used by: `identify` (re-export) → `inspect::mod` registry.
//! Uses: `identify::has_at`, the `classify_inspector!` macro.

use super::has_at;

// ELF (Android `.so`, `.odex`, `.oat`): the magic, then class 1 (32-bit) or 2 (64-bit).
classify_inspector!(Elf, "elf", "executable", [], |c: &[u8]| has_at(
    c, 0, b"\x7FELF"
) && matches!(
    c.get(4),
    Some(1 | 2)
));

// Mach-O (iOS binaries and dylibs): 32- or 64-bit magic, either byte order. The
// universal ("fat") magic 0xCAFEBABE is left out: Java class files share it.
classify_inspector!(MachO, "macho", "executable", [], |c: &[u8]| [
    [0xFE, 0xED, 0xFA, 0xCE],
    [0xFE, 0xED, 0xFA, 0xCF],
    [0xCE, 0xFA, 0xED, 0xFE],
    [0xCF, 0xFA, 0xED, 0xFE],
]
.iter()
.any(|m| has_at(c, 0, m)));

// Android DEX: "dex\n", a three-digit version, then NUL.
classify_inspector!(Dex, "dex", "executable", [], |c: &[u8]| has_at(
    c, 0, b"dex\n"
) && c
    .get(4..7)
    .is_some_and(|v| v.iter().all(u8::is_ascii_digit))
    && c.get(7) == Some(&0));

// Hermes bytecode (React Native bundles, e.g. `index.android.bundle`, `.jsbundle`):
// the 8-byte magic 0x1F1903C103BC1FC6.
classify_inspector!(Hermes, "hermes", "executable", [], |c: &[u8]| has_at(
    c,
    0,
    &[0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F]
));
