//! Small crate-wide helpers with no domain logic.
//!
//! Defines: `sha256_hex` — the crate's single SHA-256-to-lowercase-hex helper.
//! Used by: `report::export` (export-report hashes), `decrypt::context` (audit
//! records), and the binary's `support::reporting` (`--verify` attestation).
//! Uses: `sha2`.
//!
//! WHY a foundation module: the hash helper is needed below (`decrypt`) and
//! above (`report`) the engine, so it must live beside `models`/`filter` at the
//! bottom of the layering — one definition, no drift between the three callers.

use sha2::{Digest, Sha256};

/// SHA-256 of `bytes` as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::sha256_hex;

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
