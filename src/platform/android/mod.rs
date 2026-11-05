//! Android artefact parsing.
//!
//! Defines: the Android namespace. Today it holds:
//!   • `backup` — the `adb backup` (`.ab`) reader: header, password unlock, payload
//!     decoding, presented as a [`crate::core::source::Source`].
//!   • `paths` — where each archive member lived on the device.
//! Used by: the binary's `support::sources` (opens an `.ab` operand) and `ops::rebuild`
//! (maps members to device paths).
//! Uses: `core` (the `Source` trait), and the password policy in `platform::ios::backup`.

pub mod backup;
pub mod paths;
