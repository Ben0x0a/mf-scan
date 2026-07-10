//! Per-OS artefact parsing — the low-level understanding of how each mobile
//! platform lays out its acquisition.
//!
//! Defines: the platform namespace. Today it holds:
//!   • `ios` — iOS-specific artefact resolution: the container GUID → bundle-id map
//!     and the iTunes/Finder backup reader (domain/relativePath view, keybag,
//!     decryption).
//! Used by: `apps` (the cross-platform app resolvers built on top), `report`, and
//! the binary's backup-aware reporting.
//! Uses: `core` (the `Source` trait + data types) and `formats` (the `sqlite` reader
//! for `Manifest.db`).
//!
//! WHY this folder: it isolates the *low-level, per-OS* parsing from the
//! *cross-platform* `apps` layer that consumes it. As Android-specific parsing grows
//! its own primitives, it lands here as `platform::android`, keeping the per-OS
//! knowledge symmetric and separate from the operations built on it.

pub mod ios;
