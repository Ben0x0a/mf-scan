//! Application-data location and selection, across acquisition types.
//!
//! Defines: this namespace and its public surface, re-exported from the submodules
//! below — the catalogue ([`AppCatalog`], [`detect`], [`entries_under`]) and its
//! data types ([`Platform`], [`ContainerKind`], [`GroupLink`], [`AppContainer`],
//! [`AppSummary`]).
//! Used by: the binary's `app` subcommand (`run::app`) for `app grep` (inventory),
//! `app paths` (per-app locations), and `app export`.
//! Uses: the data types ([`types`]), the catalogue/orchestration ([`catalog`]),
//! the per-platform resolvers ([`ios_ffs`], [`ios_backup`], [`android`]), and the
//! Mach-O [`entitlements`] reader.
//!
//! WHY this lives outside `engine`: locating an app's data is a concern layered on
//! top of an opened [`crate::core::source::Source`], entirely separate from byte-search —
//! mirroring the existing post-search container annotation, which is the only other
//! app-aware code in the tool. The search engine stays app-agnostic.
//!
//! ── How an app's containers are resolved per platform ───────────────────────
//! - iOS FFS: from the container metadata plists (see [`ios_ffs`]); App Groups are
//!   attributed to an app authoritatively via the app binary's code-signature
//!   entitlements ([`entitlements`]), with a reverse-DNS vendor-token heuristic as
//!   the fallback when the binary can't be read.
//! - iOS backup: from `Manifest.db`'s domains (see [`ios_backup`]); App Groups,
//!   having no binary to read, are attributed by the vendor-token heuristic only.
//! - Android: by package name appearing under known storage roots (see [`android`]).

pub mod android;
pub mod catalog;
pub mod entitlements;
pub mod ios_backup;
pub mod ios_ffs;
pub mod types;

pub use catalog::{AppCatalog, detect, entries_under};
pub use types::{AppContainer, AppSummary, ContainerKind, GroupLink, Platform};
