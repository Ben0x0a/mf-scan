//! Application-data location and selection, across acquisition types.
//!
//! Defines: this namespace and its public surface, re-exported from the submodules
//! below — the catalogue ([`AppCatalog`], [`detect`], [`entries_under`]) and its
//! data types ([`Platform`], [`ContainerKind`], [`GroupLink`], [`AppContainer`],
//! [`AppSummary`], [`SigningRecord`]).
//! Used by: the binary's `app` subcommand (`run::app`) for `app grep` (inventory),
//! `app paths` (per-app locations), and `app export`.
//! Uses: the data types ([`types`]), the catalogue/orchestration ([`catalog`]),
//! the per-platform resolvers ([`ios_ffs`], [`ios_backup`], [`android`]), and
//! [`crate::platform::ios::references`] (MobileContainerManager's entitlement records).
//!
//! WHY this lives outside `engine`: locating an app's data is a concern layered on
//! top of an opened [`crate::core::source::Source`], entirely separate from byte-search —
//! mirroring the existing post-search container annotation, which is the only other
//! app-aware code in the tool. The search engine stays app-agnostic.
//!
//! ── How an app's containers are resolved per platform ───────────────────────
//! - iOS FFS: from the container metadata plists (see [`ios_ffs`]), which also
//!   declare each extension container's owning app. App Groups are attributed
//!   authoritatively from MobileContainerManager's `references.sqlite3`
//!   ([`crate::platform::ios::references`]), with a reverse-DNS vendor-token
//!   heuristic as the fallback when the source has no record for the app.
//! - iOS backup: from `Manifest.db`'s domains (see [`ios_backup`]); a backup ships
//!   no MCM database, so App Groups are attributed by the vendor-token heuristic
//!   only — which is why that heuristic is kept rather than removed.
//! - Android: by package name appearing under known storage roots (see [`android`]).

pub mod android;
pub mod catalog;
pub mod globs;

pub mod ios_backup;
pub mod ios_ffs;
pub mod types;

pub use catalog::{AppCatalog, detect, entries_under};
pub use globs::{AppGlob, expand as expand_app_globs};
pub use types::{AppContainer, AppSummary, ContainerKind, GroupLink, Platform, SigningRecord};
