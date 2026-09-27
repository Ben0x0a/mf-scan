//! iOS-specific artefact resolution for mf-scan.
//!
//! Defines: this namespace for iOS-specific analysis modules — `containers`
//! (app-container GUID → bundle-ID mapping, from the per-container metadata
//! plists), `references` (MobileContainerManager's code-signing/entitlement
//! database), `domains` (the backup domain grammar and its mount points), and
//! `backup` (the iTunes/Finder backup source). Future modules for
//! iOS artefacts (e.g. SpringBoard state, keychain, application state DB) belong
//! here.
//! Used by: `run::grep` (builds an `AppContainerMap` per source and annotates
//! `MatchRecord::bundle_id` in the post-search pass) and `ops::apps` (which reads
//! `containers` + `references` to resolve an app's data locations).
//! Uses: `backup`, `containers`, `domains`, `references`.

pub mod backup;
pub mod containers;
pub mod domains;
pub mod references;
