//! iOS-specific artefact resolution for mf-scan.
//!
//! Defines: this namespace for iOS-specific analysis modules. Currently exports
//! `containers` (app-container GUID → bundle-ID mapping). Future modules for
//! iOS artefacts (e.g. SpringBoard state, keychain, application state DB) belong
//! here.
//! Used by: `run::grep` (builds an `AppContainerMap` per source and annotates
//! `MatchRecord::bundle_id` in the post-search pass).
//! Uses: `containers`.

pub mod containers;
