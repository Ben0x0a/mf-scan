//! Behaviour presets loaded from YAML files in the `presets/` directory.
//!
//! Defines: `Preset` (the deserialised YAML structure); re-exports `fast` (the
//! compiled-in fallback globs for `--fast` when `_fast.yml` is unreachable).
//! Used by: `run` (loads and applies presets when `--preset` or `--fast` is given).
//! Uses: `serde` and `serde_yaml` for deserialisation.

pub mod fast;

use serde::Deserialize;

/// A preset loaded from a YAML file in the `presets/` directory.
///
/// All fields are optional — unset fields leave the CLI value unchanged.
/// CLI flags always take precedence; preset values act as defaults.
/// Unknown fields are rejected so that typos in YAML are caught early.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub exclude_media: Option<bool>,
    pub ignore_case: Option<bool>,
    pub literal_string: Option<bool>,
    pub recursive: Option<bool>,
    pub match_path: Option<bool>,
    pub inspect: Option<bool>,
    pub count: Option<bool>,
    pub verify: Option<bool>,
    pub threads: Option<usize>,
    pub path: Option<Vec<String>>,
    pub not_path: Option<Vec<String>>,
    pub file_type: Option<Vec<String>>,
}

impl Preset {
    /// Deserialise a preset from YAML text.
    pub fn from_yaml(content: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(content)
    }
}
