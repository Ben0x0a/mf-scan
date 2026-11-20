//! An app's ids resolved in a source: `--app` for the search commands (the path
//! prefixes of everything the app keeps), and what each id resolved to, said the same
//! way for `--app`, `app paths` and `app export`.
//!
//! Defines: `app_scope`, `scoped_run` (the run record of a search limited by
//! `--app`), and `report_resolution` (the one printer of an `AppResolution`).
//! Used by: `run::grep`, `run::find`, `run::diff` (both sides), and `run::app`
//! (`report_resolution`).
//! Uses: `mf_scan::ops::apps` (`AppCatalog`, `AppResolution`, `Platform`: the same
//! catalog `app paths` uses), `mf_scan::core::models::RunInfo`.
//!
//! WHY resolved per source, before the search: the containers differ by acquisition
//! (iOS file system, iOS backup, Android), and the search engine and its filter stay
//! app-agnostic: they only see path prefixes.
//!
//! WHY the resolution is printed: a filter that quietly searches more, or less, than
//! asked misleads. Each id's containers are counted, a group attributed by name only
//! (a guess) is named, data the app may keep outside its containers is pointed to,
//! and an id found nowhere is reported, as a search limited to nothing would
//! otherwise read as "no matches".

use mf_scan::core::models::RunInfo;

use crate::cmd::support::{Caveat, caveat};
use mf_scan::core::source::Source;
use mf_scan::ops::apps::{AppCatalog, AppResolution, ContainerKind, Platform};
use mf_scan::platform::ios::containers::AppContainerMap;

/// `--app`: the path prefixes of every container of the apps `ids` in `source` (data,
/// extensions and widgets, bundle, App Groups, as `app paths` lists them); `None`
/// without `--app`. What each id resolved to is printed to stderr, `label` naming
/// the source. `map`: the source's container map, when the caller built one.
pub(crate) fn app_scope(
    source: &dyn Source,
    ids: &[String],
    label: &str,
    map: Option<&AppContainerMap>,
) -> Option<Vec<String>> {
    if ids.is_empty() {
        return None;
    }
    let catalog = AppCatalog::build_with(source, map);
    let scope = catalog.scope(ids);
    for resolved in &scope.apps {
        report_resolution(resolved, catalog.platform, label);
    }
    for id in &scope.missing {
        eprintln!("{id:?}: no data for this app in {label}");
    }
    caveat(Caveat::Containers);
    Some(scope.prefixes)
}

/// Say on stderr what an app id resolved to in the source `label` names: the other
/// ids it matched, how many containers (and whether only App Groups), each group
/// attributed by name only, and what the app may keep outside its containers.
pub(crate) fn report_resolution(resolved: &AppResolution, platform: Platform, label: &str) {
    let id = &resolved.id;
    if !resolved.aliases.is_empty() {
        eprintln!("{id:?} also matched {}", resolved.aliases.join(", "));
    }
    let containers = &resolved.containers;
    if containers.is_empty() {
        eprintln!("{id:?}: no data for this app in {label}");
        return;
    }
    let groups = containers
        .iter()
        .filter(|c| c.kind == ContainerKind::AppGroup)
        .count();
    let of_groups = match groups {
        0 => String::new(),
        _ if resolved.only_groups() => {
            ", all App Groups (no container of its own: not installed?)".to_string()
        }
        n => format!(", {n} of them App Groups"),
    };
    eprintln!(
        "{id:?} in {label}: {} container(s){of_groups}",
        containers.len()
    );
    for group in resolved.guessed_groups() {
        eprintln!(
            "  group {} attributed by name only (no entitlement record): may not be this app's",
            group.id
        );
    }
    if let Some(note) = platform.outside_containers(id) {
        eprintln!("  note: {note}");
    }
}

/// `run`, recording the container prefixes `--app` limited this source to, when it
/// did: an export's report must say the search was not of the whole source.
pub(crate) fn scoped_run(run: &RunInfo, scope: Option<&[String]>) -> RunInfo {
    let mut run = run.clone();
    if let Some(prefixes) = scope {
        run.app_containers = prefixes.to_vec();
    }
    run
}
