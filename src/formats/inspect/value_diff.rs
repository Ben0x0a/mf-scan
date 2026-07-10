//! Structured diff of two JSON value trees — the shared core behind the JSON and
//! plist intra-file diffs.
//!
//! Defines: [`diff_values`], which walks two [`serde_json::Value`] trees and reports
//! the key paths that were added, removed, or changed.
//! Used by: `inspect::json` and `inspect::plist` (which parse their format into a
//! `Value` and call this).
//! Uses: `serde_json`, `crate::core::models::ContentDiff`.
//!
//! Objects are compared key-by-key; arrays are compared by index (a positional diff
//! — good enough for a "what changed" summary, without the cost of an alignment).
//! Scalars compare by value. Paths read like `$.users[3].token`.

use serde_json::{Value, json};

use crate::core::models::ContentDiff;

/// Cap on how many paths of each kind are listed in the detail (a changed config can
/// touch thousands of keys; the counts stay exact, the listing stays bounded).
const MAX_LISTED: usize = 50;

/// Diff two value trees into a [`ContentDiff`] tagged with `format`.
pub(super) fn diff_values(format: &str, old: &Value, new: &Value) -> ContentDiff {
    let mut d = Paths::default();
    walk("$", old, new, &mut d);

    let summary = format!(
        "{} key(s) added, {} removed, {} changed",
        d.added.len(),
        d.removed.len(),
        d.changed.len()
    );
    let detail = json!({
        "counts": {
            "added": d.added.len(),
            "removed": d.removed.len(),
            "changed": d.changed.len(),
        },
        "added": cap(&d.added),
        "removed": cap(&d.removed),
        "changed": cap(&d.changed),
    });
    ContentDiff {
        format: format.to_string(),
        summary,
        detail,
    }
}

/// The accumulated changed paths, by kind.
#[derive(Default)]
struct Paths {
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
}

/// Recursively compare `old` and `new` at `path`, recording differences in `d`.
fn walk(path: &str, old: &Value, new: &Value, d: &mut Paths) {
    match (old, new) {
        (Value::Object(o), Value::Object(n)) => {
            for (k, ov) in o {
                let child = format!("{path}.{k}");
                match n.get(k) {
                    Some(nv) => walk(&child, ov, nv, d),
                    None => d.removed.push(child),
                }
            }
            for k in n.keys() {
                if !o.contains_key(k) {
                    d.added.push(format!("{path}.{k}"));
                }
            }
        }
        (Value::Array(o), Value::Array(n)) => {
            let common = o.len().min(n.len());
            for i in 0..common {
                walk(&format!("{path}[{i}]"), &o[i], &n[i], d);
            }
            for i in common..o.len() {
                d.removed.push(format!("{path}[{i}]"));
            }
            for i in common..n.len() {
                d.added.push(format!("{path}[{i}]"));
            }
        }
        // A scalar (or a type change, e.g. string -> object) counts as one change.
        _ => {
            if old != new {
                d.changed.push(path.to_string());
            }
        }
    }
}

/// The first [`MAX_LISTED`] paths (the counts in the detail stay exact).
fn cap(paths: &[String]) -> Vec<&str> {
    paths.iter().take(MAX_LISTED).map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::diff_values;
    use serde_json::json;

    #[test]
    fn reports_added_removed_and_changed_paths() {
        let old = json!({ "a": 1, "obj": { "k": "v" }, "arr": [1, 2, 3], "gone": true });
        let new = json!({ "a": 1, "obj": { "k": "w" }, "arr": [1, 2], "new": 5 });
        let d = diff_values("json", &old, &new);

        assert_eq!(d.format, "json");
        // added: $.new; removed: $.gone and $.arr[2]; changed: $.obj.k
        assert_eq!(d.detail["counts"]["added"], 1);
        assert_eq!(d.detail["counts"]["removed"], 2);
        assert_eq!(d.detail["counts"]["changed"], 1);
        assert_eq!(d.detail["changed"][0], "$.obj.k");
    }

    #[test]
    fn type_change_counts_as_one_change() {
        // A key whose value changes shape (scalar -> object) is a single change.
        let old = json!({ "x": "scalar" });
        let new = json!({ "x": { "nested": 1 } });
        let d = diff_values("json", &old, &new);
        assert_eq!(d.detail["counts"]["changed"], 1);
        assert_eq!(d.detail["changed"][0], "$.x");
    }

    #[test]
    fn identical_values_report_no_changes() {
        let v = json!({ "a": [1, 2], "b": { "c": true } });
        let d = diff_values("json", &v, &v);
        assert_eq!(d.summary, "0 key(s) added, 0 removed, 0 changed");
    }
}
