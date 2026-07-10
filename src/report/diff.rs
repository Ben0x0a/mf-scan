//! Diff report formatting (txt / json / csv).
//!
//! Defines: [`write_diff`], which renders a [`DiffReport`] to any `Write` sink in
//! the chosen [`OutputFormat`].
//! Used by: the binary's `run::diff`.
//! Uses: `crate::ops::diff::{Change, DiffReport}`, `crate::report::output::OutputFormat`,
//! `serde`/`serde_json` (JSON), `csv` (CSV).
//!
//! txt is change-only (unchanged files are summarised, not listed) so a human sees
//! just what moved; json/csv carry every file's verdict for machine consumption.

use std::io::Write;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::ops::diff::{Change, DiffReport, FileDiff};
use crate::report::output::OutputFormat;

/// Write `report` to `w` in `format`.
pub fn write_diff(report: &DiffReport, format: OutputFormat, w: &mut dyn Write) -> Result<()> {
    match format {
        OutputFormat::Txt => write_txt(report, w),
        OutputFormat::Json => write_json(report, w),
        OutputFormat::Csv => write_csv(report, w),
    }
}

/// The single-character marker shown for each change in txt output.
fn marker(change: Change) -> char {
    match change {
        Change::Added => '+',
        Change::Removed => '-',
        Change::Modified => '~',
        Change::Unchanged => ' ',
    }
}

/// txt: one `<marker> <path>` line per changed file (added `+`, removed `-`,
/// modified `~`), then a one-line summary. Unchanged files are counted, not listed.
/// An intra-file diff (`--inspect`) appears as an indented `[format] summary` line.
fn write_txt(report: &DiffReport, w: &mut dyn Write) -> Result<()> {
    for f in &report.files {
        if f.change == Change::Unchanged {
            continue;
        }
        writeln!(w, "{} {}", marker(f.change), f.path).context("failed writing diff output")?;
        if let Some(c) = &f.content {
            writeln!(w, "    [{}] {}", c.format, c.summary)
                .context("failed writing diff detail")?;
        }
    }
    let (added, removed, modified, unchanged) = report.counts();
    writeln!(
        w,
        "{added} added, {removed} removed, {modified} modified, {unchanged} unchanged"
    )
    .context("failed writing diff summary")?;
    Ok(())
}

/// The intra-file diff carried in JSON output (`--inspect`).
#[derive(Serialize)]
struct JsonContent<'a> {
    format: &'a str,
    summary: &'a str,
    detail: &'a serde_json::Value,
}

/// JSON projection of one file's verdict; sizes are omitted where the file is
/// absent on that side, and `content` only when an intra-file diff was produced.
#[derive(Serialize)]
struct JsonFile<'a> {
    path: &'a str,
    change: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_a: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_b: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<JsonContent<'a>>,
}

impl<'a> From<&'a FileDiff> for JsonFile<'a> {
    fn from(f: &'a FileDiff) -> Self {
        Self {
            path: &f.path,
            change: f.change.as_str(),
            size_a: f.size_a,
            size_b: f.size_b,
            content: f.content.as_ref().map(|c| JsonContent {
                format: &c.format,
                summary: &c.summary,
                detail: &c.detail,
            }),
        }
    }
}

#[derive(Serialize)]
struct JsonSummary {
    added: usize,
    removed: usize,
    modified: usize,
    unchanged: usize,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    summary: JsonSummary,
    files: Vec<JsonFile<'a>>,
}

/// json: `{ summary, files }` with every file's verdict (unchanged included).
fn write_json(report: &DiffReport, w: &mut dyn Write) -> Result<()> {
    let (added, removed, modified, unchanged) = report.counts();
    let out = JsonReport {
        summary: JsonSummary {
            added,
            removed,
            modified,
            unchanged,
        },
        files: report.files.iter().map(JsonFile::from).collect(),
    };
    serde_json::to_writer_pretty(&mut *w, &out).context("failed writing diff JSON")?;
    writeln!(w).context("failed writing diff JSON")?;
    Ok(())
}

/// CSV row: fixed columns so the set never varies; absent sizes are empty, and
/// `detail` carries the intra-file diff summary (empty when none).
#[derive(Serialize)]
struct CsvRow<'a> {
    path: &'a str,
    change: &'static str,
    size_a: String,
    size_b: String,
    detail: &'a str,
}

/// csv: header row plus one row per file (unchanged included).
fn write_csv(report: &DiffReport, w: &mut dyn Write) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(w);
    for f in &report.files {
        wtr.serialize(CsvRow {
            path: &f.path,
            change: f.change.as_str(),
            size_a: f.size_a.map(|n| n.to_string()).unwrap_or_default(),
            size_b: f.size_b.map(|n| n.to_string()).unwrap_or_default(),
            detail: f.content.as_ref().map_or("", |c| c.summary.as_str()),
        })
        .context("failed writing diff CSV row")?;
    }
    wtr.flush().context("failed flushing diff CSV")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::ContentDiff;
    use serde_json::{Value, json};

    fn sample_report() -> DiffReport {
        DiffReport {
            files: vec![
                FileDiff {
                    path: "new.txt".into(),
                    change: Change::Added,
                    size_a: None,
                    size_b: Some(10),
                    content: None,
                },
                FileDiff {
                    path: "gone.txt".into(),
                    change: Change::Removed,
                    size_a: Some(5),
                    size_b: None,
                    content: None,
                },
                FileDiff {
                    path: "conf.json".into(),
                    change: Change::Modified,
                    size_a: Some(20),
                    size_b: Some(22),
                    content: Some(ContentDiff {
                        format: "json".into(),
                        summary: "1 key(s) changed".into(),
                        detail: json!({ "counts": { "changed": 1 } }),
                    }),
                },
                FileDiff {
                    path: "same.txt".into(),
                    change: Change::Unchanged,
                    size_a: Some(3),
                    size_b: Some(3),
                    content: None,
                },
            ],
        }
    }

    fn render(format: OutputFormat) -> String {
        let mut buf = Vec::new();
        write_diff(&sample_report(), format, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn txt_lists_changes_with_markers_and_inline_detail() {
        let out = render(OutputFormat::Txt);
        assert!(out.contains("+ new.txt"));
        assert!(out.contains("- gone.txt"));
        assert!(out.contains("~ conf.json"));
        assert!(out.contains("    [json] 1 key(s) changed")); // indented intra-file diff
        assert!(!out.contains("same.txt")); // unchanged not listed
        assert!(out.contains("1 added, 1 removed, 1 modified, 1 unchanged"));
    }

    #[test]
    fn json_carries_every_verdict_and_the_content_diff() {
        let out = render(OutputFormat::Json);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["summary"],
            json!({ "added": 1, "removed": 1, "modified": 1, "unchanged": 1 })
        );
        assert_eq!(v["files"].as_array().unwrap().len(), 4); // unchanged included
        let conf = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["path"] == "conf.json")
            .unwrap();
        assert_eq!(conf["content"]["format"], "json");
        assert_eq!(conf["content"]["summary"], "1 key(s) changed");
    }

    #[test]
    fn csv_has_a_fixed_header_with_detail_column() {
        let out = render(OutputFormat::Csv);
        let header = out.lines().next().unwrap();
        assert_eq!(header, "path,change,size_a,size_b,detail");
        assert!(out.contains("conf.json,modified,20,22,1 key(s) changed"));
    }
}
