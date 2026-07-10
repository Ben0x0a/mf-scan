//! The search driver with a live terminal progress reporter.
//!
//! Defines: [`search_with_reporter`], which runs the engine search while a
//! background thread redraws a `scanned X/Y` line on a TTY stderr.
//! Used by: `run::grep`.
//! Uses: `mf_scan::ops::search` (the search it drives), `mf_scan::engine` (the
//! [`Progress`] trait it implements), and `mf_scan::core::source` (the [`Source`]
//! it searches).
//!
//! The reporter thread only reads shared atomic counters the engine increments —
//! it performs no I/O of its own beyond the stderr redraw, and is not spawned when
//! stderr is piped/redirected, so captured output stays clean.

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;

use mf_scan::core::filter::EntryFilter;
use mf_scan::core::source::Source;
use mf_scan::decrypt::DecryptionContext;
use mf_scan::engine::Progress;
use mf_scan::ops::search::{Findings, Query, search_source};

/// Run the search, showing a live progress line on stderr when it is a terminal.
///
/// The reporter runs on its own thread while the parallel search executes; on a
/// non-terminal stderr (piped/redirected) no reporter is spawned, so logs and
/// captured output stay clean. The shared counters carry no I/O — the engine
/// only increments them.
pub(crate) fn search_with_reporter(
    source: &dyn Source,
    query: &Query,
    deep: bool,
    match_path: bool,
    filter: &EntryFilter,
    decrypt: Option<&DecryptionContext>,
) -> Result<Findings> {
    let progress = Arc::new(TtyProgress::default());
    let stop = Arc::new(AtomicBool::new(false));

    let reporter = if std::io::stderr().is_terminal() {
        let progress = Arc::clone(&progress);
        let stop = Arc::clone(&stop);
        Some(std::thread::spawn(move || {
            report_progress(&progress, &stop)
        }))
    } else {
        None
    };

    let result = search_source(
        source,
        query,
        deep,
        match_path,
        filter,
        decrypt,
        progress.as_ref(),
    );

    stop.store(true, Ordering::Relaxed);
    if let Some(reporter) = reporter {
        let _ = reporter.join();
        eprint!("\r\x1b[K"); // clear the progress line before results are read
        let _ = std::io::stderr().flush();
    }
    result
}

/// Shared scan counters; the reporter thread reads them, the engine writes them.
#[derive(Default)]
struct TtyProgress {
    total: AtomicUsize,
    done: AtomicUsize,
}

impl Progress for TtyProgress {
    fn set_total(&self, total: usize) {
        self.total.store(total, Ordering::Relaxed);
    }
    fn inc(&self) {
        self.done.fetch_add(1, Ordering::Relaxed);
    }
}

/// Redraw `scanned X/Y files` on stderr until told to stop.
fn report_progress(progress: &TtyProgress, stop: &AtomicBool) {
    loop {
        let total = progress.total.load(Ordering::Relaxed);
        if total > 0 {
            let done = progress.done.load(Ordering::Relaxed);
            eprint!("\r\x1b[Kmf-scan: scanned {done}/{total} files");
            let _ = std::io::stderr().flush();
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}
