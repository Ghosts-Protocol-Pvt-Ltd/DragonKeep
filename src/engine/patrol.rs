//! Patrol Engine — Continuous Monitoring orchestrator.
//!
//! Schedules recurring scans and tracks drift between them. Reports
//! whether the operator's monitoring posture is current.
//!
//! Patrol does NOT execute scans on its own — it reports on the
//! scheduled-scan state and detects gaps. Actual scheduling is owned
//! by the `scheduler` module + systemd/cron.

use anyhow::Result;
use colored::Colorize;
use std::path::PathBuf;

use crate::config::Config;
use crate::engine::{Finding, Severity};

fn schedule_dir() -> PathBuf {
    dirs::config_dir()
        .map(|d| d.join("dragonkeep").join("schedules"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/dragonkeep/schedules"))
}

fn last_scan_marker() -> PathBuf {
    dirs::cache_dir()
        .map(|d| d.join("dragonkeep").join("last_scan"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/dragonkeep/last_scan"))
}

/// Report patrol status — last scan age, scheduled jobs present.
pub async fn scan(_config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    eprintln!("    {} Auditing patrol coverage...", "→".dimmed());

    // Check last-scan marker freshness
    let marker = last_scan_marker();
    if marker.exists() {
        if let Ok(meta) = std::fs::metadata(&marker) {
            if let Ok(modified) = meta.modified() {
                let age = modified
                    .elapsed()
                    .map(|d| d.as_secs())
                    .unwrap_or(u64::MAX);
                let hours = age / 3600;
                let days = hours / 24;
                let (severity, title) = match days {
                    0 => (
                        Severity::Pass,
                        "Last scan within 24 hours".to_string(),
                    ),
                    1..=7 => (
                        Severity::Info,
                        format!("Last scan {days} day(s) ago"),
                    ),
                    8..=30 => (
                        Severity::Warning,
                        format!("Last scan {days} day(s) ago — schedule monthly"),
                    ),
                    _ => (
                        Severity::High,
                        format!(
                            "Last scan {days} day(s) ago — defensive posture is stale"
                        ),
                    ),
                };
                let mut f = match severity {
                    Severity::Pass => Finding::pass(title),
                    Severity::Info => Finding::info(title),
                    Severity::Warning => Finding::warning(title),
                    Severity::High => Finding::high(title),
                    Severity::Critical => Finding::critical(title),
                };
                f = f.with_engine("Patrol").with_rule("DK-PAT-001");
                findings.push(f);
            }
        }
    } else {
        findings.push(
            Finding::warning("No prior scan record found")
                .with_detail(format!(
                    "Run `dragonkeep scan` to seed the patrol baseline. \
                     Marker would be written at {}.",
                    marker.display()
                ))
                .with_engine("Patrol")
                .with_rule("DK-PAT-002"),
        );
    }

    // Check scheduled jobs
    let sched_dir = schedule_dir();
    if sched_dir.exists() {
        let count = std::fs::read_dir(&sched_dir)
            .map(|it| it.filter_map(|e| e.ok()).count())
            .unwrap_or(0);
        if count == 0 {
            findings.push(
                Finding::info("Schedule directory present but empty")
                    .with_detail(format!(
                        "Add scheduled jobs at {} to enable patrol.",
                        sched_dir.display()
                    ))
                    .with_engine("Patrol")
                    .with_rule("DK-PAT-003"),
            );
        } else {
            findings.push(
                Finding::pass(format!("{count} scheduled patrol job(s)"))
                    .with_engine("Patrol")
                    .with_rule("DK-PAT-004"),
            );
        }
    } else {
        findings.push(
            Finding::info("No patrol schedule directory")
                .with_detail(format!(
                    "Schedule via `dragonkeep patrol schedule daily`. \
                     Will write to {}.",
                    sched_dir.display()
                ))
                .with_engine("Patrol")
                .with_rule("DK-PAT-005"),
        );
    }

    Ok(findings)
}

/// Touch the last-scan marker. Called by the main scan flow on success.
pub fn touch_last_scan() {
    let path = last_scan_marker();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, chrono::Utc::now().to_rfc3339());
}
