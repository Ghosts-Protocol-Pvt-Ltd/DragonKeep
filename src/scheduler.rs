use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::{Finding, Severity};
use crate::report::{Report, ReportSummary};

// ---------------------------------------------------------------------------
// Crontab marker — used to locate/replace our entry
// ---------------------------------------------------------------------------
const CRON_MARKER: &str = "# DragonKeep scheduled scan — do not edit";

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// How often a scheduled scan should run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanInterval {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    /// Arbitrary interval in minutes.
    Custom(u64),
}

impl ScanInterval {
    /// Return the cron schedule expression (5-field).
    fn to_cron(&self) -> String {
        match self {
            ScanInterval::Hourly => "0 * * * *".into(),
            ScanInterval::Daily => "0 2 * * *".into(),
            ScanInterval::Weekly => "0 2 * * 0".into(),
            ScanInterval::Monthly => "0 2 1 * *".into(),
            ScanInterval::Custom(minutes) => {
                if *minutes < 60 {
                    format!("*/{minutes} * * * *")
                } else if minutes % (24 * 60) == 0 {
                    let days = minutes / (24 * 60);
                    format!("0 2 */{days} * *")
                } else if minutes % 60 == 0 {
                    let hours = minutes / 60;
                    format!("0 */{hours} * * *")
                } else {
                    format!("*/{minutes} * * * *")
                }
            }
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> String {
        match self {
            ScanInterval::Hourly => "every hour".into(),
            ScanInterval::Daily => "daily at 02:00".into(),
            ScanInterval::Weekly => "weekly (Sun 02:00)".into(),
            ScanInterval::Monthly => "monthly (1st 02:00)".into(),
            ScanInterval::Custom(m) => format!("every {m} minutes"),
        }
    }
}

/// Persistent configuration for the scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Whether scheduled scanning is active.
    pub enabled: bool,
    /// How often to scan.
    pub interval: ScanInterval,
    /// Scan profile name (quick, standard, deep, …).
    pub profile: String,
    /// Specific engines to run, or `None` for the profile default.
    #[serde(default)]
    pub modules: Option<Vec<String>>,
    /// Directory where JSON reports are persisted.
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    /// Keep at most this many reports (FIFO cleanup).
    #[serde(default = "default_max_reports")]
    pub max_reports: usize,
    /// Which severities should trigger a desktop/log notification.
    #[serde(default)]
    pub notify_on: Vec<Severity>,
}

fn default_output_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/etc"))
        .join("dragonkeep")
        .join("reports")
}

fn default_max_reports() -> usize {
    30
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: ScanInterval::Daily,
            profile: "standard".into(),
            modules: None,
            output_dir: default_output_dir(),
            max_reports: default_max_reports(),
            notify_on: vec![Severity::Critical, Severity::High],
        }
    }
}

// ---------------------------------------------------------------------------
// Saved report metadata
// ---------------------------------------------------------------------------

/// Metadata about a previously-saved report JSON file.
#[derive(Debug, Clone)]
pub struct SavedReport {
    pub path: PathBuf,
    pub timestamp: DateTime<Utc>,
    pub size_bytes: u64,
    pub findings_summary: Option<ReportSummary>,
}

impl SavedReport {
    /// Parse a `Report` from the JSON on disk and populate `findings_summary`.
    pub fn load_summary(&mut self) -> Result<()> {
        let data = fs::read_to_string(&self.path)
            .with_context(|| format!("reading report {}", self.path.display()))?;
        let report: Report = serde_json::from_str(&data)
            .with_context(|| format!("parsing report {}", self.path.display()))?;
        self.findings_summary = Some(report.summary);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Diff / history types
// ---------------------------------------------------------------------------

/// Result of comparing two report files.
#[derive(Debug, Clone, Serialize)]
pub struct ReportDiff {
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub unchanged_count: usize,
    /// Findings whose severity changed between old → new, keyed by title.
    pub severity_changes: HashMap<String, (Severity, Severity)>,
}

/// Direction of finding-count trend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trend {
    Improving,
    Stable,
    Degrading,
}

impl std::fmt::Display for Trend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Trend::Improving => write!(f, "↓ Improving"),
            Trend::Stable => write!(f, "→ Stable"),
            Trend::Degrading => write!(f, "↑ Degrading"),
        }
    }
}

/// Aggregate statistics over a window of reports.
#[derive(Debug, Clone, Serialize)]
pub struct TrendReport {
    pub total_scans: usize,
    pub avg_findings: f32,
    pub trend: Trend,
    /// (date string, critical-finding count) pairs.
    pub critical_trend: Vec<(String, usize)>,
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

pub struct Scheduler {
    config: ScheduleConfig,
}

impl Scheduler {
    pub fn new(config: ScheduleConfig) -> Self {
        Self { config }
    }

    // -- crontab management -------------------------------------------------

    /// Build the crontab line that invokes `dragonkeep`.
    pub fn generate_crontab_entry(&self) -> String {
        let ts_fmt = "%Y%m%d-%H%M%S";
        let out = self.config.output_dir.display();
        let profile = &self.config.profile;

        let mut cmd = format!(
            "dragonkeep scan --profile {profile} --format json -o {out}/scan-$(date +{ts_fmt}).json --quiet"
        );

        if let Some(ref mods) = self.config.modules {
            if !mods.is_empty() {
                let joined = mods.join(",");
                cmd = format!(
                    "dragonkeep scan -m {joined} --format json -o {out}/scan-$(date +{ts_fmt}).json --quiet"
                );
            }
        }

        let schedule = self.config.interval.to_cron();
        format!("{CRON_MARKER}\n{schedule} {cmd}")
    }

    /// Install (or replace) the DragonKeep crontab entry.
    pub fn install_cron(&self) -> Result<()> {
        if !self.config.enabled {
            anyhow::bail!("scheduler is disabled in config — set enabled = true first");
        }

        // Ensure the output directory exists
        fs::create_dir_all(&self.config.output_dir)
            .with_context(|| format!("creating report dir {}", self.config.output_dir.display()))?;

        let existing = read_crontab()?;
        let cleaned = remove_dragonkeep_entry(&existing);
        let entry = self.generate_crontab_entry();
        let new_crontab = if cleaned.trim().is_empty() {
            format!("{entry}\n")
        } else {
            format!("{}\n{entry}\n", cleaned.trim_end())
        };

        write_crontab(&new_crontab)?;
        Ok(())
    }

    /// Remove any DragonKeep entry from crontab.
    pub fn uninstall_cron(&self) -> Result<()> {
        let existing = read_crontab()?;
        let cleaned = remove_dragonkeep_entry(&existing);
        write_crontab(&cleaned)?;
        Ok(())
    }

    // -- report management --------------------------------------------------

    /// List all saved JSON reports in `output_dir`, newest first.
    pub fn list_reports(&self) -> Result<Vec<SavedReport>> {
        let dir = &self.config.output_dir;
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut reports = Vec::new();
        for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let meta = entry.metadata()?;
            let timestamp = parse_timestamp_from_filename(&path)
                .or_else(|| {
                    meta.modified()
                        .ok()
                        .map(|t| DateTime::<Utc>::from(t))
                })
                .unwrap_or_else(Utc::now);

            reports.push(SavedReport {
                path,
                timestamp,
                size_bytes: meta.len(),
                findings_summary: None,
            });
        }

        reports.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(reports)
    }

    /// Delete reports beyond `max_reports`, return count deleted.
    pub fn cleanup_old_reports(&self) -> Result<usize> {
        let reports = self.list_reports()?;
        let max = self.config.max_reports;
        if reports.len() <= max {
            return Ok(0);
        }

        let to_remove = &reports[max..];
        let mut removed = 0usize;
        for report in to_remove {
            if fs::remove_file(&report.path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Human-readable status string.
    pub fn show_status(&self) -> String {
        let mut lines = Vec::new();

        lines.push(format!(
            "Scheduled scanning: {}",
            if self.config.enabled { "enabled" } else { "disabled" }
        ));
        lines.push(format!("Interval: {}", self.config.interval.label()));
        lines.push(format!("Profile: {}", self.config.profile));

        if let Some(ref mods) = self.config.modules {
            lines.push(format!("Modules: {}", mods.join(", ")));
        }

        lines.push(format!("Report dir: {}", self.config.output_dir.display()));
        lines.push(format!("Max reports: {}", self.config.max_reports));

        // Cron status
        match read_crontab() {
            Ok(cron) if cron.contains(CRON_MARKER) => {
                lines.push("Cron entry: installed".into());
                if let Some(next) = estimate_next_run(&self.config.interval) {
                    lines.push(format!("Next run: ~{}", next.format("%Y-%m-%d %H:%M UTC")));
                }
            }
            _ => {
                lines.push("Cron entry: not installed".into());
            }
        }

        // Report count
        match self.list_reports() {
            Ok(r) => lines.push(format!("Saved reports: {}", r.len())),
            Err(_) => lines.push("Saved reports: (unable to read)".into()),
        }

        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Diff / trend analysis (free functions)
// ---------------------------------------------------------------------------

/// Compare two report JSON files and return a structured diff.
pub fn diff_reports(old: &Path, new: &Path) -> Result<ReportDiff> {
    let old_report = load_report(old)?;
    let new_report = load_report(new)?;

    let old_findings = collect_findings(&old_report);
    let new_findings = collect_findings(&new_report);

    let old_set: HashMap<String, &Finding> = old_findings.iter().map(|f| (f.title.clone(), f)).collect();
    let new_set: HashMap<String, &Finding> = new_findings.iter().map(|f| (f.title.clone(), f)).collect();

    let mut added = Vec::new();
    let mut resolved = Vec::new();
    let mut unchanged = 0usize;
    let mut severity_changes: HashMap<String, (Severity, Severity)> = HashMap::new();

    for (title, nf) in &new_set {
        match old_set.get(title) {
            Some(of) => {
                if of.severity != nf.severity {
                    severity_changes
                        .insert(title.clone(), (of.severity.clone(), nf.severity.clone()));
                } else {
                    unchanged += 1;
                }
            }
            None => added.push((*nf).clone()),
        }
    }

    for (title, of) in &old_set {
        if !new_set.contains_key(title) {
            resolved.push((*of).clone());
        }
    }

    Ok(ReportDiff {
        new_findings: added,
        resolved_findings: resolved,
        unchanged_count: unchanged,
        severity_changes,
    })
}

/// Analyse finding trends over `days` days of history.
pub fn trend_analysis(reports: &[SavedReport], days: usize) -> Result<TrendReport> {
    let cutoff = Utc::now() - chrono::Duration::days(days as i64);
    let window: Vec<&SavedReport> = reports.iter().filter(|r| r.timestamp >= cutoff).collect();

    if window.is_empty() {
        return Ok(TrendReport {
            total_scans: 0,
            avg_findings: 0.0,
            trend: Trend::Stable,
            critical_trend: Vec::new(),
        });
    }

    let mut totals: Vec<usize> = Vec::new();
    let mut critical_trend: Vec<(String, usize)> = Vec::new();

    for sr in &window {
        let report = load_report(&sr.path)?;
        totals.push(report.summary.total_findings);
        critical_trend.push((
            sr.timestamp.format("%Y-%m-%d").to_string(),
            report.summary.critical,
        ));
    }

    let total_scans = window.len();
    let avg_findings = totals.iter().sum::<usize>() as f32 / total_scans as f32;

    let trend = compute_trend(&totals);

    Ok(TrendReport {
        total_scans,
        avg_findings,
        trend,
        critical_trend,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn load_report(path: &Path) -> Result<Report> {
    let data =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&data).with_context(|| format!("parsing {}", path.display()))
}

fn collect_findings(report: &Report) -> Vec<Finding> {
    report
        .sections
        .iter()
        .flat_map(|s| s.findings.clone())
        .collect()
}

/// Try to extract a UTC timestamp from a filename like `scan-20240715-020001.json`.
fn parse_timestamp_from_filename(path: &Path) -> Option<DateTime<Utc>> {
    let stem = path.file_stem()?.to_str()?;
    // Expected: "scan-YYYYMMDD-HHMMSS"
    let ts_part = stem.strip_prefix("scan-")?;
    NaiveDateTime::parse_from_str(ts_part, "%Y%m%d-%H%M%S")
        .ok()
        .map(|ndt| ndt.and_utc())
}

fn read_crontab() -> Result<String> {
    let output = Command::new("crontab")
        .arg("-l")
        .output()
        .context("failed to execute `crontab -l`")?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        // crontab -l exits non-zero when empty — treat as blank
        Ok(String::new())
    }
}

fn write_crontab(contents: &str) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn `crontab -`")?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(contents.as_bytes())
            .context("writing to crontab stdin")?;
    }

    let status = child.wait().context("waiting for crontab")?;
    if !status.success() {
        anyhow::bail!("crontab exited with {status}");
    }
    Ok(())
}

/// Strip the DragonKeep marker + the command line that follows it.
fn remove_dragonkeep_entry(crontab: &str) -> String {
    let mut result = Vec::new();
    let mut skip_next = false;

    for line in crontab.lines() {
        if line.trim() == CRON_MARKER {
            skip_next = true;
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        result.push(line);
    }

    let mut out = result.join("\n");
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Rough next-run estimate (just wall-clock + interval, not real cron parsing).
fn estimate_next_run(interval: &ScanInterval) -> Option<DateTime<Utc>> {
    let now = Utc::now();
    let delta = match interval {
        ScanInterval::Hourly => chrono::Duration::hours(1),
        ScanInterval::Daily => chrono::Duration::days(1),
        ScanInterval::Weekly => chrono::Duration::weeks(1),
        ScanInterval::Monthly => chrono::Duration::days(30),
        ScanInterval::Custom(m) => chrono::Duration::minutes(*m as i64),
    };
    now.checked_add_signed(delta)
}

/// Simple linear-regression-style trend: compare first half average to second half.
fn compute_trend(values: &[usize]) -> Trend {
    if values.len() < 2 {
        return Trend::Stable;
    }
    let mid = values.len() / 2;
    let first_avg = values[..mid].iter().sum::<usize>() as f64 / mid as f64;
    let second_avg = values[mid..].iter().sum::<usize>() as f64 / (values.len() - mid) as f64;

    let delta = second_avg - first_avg;
    // Threshold: ±10 % of the overall average
    let overall = values.iter().sum::<usize>() as f64 / values.len() as f64;
    let threshold = (overall * 0.10).max(1.0);

    if delta < -threshold {
        Trend::Improving
    } else if delta > threshold {
        Trend::Degrading
    } else {
        Trend::Stable
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ScheduleConfig {
        ScheduleConfig {
            enabled: true,
            interval: ScanInterval::Daily,
            profile: "quick".into(),
            modules: None,
            output_dir: PathBuf::from("/home/test/.config/dragonkeep/reports"),
            max_reports: 30,
            notify_on: vec![Severity::Critical],
        }
    }

    #[test]
    fn cron_expressions() {
        assert_eq!(ScanInterval::Hourly.to_cron(), "0 * * * *");
        assert_eq!(ScanInterval::Daily.to_cron(), "0 2 * * *");
        assert_eq!(ScanInterval::Weekly.to_cron(), "0 2 * * 0");
        assert_eq!(ScanInterval::Monthly.to_cron(), "0 2 1 * *");
        assert_eq!(ScanInterval::Custom(15).to_cron(), "*/15 * * * *");
        assert_eq!(ScanInterval::Custom(120).to_cron(), "0 */2 * * *");
    }

    #[test]
    fn generate_crontab_entry_basic() {
        let sched = Scheduler::new(test_config());
        let entry = sched.generate_crontab_entry();
        assert!(entry.contains(CRON_MARKER));
        assert!(entry.contains("0 2 * * *"));
        assert!(entry.contains("--profile quick"));
        assert!(entry.contains("--format json"));
        assert!(entry.contains("--quiet"));
    }

    #[test]
    fn generate_crontab_entry_with_modules() {
        let mut cfg = test_config();
        cfg.modules = Some(vec!["sentinel".into(), "bastion".into()]);
        let sched = Scheduler::new(cfg);
        let entry = sched.generate_crontab_entry();
        assert!(entry.contains("-m sentinel,bastion"));
    }

    #[test]
    fn remove_dragonkeep_entry_strips_marker_and_command() {
        let crontab = format!(
            "0 * * * * /usr/bin/backup\n{CRON_MARKER}\n0 2 * * * dragonkeep scan\n30 3 * * * /usr/bin/other\n"
        );
        let cleaned = remove_dragonkeep_entry(&crontab);
        assert!(!cleaned.contains("dragonkeep"));
        assert!(cleaned.contains("/usr/bin/backup"));
        assert!(cleaned.contains("/usr/bin/other"));
    }

    #[test]
    fn remove_entry_from_empty_crontab() {
        let cleaned = remove_dragonkeep_entry("");
        assert!(cleaned.is_empty() || cleaned == "\n");
    }

    #[test]
    fn parse_timestamp_valid() {
        let p = PathBuf::from("/reports/scan-20240715-020001.json");
        let ts = parse_timestamp_from_filename(&p).unwrap();
        assert_eq!(ts.format("%Y-%m-%d %H:%M:%S").to_string(), "2024-07-15 02:00:01");
    }

    #[test]
    fn parse_timestamp_invalid() {
        let p = PathBuf::from("/reports/random-file.json");
        assert!(parse_timestamp_from_filename(&p).is_none());
    }

    #[test]
    fn trend_improving() {
        assert_eq!(compute_trend(&[100, 90, 80, 50, 40, 30]), Trend::Improving);
    }

    #[test]
    fn trend_degrading() {
        assert_eq!(compute_trend(&[10, 20, 30, 50, 60, 80]), Trend::Degrading);
    }

    #[test]
    fn trend_stable() {
        assert_eq!(compute_trend(&[50, 51, 49, 50, 51, 50]), Trend::Stable);
    }

    #[test]
    fn trend_single_value() {
        assert_eq!(compute_trend(&[42]), Trend::Stable);
    }

    #[test]
    fn config_default_values() {
        let cfg = ScheduleConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.interval, ScanInterval::Daily);
        assert_eq!(cfg.profile, "standard");
        assert_eq!(cfg.max_reports, 30);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let cfg = test_config();
        let json = serde_json::to_string_pretty(&cfg).unwrap();
        let parsed: ScheduleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enabled, cfg.enabled);
        assert_eq!(parsed.interval, cfg.interval);
        assert_eq!(parsed.profile, cfg.profile);
        assert_eq!(parsed.max_reports, cfg.max_reports);
    }

    #[test]
    fn show_status_contains_key_info() {
        let sched = Scheduler::new(test_config());
        let status = sched.show_status();
        assert!(status.contains("enabled"));
        assert!(status.contains("daily"));
        assert!(status.contains("quick"));
    }

    #[test]
    fn interval_labels() {
        assert_eq!(ScanInterval::Hourly.label(), "every hour");
        assert_eq!(ScanInterval::Daily.label(), "daily at 02:00");
        assert_eq!(ScanInterval::Custom(45).label(), "every 45 minutes");
    }
}
