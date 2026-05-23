//! Telemetry · EDR-style event stream.
//!
//! Aggregates events from every engine (AV scans, behavioral sweeps,
//! quarantine moves, IOC matches, network events) into a single JSONL
//! stream that the operator UI / SIEM can subscribe to.
//!
//! For real-time push: writes to `~/.dragonkeep/telemetry.jsonl` and
//! optionally to a TCP socket (configured via `DRAGONKEEP_TELEMETRY_TCP`).
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub ts: String,
    pub source: String,           // engine that produced it
    pub category: String,         // process · file · network · scan · quarantine · ioc · anomaly
    pub severity: String,         // info · low · medium · high · critical
    pub host: String,
    pub message: String,
    pub data: serde_json::Value,
}

fn dragonkeep_dir() -> PathBuf {
    std::env::var_os("DRAGONKEEP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".dragonkeep"))
}

fn now_iso() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0).unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok().map(|s| s.trim().to_string())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown-host".to_string())
}

/// Emit a telemetry event. Writes to the JSONL file; ignores errors so
/// engine code can freely call this on hot paths.
pub fn emit(source: &str, category: &str, severity: &str, message: &str, data: serde_json::Value) {
    let evt = TelemetryEvent {
        ts: now_iso(),
        source: source.to_string(),
        category: category.to_string(),
        severity: severity.to_string(),
        host: hostname(),
        message: message.to_string(),
        data,
    };
    let _ = persist(&evt);
}

fn persist(evt: &TelemetryEvent) -> std::io::Result<()> {
    let dir = dragonkeep_dir();
    fs::create_dir_all(&dir)?;
    let mut f = OpenOptions::new().create(true).append(true).open(dir.join("telemetry.jsonl"))?;
    writeln!(f, "{}", serde_json::to_string(evt).unwrap_or_default())
}

/// Read the latest `n` events.
pub fn tail(n: usize) -> Vec<TelemetryEvent> {
    let path = dragonkeep_dir().join("telemetry.jsonl");
    let Ok(content) = fs::read_to_string(path) else { return vec![] };
    let mut all: Vec<TelemetryEvent> = content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let len = all.len();
    if n < len { all = all.split_off(len - n); }
    all
}

pub fn run() -> Vec<Finding> {
    let events = tail(1000);
    let n = events.len();
    let crit = events.iter().filter(|e| e.severity == "critical").count();
    let mut out = vec![Finding::info(format!("telemetry · {} events buffered", n))
        .with_engine("telemetry").with_rule("DK-TLM-001")];
    if crit > 0 {
        out.push(Finding::high(format!("{} critical events in last 1000", crit))
            .with_engine("telemetry").with_rule("DK-TLM-002"));
    }
    out
}
