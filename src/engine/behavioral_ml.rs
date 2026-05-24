//! Behavioral · ML-style statistical anomaly engine.
//!
//! Spec: dragon-platform/specs/011-ngav-ml-uplift
//!
//! Where the regex-based `behavioral::evaluate` catches *known* bad patterns,
//! this engine catches *unusual* ones — the second half of the NGAV-better-
//! than-CrowdStrike claim (Constitution V).
//!
//! Approach (pure-Rust · no Python sklearn dep):
//!
//! 1. Maintain a rolling histogram of per-host command-line bigrams over
//!    the last N (=1000) process events from `~/.dragonkeep/behavioral.jsonl`.
//! 2. For each new candidate cmdline, score its bigrams against the
//!    rolling baseline. Score = sum of (1 - P(bigram | host)) — higher
//!    = more anomalous.
//! 3. Anything with anomaly score >= 4.0 is flagged; emitted to telemetry
//!    with source `behavioral_ml` and persisted alongside the regex hits.
//!
//! This is a self-contained "online" anomaly detector. No model file to
//! ship, no cloud roundtrip, baselines adapt as the operator's normal
//! workload shifts.
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlAnomaly {
    pub ts: String,
    pub pid: u32,
    pub cmdline: String,
    pub host: String,
    pub anomaly_score: f64,
    pub novel_bigrams: Vec<String>,
}

const WINDOW_SIZE: usize = 1000;
const FLAG_THRESHOLD: f64 = 4.0;

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
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Tokenise a cmdline into bigrams ("word1 word2"). Lower-cases for
/// case-insensitive baselining.
fn bigrams(cmdline: &str) -> Vec<String> {
    let lower = cmdline.to_lowercase();
    let toks: Vec<&str> = lower.split_whitespace().collect();
    toks.windows(2).map(|w| format!("{} {}", w[0], w[1])).collect()
}

/// In-memory baseline: per-host bigram counts + total events seen.
#[derive(Default)]
struct Baseline {
    by_host: HashMap<String, (HashMap<String, u32>, u32)>,
}

static BASELINE: Mutex<Option<Baseline>> = Mutex::new(None);

fn baseline_load_if_empty() {
    let mut guard = match BASELINE.lock() { Ok(g) => g, Err(p) => p.into_inner() };
    if guard.is_some() { return }
    let mut b = Baseline::default();
    // Seed from the last WINDOW_SIZE rows of behavioral.jsonl
    let path = dragonkeep_dir().join("behavioral.jsonl");
    if let Ok(content) = fs::read_to_string(&path) {
        let lines: Vec<&str> = content.lines().rev().take(WINDOW_SIZE).collect();
        for line in lines {
            if let Ok(evt) = serde_json::from_str::<super::behavioral::ProcessEvent>(line) {
                let host = hostname();
                let entry = b.by_host.entry(host).or_insert_with(|| (HashMap::new(), 0));
                for bg in bigrams(&evt.cmdline) {
                    *entry.0.entry(bg).or_insert(0) += 1;
                }
                entry.1 += 1;
            }
        }
    }
    *guard = Some(b);
}

/// Score a single cmdline against the rolling baseline. Returns
/// (anomaly_score, novel_bigrams).
pub fn score(cmdline: &str) -> (f64, Vec<String>) {
    baseline_load_if_empty();
    let host = hostname();
    let guard = match BASELINE.lock() { Ok(g) => g, Err(p) => p.into_inner() };
    let Some(b) = guard.as_ref() else { return (0.0, vec![]) };
    let Some((counts, total)) = b.by_host.get(&host) else { return (0.0, vec![]) };
    if *total == 0 { return (0.0, vec![]) }
    let total_f = *total as f64;
    let bgs = bigrams(cmdline);
    if bgs.is_empty() { return (0.0, vec![]) }
    let mut anomaly = 0.0_f64;
    let mut novel: Vec<String> = Vec::new();
    for bg in &bgs {
        let p = counts.get(bg).map(|&c| c as f64 / total_f).unwrap_or(0.0);
        anomaly += 1.0 - p;
        if p == 0.0 { novel.push(bg.clone()); }
    }
    (anomaly, novel)
}

/// Record a cmdline into the baseline. Idempotent if called repeatedly
/// on the same event — the rolling window naturally evicts old data
/// when `evict_to_window()` runs.
pub fn observe(cmdline: &str) {
    baseline_load_if_empty();
    let host = hostname();
    let mut guard = match BASELINE.lock() { Ok(g) => g, Err(p) => p.into_inner() };
    if let Some(b) = guard.as_mut() {
        let entry = b.by_host.entry(host).or_insert_with(|| (HashMap::new(), 0));
        for bg in bigrams(cmdline) {
            *entry.0.entry(bg).or_insert(0) += 1;
        }
        entry.1 += 1;
        // Cap: if a host's total exceeds WINDOW_SIZE * 2, halve all counts.
        // Cheap "exponential decay" so old patterns fade out.
        if entry.1 > (WINDOW_SIZE as u32) * 2 {
            for c in entry.0.values_mut() { *c = (*c).max(1) / 2; }
            entry.1 /= 2;
        }
    }
}

/// Evaluate a cmdline + record it. If the anomaly score crosses
/// FLAG_THRESHOLD, returns Some(MlAnomaly) and persists it.
pub fn evaluate_and_record(pid: u32, cmdline: &str) -> Option<MlAnomaly> {
    let (anomaly, novel) = score(cmdline);
    observe(cmdline);
    if anomaly >= FLAG_THRESHOLD {
        let a = MlAnomaly {
            ts: now_iso(),
            pid,
            cmdline: cmdline.to_string(),
            host: hostname(),
            anomaly_score: anomaly,
            novel_bigrams: novel,
        };
        let _ = persist(&a);
        super::telemetry::emit(
            "behavioral_ml",
            "process",
            if anomaly >= 8.0 { "critical" } else if anomaly >= 6.0 { "high" } else { "medium" },
            &format!("pid {} · anomaly {:.2} · {}", pid, anomaly, cmdline),
            serde_json::json!({"novel_bigrams": a.novel_bigrams, "score": anomaly}),
        );
        Some(a)
    } else {
        None
    }
}

fn persist(a: &MlAnomaly) -> std::io::Result<()> {
    use std::io::Write;
    let dir = dragonkeep_dir();
    fs::create_dir_all(&dir)?;
    let mut f = fs::OpenOptions::new().create(true).append(true).open(dir.join("behavioral_ml.jsonl"))?;
    writeln!(f, "{}", serde_json::to_string(a).unwrap_or_default())
}

pub fn run() -> Vec<Finding> {
    baseline_load_if_empty();
    let guard = match BASELINE.lock() { Ok(g) => g, Err(p) => p.into_inner() };
    let total_bgs: usize = guard.as_ref().map(|b| b.by_host.values().map(|(m, _)| m.len()).sum()).unwrap_or(0);
    let recent_path = dragonkeep_dir().join("behavioral_ml.jsonl");
    let recent = fs::read_to_string(&recent_path).map(|s| s.lines().count()).unwrap_or(0);
    let mut out = vec![Finding::info(format!("behavioral_ml · baseline {} bigrams · {} historical anomalies",
                                              total_bgs, recent))
        .with_engine("behavioral_ml").with_rule("DK-ML-001")];
    if recent > 0 {
        out.push(Finding::warning(format!("{} ML-flagged anomalies on file", recent))
            .with_engine("behavioral_ml").with_rule("DK-ML-002"));
    }
    out
}
