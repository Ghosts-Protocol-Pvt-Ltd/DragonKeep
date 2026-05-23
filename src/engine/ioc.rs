//! IOC — indicator-of-compromise store + bulk-match. Holds hashes
//! (sha256/sha1/md5), domains, IPs, URLs, and YARA rule IDs. Match
//! returns the rows for each known value and the unknowns separately.
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    pub source: String,
    pub notes: Option<String>,
    pub added_at: String,
    #[serde(default)]
    pub match_count: u32,
}

fn dragonkeep_dir() -> PathBuf {
    std::env::var_os("DRAGONKEEP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".dragonkeep"))
}

fn now_iso() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0).unwrap_or_default();
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn store_path() -> PathBuf { dragonkeep_dir().join("ioc.jsonl") }

pub fn load_all() -> Vec<IocRecord> {
    let Ok(content) = fs::read_to_string(store_path()) else { return vec![] };
    content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

pub fn add(kind: &str, value: &str, source: &str, notes: Option<String>) -> std::io::Result<IocRecord> {
    let record = IocRecord {
        id: uuid::Uuid::new_v4().to_string(),
        kind: kind.to_string(),
        value: value.to_string(),
        source: source.to_string(),
        notes,
        added_at: now_iso(),
        match_count: 0,
    };
    let path = store_path();
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(f, "{}", serde_json::to_string(&record).unwrap_or_default())?;
    Ok(record)
}

/// Bulk match: returns (matched_records, unmatched_inputs).
pub fn match_many(values: &[String]) -> (Vec<IocRecord>, Vec<String>) {
    let store = load_all();
    let mut by_value: std::collections::HashMap<&str, &IocRecord> = std::collections::HashMap::new();
    for r in &store { by_value.insert(r.value.as_str(), r); }
    let mut matched = Vec::new();
    let mut unmatched = Vec::new();
    for v in values {
        let trimmed = v.trim();
        if trimmed.is_empty() { continue }
        match by_value.get(trimmed) {
            Some(r) => matched.push((*r).clone()),
            None    => unmatched.push(trimmed.to_string()),
        }
    }
    (matched, unmatched)
}

/// Quick check: is a SHA-256 in the IOC store?
pub fn contains_hash(sha256: &str) -> bool {
    let hashes: HashSet<String> = load_all()
        .into_iter()
        .filter(|r| matches!(r.kind.as_str(), "sha256" | "sha1" | "md5"))
        .map(|r| r.value)
        .collect();
    hashes.contains(sha256)
}

pub fn run() -> Vec<Finding> {
    let n = load_all().len();
    vec![Finding::info(format!("ioc store · {} indicators", n))
        .with_engine("ioc")
        .with_rule("DK-IOC-001")]
}
