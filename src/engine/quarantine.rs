//! Quarantine — move suspicious/malicious files into a sealed vault under
//! `~/.dragonkeep/quarantine/`. Records are appended to `quarantine.jsonl`.
//!
//! Restore returns a file to its origin; purge deletes it permanently.
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::Finding;
use crate::engine::antivirus::FileVerdict;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: String,
    pub original_path: String,
    pub vault_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub quarantined_at: String,
    pub reason: String,
    pub matched_rules: Vec<String>,
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

fn vault_dir() -> PathBuf {
    let d = dragonkeep_dir().join("quarantine");
    let _ = fs::create_dir_all(&d);
    d
}

/// Move a file into the vault. Best-effort: if the move fails the file
/// remains in place. Returns the record (or None).
pub fn stash(src: &Path, verdict: &FileVerdict) -> Option<QuarantineRecord> {
    let id = uuid::Uuid::new_v4().to_string();
    let vault = vault_dir().join(&id);
    let bytes = fs::read(src).ok()?;
    fs::write(&vault, &bytes).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&vault, fs::Permissions::from_mode(0o600));
    }
    let record = QuarantineRecord {
        id: id.clone(),
        original_path: src.display().to_string(),
        vault_path: vault.display().to_string(),
        sha256: verdict.sha256.clone().unwrap_or_default(),
        size_bytes: verdict.size,
        quarantined_at: now_iso(),
        reason: verdict.verdict.clone(),
        matched_rules: verdict.matched_rules.clone(),
    };
    let _ = persist(&record);
    let _ = fs::remove_file(src);
    Some(record)
}

fn persist(record: &QuarantineRecord) -> std::io::Result<()> {
    let path = dragonkeep_dir().join("quarantine.jsonl");
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", serde_json::to_string(record).unwrap_or_default())
}

fn load_all() -> Vec<QuarantineRecord> {
    let path = dragonkeep_dir().join("quarantine.jsonl");
    let Ok(content) = fs::read_to_string(&path) else { return vec![] };
    content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn write_all(records: &[QuarantineRecord]) -> std::io::Result<()> {
    let path = dragonkeep_dir().join("quarantine.jsonl");
    let tmp = path.with_extension("jsonl.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        for r in records {
            writeln!(f, "{}", serde_json::to_string(r).unwrap_or_default())?;
        }
    }
    fs::rename(tmp, path)
}

pub fn list() -> Vec<QuarantineRecord> {
    let mut rows = load_all();
    rows.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
    rows
}

/// Restore by id. Writes the vault bytes back to the original path.
pub fn restore(id: &str) -> std::io::Result<()> {
    let rows = load_all();
    let Some(rec) = rows.iter().find(|r| r.id == id).cloned() else {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no such record"));
    };
    let vault = PathBuf::from(&rec.vault_path);
    if !vault.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "vault file missing"));
    }
    let dest = PathBuf::from(&rec.original_path);
    if let Some(parent) = dest.parent() { fs::create_dir_all(parent).ok(); }
    fs::write(&dest, fs::read(&vault)?)?;
    fs::remove_file(&vault).ok();
    let remaining: Vec<_> = rows.into_iter().filter(|r| r.id != id).collect();
    write_all(&remaining)
}

/// Permanently delete by id.
pub fn purge(id: &str) -> std::io::Result<()> {
    let rows = load_all();
    let Some(rec) = rows.iter().find(|r| r.id == id).cloned() else {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no such record"));
    };
    fs::remove_file(&rec.vault_path).ok();
    let remaining: Vec<_> = rows.into_iter().filter(|r| r.id != id).collect();
    write_all(&remaining)
}

pub fn run() -> Vec<Finding> {
    let rows = load_all();
    if rows.is_empty() {
        return vec![Finding::pass("quarantine vault · empty")
            .with_engine("quarantine")
            .with_rule("DK-QU-001")];
    }
    let mut out = vec![Finding::warning(format!("quarantine · {} files isolated", rows.len()))
        .with_engine("quarantine")
        .with_rule("DK-QU-001")];
    for r in rows.iter().take(5) {
        out.push(Finding::high(format!("isolated · {}", r.original_path))
            .with_detail(format!("sha256 {}…", &r.sha256.chars().take(16).collect::<String>()))
            .with_engine("quarantine"));
    }
    out
}
