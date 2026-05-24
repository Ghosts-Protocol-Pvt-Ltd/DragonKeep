//! Antivirus — file scanning with built-in YARA-style regex rules and
//! SHA-256 hash matching against the DragonKeep IOC store. Suspicious
//! and malicious files are auto-quarantined when configured.
//!
//! State directory: `~/.dragonkeep/` (overridable via `DRAGONKEEP_DIR`).
//! Output JSONL: `~/.dragonkeep/scans.jsonl` — one record per scan run.
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::Finding;
use crate::engine::ioc;
use crate::engine::quarantine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub path: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub verdict: String,
    pub matched_rules: Vec<String>,
    pub matched_hashes: Vec<String>,
    pub files_scanned: usize,
    pub detail: Option<String>,
}

/// Built-in YARA-style rule set. Each entry is `(rule_name, regex_bytes)`.
/// The regex is compiled once per scan; matches are recorded but never
/// executed against the file beyond a byte-level search.
fn builtin_rules() -> Vec<(&'static str, regex::bytes::Regex)> {
    let raw: &[(&str, &str)] = &[
        ("eicar-test",         r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR"),
        ("webshell-php-eval",  r"(?i)<\?php[^?]{0,200}eval\s*\(\s*\$_(?:POST|GET|REQUEST)"),
        ("powershell-iex-b64", r"(?i)IEX\s*\(\s*\[?Convert::FromBase64String"),
        ("metasploit-payload", r"(?i)msfvenom|meterpreter|metsrv\.dll"),
        ("c2-cobalt-strike",   r"(?i)cobaltstrike|beacon\.dll|teamserver"),
        ("reverse-shell-bash", r"bash\s+-i\s*>&?\s*/dev/tcp/"),
        ("password-stealer",   r"(?i)passwords?\.txt|wallet\.dat|keychain"),
    ];
    raw.iter()
        .filter_map(|(n, p)| regex::bytes::Regex::new(p).ok().map(|r| (*n, r)))
        .collect()
}

const SUSPICIOUS_EXT: &[&str] = &["exe", "scr", "vbs", "bat", "cmd", "ps1", "dll", "jar", "pyc"];
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;  // 32 MB cap per file

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

fn sha256_of(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut f = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 { break }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Scan verdict for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVerdict {
    pub verdict: String,
    pub matched_rules: Vec<String>,
    pub matched_hashes: Vec<String>,
    pub sha256: Option<String>,
    pub size: u64,
    /// Shannon entropy of the densest 4 KB window in the file. > 7.6
    /// strongly suggests packing / encryption.
    pub max_entropy: f32,
}

/// Compute Shannon entropy for a byte slice (max 8.0 bits).
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0 }
    let mut hist = [0u32; 256];
    for &b in data { hist[b as usize] += 1; }
    let len = data.len() as f32;
    let mut h = 0.0_f32;
    for &c in hist.iter() {
        if c == 0 { continue }
        let p = c as f32 / len;
        h -= p * p.log2();
    }
    h
}

/// Maximum Shannon entropy across overlapping 4 KB windows.
/// Returns 0.0 for inputs smaller than the window.
fn max_window_entropy(data: &[u8]) -> f32 {
    const WIN: usize = 4096;
    if data.len() < WIN { return shannon_entropy(data); }
    let mut hi = 0.0_f32;
    let step = WIN / 2;  // 50% overlap so we catch packed regions at any offset
    let mut i = 0;
    while i + WIN <= data.len() {
        let e = shannon_entropy(&data[i..i + WIN]);
        if e > hi { hi = e; }
        i += step;
    }
    hi
}

/// Scan one file and return its verdict.
pub fn scan_file(path: &Path) -> FileVerdict {
    let mut verdict = FileVerdict {
        verdict: "clean".to_string(),
        matched_rules: Vec::new(),
        matched_hashes: Vec::new(),
        sha256: None,
        size: 0,
        max_entropy: 0.0,
    };
    let meta = match fs::metadata(path) { Ok(m) => m, Err(_) => return verdict };
    if !meta.is_file() { return verdict }
    verdict.size = meta.len();
    if meta.len() > MAX_FILE_BYTES { return verdict }
    let mut content = Vec::with_capacity(meta.len() as usize);
    if fs::File::open(path).and_then(|mut f| f.read_to_end(&mut content)).is_err() {
        return verdict
    }
    let sha = sha256_of(path);
    verdict.sha256 = sha.clone();
    for (name, rule) in builtin_rules() {
        if rule.is_match(&content) {
            verdict.matched_rules.push(name.to_string());
        }
    }
    if let Some(ref s) = sha {
        if ioc::contains_hash(s) {
            verdict.matched_hashes.push(s.clone());
        }
    }

    // PE entropy heuristic — packed/encrypted binaries cluster above 7.5 bits.
    // Spec 013 acceptance criterion 2.
    let is_pe = content.starts_with(b"MZ");
    if is_pe {
        let h = max_window_entropy(&content);
        verdict.max_entropy = h;
        if h >= 7.6 {
            verdict.matched_rules.push(format!("packed-binary-entropy-{:.2}", h));
        }
    }

    if !verdict.matched_hashes.is_empty() {
        verdict.verdict = "malicious".into();
    } else if !verdict.matched_rules.is_empty() {
        verdict.verdict = "suspicious".into();
    } else if is_pe
        && path.extension().and_then(|e| e.to_str()).map(|e| SUSPICIOUS_EXT.contains(&e.to_lowercase().as_str())).unwrap_or(false)
    {
        verdict.verdict = "suspicious".into();
        verdict.matched_rules.push("pe-executable".into());
    }
    verdict
}

/// Scan a path (file or directory). Returns the aggregate ScanRecord.
/// When `auto_quarantine` is set, files with verdict suspicious/malicious
/// are moved into the quarantine vault as a side effect.
pub fn scan(target: &Path, recursive: bool, auto_quarantine: bool) -> ScanRecord {
    let started = now_iso();
    let mut paths: Vec<PathBuf> = Vec::new();
    if target.is_file() {
        paths.push(target.to_path_buf());
    } else if target.is_dir() {
        if recursive {
            walk_dir(target, &mut paths);
        } else if let Ok(rd) = fs::read_dir(target) {
            for e in rd.flatten() {
                if e.path().is_file() { paths.push(e.path()); }
            }
        }
    }
    if paths.len() > 5000 { paths.truncate(5000); }
    let mut worst = "clean".to_string();
    let mut all_rules: Vec<String> = Vec::new();
    let mut all_hashes: Vec<String> = Vec::new();
    for p in &paths {
        let v = scan_file(p);
        if (v.verdict == "suspicious" || v.verdict == "malicious") && auto_quarantine {
            let _ = quarantine::stash(p, &v);
        }
        if v.verdict == "malicious" {
            worst = "malicious".into();
        } else if v.verdict == "suspicious" && worst != "malicious" {
            worst = "suspicious".into();
        }
        all_rules.extend(v.matched_rules);
        all_hashes.extend(v.matched_hashes);
    }
    all_rules.sort(); all_rules.dedup();
    all_hashes.sort(); all_hashes.dedup();
    let id = format!("{}-{}", started, &paths.len());
    let record = ScanRecord {
        id: id.clone(),
        path: target.display().to_string(),
        started_at: started,
        finished_at: Some(now_iso()),
        verdict: worst,
        matched_rules: all_rules,
        matched_hashes: all_hashes,
        files_scanned: paths.len(),
        detail: None,
    };
    let _ = persist(&record);
    record
}

fn walk_dir(base: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(base) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_dir(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
        if out.len() > 5000 { return }
    }
}

fn persist(record: &ScanRecord) -> std::io::Result<()> {
    let dir = dragonkeep_dir();
    fs::create_dir_all(&dir)?;
    let path = dir.join("scans.jsonl");
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", serde_json::to_string(record).unwrap_or_default())
}

/// Adapter to the engine surface — a quick posture-check finding.
pub fn run() -> Vec<Finding> {
    let dir = dragonkeep_dir();
    let scans_path = dir.join("scans.jsonl");
    let mut count = 0usize;
    let mut last_malicious: Option<String> = None;
    if let Ok(content) = fs::read_to_string(&scans_path) {
        for line in content.lines().rev().take(200) {
            count += 1;
            if let Ok(r) = serde_json::from_str::<ScanRecord>(line) {
                if r.verdict == "malicious" {
                    last_malicious = Some(r.path);
                    break;
                }
            }
        }
    }
    let mut out = vec![Finding::info(format!("antivirus · {} scans recorded", count))
        .with_engine("antivirus")
        .with_rule("DK-AV-001")];
    if let Some(p) = last_malicious {
        out.push(Finding::critical("Malicious file detected by AV scan")
            .with_detail(format!("at {}", p))
            .with_engine("antivirus")
            .with_rule("DK-AV-002"));
    }
    out
}
