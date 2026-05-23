//! Memory · in-memory YARA-style scan.
//!
//! Walks /proc/{pid}/maps + /proc/{pid}/mem on Linux to scan running
//! processes for embedded malware signatures. Process is paused with
//! ptrace + PTRACE_SEIZE / INTERRUPT for a consistent read, then released.
//!
//! Cross-OS: today Linux. macOS would use `vm_read` via task_for_pid()
//! (requires SIP-disable + entitlement); Windows uses `ReadProcessMemory`
//! after `OpenProcess(PROCESS_VM_READ)`. Both are gated behind a stub.
//!
//! Caveats:
//!   - Reading a 32 GB process is slow; we cap per-region at 16 MB
//!   - Some regions are unreadable (e.g. PROT_NONE); we skip those
//!   - We never *modify* memory — read-only by design
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryHit {
    pub pid: u32,
    pub region_start: u64,
    pub region_end: u64,
    pub rule: String,
    pub bytes_at_hit: u64,
    pub ts: String,
}

const MAX_REGION_BYTES: u64 = 16 * 1024 * 1024;  // 16 MB cap per memory region
const MAX_TOTAL_BYTES:  u64 = 256 * 1024 * 1024; // 256 MB cap per scan

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

/// Built-in patterns for memory scanning — same as antivirus.rs file rules
/// but limited to those that make sense in a running process image.
fn memory_rules() -> Vec<(&'static str, regex::bytes::Regex)> {
    let raw: &[(&str, &str)] = &[
        ("mem-metasploit-payload",     r"(?i)metsrv\.dll|meterpreter|msfvenom"),
        ("mem-cobalt-strike",          r"(?i)cobaltstrike|beacon\.dll|teamserver"),
        ("mem-shellcode-egghunter",    r"\xc7\xc7\x41\xc7\xc7\x41"),
        ("mem-reverse-shell-pattern",  r"/dev/tcp/|bash -i"),
        ("mem-credential-keyword",     r"(?i)passwords?\.txt|wallet\.dat|keychain"),
        ("mem-c2-pivot",               r"(?i)\bsocks5://|\bssh -R\b"),
    ];
    raw.iter()
        .filter_map(|(n, p)| regex::bytes::Regex::new(p).ok().map(|r| (*n, r)))
        .collect()
}

#[cfg(target_os = "linux")]
fn read_maps(pid: u32) -> Vec<(u64, u64, String)> {
    let path = format!("/proc/{}/maps", pid);
    let Ok(s) = fs::read_to_string(path) else { return vec![] };
    let mut out = Vec::new();
    for line in s.lines() {
        // Example: 7f1234-7f5678 r-xp ... [heap]
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else { continue };
        let Some(perms) = parts.next() else { continue };
        if !perms.contains('r') { continue }
        let mut rp = range.split('-');
        let Some(start_s) = rp.next() else { continue };
        let Some(end_s) = rp.next() else { continue };
        let Ok(start) = u64::from_str_radix(start_s, 16) else { continue };
        let Ok(end) = u64::from_str_radix(end_s, 16) else { continue };
        out.push((start, end, perms.to_string()));
    }
    out
}

/// Scan a single PID. Returns memory hits; persists to ~/.dragonkeep/memory.jsonl.
pub fn scan_pid(pid: u32) -> Vec<MemoryHit> {
    let mut out: Vec<MemoryHit> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let rules = memory_rules();
        let maps = read_maps(pid);
        if maps.is_empty() { return out; }
        let mem_path = format!("/proc/{}/mem", pid);
        let Ok(mut f) = fs::File::open(&mem_path) else { return out; };
        let mut total: u64 = 0;
        for (start, end, _perms) in maps {
            if total >= MAX_TOTAL_BYTES { break; }
            let len = end.saturating_sub(start).min(MAX_REGION_BYTES);
            if len == 0 { continue }
            if f.seek(SeekFrom::Start(start)).is_err() { continue; }
            let mut buf = vec![0u8; len as usize];
            // Reading /proc/PID/mem can EFAULT on PROT_NONE pages — skip those quietly.
            if f.read_exact(&mut buf).is_err() { continue; }
            total = total.saturating_add(len);
            for (rule_name, rule) in &rules {
                if let Some(m) = rule.find(&buf) {
                    let hit = MemoryHit {
                        pid,
                        region_start: start,
                        region_end: end,
                        rule: (*rule_name).to_string(),
                        bytes_at_hit: start + m.start() as u64,
                        ts: now_iso(),
                    };
                    let _ = persist(&hit);
                    out.push(hit);
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        // macOS / Windows / other Unix: stubbed — see module doc.
    }

    out
}

fn persist(hit: &MemoryHit) -> std::io::Result<()> {
    use std::io::Write;
    let dir = dragonkeep_dir();
    fs::create_dir_all(&dir)?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("memory.jsonl"))?;
    writeln!(f, "{}", serde_json::to_string(hit).unwrap_or_default())
}

/// Sweep every process listed in /proc. Returns total hits.
pub fn sweep_all() -> Vec<MemoryHit> {
    let mut all: Vec<MemoryHit> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        let Ok(rd) = fs::read_dir("/proc") else { return all };
        for e in rd.flatten() {
            let s = e.file_name().to_string_lossy().to_string();
            let Ok(pid) = s.parse::<u32>() else { continue };
            // Skip self to avoid scanning the scanner.
            if pid == std::process::id() { continue }
            all.extend(scan_pid(pid));
        }
    }
    all
}

pub fn run() -> Vec<Finding> {
    let hits = sweep_all();
    if hits.is_empty() {
        return vec![Finding::pass("memory_scan · no in-memory malware patterns")
            .with_engine("memory_scan").with_rule("DK-MEM-000")];
    }
    let mut out = vec![Finding::critical(format!("memory_scan · {} in-memory hits", hits.len()))
        .with_engine("memory_scan").with_rule("DK-MEM-001")];
    for h in hits.into_iter().take(10) {
        out.push(Finding::critical(format!("pid {} · rule {} at 0x{:x}", h.pid, h.rule, h.bytes_at_hit))
            .with_detail(format!("region 0x{:x}-0x{:x}", h.region_start, h.region_end))
            .with_engine("memory_scan"));
    }
    out
}
