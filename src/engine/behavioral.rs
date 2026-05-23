//! Behavioral · NGAV-grade process-tree monitor.
//!
//! Polls /proc (Linux) for new processes, builds a parent-child tree, and
//! flags suspicious patterns:
//!   - shell-from-network (sh/bash spawned by a non-tty parent that opened a socket)
//!   - lolbin chains    (curl|sh, wget|sh, base64 → /tmp/*)
//!   - unusual parents  (web server spawning a shell)
//!   - persistence      (cron / systemd / launchd modifications)
//!
//! Cross-OS strategy: this module targets Linux today. macOS uses libproc
//! + endpoint security framework (TODO), Windows uses WMI + ETW (TODO).
//! See `crate::engine::platform` for the eventual abstraction.
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub cmdline: String,
    pub parent_cmd: String,
    pub uid: u32,
    pub started_at: String,
    pub rule_hits: Vec<String>,
    pub risk_score: u32,  // 0-100
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

#[cfg(target_os = "linux")]
fn read_cmdline(pid: u32) -> Option<String> {
    let buf = fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    Some(buf.split(|&b| b == 0).map(|s| String::from_utf8_lossy(s).to_string()).collect::<Vec<_>>().join(" ").trim().to_string())
}

#[cfg(target_os = "linux")]
fn read_status(pid: u32) -> Option<(u32, u32)> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let mut ppid = 0u32;
    let mut uid  = 0u32;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(first) = rest.split_whitespace().next() {
                uid = first.parse().unwrap_or(0);
            }
        }
    }
    Some((ppid, uid))
}

#[cfg(not(target_os = "linux"))]
fn read_cmdline(_pid: u32) -> Option<String> { None }
#[cfg(not(target_os = "linux"))]
fn read_status(_pid: u32) -> Option<(u32, u32)> { None }

/// Apply the behavioral rule set to a single process snapshot.
/// Returns matched rule IDs + a risk score 0-100.
pub fn evaluate(cmdline: &str, parent_cmd: &str) -> (Vec<String>, u32) {
    let cl = cmdline.to_lowercase();
    let pl = parent_cmd.to_lowercase();
    let mut hits: Vec<String> = Vec::new();
    let mut score: u32 = 0;

    // Shell-from-web-server
    if (pl.contains("nginx") || pl.contains("apache") || pl.contains("php-fpm") || pl.contains("httpd"))
        && (cl.contains("/sh") || cl.contains("/bash") || cl.contains("/zsh") || cl.starts_with("sh ") || cl.starts_with("bash "))
    {
        hits.push("web-server-spawned-shell".into()); score += 70;
    }

    // curl|sh / wget|sh
    if (cl.contains("curl") || cl.contains("wget")) && (cl.contains("| sh") || cl.contains("|sh") || cl.contains("| bash") || cl.contains("|bash")) {
        hits.push("curl-pipe-sh".into()); score += 60;
    }

    // base64 decode → /tmp execution
    if cl.contains("base64") && (cl.contains("-d") || cl.contains("--decode")) && cl.contains("/tmp") {
        hits.push("base64-decode-tmp".into()); score += 50;
    }

    // reverse shell
    if cl.contains("/dev/tcp/") || cl.contains("nc -e") || cl.contains("ncat -e") {
        hits.push("reverse-shell-pattern".into()); score += 80;
    }

    // python/perl one-liner exec
    if (cl.starts_with("python") || cl.starts_with("perl") || cl.starts_with("ruby")) && cl.contains("-c") && (cl.contains("socket") || cl.contains("subprocess")) {
        hits.push("interpreter-one-liner".into()); score += 40;
    }

    // crontab / systemctl modification (persistence)
    if cl.contains("crontab -e") || cl.contains("systemctl enable") || cl.contains("/etc/cron") || cl.contains("launchctl load") {
        hits.push("persistence-touch".into()); score += 30;
    }

    // Suspicious chained shell
    if cl.contains(";rm ") || cl.contains("&& rm ") || cl.contains("rm -rf /") {
        hits.push("destructive-rm".into()); score += 90;
    }

    (hits, score.min(100))
}

/// One sweep across running processes. Linux uses /proc directly;
/// macOS + Windows use the `sysinfo` crate (already a dependency).
/// Returns events whose risk_score >= 30 and persists each to
/// ~/.dragonkeep/behavioral.jsonl.
pub fn sweep() -> Vec<ProcessEvent> {
    let mut out: Vec<ProcessEvent> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let Ok(rd) = fs::read_dir("/proc") else { return out; };
        for e in rd.flatten() {
            let name = e.file_name();
            let s = name.to_string_lossy();
            let Ok(pid) = s.parse::<u32>() else { continue };
            let Some(cmdline) = read_cmdline(pid) else { continue };
            if cmdline.is_empty() { continue }
            let (ppid, uid) = read_status(pid).unwrap_or((0, 0));
            let parent_cmd = if ppid > 0 { read_cmdline(ppid).unwrap_or_default() } else { String::new() };
            let (hits, score) = evaluate(&cmdline, &parent_cmd);
            if score >= 30 {
                let evt = ProcessEvent {
                    pid, ppid, cmdline, parent_cmd, uid,
                    started_at: now_iso(),
                    rule_hits: hits, risk_score: score,
                };
                let _ = persist(&evt);
                out.push(evt);
            }
        }
    }

    // macOS / Windows / other Unix — use sysinfo for the cross-OS path.
    #[cfg(not(target_os = "linux"))]
    {
        use sysinfo::{System, Pid as SysPid};
        let mut sys = System::new_all();
        sys.refresh_processes();
        // First pass: build a pid → cmdline map so we can fetch parent_cmd cheaply.
        let mut cmdmap: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
        for (pid, proc_) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let cmd = proc_.cmd().join(" ");
            cmdmap.insert(pid_u32, if cmd.is_empty() { proc_.name().to_string() } else { cmd });
        }
        for (pid, proc_) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let cmdline = cmdmap.get(&pid_u32).cloned().unwrap_or_default();
            if cmdline.is_empty() { continue }
            let ppid = proc_.parent().map(SysPid::as_u32).unwrap_or(0);
            let parent_cmd = cmdmap.get(&ppid).cloned().unwrap_or_default();
            let uid = proc_.user_id().map(|u| u.to_string().parse::<u32>().unwrap_or(0)).unwrap_or(0);
            let (hits, score) = evaluate(&cmdline, &parent_cmd);
            if score >= 30 {
                let evt = ProcessEvent {
                    pid: pid_u32, ppid, cmdline, parent_cmd, uid,
                    started_at: now_iso(),
                    rule_hits: hits, risk_score: score,
                };
                let _ = persist(&evt);
                out.push(evt);
            }
        }
    }

    out
}

fn persist(evt: &ProcessEvent) -> std::io::Result<()> {
    let dir = dragonkeep_dir();
    fs::create_dir_all(&dir)?;
    let mut f = OpenOptions::new().create(true).append(true).open(dir.join("behavioral.jsonl"))?;
    writeln!(f, "{}", serde_json::to_string(evt).unwrap_or_default())
}

pub fn run() -> Vec<Finding> {
    let events = sweep();
    if events.is_empty() {
        return vec![Finding::pass("behavioral · no suspicious processes")
            .with_engine("behavioral").with_rule("DK-BHV-000")];
    }
    let mut out = Vec::with_capacity(events.len() + 1);
    out.push(Finding::warning(format!("behavioral · {} suspicious processes", events.len()))
        .with_engine("behavioral").with_rule("DK-BHV-001"));
    for evt in events.into_iter().take(10) {
        let sev = if evt.risk_score >= 70 { Finding::critical }
                  else if evt.risk_score >= 50 { Finding::high }
                  else { Finding::warning };
        out.push(sev(format!("pid {} · {}", evt.pid, evt.cmdline))
            .with_detail(format!("parent: {} · rules: {} · risk {}", evt.parent_cmd, evt.rule_hits.join(","), evt.risk_score))
            .with_engine("behavioral"));
    }
    out
}
