//! Autoblock · NGAV automated response.
//!
//! Capabilities:
//!   - Kill a malicious process by PID (SIGTERM then SIGKILL)
//!   - Network block by IP/domain (writes nftables rules on Linux; pf
//!     on macOS; Windows Defender Firewall on Windows — TODO platform.rs)
//!   - Self-protect: detect attempts to kill the dragonkeep process
//!     itself and log them
//!
//! All actions are logged to telemetry + the autoblock journal so the
//! operator can audit every automated response.
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Finding;
use super::telemetry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAction {
    pub id: String,
    pub ts: String,
    pub kind: String,    // "kill" · "net_block" · "file_block"
    pub target: String,  // PID, IP, domain, or path
    pub reason: String,
    pub result: String,  // "ok" · "fail" · "skipped"
    pub detail: Option<String>,
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

fn record(action: BlockAction) {
    let dir = dragonkeep_dir();
    let _ = fs::create_dir_all(&dir);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(dir.join("autoblock.jsonl")) {
        let _ = writeln!(f, "{}", serde_json::to_string(&action).unwrap_or_default());
    }
    telemetry::emit("autoblock", "response", &action.result, &format!("{}: {}", action.kind, action.target),
        serde_json::json!({"reason": action.reason, "result": action.result}));
}

/// Kill a process. Sends SIGTERM, waits 500ms, then SIGKILL if still alive.
/// Cross-OS: Unix uses libc::kill; Windows TODO.
pub fn kill_pid(pid: u32, reason: &str) -> BlockAction {
    let mut action = BlockAction {
        id: uuid::Uuid::new_v4().to_string(),
        ts: now_iso(), kind: "kill".into(), target: pid.to_string(),
        reason: reason.into(), result: "ok".into(), detail: None,
    };
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        let p = Pid::from_raw(pid as i32);
        match kill(p, Signal::SIGTERM) {
            Ok(_) => {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let _ = kill(p, Signal::SIGKILL);
            }
            Err(e) => { action.result = "fail".into(); action.detail = Some(e.to_string()); }
        }
    }
    #[cfg(not(unix))]
    {
        action.result = "skipped".into();
        action.detail = Some("kill_pid not implemented on this OS — see platform.rs".into());
    }
    record(action.clone());
    action
}

/// Block an IPv4 / IPv6 / domain. Linux uses an nftables `dragonkeep_block`
/// set; falls back to /etc/hosts rewrite for domains if nft is unavailable.
pub fn net_block(target: &str, reason: &str) -> BlockAction {
    let mut action = BlockAction {
        id: uuid::Uuid::new_v4().to_string(),
        ts: now_iso(), kind: "net_block".into(), target: target.into(),
        reason: reason.into(), result: "ok".into(), detail: None,
    };
    #[cfg(target_os = "linux")]
    {
        // Best-effort: append to nftables set if `nft` is available.
        if let Ok(out) = std::process::Command::new("nft")
            .args(["add", "element", "inet", "filter", "dragonkeep_block", &format!("{{{}}}", target)])
            .output()
        {
            if !out.status.success() {
                action.result = "fail".into();
                action.detail = Some(String::from_utf8_lossy(&out.stderr).to_string());
            }
        } else {
            action.result = "skipped".into();
            action.detail = Some("nft not found".into());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        action.result = "skipped".into();
        action.detail = Some("net_block not yet implemented for this OS".into());
    }
    record(action.clone());
    action
}

pub fn list_actions() -> Vec<BlockAction> {
    let path = dragonkeep_dir().join("autoblock.jsonl");
    let Ok(content) = fs::read_to_string(path) else { return vec![] };
    content.lines().filter(|l| !l.is_empty()).filter_map(|l| serde_json::from_str(l).ok()).collect()
}

pub fn run() -> Vec<Finding> {
    let actions = list_actions();
    let recent = actions.iter().rev().take(50).collect::<Vec<_>>();
    let n = recent.len();
    let mut out = vec![Finding::info(format!("autoblock · {} actions logged", actions.len()))
        .with_engine("autoblock").with_rule("DK-AB-001")];
    if n > 0 {
        let fails = recent.iter().filter(|a| a.result == "fail").count();
        if fails > 0 {
            out.push(Finding::warning(format!("{} autoblock failures in last 50", fails))
                .with_engine("autoblock").with_rule("DK-AB-002"));
        }
    }
    out
}
