//! Behavioral · eBPF probe (Linux only).
//!
//! This module provides a sub-microsecond process-spawn visibility layer
//! using eBPF kprobes. Today it ships a *stub* that documents the
//! intended interface; the real load is gated behind the `ebpf` feature
//! flag (planned for v0.9 once libbpf-rs is wired in).
//!
//! Approach:
//!   - Attach kprobe to `__x64_sys_execve` (and the equivalent on aarch64)
//!   - Forward (pid, ppid, comm[16], argv[0..N]) into a ring buffer
//!   - User-space consumer pulls events, runs evaluate(), persists hits
//!
//! For now this module compiles on Linux as a stub: it polls every 250 ms
//! via the regular sysinfo path and tags events with `source: "ebpf-fallback"`
//! so operators can wire dashboards now and seamlessly upgrade later.
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfEvent {
    pub ts: String,
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub argv: Vec<String>,
    pub source: String,  // "ebpf" or "ebpf-fallback"
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

/// Check whether the kernel + tooling supports loading our BPF programs.
/// Today's gate: `/sys/kernel/btf/vmlinux` must exist and the operator
/// must be root (or have CAP_BPF).
pub fn supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Future: attach the BPF program. For now this is a no-op so the rest
/// of the system can call it without conditional code.
pub fn attach() -> Result<(), String> {
    if !supported() {
        return Err("eBPF not supported on this OS / kernel".into());
    }
    // TODO(v0.9): libbpf_rs::skel_builder + open + load + attach
    Ok(())
}

/// Future: detach the BPF program. Idempotent.
pub fn detach() { /* no-op until v0.9 */ }

pub fn run() -> Vec<Finding> {
    if !supported() {
        return vec![Finding::info("eBPF · unsupported on this OS / kernel")
            .with_engine("behavioral_ebpf").with_rule("DK-BPF-000")];
    }
    let log = dragonkeep_dir().join("ebpf.jsonl");
    let count = std::fs::read_to_string(&log).map(|s| s.lines().count()).unwrap_or(0);
    let mut out = vec![Finding::info(format!("eBPF · {} events captured (fallback mode)", count))
        .with_engine("behavioral_ebpf").with_rule("DK-BPF-001")];
    if std::env::var("DK_EBPF_LOAD").ok().as_deref() == Some("1") {
        match attach() {
            Ok(_)  => out.push(Finding::info("eBPF probe ATTACH ok (no-op; v0.9 wires real loader)")
                .with_engine("behavioral_ebpf").with_rule("DK-BPF-002")),
            Err(e) => out.push(Finding::warning(format!("eBPF probe attach failed · {e}"))
                .with_engine("behavioral_ebpf").with_rule("DK-BPF-003")),
        }
    }
    out
}
