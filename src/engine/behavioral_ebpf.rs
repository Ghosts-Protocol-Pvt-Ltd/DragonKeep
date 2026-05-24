//! Behavioral · eBPF probe (Linux only).
//!
//! Spec: dragon-platform/specs/002-ebpf-userspace-loader/
//!
//! Two compile modes:
//!
//!   default              — stub. supported() / attach() / detach() exist but
//!                          do nothing. Lets the rest of the codebase reference
//!                          this module without pulling libbpf.
//!
//!   --features ebpf      — real loader. Compiles process_trace.bpf.c via
//!                          libbpf-cargo (build.rs), loads + attaches at
//!                          startup, drains the ring buffer in a poll thread,
//!                          feeds events into engine::behavioral::evaluate.
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

// ─── Default path (no `--features ebpf`) ────────────────────────

#[cfg(not(feature = "ebpf"))]
mod loader {
    pub fn attach() -> Result<(), String> {
        Err("eBPF support not compiled in · rebuild with `cargo build --features ebpf`".into())
    }
    pub fn detach() {}
}

// ─── Real path (with `--features ebpf`) ─────────────────────────
//
// We deliberately import the generated skeleton inside this module so
// the rest of the engine surface keeps compiling without the feature.

#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[path = "../bpf/process_trace.skel.rs"]
mod process_trace_skel;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod loader {
    use super::*;
    use libbpf_rs::{RingBufferBuilder, MapCore, OpenObject};
    use std::mem::MaybeUninit;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Layout must match `struct event` in process_trace.bpf.c.
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct Event {
        pid:    u32,
        ppid:   u32,
        uid:    u32,
        ts_ns:  u64,
        comm:   [u8; 16],
        args:   [u8; 256],
    }
    unsafe impl plain::Plain for Event {}

    static RUNNING: AtomicBool = AtomicBool::new(false);
    static OBJ:     OnceLock<&'static mut OpenObject> = OnceLock::new();

    fn read_cmdline(pid: u32) -> String {
        std::fs::read(format!("/proc/{}/cmdline", pid))
            .ok()
            .map(|b| b.split(|&c| c == 0).map(|s| String::from_utf8_lossy(s).to_string())
                     .collect::<Vec<_>>().join(" ").trim().to_string())
            .unwrap_or_default()
    }

    pub fn attach() -> Result<(), String> {
        if RUNNING.load(Ordering::SeqCst) {
            return Ok(());
        }
        if !super::supported() {
            return Err("BTF (/sys/kernel/btf/vmlinux) not present — kernel rebuild needed".into());
        }
        // Leak the OpenObject — it must live for the lifetime of the program.
        let open = Box::leak(Box::new(MaybeUninit::uninit()));
        let builder = process_trace_skel::ProcessTraceSkelBuilder::default();
        let mut skel = builder.open(open).map_err(|e| format!("open: {e}"))?
                              .load().map_err(|e| format!("load: {e}"))?;
        skel.attach().map_err(|e| format!("attach: {e}"))?;

        // Build the ring buffer with our event handler.
        let mut rb_builder = RingBufferBuilder::new();
        rb_builder
            .add(&skel.maps.events, |data: &[u8]| -> i32 {
                let mut evt = Event {
                    pid: 0, ppid: 0, uid: 0, ts_ns: 0,
                    comm: [0; 16], args: [0; 256],
                };
                if plain::copy_from_bytes(&mut evt, data).is_err() {
                    return 0;
                }
                // Take just the printable comm + args
                let comm = std::str::from_utf8(&evt.comm).unwrap_or("").trim_end_matches('\0');
                let cmdline = read_cmdline(evt.pid);
                let cmdline = if cmdline.is_empty() { comm.to_string() } else { cmdline };
                let parent_cmd = read_cmdline(evt.ppid);

                let (hits, score) = crate::engine::behavioral::evaluate(&cmdline, &parent_cmd);
                if score >= 30 {
                    let pe = crate::engine::behavioral::ProcessEvent {
                        pid: evt.pid, ppid: evt.ppid,
                        cmdline: cmdline.clone(), parent_cmd, uid: evt.uid,
                        started_at: now_iso(),
                        rule_hits: hits.clone(), risk_score: score,
                    };
                    // Reuse the existing persist path (private — so we serialise here too).
                    let _ = persist(&pe);
                    crate::engine::telemetry::emit(
                        "behavioral_ebpf",
                        "process",
                        if score >= 70 { "critical" } else if score >= 50 { "high" } else { "medium" },
                        &format!("pid {} · {}", evt.pid, cmdline),
                        serde_json::json!({"rule_hits": hits, "risk_score": score}),
                    );
                }
                0
            })
            .map_err(|e| format!("ringbuf add: {e}"))?;
        let rb = rb_builder.build().map_err(|e| format!("ringbuf build: {e}"))?;

        // Spawn polling thread. Leaking is fine — daemon lifetime is process lifetime.
        std::thread::Builder::new().name("dragon-ebpf".into())
            .spawn(move || {
                RUNNING.store(true, Ordering::SeqCst);
                while RUNNING.load(Ordering::SeqCst) {
                    let _ = rb.poll(std::time::Duration::from_millis(100));
                }
            })
            .map_err(|e| format!("spawn: {e}"))?;

        // Skel must outlive the thread too.
        Box::leak(Box::new(skel));
        Ok(())
    }

    pub fn detach() {
        RUNNING.store(false, Ordering::SeqCst);
    }

    fn persist(evt: &crate::engine::behavioral::ProcessEvent) -> std::io::Result<()> {
        use std::io::Write;
        let dir = super::dragonkeep_dir();
        std::fs::create_dir_all(&dir)?;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("behavioral.jsonl"))?;
        writeln!(f, "{}", serde_json::to_string(evt).unwrap_or_default())
    }
}

// ─── Public surface · proxies through `loader` ──────────────────

/// Attach the BPF program. Idempotent. Returns Err with an actionable
/// message if the kernel is missing BTF or if the binary was built
/// without `--features ebpf`.
pub fn attach() -> Result<(), String> {
    #[cfg(target_os = "linux")] { loader::attach() }
    #[cfg(not(target_os = "linux"))] { Err("eBPF is Linux-only".into()) }
}

/// Detach. Idempotent. Always safe to call.
pub fn detach() {
    #[cfg(target_os = "linux")] { loader::detach() }
}

pub fn run() -> Vec<Finding> {
    if !supported() {
        return vec![Finding::info("eBPF · unsupported on this OS / kernel")
            .with_engine("behavioral_ebpf").with_rule("DK-BPF-000")];
    }
    let log = dragonkeep_dir().join("ebpf.jsonl");
    let count = std::fs::read_to_string(&log).map(|s| s.lines().count()).unwrap_or(0);
    let mut out = vec![Finding::info(format!("eBPF · {} events captured", count))
        .with_engine("behavioral_ebpf").with_rule("DK-BPF-001")];
    if std::env::var("DK_EBPF_LOAD").ok().as_deref() == Some("1") {
        match attach() {
            Ok(_)  => out.push(Finding::info("eBPF probe attached")
                .with_engine("behavioral_ebpf").with_rule("DK-BPF-002")),
            Err(e) => out.push(Finding::warning(format!("eBPF probe attach failed · {e}"))
                .with_engine("behavioral_ebpf").with_rule("DK-BPF-003")),
        }
    }
    out
}
