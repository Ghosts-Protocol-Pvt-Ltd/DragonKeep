//! Behavioral · Windows ETW (Event Tracing for Windows).
//!
//! Spec: dragon-platform/specs/004-windows-etw/
//!
//! Subscribes to the `Microsoft-Windows-Kernel-Process` provider
//! (`{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`) and feeds each
//! ProcessStart event into `engine::behavioral::evaluate` — the
//! same single source of truth the Linux + macOS paths use.
//!
//! Two compile modes:
//!
//!   default          — stub. start() returns a friendly error.
//!   --features etw   — real loader (Windows-only via cfg).
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use super::Finding;

/// `Microsoft-Windows-Kernel-Process` provider GUID.
pub const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    // Minimal admin-check using GetTokenInformation. We avoid pulling
    // a full winapi dependency by using `windows-sys` if present, but
    // for now we fall back to a heuristic: writing to %SystemRoot%.
    std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(r"C:\Windows\Temp\dragonkeep_elev_probe")
        .map(|_| true)
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn is_elevated() -> bool { false }

// ─── Default path (no `--features etw`) ─────────────────────────

#[cfg(not(feature = "etw"))]
pub fn start() -> Result<(), String> {
    Err("ETW support not compiled in · rebuild with `cargo build --features etw`".into())
}

#[cfg(not(feature = "etw"))]
pub fn stop() {}

// ─── Real path (with `--features etw` on Windows) ───────────────

#[cfg(all(target_os = "windows", feature = "etw"))]
mod runtime {
    use ferrisetw::provider::Provider;
    use ferrisetw::trace::UserTrace;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    static RUNNING: AtomicBool = AtomicBool::new(false);
    static TRACE:   OnceLock<UserTrace> = OnceLock::new();

    fn read_cmdline(pid: u32) -> String {
        use sysinfo::{System, Pid as SysPid};
        let mut s = System::new();
        s.refresh_process(SysPid::from_u32(pid));
        s.process(SysPid::from_u32(pid))
            .map(|p| p.cmd().join(" "))
            .unwrap_or_default()
    }

    pub fn start() -> Result<(), String> {
        if RUNNING.load(Ordering::SeqCst) { return Ok(()); }
        if !super::is_elevated() {
            return Err("ETW session requires Administrator · re-run elevated".into());
        }

        let kernel_process = Provider::by_guid(super::KERNEL_PROCESS_GUID)
            .add_callback(|record, schema_locator| {
                // Filter ProcessStart events (event id 1).
                if record.event_id() != 1 { return }
                let pid  = record.process_id();
                let parser = match schema_locator.event_schema(record) {
                    Ok(s) => ferrisetw::parser::Parser::create(record, &s),
                    Err(_) => return,
                };
                let cmdline: String = parser.try_parse("CommandLine").unwrap_or_default();
                let ppid:   u32    = parser.try_parse("ParentProcessID").unwrap_or(0);
                if cmdline.is_empty() { return }
                let parent_cmd = read_cmdline(ppid);
                let (hits, score) = crate::engine::behavioral::evaluate(&cmdline, &parent_cmd);
                if score >= 30 {
                    let pe = crate::engine::behavioral::ProcessEvent {
                        pid, ppid, cmdline: cmdline.clone(), parent_cmd, uid: 0,
                        started_at: super::now_iso(),
                        rule_hits: hits.clone(), risk_score: score,
                    };
                    let _ = super::persist(&pe);
                    crate::engine::telemetry::emit(
                        "behavioral_etw",
                        "process",
                        if score >= 70 { "critical" } else if score >= 50 { "high" } else { "medium" },
                        &format!("pid {} · {}", pid, cmdline),
                        serde_json::json!({"rule_hits": hits, "risk_score": score}),
                    );
                }
            })
            .build();

        let trace = UserTrace::new()
            .named("DragonKeep_Behavioral".into())
            .enable(kernel_process)
            .start_and_process()
            .map_err(|e| format!("ETW session start: {e}"))?;

        TRACE.set(trace).map_err(|_| "trace already initialised".to_string())?;
        RUNNING.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn stop() {
        RUNNING.store(false, Ordering::SeqCst);
        // UserTrace stops on Drop; OnceLock will keep it until process exit, which is fine.
    }
}

#[cfg(all(target_os = "windows", feature = "etw"))]
pub fn start() -> Result<(), String> { runtime::start() }

#[cfg(all(target_os = "windows", feature = "etw"))]
pub fn stop() { runtime::stop() }

// Used by the runtime module above
#[cfg(all(target_os = "windows", feature = "etw"))]
fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0).unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(all(target_os = "windows", feature = "etw"))]
fn persist(evt: &crate::engine::behavioral::ProcessEvent) -> std::io::Result<()> {
    use std::io::Write;
    let dir = std::env::var_os("DRAGONKEEP_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".dragonkeep"));
    std::fs::create_dir_all(&dir)?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("behavioral.jsonl"))?;
    writeln!(f, "{}", serde_json::to_string(evt).unwrap_or_default())
}

// ─── Public health surface ──────────────────────────────────────

pub fn run() -> Vec<Finding> {
    let supported = cfg!(target_os = "windows");
    if !supported {
        return vec![Finding::info("ETW · unsupported on this OS (Windows-only)")
            .with_engine("behavioral_etw").with_rule("DK-ETW-000")];
    }
    let elev = is_elevated();
    let mut out = vec![Finding::info(format!("ETW · supported · {}", if elev { "elevated" } else { "non-admin" }))
        .with_engine("behavioral_etw").with_rule("DK-ETW-001")];
    if !elev {
        out.push(Finding::warning("ETW · run as Administrator for real-time visibility")
            .with_engine("behavioral_etw").with_rule("DK-ETW-002"));
    }
    out
}
