//! Respond Engine — SOAR Playbooks (Security Orchestration, Automation,
//! Response).
//!
//! When Shield/Sentinel/Hydra/Drake produce a Critical or High finding,
//! Respond can execute a pre-configured playbook: kill a process, block
//! an IP, isolate a host, page an operator, post to a webhook.
//!
//! Playbooks live in `~/.config/dragonkeep/playbooks/*.toml`. Each file
//! is a TOML document declaring `match` rules + `actions`. The engine
//! is dry-run-first: it always shows what it would do, then asks (or
//! reads `auto_apply = true` from the playbook) before acting.
//!
//! Today: scaffold + status reporting. Phase 2 will wire actual action
//! handlers (process kill, iptables, webhook POST).

use anyhow::Result;
use colored::Colorize;
use std::path::PathBuf;

use crate::config::Config;
use crate::engine::Finding;

fn playbooks_dir() -> PathBuf {
    dirs::config_dir()
        .map(|d| d.join("dragonkeep").join("playbooks"))
        .unwrap_or_else(|| PathBuf::from("/etc/dragonkeep/playbooks"))
}

/// Audit Respond's configuration and capabilities.
pub async fn scan(_config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    eprintln!("    {} Auditing SOAR playbooks...", "→".dimmed());

    let dir = playbooks_dir();
    if !dir.exists() {
        findings.push(
            Finding::info("No SOAR playbooks configured")
                .with_detail(format!(
                    "Drop playbook TOML files into {} to enable auto-response.",
                    dir.display()
                ))
                .with_engine("Respond")
                .with_rule("DK-RES-001"),
        );
        return Ok(findings);
    }

    let playbooks: Vec<_> = std::fs::read_dir(&dir)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .and_then(|x| x.to_str())
                        .map(|x| x == "toml")
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();

    if playbooks.is_empty() {
        findings.push(
            Finding::info("Playbooks directory empty")
                .with_engine("Respond")
                .with_rule("DK-RES-002"),
        );
    } else {
        findings.push(
            Finding::pass(format!("{} SOAR playbook(s) loaded", playbooks.len()))
                .with_detail(
                    playbooks
                        .iter()
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
                .with_engine("Respond")
                .with_rule("DK-RES-003"),
        );
    }
    Ok(findings)
}
