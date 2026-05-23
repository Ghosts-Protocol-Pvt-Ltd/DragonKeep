//! Shield Engine — Managed Detection & Response (MDR) bridge.
//!
//! Correlates DragonKeep's defensive findings with Ghost Protocol's
//! Phantom Memory store. When enabled (DRAGONKEEP_MEMORY_BRIDGE env var
//! pointing at PhantomDragon Control's :4091), every Critical/High
//! defensive finding is pushed to the same engagement memory that holds
//! offensive scan findings. The result: one dossier per target, both
//! sides of the kill chain.
//!
//! Shield itself is light — it's the orchestration glue. The real
//! detection work happens in Sentinel/Hydra/Drake/Talon/Phantom; Shield
//! makes sure their output reaches Phantom Memory so cross-tool memory
//! works.

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;
use crate::engine::memory_bridge;
use crate::engine::{Finding, Severity};

/// Smoke-test the Phantom Memory bridge and report status.
pub async fn scan(_config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    eprintln!(
        "    {} Checking Phantom Memory bridge...",
        "→".dimmed()
    );

    match memory_bridge::bridge_endpoint() {
        None => {
            findings.push(
                Finding::info(
                    "Memory bridge disabled — defensive findings stay local",
                )
                .with_detail(
                    "Set DRAGONKEEP_MEMORY_BRIDGE=http://localhost:4091 \
                     (PhantomDragon Control) to enable cross-tool memory. \
                     With the bridge on, every Crit/High defensive finding \
                     joins the same target dossier as offensive scans.",
                )
                .with_engine("Shield")
                .with_rule("DK-SHL-001"),
            );
            return Ok(findings);
        }
        Some(endpoint) => match memory_bridge::check_bridge().await {
            Ok(msg) => findings.push(
                Finding::pass("Memory bridge online")
                    .with_detail(format!("{endpoint} — {msg}"))
                    .with_engine("Shield")
                    .with_rule("DK-SHL-002"),
            ),
            Err(e) => findings.push(
                Finding::warning("Memory bridge enabled but unreachable")
                    .with_detail(format!("{endpoint}: {e}"))
                    .with_fix(
                        "Start the dragon stack with `dragon serve` so \
                         PhantomDragon Control is up at :4091.",
                    )
                    .with_engine("Shield")
                    .with_rule("DK-SHL-003"),
            ),
        },
    }

    Ok(findings)
}

/// Push a batch of findings (typically the output of a full scan) to
/// Phantom Memory. Caller invokes after every scan run. No-op if the
/// bridge is disabled.
pub async fn forward(findings: &[Finding]) -> Result<usize> {
    let pushed = memory_bridge::push_batch(findings).await;
    if pushed > 0 {
        eprintln!(
            "  {} Forwarded {} finding{} to Phantom Memory",
            "→".green(),
            pushed,
            if pushed == 1 { "" } else { "s" }
        );
    }
    Ok(pushed)
}

/// Trigger an MDR-style auto-response based on severity. Today this is
/// a stub that logs; Phase 2 will hook into Respond (SOAR playbooks).
pub fn auto_respond(finding: &Finding) {
    if matches!(finding.severity, Severity::Critical) {
        eprintln!(
            "  {} Auto-response queued for: {}",
            "▲".red().bold(),
            finding.title
        );
    }
}
