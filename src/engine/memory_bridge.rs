//! Memory Bridge — Phantom Memory HTTP client.
//!
//! Pushes DragonKeep defensive findings into Ghost Protocol's Phantom
//! Memory store, the unified offensive + defensive engagement memory.
//! Reads/writes happen through PhantomDragon Control's `control_api`.
//!
//! When the bridge is enabled, every Critical/High defensive finding
//! shows up next to offensive PhantomDragon findings in the same target
//! dossier. This is the moat — nobody else has one memory store that
//! holds both sides of the engagement.
//!
//! Bridge is opt-in via the `DRAGONKEEP_MEMORY_BRIDGE` env var (set it
//! to the control_api URL, e.g. `http://localhost:4091`). When unset,
//! findings stay local.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::process::Command;

use crate::engine::{Finding, Severity};

const ENV_VAR: &str = "DRAGONKEEP_MEMORY_BRIDGE";
const ENV_TOKEN: &str = "PD_CONTROL_TOKEN";
const ENV_HOST: &str = "DRAGONKEEP_HOST_TARGET";

#[derive(Serialize)]
struct DefensiveFindingPayload<'a> {
    target: &'a str,
    source: &'a str,
    identifier: Option<&'a str>,
    context: String,
    source_ref: Option<&'a str>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct PostAck {
    ok: bool,
}

/// Returns the configured bridge endpoint, or None if disabled.
pub fn bridge_endpoint() -> Option<String> {
    env::var(ENV_VAR).ok().filter(|s| !s.is_empty())
}

/// Local host identifier — used as the "target" key in Phantom Memory
/// for defensive findings. Operator can override via env.
pub fn host_target() -> String {
    if let Ok(v) = env::var(ENV_HOST) {
        if !v.is_empty() {
            return v;
        }
    }
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let t = s.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

/// Push a single finding to Phantom Memory. Best-effort: returns Err on
/// failure but the caller is expected to swallow it (defensive findings
/// must keep flowing locally even if the bridge is down).
pub async fn push_finding(finding: &Finding) -> Result<()> {
    let endpoint = bridge_endpoint().ok_or_else(|| anyhow!("bridge disabled"))?;
    let token = env::var(ENV_TOKEN).ok().unwrap_or_default();
    let host = host_target();

    let url = format!(
        "{}/v1/memory/credentials",
        endpoint.trim_end_matches('/')
    );

    let mut context = format!("[{}] {}", finding.severity.label(), finding.title);
    if let Some(d) = &finding.detail {
        context.push_str(" — ");
        context.push_str(d);
    }
    if let Some(mitre) = &finding.mitre {
        if !mitre.is_empty() {
            context.push_str(" · MITRE ");
            context.push_str(&mitre.join(","));
        }
    }

    let payload = DefensiveFindingPayload {
        target: &host,
        source: "DRAGONKEEP",
        identifier: finding.rule_id.as_deref(),
        context,
        source_ref: finding.engine.as_deref(),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let mut req = client.post(&url).json(&payload);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let res = req.send().await?;
    if !res.status().is_success() {
        return Err(anyhow!("bridge HTTP {}", res.status()));
    }
    Ok(())
}

/// Push every Critical/High finding from a scan to Phantom Memory.
/// Lower-severity findings stay local to keep the bridge signal-to-noise
/// high. Returns the number of findings successfully pushed.
pub async fn push_batch(findings: &[Finding]) -> usize {
    if bridge_endpoint().is_none() {
        return 0;
    }
    let mut pushed = 0;
    for f in findings {
        if matches!(f.severity, Severity::Critical | Severity::High)
            && push_finding(f).await.is_ok()
        {
            pushed += 1;
        }
    }
    pushed
}

/// One-shot smoke test of the bridge — used by `dragonkeep shield status`.
pub async fn check_bridge() -> Result<String> {
    let endpoint = bridge_endpoint().ok_or_else(|| anyhow!("DRAGONKEEP_MEMORY_BRIDGE not set"))?;
    let url = format!("{}/health", endpoint.trim_end_matches('/'));
    let token = env::var(ENV_TOKEN).ok().unwrap_or_default();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;
    let mut req = client.get(&url);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let res = req.send().await?;
    if !res.status().is_success() {
        return Err(anyhow!("bridge HTTP {}", res.status()));
    }
    Ok(format!("connected to {endpoint} as host {}", host_target()))
}
