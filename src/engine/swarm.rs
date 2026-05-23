//! Swarm Engine — Multi-Host Federation.
//!
//! DragonKeep Pro can manage a fleet. Swarm aggregates findings from
//! multiple hosts through Phantom Memory (each host targets itself, and
//! Phantom Memory's per-target dossier acts as the per-host fleet view).
//!
//! Today: reports fleet-wide statistics from Phantom Memory. Each host
//! must have `DRAGONKEEP_MEMORY_BRIDGE` configured so findings land in
//! the shared store. Operator runs `dragonkeep swarm status` on any
//! host to see the entire fleet's defensive posture.

use anyhow::Result;
use colored::Colorize;
use std::env;

use crate::config::Config;
use crate::engine::memory_bridge;
use crate::engine::Finding;

/// Report fleet status by querying Phantom Memory.
pub async fn scan(_config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    eprintln!("    {} Querying fleet via Phantom Memory...", "→".dimmed());

    let endpoint = match memory_bridge::bridge_endpoint() {
        Some(e) => e,
        None => {
            findings.push(
                Finding::info("Swarm requires Phantom Memory bridge")
                    .with_detail(
                        "Set DRAGONKEEP_MEMORY_BRIDGE=http://localhost:4091 \
                         on every host you want federated. Each host pushes \
                         its findings to the shared store and Swarm reads \
                         the union back."
                            .to_string(),
                    )
                    .with_engine("Swarm")
                    .with_rule("DK-SWM-001"),
            );
            return Ok(findings);
        }
    };

    let token = env::var("PD_CONTROL_TOKEN").ok().unwrap_or_default();
    let url = format!("{}/v1/memory", endpoint.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let mut req = client.get(&url);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    match req.send().await {
        Ok(res) if res.status().is_success() => {
            match res.json::<serde_json::Value>().await {
                Ok(body) => {
                    let n = body
                        .get("targets")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    findings.push(
                        Finding::pass(format!(
                            "Swarm: {n} target(s) tracked in Phantom Memory"
                        ))
                        .with_detail(format!(
                            "Each host pushes findings as itself; Phantom Memory \
                             aggregates the union. Inspect any host: \
                             `dragon memory show <host>`."
                        ))
                        .with_engine("Swarm")
                        .with_rule("DK-SWM-002"),
                    );
                }
                Err(e) => findings.push(
                    Finding::warning("Swarm query returned non-JSON")
                        .with_detail(format!("{e}"))
                        .with_engine("Swarm")
                        .with_rule("DK-SWM-003"),
                ),
            }
        }
        Ok(res) => findings.push(
            Finding::warning(format!("Swarm query HTTP {}", res.status()))
                .with_engine("Swarm")
                .with_rule("DK-SWM-004"),
        ),
        Err(e) => findings.push(
            Finding::warning(format!("Swarm query failed: {e}"))
                .with_detail(
                    "Is the bridge endpoint reachable? `dragon serve` to start \
                     the dragon stack."
                        .to_string(),
                )
                .with_engine("Swarm")
                .with_rule("DK-SWM-005"),
        ),
    }

    Ok(findings)
}
