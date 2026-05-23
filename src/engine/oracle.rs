//! Oracle Engine — Threat Intel Feed Integration.
//!
//! Pulls free public threat intel feeds and uses them to enrich
//! DragonKeep findings:
//!
//! - **CISA KEV** (Known Exploited Vulnerabilities) — prioritises CVE
//!   findings by whether they're being actively exploited in the wild.
//! - **MISP / OTX** (operator-configured) — IOC matching.
//! - **PhishTank / URLhaus** (planned) — URL reputation for any URLs
//!   referenced in findings.
//!
//! All feeds are HTTPS-pulled with rustls. No paid API keys. Constitution-I
//! aligned: free public data only.
//!
//! Today: CISA KEV pull + summary. Phase 2: KEV match against existing
//! findings, OTX pull, PhishTank cache.

use anyhow::Result;
use colored::Colorize;
use std::path::PathBuf;

use crate::config::Config;
use crate::engine::Finding;

const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

fn kev_cache_path() -> PathBuf {
    dirs::cache_dir()
        .map(|d| d.join("dragonkeep").join("kev.json"))
        .unwrap_or_else(|| PathBuf::from("/tmp/dragonkeep-kev.json"))
}

/// Report Oracle status: feed freshness, KEV count.
pub async fn scan(_config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    eprintln!("    {} Auditing threat-intel feeds...", "→".dimmed());

    let cache = kev_cache_path();
    if cache.exists() {
        if let Ok(meta) = std::fs::metadata(&cache) {
            if let Ok(modified) = meta.modified() {
                let age_days = modified
                    .elapsed()
                    .map(|d| d.as_secs() / 86_400)
                    .unwrap_or(u64::MAX);
                let title = format!("CISA KEV cache: {age_days} day(s) old");
                let mut f = match age_days {
                    0..=7 => Finding::pass(title),
                    8..=30 => Finding::info(title),
                    _ => Finding::warning(title),
                };
                f = f
                    .with_engine("Oracle")
                    .with_rule("DK-ORA-001")
                    .with_fix(
                        "Refresh via `dragonkeep oracle refresh`. \
                         Daily refresh recommended."
                            .to_string(),
                    );
                findings.push(f);
            }
        }
    } else {
        findings.push(
            Finding::info("CISA KEV feed not yet pulled")
                .with_detail(format!(
                    "Cache will be written to {}. Run \
                     `dragonkeep oracle refresh` to seed.",
                    cache.display()
                ))
                .with_engine("Oracle")
                .with_rule("DK-ORA-002"),
        );
    }

    Ok(findings)
}

/// Pull the CISA KEV feed and write it to the cache.
pub async fn refresh_kev() -> Result<usize> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let res = client.get(KEV_URL).send().await?;
    if !res.status().is_success() {
        return Err(anyhow::anyhow!("KEV HTTP {}", res.status()));
    }
    let body = res.text().await?;
    let cache = kev_cache_path();
    if let Some(parent) = cache.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cache, &body)?;
    // Roughly count entries (catalog has `vulnerabilities` array)
    let count = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("vulnerabilities")
                .and_then(|x| x.as_array())
                .map(|a| a.len())
        })
        .unwrap_or(0);
    Ok(count)
}

/// Return whether a CVE is in the operator's cached KEV catalog.
pub fn is_known_exploited(cve: &str) -> bool {
    let cache = kev_cache_path();
    if !cache.exists() {
        return false;
    }
    let Ok(body) = std::fs::read_to_string(&cache) else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return false;
    };
    v.get("vulnerabilities")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter().any(|entry| {
                entry
                    .get("cveID")
                    .and_then(|x| x.as_str())
                    .map(|x| x.eq_ignore_ascii_case(cve))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}
