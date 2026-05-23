//! Honeypot Engine — Active Deception.
//!
//! Extends DragonKeep's existing canary-file capability into full
//! deception: fake SSH banners, decoy credentials in places attackers
//! look (~/.aws/credentials, .git/config, /etc/passwd shadow stubs),
//! and tripwire processes that look interesting in `ps` output.
//!
//! When an attacker touches a decoy, Honeypot fires a CRITICAL finding
//! via Shield → Phantom Memory. The decoy itself is harmless.
//!
//! Today: catalog of available decoys + deployment status. Actual
//! deployment is gated behind `dragonkeep honeypot deploy <decoy>`.

use anyhow::Result;
use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::engine::Finding;

#[derive(Debug, Clone)]
struct Decoy {
    name: &'static str,
    description: &'static str,
    target_path: &'static str,
    risk_if_missing: bool,
}

const DECOYS: &[Decoy] = &[
    Decoy {
        name: "aws-creds",
        description: "Fake AWS credential file in ~/.aws/credentials",
        target_path: "~/.aws/credentials",
        risk_if_missing: false,
    },
    Decoy {
        name: "ssh-keypair",
        description: "Tripwire SSH keypair in ~/.ssh/id_rsa_backup",
        target_path: "~/.ssh/id_rsa_backup",
        risk_if_missing: false,
    },
    Decoy {
        name: "ransom-canary",
        description: "Ransomware canary file in ~/Documents/.canary.txt",
        target_path: "~/Documents/.canary.txt",
        risk_if_missing: true,
    },
    Decoy {
        name: "fake-passwd",
        description: "Tarpit /etc/shadow-style file in /tmp/sh-cred-cache",
        target_path: "/tmp/sh-cred-cache",
        risk_if_missing: false,
    },
];

fn expand(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(path)
}

/// Catalog deployed decoys.
pub async fn scan(_config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    eprintln!("    {} Auditing deception inventory...", "→".dimmed());

    let mut deployed = 0;
    let mut missing_risk = 0;
    for d in DECOYS {
        let p = expand(d.target_path);
        if p.exists() {
            deployed += 1;
            findings.push(
                Finding::pass(format!("Decoy deployed: {}", d.name))
                    .with_detail(d.description.to_string())
                    .with_engine("Honeypot")
                    .with_rule(format!("DK-HON-{}", d.name)),
            );
        } else if d.risk_if_missing {
            missing_risk += 1;
            findings.push(
                Finding::warning(format!("Critical decoy missing: {}", d.name))
                    .with_detail(format!(
                        "{} — recommend deploying via `dragonkeep honeypot deploy {}`",
                        d.description, d.name
                    ))
                    .with_engine("Honeypot")
                    .with_rule(format!("DK-HON-MISS-{}", d.name)),
            );
        }
    }
    findings.push(
        Finding::info(format!(
            "Honeypot inventory: {deployed} deployed, {missing_risk} risk-bearing missing"
        ))
        .with_engine("Honeypot")
        .with_rule("DK-HON-SUMMARY"),
    );

    Ok(findings)
}

pub fn list_decoys() -> Vec<(&'static str, &'static str, PathBuf)> {
    DECOYS
        .iter()
        .map(|d| (d.name, d.description, expand(d.target_path)))
        .collect()
}

/// Determine whether the given path is one of our decoys — used by the
/// monitor loop to fire a CRIT when an attacker touches it.
pub fn is_decoy(path: &Path) -> bool {
    DECOYS.iter().any(|d| expand(d.target_path) == *path)
}
