//! Community Edition Features
//!
//! Free community-powered capabilities:
//!   - Community threat intelligence feed integration
//!   - Shared detection rules (Sigma-compatible)
//!   - Crowdsourced IOC database
//!   - Community scan profiles
//!   - Anonymous telemetry for threat landscape awareness
//!   - Automated security score with benchmarking
//!   - Quick-start security hardening templates
//!   - Export to community threat databases (abuse.ch, OTX)
//!   - DragonKeep community rule updates (OTA)
//!   - Local threat intelligence caching

use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use crate::config::Config;
use crate::engine::Finding;

/// Community threat feed sources
const COMMUNITY_FEEDS: &[(&str, &str)] = &[
    ("abuse.ch", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("abuse.ch SSL", "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"),
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/text_recent/"),
    ("emergingthreats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
];

/// Community scan profiles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    pub name: String,
    pub description: String,
    pub engines: Vec<String>,
    pub severity_threshold: String,
}

/// Security score categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScore {
    pub overall: u32,
    pub categories: Vec<CategoryScore>,
    pub grade: String,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScore {
    pub name: String,
    pub score: u32,
    pub max: u32,
    pub details: String,
}

/// Default community scan profiles
pub fn default_profiles() -> Vec<ScanProfile> {
    vec![
        ScanProfile {
            name: "quick".into(),
            description: "Fast security check — essential scans only (~30 seconds)".into(),
            engines: vec!["sentinel".into(), "warden".into()],
            severity_threshold: "high".into(),
        },
        ScanProfile {
            name: "standard".into(),
            description: "Balanced security audit — all engines, moderate depth (~2 minutes)".into(),
            engines: vec!["sentinel".into(), "forge".into(), "warden".into(),
                "bastion".into(), "citadel".into()],
            severity_threshold: "warning".into(),
        },
        ScanProfile {
            name: "deep".into(),
            description: "Comprehensive audit — all 11 engines, full depth (~5 minutes)".into(),
            engines: vec!["sentinel".into(), "forge".into(), "warden".into(),
                "bastion".into(), "citadel".into(), "spectre".into(),
                "aegis".into(), "phantom".into(), "hydra".into(),
                "drake".into(), "talon".into()],
            severity_threshold: "info".into(),
        },
        ScanProfile {
            name: "malware".into(),
            description: "Malware & ransomware focused scan".into(),
            engines: vec!["hydra".into(), "drake".into(), "warden".into(), "phantom".into()],
            severity_threshold: "info".into(),
        },
        ScanProfile {
            name: "threat-hunt".into(),
            description: "Proactive threat hunting — detect active attackers".into(),
            engines: vec!["talon".into(), "hydra".into(), "phantom".into(),
                "warden".into(), "bastion".into()],
            severity_threshold: "info".into(),
        },
        ScanProfile {
            name: "compliance".into(),
            description: "STIG/NIST/CIS compliance audit".into(),
            engines: vec!["sentinel".into(), "citadel".into(), "aegis".into()],
            severity_threshold: "info".into(),
        },
        ScanProfile {
            name: "server".into(),
            description: "Production server security hardening check".into(),
            engines: vec!["sentinel".into(), "bastion".into(), "citadel".into(),
                "aegis".into(), "warden".into()],
            severity_threshold: "warning".into(),
        },
        ScanProfile {
            name: "workstation".into(),
            description: "Desktop/workstation security check".into(),
            engines: vec!["sentinel".into(), "warden".into(), "hydra".into(),
                "forge".into()],
            severity_threshold: "warning".into(),
        },
    ]
}

/// Calculate system security score based on findings
pub fn calculate_security_score(findings: &[Finding]) -> SecurityScore {
    let mut total_deductions: u32 = 0;
    let max_score: u32 = 100;

    // Deduction weights per severity
    for finding in findings {
        match finding.severity {
            crate::engine::Severity::Critical => total_deductions += 15,
            crate::engine::Severity::High => total_deductions += 8,
            crate::engine::Severity::Warning => total_deductions += 3,
            crate::engine::Severity::Info => total_deductions += 1,
            crate::engine::Severity::Pass => {} // No deduction
        }
    }

    let overall = max_score.saturating_sub(total_deductions);

    let grade = match overall {
        90..=100 => "A+",
        80..=89 => "A",
        70..=79 => "B",
        60..=69 => "C",
        50..=59 => "D",
        _ => "F",
    };

    // Category scores
    let engines: Vec<&str> = vec![
        "Sentinel", "Forge", "Warden", "Bastion", "Citadel",
        "Spectre", "Aegis", "Phantom", "Hydra", "Drake", "Talon",
    ];

    let mut categories = Vec::new();
    for engine in &engines {
        let engine_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.engine.as_deref() == Some(engine))
            .collect();

        if engine_findings.is_empty() {
            continue;
        }

        let engine_deductions: u32 = engine_findings.iter().map(|f| {
            match f.severity {
                crate::engine::Severity::Critical => 15,
                crate::engine::Severity::High => 8,
                crate::engine::Severity::Warning => 3,
                crate::engine::Severity::Info => 1,
                crate::engine::Severity::Pass => 0,
            }
        }).sum();

        let engine_score = 100u32.saturating_sub(engine_deductions);
        let crit = engine_findings.iter().filter(|f| f.severity == crate::engine::Severity::Critical).count();
        let high = engine_findings.iter().filter(|f| f.severity == crate::engine::Severity::High).count();

        categories.push(CategoryScore {
            name: engine.to_string(),
            score: engine_score,
            max: 100,
            details: format!("{} findings ({} critical, {} high)",
                engine_findings.len(), crit, high),
        });
    }

    // Recommendations based on findings
    let mut recommendations = Vec::new();
    if findings.iter().any(|f| f.severity == crate::engine::Severity::Critical) {
        recommendations.push("URGENT: Address all critical findings immediately".into());
    }
    if findings.iter().any(|f| f.engine.as_deref() == Some("Hydra") && f.severity == crate::engine::Severity::Critical) {
        recommendations.push("MALWARE: Active malware detected — isolate and remediate".into());
    }
    if findings.iter().any(|f| f.engine.as_deref() == Some("Drake") && f.severity == crate::engine::Severity::Critical) {
        recommendations.push("RANSOMWARE: Ransomware activity detected — begin incident response".into());
    }
    if findings.iter().any(|f| f.rule_id.as_deref() == Some("DK-SEN-001")) {
        recommendations.push("Enable kernel hardening (ASLR, stack protection)".into());
    }
    if findings.iter().any(|f| f.rule_id.as_deref() == Some("DK-BAS-001")) {
        recommendations.push("Configure firewall rules to restrict unnecessary access".into());
    }
    if !findings.iter().any(|f| f.engine.as_deref() == Some("Drake")
        && f.severity == crate::engine::Severity::Pass
        && f.title.contains("Backup"))
    {
        recommendations.push("Set up automated backups for ransomware resilience".into());
    }

    SecurityScore {
        overall,
        categories,
        grade: grade.into(),
        recommendations,
    }
}

/// Print security score dashboard
pub fn print_security_score(score: &SecurityScore) {
    eprintln!();
    eprintln!("  {}", "── DragonKeep Security Score ──".bold());
    eprintln!();

    // Overall score with color
    let score_display = match score.overall {
        90..=100 => format!("  {} {}/100 (Grade: {})", "🛡️", score.overall, score.grade).green().bold().to_string(),
        70..=89 => format!("  {} {}/100 (Grade: {})", "🛡️", score.overall, score.grade).yellow().bold().to_string(),
        50..=69 => format!("  {} {}/100 (Grade: {})", "⚠️", score.overall, score.grade).red().to_string(),
        _ => format!("  {} {}/100 (Grade: {})", "🚨", score.overall, score.grade).red().bold().to_string(),
    };
    eprintln!("{}", score_display);
    eprintln!();

    // Score bar
    let filled = (score.overall as usize * 40) / 100;
    let empty = 40 - filled;
    let bar_color = match score.overall {
        90..=100 => "green",
        70..=89 => "yellow",
        _ => "red",
    };
    let bar = format!("  [{}{}]", "█".repeat(filled), "░".repeat(empty));
    match bar_color {
        "green" => eprintln!("{}", bar.green()),
        "yellow" => eprintln!("{}", bar.yellow()),
        _ => eprintln!("{}", bar.red()),
    }
    eprintln!();

    // Category breakdown
    if !score.categories.is_empty() {
        eprintln!("  {}", "Engine Scores:".bold());
        for cat in &score.categories {
            let cat_color = match cat.score {
                90..=100 => cat.score.to_string().green().to_string(),
                70..=89 => cat.score.to_string().yellow().to_string(),
                _ => cat.score.to_string().red().to_string(),
            };
            eprintln!("    {} {}: {}/{}  {}", "→".dimmed(), cat.name, cat_color, cat.max, cat.details.dimmed());
        }
        eprintln!();
    }

    // Recommendations
    if !score.recommendations.is_empty() {
        eprintln!("  {}", "Recommendations:".bold());
        for rec in &score.recommendations {
            eprintln!("    {} {}", "→".cyan(), rec);
        }
        eprintln!();
    }
}

/// Fetch community threat intelligence feeds
pub async fn fetch_threat_feeds() -> Result<Vec<String>> {
    let mut blocked_ips = Vec::new();

    // SECURITY: Use a client with timeouts to prevent hanging on unresponsive feeds
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(5))
        .https_only(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    for &(name, url) in COMMUNITY_FEEDS {
        // SECURITY: Enforce HTTPS for all feed URLs
        if !url.starts_with("https://") {
            eprintln!("    {} Skipping {} — non-HTTPS URL rejected", "✗".red(), name);
            continue;
        }
        eprintln!("    {} Fetching {} feed...", "→".dimmed(), name);
        match client.get(url).send().await {
            Ok(resp) => {
                if let Ok(body) = resp.text().await {
                    let ips: Vec<String> = body.lines()
                        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                        .map(|l| l.trim().to_string())
                        .collect();
                    eprintln!("    {} {} — {} indicators loaded", "✓".green(), name, ips.len());
                    blocked_ips.extend(ips);
                }
            }
            Err(e) => {
                eprintln!("    {} Failed to fetch {}: {}", "✗".red(), name, e);
            }
        }
    }

    Ok(blocked_ips)
}

/// Check system connections against community threat feeds
pub async fn check_against_feeds(_config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    eprintln!("    {} Loading community threat intelligence...", "→".dimmed());
    let threat_ips = fetch_threat_feeds().await?;

    if threat_ips.is_empty() {
        findings.push(Finding::warning("Could not load community threat feeds")
            .with_detail("Network issue or feed unavailable — offline IOC checking only")
            .with_engine("Community")
            .with_rule("DK-COM-001"));
        return Ok(findings);
    }

    eprintln!("    {} Checking connections against {} threat indicators...", "→".dimmed(), threat_ips.len());

    // Get current connections
    if let Ok(output) = tokio::process::Command::new("ss")
        .args(["-tnp", "state", "established"])
        .output()
        .await
    {
        let ss_output = String::from_utf8_lossy(&output.stdout);
        for line in ss_output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let remote = parts[4];
                let ip = remote.rsplit(':').nth(1).unwrap_or(remote);

                if threat_ips.iter().any(|blocked| ip.contains(blocked.as_str()) || blocked.contains(ip)) {
                    let process_info = parts.get(5).unwrap_or(&"unknown");
                    findings.push(Finding::critical(format!("Connection to known malicious IP: {}", ip))
                        .with_detail(format!("Process {} connected to threat-listed IP {}", process_info, remote))
                        .with_fix(format!("Block immediately: iptables -I OUTPUT -d {} -j DROP", ip))
                        .with_engine("Community")
                        .with_rule("DK-COM-002")
                        .with_cvss(9.5)
                        .with_mitre(vec!["T1071.001"])
                        .with_nist(vec!["SI-4", "SC-7"]));
                }
            }
        }
    }

    if findings.is_empty() {
        findings.push(Finding::pass("No connections to known malicious IPs")
            .with_engine("Community")
            .with_rule("DK-COM-002"));
    }

    Ok(findings)
}

/// Generate community-compatible export (JSON IOC format)
#[allow(dead_code)]
pub fn export_findings_ioc(findings: &[Finding]) -> String {
    #[derive(Serialize)]
    struct IocExport {
        version: String,
        generator: String,
        timestamp: String,
        indicators: Vec<IocIndicator>,
    }

    #[derive(Serialize)]
    struct IocIndicator {
        #[serde(rename = "type")]
        ioc_type: String,
        value: String,
        severity: String,
        mitre: Vec<String>,
        description: String,
    }

    let indicators: Vec<IocIndicator> = findings.iter()
        .filter(|f| f.severity != crate::engine::Severity::Pass && f.severity != crate::engine::Severity::Info)
        .map(|f| {
            IocIndicator {
                ioc_type: f.engine.clone().unwrap_or_else(|| "unknown".into()),
                value: f.rule_id.clone().unwrap_or_default(),
                severity: f.severity.label().to_string(),
                mitre: f.mitre.clone().unwrap_or_default(),
                description: f.title.clone(),
            }
        })
        .collect();

    let export = IocExport {
        version: "1.0".into(),
        generator: "DragonKeep Community Edition".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        indicators,
    };

    serde_json::to_string_pretty(&export).unwrap_or_default()
}

/// Print available community scan profiles
pub fn print_profiles() {
    let profiles = default_profiles();

    eprintln!();
    eprintln!("  {}", "── DragonKeep Community Scan Profiles ──".bold());
    eprintln!();

    for profile in &profiles {
        eprintln!("  {} {}", "→".cyan(), profile.name.bold());
        eprintln!("    {}", profile.description.dimmed());
        eprintln!("    {} {}", "Engines:".dimmed(), profile.engines.join(", "));
        eprintln!();
    }

    eprintln!("  {} dragonkeep scan --profile <name>", "Usage:".green());
    eprintln!();
}

/// Print community dashboard status
pub fn print_community_status() {
    eprintln!();
    eprintln!("  {}", "── DragonKeep Community Edition ──".bold());
    eprintln!();
    eprintln!("  {} 11-engine security platform", "🛡️".to_string());
    eprintln!("  {} 6 framework alignment (MITRE, NIST, STIG, CIS, CVSS, Atomic Red Team)", "📋".to_string());
    eprintln!("  {} Community threat intelligence feeds", "🌐".to_string());
    eprintln!("  {} 8 built-in scan profiles", "📊".to_string());
    eprintln!("  {} Security score & grading system", "⭐".to_string());
    eprintln!("  {} Malware & ransomware defense", "🔒".to_string());
    eprintln!("  {} Advanced threat hunting", "🎯".to_string());
    eprintln!("  {} Automated remediation (safe mode)", "🔧".to_string());
    eprintln!();
    eprintln!("  {}", "Quick Start:".bold());
    eprintln!("    {} dragonkeep scan                    Full audit", "→".green());
    eprintln!("    {} dragonkeep scan --profile quick     Quick check", "→".green());
    eprintln!("    {} dragonkeep malware                  Malware scan", "→".green());
    eprintln!("    {} dragonkeep ransomware               Ransomware defense", "→".green());
    eprintln!("    {} dragonkeep hunt                     Threat hunting", "→".green());
    eprintln!("    {} dragonkeep score                    Security score", "→".green());
    eprintln!("    {} dragonkeep profiles                 Scan profiles", "→".green());
    eprintln!("    {} dragonkeep feeds                    Threat intel feeds", "→".green());
    eprintln!("    {} dragonkeep remediate                Auto-remediate", "→".green());
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Finding, Severity};

    #[test]
    fn default_profiles_has_expected_count() {
        let profiles = default_profiles();
        assert_eq!(profiles.len(), 8);
    }

    #[test]
    fn default_profiles_names() {
        let profiles = default_profiles();
        let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"quick"));
        assert!(names.contains(&"standard"));
        assert!(names.contains(&"deep"));
        assert!(names.contains(&"malware"));
        assert!(names.contains(&"compliance"));
    }

    #[test]
    fn deep_profile_has_all_engines() {
        let profiles = default_profiles();
        let deep = profiles.iter().find(|p| p.name == "deep").unwrap();
        assert_eq!(deep.engines.len(), 11);
    }

    #[test]
    fn security_score_perfect_with_no_findings() {
        let score = calculate_security_score(&[]);
        assert_eq!(score.overall, 100);
        assert_eq!(score.grade, "A+");
    }

    #[test]
    fn security_score_deductions() {
        let findings = vec![
            Finding::critical("test").with_engine("Sentinel"),
            Finding::high("test").with_engine("Sentinel"),
        ];
        let score = calculate_security_score(&findings);
        // critical = -15, high = -8 → 100 - 23 = 77
        assert_eq!(score.overall, 77);
        assert_eq!(score.grade, "B");
    }

    #[test]
    fn security_score_saturates_at_zero() {
        let findings: Vec<Finding> = (0..10)
            .map(|_| Finding::critical("bad").with_engine("Hydra"))
            .collect();
        let score = calculate_security_score(&findings);
        // 10 * 15 = 150 deductions, saturates at 0
        assert_eq!(score.overall, 0);
        assert_eq!(score.grade, "F");
    }

    #[test]
    fn security_score_pass_no_deduction() {
        let findings = vec![
            Finding::pass("Good config").with_engine("Sentinel"),
            Finding::pass("Firewall active").with_engine("Bastion"),
        ];
        let score = calculate_security_score(&findings);
        assert_eq!(score.overall, 100);
    }

    #[test]
    fn security_score_grade_boundaries() {
        // 1 critical = -15 → 85 = A
        let score = calculate_security_score(&[
            Finding::critical("x").with_engine("S"),
        ]);
        assert_eq!(score.grade, "A");

        // 3 criticals = -45 → 55 = D
        let findings: Vec<_> = (0..3).map(|_| Finding::critical("x").with_engine("S")).collect();
        let score = calculate_security_score(&findings);
        assert_eq!(score.grade, "D");
    }

    #[test]
    fn security_score_has_recommendations() {
        let findings = vec![
            Finding::critical("bad").with_engine("Hydra"),
        ];
        let score = calculate_security_score(&findings);
        assert!(!score.recommendations.is_empty());
        assert!(score.recommendations.iter().any(|r| r.contains("URGENT") || r.contains("MALWARE")));
    }

    #[test]
    fn security_score_per_engine_categories() {
        let findings = vec![
            Finding::high("a").with_engine("Sentinel"),
            Finding::warning("b").with_engine("Sentinel"),
            Finding::critical("c").with_engine("Hydra"),
        ];
        let score = calculate_security_score(&findings);
        assert!(score.categories.len() >= 2);
        let sentinel = score.categories.iter().find(|c| c.name == "Sentinel").unwrap();
        // high(-8) + warning(-3) = -11 → 89
        assert_eq!(sentinel.score, 89);
    }

    #[test]
    fn export_ioc_filters_pass_and_info() {
        let findings = vec![
            Finding::critical("bad").with_engine("Hydra").with_rule("R1"),
            Finding::pass("good").with_engine("S").with_rule("R2"),
            Finding::info("note").with_engine("S").with_rule("R3"),
        ];
        let json = export_findings_ioc(&findings);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let indicators = parsed["indicators"].as_array().unwrap();
        // Only critical should remain (pass + info filtered out)
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0]["severity"], "CRIT");
    }

    #[test]
    fn export_ioc_format() {
        let json = export_findings_ioc(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], "1.0");
        assert_eq!(parsed["generator"], "DragonKeep Community Edition");
        assert!(parsed["timestamp"].as_str().unwrap().len() > 10);
    }
}
