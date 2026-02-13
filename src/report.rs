use chrono::Utc;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::engine::{Finding, Severity};

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub generated_at: String,
    pub hostname: String,
    pub sections: Vec<ReportSection>,
    pub summary: ReportSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSection {
    pub name: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub warning: usize,
    pub info: usize,
    pub pass: usize,
    /// CVSS max score across all findings
    pub max_cvss: f32,
}

pub struct Reporter {
    sections: Vec<ReportSection>,
}

impl Reporter {
    pub fn new() -> Self {
        Self {
            sections: Vec::new(),
        }
    }

    pub fn add_section(&mut self, name: &str, findings: Vec<Finding>) {
        self.sections.push(ReportSection {
            name: name.to_string(),
            findings,
        });
    }

    /// Get all findings across all sections
    pub fn all_findings(&self) -> Vec<Finding> {
        self.sections.iter()
            .flat_map(|s| s.findings.clone())
            .collect()
    }

    fn compute_summary(&self) -> ReportSummary {
        let mut summary = ReportSummary::default();
        for section in &self.sections {
            for finding in &section.findings {
                summary.total_findings += 1;
                match finding.severity {
                    Severity::Critical => summary.critical += 1,
                    Severity::High => summary.high += 1,
                    Severity::Warning => summary.warning += 1,
                    Severity::Info => summary.info += 1,
                    Severity::Pass => summary.pass += 1,
                }
                if let Some(cvss) = finding.cvss {
                    if cvss > summary.max_cvss {
                        summary.max_cvss = cvss;
                    }
                }
            }
        }
        summary
    }

    fn build_report(&self) -> Report {
        use sysinfo::System;
        Report {
            generated_at: Utc::now().to_rfc3339(),
            hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
            sections: self.sections.iter().map(|s| {
                ReportSection {
                    name: s.name.clone(),
                    findings: s.findings.clone(),
                }
            }).collect(),
            summary: self.compute_summary(),
        }
    }

    pub fn print(&self, format: &OutputFormat) {
        match format {
            OutputFormat::Json => {
                let report = self.build_report();
                if let Ok(json) = serde_json::to_string_pretty(&report) {
                    println!("{}", json);
                }
            }
            OutputFormat::Sarif => {
                if let Ok(sarif) = self.build_sarif() {
                    println!("{}", sarif);
                }
            }
            OutputFormat::Minimal => {
                let summary = self.compute_summary();
                for section in &self.sections {
                    for finding in &section.findings {
                        let cvss_str = finding.cvss
                            .map(|c| format!(" (CVSS:{:.1})", c))
                            .unwrap_or_default();
                        println!("[{}] {}: {}{}", finding.severity.label(), section.name, finding.title, cvss_str);
                    }
                }
                println!();
                println!("Total: {} | Critical: {} | High: {} | Warning: {} | Info: {} | Pass: {} | Max CVSS: {:.1}",
                    summary.total_findings,
                    summary.critical,
                    summary.high,
                    summary.warning,
                    summary.info,
                    summary.pass,
                    summary.max_cvss,
                );
            }
            OutputFormat::Pretty => {
                for section in &self.sections {
                    eprintln!();
                    eprintln!("  {}", format!("── {} ──", section.name).bold());
                    for finding in &section.findings {
                        let icon = finding.severity.icon();
                        let label = finding.severity.colored_label();
                        let cvss_str = finding.cvss
                            .map(|c| format!(" {}", format!("[CVSS:{:.1}]", c).dimmed()))
                            .unwrap_or_default();
                        eprintln!("  {} {} {}{}", icon, label, finding.title, cvss_str);
                        if let Some(detail) = &finding.detail {
                            eprintln!("      {}", detail.dimmed());
                        }
                        if let Some(fix) = &finding.fix {
                            eprintln!("      {} {}", "Fix:".cyan(), fix);
                        }
                        // Show MITRE ATT&CK references
                        if let Some(mitre) = &finding.mitre {
                            eprintln!("      {} {}", "ATT&CK:".magenta(), mitre.join(", "));
                        }
                        // Show CIS Benchmark ID
                        if let Some(cis) = &finding.cis_id {
                            eprintln!("      {} CIS {}", "Benchmark:".blue(), cis);
                        }
                        // Show DISA STIG ID
                        if let Some(stig) = &finding.stig {
                            eprintln!("      {} {}", "STIG:".blue(), stig);
                        }
                        // Show NIST SP 800-53 controls
                        if let Some(nist) = &finding.nist {
                            eprintln!("      {} {}", "NIST:".blue(), nist.join(", "));
                        }
                        // Show CVEs
                        if let Some(cves) = &finding.cve {
                            eprintln!("      {} {}", "CVE:".red(), cves.join(", "));
                        }
                    }
                }

                let summary = self.compute_summary();
                eprintln!();
                eprintln!("  {}", "── Summary ──".bold());
                eprintln!("  {} Total findings: {}", "→".dimmed(), summary.total_findings);
                if summary.critical > 0 {
                    eprintln!("  {} Critical: {}", "✗".red().bold(), summary.critical);
                }
                if summary.high > 0 {
                    eprintln!("  {} High: {}", "✗".red(), summary.high);
                }
                if summary.warning > 0 {
                    eprintln!("  {} Warnings: {}", "!".yellow(), summary.warning);
                }
                eprintln!("  {} Info: {}", "i".blue(), summary.info);
                eprintln!("  {} Passed: {}", "✓".green(), summary.pass);
                if summary.max_cvss > 0.0 {
                    let cvss_color = if summary.max_cvss >= 9.0 {
                        format!("{:.1}", summary.max_cvss).red().bold().to_string()
                    } else if summary.max_cvss >= 7.0 {
                        format!("{:.1}", summary.max_cvss).red().to_string()
                    } else if summary.max_cvss >= 4.0 {
                        format!("{:.1}", summary.max_cvss).yellow().to_string()
                    } else {
                        format!("{:.1}", summary.max_cvss).green().to_string()
                    };
                    eprintln!("  {} Max CVSS: {}", "⚡".dimmed(), cvss_color);
                }
                eprintln!();
            }
        }
    }

    /// Generate SARIF v2.1.0 output (Static Analysis Results Interchange Format)
    /// Compatible with GitHub Code Scanning, Azure DevOps, and other SARIF consumers
    fn build_sarif(&self) -> anyhow::Result<String> {
        use serde_json::json;

        // SECURITY: Redact hostname from SARIF to prevent information disclosure in shared reports
        let hostname = "[redacted]".to_string();
        let timestamp = Utc::now().to_rfc3339();

        let mut rules = Vec::new();
        let mut results = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();

        for section in &self.sections {
            for finding in &section.findings {
                let rule_id = finding.rule_id.clone()
                    .unwrap_or_else(|| format!("DK-{}", finding.title.chars()
                        .filter(|c| c.is_alphanumeric())
                        .take(20)
                        .collect::<String>()
                        .to_uppercase()));

                // Add rule definition (deduplicated)
                if seen_rules.insert(rule_id.clone()) {
                    let mut rule = json!({
                        "id": rule_id,
                        "name": finding.title,
                        "shortDescription": {
                            "text": finding.title
                        },
                        "defaultConfiguration": {
                            "level": finding.severity.sarif_level()
                        }
                    });

                    if let Some(detail) = &finding.detail {
                        rule["fullDescription"] = json!({
                            "text": detail
                        });
                    }

                    if let Some(fix) = &finding.fix {
                        rule["help"] = json!({
                            "text": fix
                        });
                    }

                    // Add CVSS properties
                    if let Some(cvss) = finding.cvss {
                        rule["properties"] = json!({
                            "cvss": cvss,
                            "security-severity": format!("{:.1}", cvss)
                        });
                    }

                    rules.push(rule);
                }

                // Build result
                let mut result = json!({
                    "ruleId": rule_id,
                    "level": finding.severity.sarif_level(),
                    "message": {
                        "text": finding.title
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": format!("host://{}", hostname),
                                "uriBaseId": "SYSTEM"
                            }
                        }
                    }]
                });

                // Add properties for metadata
                let mut props = serde_json::Map::new();
                if let Some(engine) = &finding.engine {
                    props.insert("engine".into(), json!(engine));
                }
                if let Some(mitre) = &finding.mitre {
                    props.insert("mitre-attack".into(), json!(mitre));
                }
                if let Some(cis) = &finding.cis_id {
                    props.insert("cis-benchmark".into(), json!(cis));
                }
                if let Some(cves) = &finding.cve {
                    props.insert("cve".into(), json!(cves));
                }
                if let Some(stig) = &finding.stig {
                    props.insert("disa-stig".into(), json!(stig));
                }
                if let Some(nist) = &finding.nist {
                    props.insert("nist-800-53".into(), json!(nist));
                }
                if let Some(cvss) = finding.cvss {
                    props.insert("cvss".into(), json!(cvss));
                }
                if !props.is_empty() {
                    result["properties"] = json!(props);
                }

                // Add fix suggestion
                if let Some(fix) = &finding.fix {
                    result["fixes"] = json!([{
                        "description": {
                            "text": fix
                        }
                    }]);
                }

                results.push(result);
            }
        }

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "DragonKeep",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/Ghosts-Protocol-Pvt-Ltd/DragonKeep",
                        "rules": rules
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": true,
                    "endTimeUtc": timestamp,
                    "machine": "[redacted]"
                }]
            }]
        });

        Ok(serde_json::to_string_pretty(&sarif)?)
    }

    pub fn save_json(&self, path: &str) -> anyhow::Result<()> {
        let report = self.build_report();
        let json = serde_json::to_string_pretty(&report)?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        // SECURITY: Atomic write — write to temp then rename to prevent partial reports
        let tmp_path = format!("{}.tmp.{}", path, std::process::id());
        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub fn save_sarif(&self, path: &str) -> anyhow::Result<()> {
        let sarif = self.build_sarif()?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        // SECURITY: Atomic write — write to temp then rename to prevent partial reports
        let tmp_path = format!("{}.tmp.{}", path, std::process::id());
        std::fs::write(&tmp_path, &sarif)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }
}
