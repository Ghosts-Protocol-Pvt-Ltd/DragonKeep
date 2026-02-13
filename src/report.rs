use chrono::Utc;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::engine::Finding;

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
    pub warning: usize,
    pub info: usize,
    pub pass: usize,
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

    fn compute_summary(&self) -> ReportSummary {
        let mut summary = ReportSummary::default();
        for section in &self.sections {
            for finding in &section.findings {
                summary.total_findings += 1;
                match finding.severity {
                    Severity::Critical => summary.critical += 1,
                    Severity::Warning => summary.warning += 1,
                    Severity::Info => summary.info += 1,
                    Severity::Pass => summary.pass += 1,
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
            OutputFormat::Minimal => {
                let summary = self.compute_summary();
                for section in &self.sections {
                    for finding in &section.findings {
                        println!("[{}] {}: {}", finding.severity.label(), section.name, finding.title);
                    }
                }
                println!();
                println!("Total: {} | Critical: {} | Warning: {} | Info: {} | Pass: {}",
                    summary.total_findings,
                    summary.critical,
                    summary.warning,
                    summary.info,
                    summary.pass,
                );
            }
            OutputFormat::Pretty => {
                for section in &self.sections {
                    eprintln!();
                    eprintln!("  {}", format!("── {} ──", section.name).bold());
                    for finding in &section.findings {
                        let icon = finding.severity.icon();
                        let label = finding.severity.colored_label();
                        eprintln!("  {} {} {}", icon, label, finding.title);
                        if let Some(detail) = &finding.detail {
                            eprintln!("      {}", detail.dimmed());
                        }
                        if let Some(fix) = &finding.fix {
                            eprintln!("      {} {}", "Fix:".cyan(), fix);
                        }
                    }
                }

                let summary = self.compute_summary();
                eprintln!();
                eprintln!("  ── Summary ──");
                eprintln!("  {} Total findings: {}", "→".dimmed(), summary.total_findings);
                if summary.critical > 0 {
                    eprintln!("  {} Critical: {}", "✗".red(), summary.critical);
                }
                if summary.warning > 0 {
                    eprintln!("  {} Warnings: {}", "!".yellow(), summary.warning);
                }
                eprintln!("  {} Info: {}", "i".blue(), summary.info);
                eprintln!("  {} Passed: {}", "✓".green(), summary.pass);
                eprintln!();
            }
        }
    }

    pub fn save_json(&self, path: &str) -> anyhow::Result<()> {
        let report = self.build_report();
        let json = serde_json::to_string_pretty(&report)?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, json)?;
        Ok(())
    }
}

use crate::engine::Severity;
