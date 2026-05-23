pub mod sentinel;
pub mod forge;
pub mod warden;
pub mod bastion;
pub mod citadel;
pub mod spectre;
pub mod aegis;
pub mod phantom;
pub mod hydra;
pub mod drake;
pub mod talon;
// v0.6 — defensive expansion (the DragonShield drop)
pub mod memory_bridge;
pub mod shield;
pub mod patrol;
pub mod proof;
pub mod respond;
pub mod honeypot;
pub mod swarm;
pub mod oracle;
// v0.7 — antivirus-grade trio (the DragonAV drop)
pub mod antivirus;
pub mod quarantine;
pub mod ioc;
// v0.8 — NGAV upgrade (Falcon-class behavioral + telemetry + autoblock)
pub mod behavioral;
pub mod telemetry;
pub mod autoblock;
pub mod platform;
// v0.9 — kernel + memory layer
pub mod behavioral_ebpf;
pub mod memory_scan;

use colored::Colorize;
use serde::{Deserialize, Serialize};

/// Severity level for a finding (aligned with CVSS v3.1 qualitative ratings)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Pass,
    Info,
    Warning,
    High,
    Critical,
}

impl Severity {
    pub fn icon(&self) -> &'static str {
        match self {
            Severity::Critical => "✗",
            Severity::High => "✗",
            Severity::Warning => "!",
            Severity::Info => "i",
            Severity::Pass => "✓",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Warning => "WARN",
            Severity::Info => "INFO",
            Severity::Pass => "PASS",
        }
    }

    pub fn colored_label(&self) -> String {
        match self {
            Severity::Critical => "CRIT".red().bold().to_string(),
            Severity::High => "HIGH".red().to_string(),
            Severity::Warning => "WARN".yellow().bold().to_string(),
            Severity::Info => "INFO".blue().to_string(),
            Severity::Pass => "PASS".green().to_string(),
        }
    }

    /// Map to SARIF level
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Warning => "warning",
            Severity::Info => "note",
            Severity::Pass => "none",
        }
    }
}

/// A single finding from an engine scan
///
/// Framework alignment:
///   - CVSS v3.1 base scores (FIRST.org)
///   - CIS Benchmarks (cisecurity.org)
///   - MITRE ATT&CK technique IDs (attack.mitre.org) — also maps to Atomic Red Team tests
///   - DISA STIGs (public.cyber.mil)
///   - NIST SP 800-53 Rev 5 controls (csrc.nist.gov)
///   - CVE identifiers (cve.mitre.org)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub detail: Option<String>,
    pub fix: Option<String>,
    /// CVSS v3.1 base score (0.0 – 10.0) per FIRST.org specification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f32>,
    /// CIS Benchmark ID (e.g., "1.1.1.1", "5.2.4")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cis_id: Option<String>,
    /// MITRE ATT&CK technique IDs (e.g., ["T1059", "T1053.003"])
    /// These directly map to Atomic Red Team tests at:
    /// https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/<technique_id>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre: Option<Vec<String>>,
    /// CVE identifiers if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<Vec<String>>,
    /// Engine that produced this finding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    /// Unique rule ID for deduplication/suppression (e.g., "DK-SEN-001")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// DISA STIG ID (e.g., "RHEL-08-010010") — public.cyber.mil
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stig: Option<String>,
    /// NIST SP 800-53 Rev 5 control IDs (e.g., ["AC-6", "CM-6(1)"])
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nist: Option<Vec<String>>,
}

impl Finding {
    pub fn critical(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            severity: Severity::Critical,
            detail: None, fix: None, cvss: None,
            cis_id: None, mitre: None, cve: None,
            engine: None, rule_id: None,
            stig: None, nist: None,
        }
    }

    pub fn high(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            severity: Severity::High,
            detail: None, fix: None, cvss: None,
            cis_id: None, mitre: None, cve: None,
            engine: None, rule_id: None,
            stig: None, nist: None,
        }
    }

    pub fn warning(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            severity: Severity::Warning,
            detail: None, fix: None, cvss: None,
            cis_id: None, mitre: None, cve: None,
            engine: None, rule_id: None,
            stig: None, nist: None,
        }
    }

    pub fn info(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            severity: Severity::Info,
            detail: None, fix: None, cvss: None,
            cis_id: None, mitre: None, cve: None,
            engine: None, rule_id: None,
            stig: None, nist: None,
        }
    }

    pub fn pass(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            severity: Severity::Pass,
            detail: None, fix: None, cvss: None,
            cis_id: None, mitre: None, cve: None,
            engine: None, rule_id: None,
            stig: None, nist: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    pub fn with_cvss(mut self, score: f32) -> Self {
        self.cvss = Some(score);
        self
    }

    pub fn with_cis(mut self, id: impl Into<String>) -> Self {
        self.cis_id = Some(id.into());
        self
    }

    pub fn with_mitre(mut self, techniques: Vec<&str>) -> Self {
        self.mitre = Some(techniques.into_iter().map(String::from).collect());
        self
    }

    pub fn with_cve(mut self, cves: Vec<&str>) -> Self {
        self.cve = Some(cves.into_iter().map(String::from).collect());
        self
    }

    pub fn with_engine(mut self, engine: impl Into<String>) -> Self {
        self.engine = Some(engine.into());
        self
    }

    pub fn with_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    /// DISA STIG reference (e.g., "RHEL-08-010010")
    pub fn with_stig(mut self, stig_id: impl Into<String>) -> Self {
        self.stig = Some(stig_id.into());
        self
    }

    /// NIST SP 800-53 Rev 5 controls (e.g., ["AC-6", "CM-6(1)"])
    pub fn with_nist(mut self, controls: Vec<&str>) -> Self {
        self.nist = Some(controls.into_iter().map(String::from).collect());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Severity ──

    #[test]
    fn severity_ordering() {
        assert!(Severity::Pass < Severity::Info);
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_icons() {
        assert_eq!(Severity::Pass.icon(), "✓");
        assert_eq!(Severity::Info.icon(), "i");
        assert_eq!(Severity::Warning.icon(), "!");
        assert_eq!(Severity::High.icon(), "✗");
        assert_eq!(Severity::Critical.icon(), "✗");
    }

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Pass.label(), "PASS");
        assert_eq!(Severity::Info.label(), "INFO");
        assert_eq!(Severity::Warning.label(), "WARN");
        assert_eq!(Severity::High.label(), "HIGH");
        assert_eq!(Severity::Critical.label(), "CRIT");
    }

    #[test]
    fn severity_sarif_levels() {
        assert_eq!(Severity::Critical.sarif_level(), "error");
        assert_eq!(Severity::High.sarif_level(), "error");
        assert_eq!(Severity::Warning.sarif_level(), "warning");
        assert_eq!(Severity::Info.sarif_level(), "note");
        assert_eq!(Severity::Pass.sarif_level(), "none");
    }

    // ── Finding builder pattern ──

    #[test]
    fn finding_critical_builder() {
        let f = Finding::critical("Test finding");
        assert_eq!(f.title, "Test finding");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.detail.is_none());
        assert!(f.fix.is_none());
    }

    #[test]
    fn finding_all_severity_constructors() {
        assert_eq!(Finding::critical("c").severity, Severity::Critical);
        assert_eq!(Finding::high("h").severity, Severity::High);
        assert_eq!(Finding::warning("w").severity, Severity::Warning);
        assert_eq!(Finding::info("i").severity, Severity::Info);
        assert_eq!(Finding::pass("p").severity, Severity::Pass);
    }

    #[test]
    fn finding_builder_chaining() {
        let f = Finding::high("SSH weak config")
            .with_detail("Allows password auth")
            .with_fix("Set PasswordAuthentication no")
            .with_cvss(7.5)
            .with_cis("5.2.4")
            .with_mitre(vec!["T1110", "T1021.004"])
            .with_cve(vec!["CVE-2023-1234"])
            .with_engine("Sentinel")
            .with_rule("DK-SEN-005")
            .with_stig("RHEL-08-010010")
            .with_nist(vec!["AC-6", "IA-5"]);

        assert_eq!(f.title, "SSH weak config");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.detail.as_deref(), Some("Allows password auth"));
        assert_eq!(f.fix.as_deref(), Some("Set PasswordAuthentication no"));
        assert_eq!(f.cvss, Some(7.5));
        assert_eq!(f.cis_id.as_deref(), Some("5.2.4"));
        assert_eq!(f.mitre.as_ref().unwrap().len(), 2);
        assert_eq!(f.cve.as_ref().unwrap()[0], "CVE-2023-1234");
        assert_eq!(f.engine.as_deref(), Some("Sentinel"));
        assert_eq!(f.rule_id.as_deref(), Some("DK-SEN-005"));
        assert_eq!(f.stig.as_deref(), Some("RHEL-08-010010"));
        assert_eq!(f.nist.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn finding_serialization() {
        let f = Finding::warning("Test")
            .with_cvss(5.0)
            .with_engine("Bastion");
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("Test"));
        assert!(json.contains("Warning"));
        // Fields with skip_serializing_if should be omitted when None
        assert!(!json.contains("cis_id"));
        assert!(!json.contains("mitre"));
    }

    #[test]
    fn finding_deserialization() {
        let json = r#"{
            "title": "Open port",
            "severity": "High",
            "detail": "Port 22 exposed",
            "fix": null,
            "engine": "Bastion"
        }"#;
        let f: Finding = serde_json::from_str(json).unwrap();
        assert_eq!(f.title, "Open port");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.detail.as_deref(), Some("Port 22 exposed"));
    }
}
