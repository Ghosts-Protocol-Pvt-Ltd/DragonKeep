pub mod sentinel;
pub mod forge;
pub mod warden;
pub mod bastion;
pub mod citadel;
pub mod spectre;
pub mod aegis;
pub mod phantom;

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
