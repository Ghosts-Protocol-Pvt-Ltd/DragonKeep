pub mod sentinel;
pub mod forge;
pub mod warden;
pub mod bastion;
pub mod citadel;

use colored::Colorize;
use serde::{Deserialize, Serialize};

/// Severity level for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    Warning,
    Info,
    Pass,
}

impl Severity {
    pub fn icon(&self) -> &'static str {
        match self {
            Severity::Critical => "✗",
            Severity::Warning => "!",
            Severity::Info => "i",
            Severity::Pass => "✓",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::Warning => "WARN",
            Severity::Info => "INFO",
            Severity::Pass => "PASS",
        }
    }

    pub fn colored_label(&self) -> String {
        match self {
            Severity::Critical => "CRIT".red().bold().to_string(),
            Severity::Warning => "WARN".yellow().bold().to_string(),
            Severity::Info => "INFO".blue().to_string(),
            Severity::Pass => "PASS".green().to_string(),
        }
    }
}

/// A single finding from an engine scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub detail: Option<String>,
    pub fix: Option<String>,
}

impl Finding {
    pub fn critical(title: impl Into<String>) -> Self {
        Self { title: title.into(), severity: Severity::Critical, detail: None, fix: None }
    }

    pub fn warning(title: impl Into<String>) -> Self {
        Self { title: title.into(), severity: Severity::Warning, detail: None, fix: None }
    }

    pub fn info(title: impl Into<String>) -> Self {
        Self { title: title.into(), severity: Severity::Info, detail: None, fix: None }
    }

    pub fn pass(title: impl Into<String>) -> Self {
        Self { title: title.into(), severity: Severity::Pass, detail: None, fix: None }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}
