use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub sentinel: SentinelConfig,
    pub forge: ForgeConfig,
    pub warden: WardenConfig,
    pub bastion: BastionConfig,
    pub citadel: CitadelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Safe mode — never apply changes without confirmation
    pub safe_mode: bool,
    /// Log level: trace, debug, info, warn, error
    pub log_level: String,
    /// Report output directory
    pub report_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub enabled: bool,
    /// Check for CVEs against installed packages
    pub cve_check: bool,
    /// Scan for rootkits
    pub rootkit_scan: bool,
    /// Check file permissions
    pub permission_audit: bool,
    /// Check for open ports
    pub port_scan: bool,
    /// Check SSH config
    pub ssh_audit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeConfig {
    pub enabled: bool,
    /// Default performance profile
    pub default_profile: String,
    /// GPU optimization
    pub gpu_tuning: bool,
    /// I/O scheduler optimization
    pub io_tuning: bool,
    /// Memory optimization
    pub memory_tuning: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WardenConfig {
    pub enabled: bool,
    /// CPU usage threshold for alerts (%)
    pub cpu_threshold: f32,
    /// Memory usage threshold for alerts (%)
    pub memory_threshold: f32,
    /// Monitor refresh interval (ms)
    pub refresh_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BastionConfig {
    pub enabled: bool,
    /// Check firewall rules
    pub firewall_audit: bool,
    /// DNS security check
    pub dns_check: bool,
    /// Scan listening ports
    pub port_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitadelConfig {
    pub enabled: bool,
    /// Kernel parameter hardening
    pub kernel_hardening: bool,
    /// File permission hardening
    pub fs_hardening: bool,
    /// Service audit
    pub service_audit: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                safe_mode: true,
                log_level: "info".into(),
                report_dir: dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                    .join("dragonkeep")
                    .join("reports")
                    .to_string_lossy()
                    .to_string(),
            },
            sentinel: SentinelConfig {
                enabled: true,
                cve_check: true,
                rootkit_scan: true,
                permission_audit: true,
                port_scan: true,
                ssh_audit: true,
            },
            forge: ForgeConfig {
                enabled: true,
                default_profile: "balanced".into(),
                gpu_tuning: true,
                io_tuning: true,
                memory_tuning: true,
            },
            warden: WardenConfig {
                enabled: true,
                cpu_threshold: 90.0,
                memory_threshold: 85.0,
                refresh_interval: 1000,
            },
            bastion: BastionConfig {
                enabled: true,
                firewall_audit: true,
                dns_check: true,
                port_scan: true,
            },
            citadel: CitadelConfig {
                enabled: true,
                kernel_hardening: true,
                fs_hardening: true,
                service_audit: true,
            },
        }
    }
}

impl Config {
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("dragonkeep")
            .join("config.toml")
    }

    pub fn load_or_default() -> Result<Self> {
        let path = Self::default_path();
        if path.exists() {
            Self::load_from(path.to_str().unwrap_or(""))
        } else {
            Ok(Self::default())
        }
    }

    pub fn load_from(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
