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
    pub spectre: SpectreConfig,
    pub aegis: AegisConfig,
    pub phantom: PhantomConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectreConfig {
    pub enabled: bool,
    /// Scan for exposed AI/ML inference ports
    pub port_scan: bool,
    /// Check for leaked API keys
    pub key_scan: bool,
    /// Scan for unsafe model files (pickle-based)
    pub model_scan: bool,
    /// Check GPU memory residuals
    pub gpu_check: bool,
    /// Scan Python files for unsafe deserialization
    pub deserialization_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisConfig {
    pub enabled: bool,
    /// Verify critical binary integrity
    pub binary_verification: bool,
    /// Audit package manager security settings
    pub package_audit: bool,
    /// Check for EOL distro / stale kernel
    pub currency_check: bool,
    /// Audit container security
    pub container_audit: bool,
    /// Check systemd unit file integrity
    pub systemd_audit: bool,
    /// Scan for unsigned kernel modules
    pub module_audit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomConfig {
    pub enabled: bool,
    /// Detect reverse shell patterns in process command lines
    pub shell_detection: bool,
    /// Scan for LD_PRELOAD injection
    pub preload_scan: bool,
    /// Check for deleted executables still running
    pub deleted_exe_scan: bool,
    /// Audit crontab entries for suspicious patterns
    pub cron_audit: bool,
    /// Detect unusual outbound connections
    pub connection_scan: bool,
    /// Check for process name masquerading
    pub masquerade_detection: bool,
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
            spectre: SpectreConfig {
                enabled: true,
                port_scan: true,
                key_scan: true,
                model_scan: true,
                gpu_check: true,
                deserialization_scan: true,
            },
            aegis: AegisConfig {
                enabled: true,
                binary_verification: true,
                package_audit: true,
                currency_check: true,
                container_audit: true,
                systemd_audit: true,
                module_audit: true,
            },
            phantom: PhantomConfig {
                enabled: true,
                shell_detection: true,
                preload_scan: true,
                deleted_exe_scan: true,
                cron_audit: true,
                connection_scan: true,
                masquerade_detection: true,
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
