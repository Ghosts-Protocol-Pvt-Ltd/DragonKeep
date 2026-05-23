//! Platform · cross-OS abstraction layer.
//!
//! Centralises every OS-specific primitive DragonKeep uses so individual
//! engines stay portable. Today Linux is the production target; macOS
//! and Windows are stubbed with clear TODOs.
//!
//! See [[dragon-cross-os]] for the strategy.
//!
//! Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformKind {
    Linux,
    MacOs,
    Windows,
    Unknown,
}

pub fn detect() -> PlatformKind {
    #[cfg(target_os = "linux")]   { PlatformKind::Linux }
    #[cfg(target_os = "macos")]   { PlatformKind::MacOs }
    #[cfg(target_os = "windows")] { PlatformKind::Windows }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))] { PlatformKind::Unknown }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsCapabilities {
    pub kind: PlatformKind,
    pub kernel: String,
    pub hostname: String,
    pub supports_proc_fs: bool,    // Linux /proc
    pub supports_endpoint_sec: bool,  // macOS ESF
    pub supports_etw: bool,        // Windows ETW
    pub supports_nftables: bool,
    pub supports_pf: bool,
    pub supports_windows_firewall: bool,
}

pub fn capabilities() -> OsCapabilities {
    let kind = detect();
    OsCapabilities {
        kind,
        kernel: std::env::var("OSTYPE").unwrap_or_else(|_| format!("{:?}", kind).to_lowercase()),
        hostname: std::fs::read_to_string("/etc/hostname")
            .ok().map(|s| s.trim().to_string())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .unwrap_or_else(|| "unknown".into()),
        supports_proc_fs:           matches!(kind, PlatformKind::Linux),
        supports_endpoint_sec:      matches!(kind, PlatformKind::MacOs),
        supports_etw:               matches!(kind, PlatformKind::Windows),
        supports_nftables:          matches!(kind, PlatformKind::Linux),
        supports_pf:                matches!(kind, PlatformKind::MacOs),
        supports_windows_firewall:  matches!(kind, PlatformKind::Windows),
    }
}

/// Quarantine vault path — different per OS to match platform conventions.
pub fn vault_dir() -> std::path::PathBuf {
    let base = std::env::var_os("DRAGONKEEP_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            #[cfg(target_os = "windows")]
            { dirs::data_dir().unwrap_or_default().join("DragonKeep") }
            #[cfg(not(target_os = "windows"))]
            { dirs::home_dir().unwrap_or_default().join(".dragonkeep") }
        });
    base.join("quarantine")
}

/// User-friendly OS label.
pub fn label() -> String {
    match detect() {
        PlatformKind::Linux   => "Linux".into(),
        PlatformKind::MacOs   => "macOS".into(),
        PlatformKind::Windows => "Windows".into(),
        PlatformKind::Unknown => "Unknown OS".into(),
    }
}
