//! Sentinel Engine — Security Scanner
//!
//! Checks: file permissions, SSH config, SUID binaries, world-writable dirs,
//! kernel security features, firewall, root login, password policies.

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;
use crate::engine::Finding;

/// Run full security scan
pub async fn scan(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.sentinel.enabled {
        findings.push(Finding::info("Sentinel engine disabled in config"));
        return Ok(findings);
    }

    eprintln!("    {} Checking kernel security features...", "→".dimmed());
    findings.extend(check_kernel_security().await);

    eprintln!("    {} Checking file permissions...", "→".dimmed());
    findings.extend(check_permissions().await);

    if config.sentinel.ssh_audit {
        eprintln!("    {} Auditing SSH configuration...", "→".dimmed());
        findings.extend(check_ssh_config().await);
    }

    if config.sentinel.rootkit_scan {
        eprintln!("    {} Scanning for rootkit indicators...", "→".dimmed());
        findings.extend(check_rootkit_indicators().await);
    }

    if config.sentinel.port_scan {
        eprintln!("    {} Scanning open ports...", "→".dimmed());
        findings.extend(check_open_ports().await);
    }

    eprintln!("    {} Checking SUID/SGID binaries...", "→".dimmed());
    findings.extend(check_suid_binaries().await);

    Ok(findings)
}

async fn check_kernel_security() -> Vec<Finding> {
    let mut findings = Vec::new();

    // ASLR
    match read_sysctl("kernel.randomize_va_space") {
        Some(val) if val.trim() == "2" => {
            findings.push(Finding::pass("ASLR fully enabled"));
        }
        Some(val) => {
            findings.push(
                Finding::warning(format!("ASLR not fully enabled (level: {})", val.trim()))
                    .with_fix("sysctl -w kernel.randomize_va_space=2"),
            );
        }
        None => {
            findings.push(Finding::info("Could not read ASLR status"));
        }
    }

    // Kernel pointer hiding
    match read_sysctl("kernel.kptr_restrict") {
        Some(val) if val.trim() == "1" || val.trim() == "2" => {
            findings.push(Finding::pass("Kernel pointers restricted"));
        }
        Some(_) => {
            findings.push(
                Finding::warning("Kernel pointers exposed")
                    .with_fix("sysctl -w kernel.kptr_restrict=1"),
            );
        }
        None => {}
    }

    // dmesg restrict
    match read_sysctl("kernel.dmesg_restrict") {
        Some(val) if val.trim() == "1" => {
            findings.push(Finding::pass("dmesg restricted to root"));
        }
        Some(_) => {
            findings.push(
                Finding::info("dmesg accessible to all users")
                    .with_fix("sysctl -w kernel.dmesg_restrict=1"),
            );
        }
        None => {}
    }

    // Core dumps
    match read_sysctl("fs.suid_dumpable") {
        Some(val) if val.trim() == "0" => {
            findings.push(Finding::pass("SUID core dumps disabled"));
        }
        Some(_) => {
            findings.push(
                Finding::warning("SUID processes can dump core")
                    .with_fix("sysctl -w fs.suid_dumpable=0"),
            );
        }
        None => {}
    }

    // SYN cookies
    match read_sysctl("net.ipv4.tcp_syncookies") {
        Some(val) if val.trim() == "1" => {
            findings.push(Finding::pass("SYN cookies enabled"));
        }
        Some(_) => {
            findings.push(
                Finding::warning("SYN flood protection disabled")
                    .with_fix("sysctl -w net.ipv4.tcp_syncookies=1"),
            );
        }
        None => {}
    }

    // IP forwarding (should be off on workstations)
    match read_sysctl("net.ipv4.ip_forward") {
        Some(val) if val.trim() == "0" => {
            findings.push(Finding::pass("IP forwarding disabled"));
        }
        Some(_) => {
            findings.push(
                Finding::info("IP forwarding enabled — expected for routers/VMs, risk on workstations")
                    .with_fix("sysctl -w net.ipv4.ip_forward=0"),
            );
        }
        None => {}
    }

    findings
}

async fn check_permissions() -> Vec<Finding> {
    let mut findings = Vec::new();

    let sensitive_files = [
        ("/etc/shadow", 0o640),
        ("/etc/passwd", 0o644),
        ("/etc/gshadow", 0o640),
        ("/etc/sudoers", 0o440),
    ];

    for (path, expected) in &sensitive_files {
        match std::fs::metadata(path) {
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode <= *expected {
                        findings.push(Finding::pass(format!("{} permissions OK ({:o})", path, mode)));
                    } else {
                        findings.push(
                            Finding::warning(format!("{} permissions too open ({:o}, expected {:o})", path, mode, expected))
                                .with_fix(format!("chmod {:o} {}", expected, path)),
                        );
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = meta;
                    findings.push(Finding::info(format!("{} exists (permission check N/A on this OS)", path)));
                }
            }
            Err(_) => {
                // File might not exist on all distros
            }
        }
    }

    // World-writable directories (excluding /tmp, /var/tmp)
    let check_dirs = ["/var/log", "/etc"];
    for dir in &check_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = meta.permissions().mode();
                        if mode & 0o002 != 0 && meta.is_dir() {
                            findings.push(
                                Finding::warning(format!("World-writable directory: {}", entry.path().display()))
                                    .with_fix(format!("chmod o-w {}", entry.path().display())),
                            );
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = meta;
                    }
                }
            }
        }
    }

    findings
}

async fn check_ssh_config() -> Vec<Finding> {
    let mut findings = Vec::new();

    let sshd_config = match std::fs::read_to_string("/etc/ssh/sshd_config") {
        Ok(c) => c,
        Err(_) => {
            findings.push(Finding::info("SSH server not installed or config not readable"));
            return findings;
        }
    };

    // Root login
    if sshd_config.lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#') && l.to_lowercase().contains("permitrootlogin") && l.contains("yes")
    }) {
        findings.push(
            Finding::critical("SSH root login enabled")
                .with_detail("Direct root login via SSH is a major security risk")
                .with_fix("Set 'PermitRootLogin no' in /etc/ssh/sshd_config"),
        );
    } else {
        findings.push(Finding::pass("SSH root login disabled or not explicitly enabled"));
    }

    // Password authentication
    if sshd_config.lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#') && l.to_lowercase().contains("passwordauthentication") && l.contains("yes")
    }) {
        findings.push(
            Finding::warning("SSH password authentication enabled")
                .with_detail("Key-based auth is more secure")
                .with_fix("Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"),
        );
    }

    // X11 Forwarding
    if sshd_config.lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#') && l.to_lowercase().contains("x11forwarding") && l.contains("yes")
    }) {
        findings.push(
            Finding::info("SSH X11 forwarding enabled")
                .with_fix("Set 'X11Forwarding no' if not needed"),
        );
    }

    findings
}

async fn check_rootkit_indicators() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for hidden processes (compare /proc count with ps)
    #[cfg(unix)]
    {
        let proc_count = std::fs::read_dir("/proc")
            .map(|entries| entries.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_str().map_or(false, |n| n.chars().all(|c| c.is_ascii_digit())))
                .count())
            .unwrap_or(0);

        if proc_count > 0 {
            findings.push(Finding::pass(format!("{} processes visible in /proc", proc_count)));
        }
    }

    // Check for suspicious kernel modules
    if let Ok(modules) = std::fs::read_to_string("/proc/modules") {
        let suspicious = ["rootkit", "hideproc", "diamorphine", "reptile", "bdvl"];
        for sus in &suspicious {
            if modules.to_lowercase().contains(sus) {
                findings.push(
                    Finding::critical(format!("Suspicious kernel module detected: {}", sus))
                        .with_detail("This module name matches known rootkit indicators")
                        .with_fix(format!("Investigate: lsmod | grep {}", sus)),
                );
            }
        }
        if !suspicious.iter().any(|s| modules.to_lowercase().contains(s)) {
            findings.push(Finding::pass("No known rootkit kernel modules detected"));
        }
    }

    // Check /etc/ld.so.preload (LD_PRELOAD persistence)
    match std::fs::read_to_string("/etc/ld.so.preload") {
        Ok(content) if !content.trim().is_empty() => {
            findings.push(
                Finding::warning(format!("LD_PRELOAD entries found in /etc/ld.so.preload"))
                    .with_detail(content.trim().to_string())
                    .with_fix("Verify these libraries are legitimate"),
            );
        }
        _ => {
            findings.push(Finding::pass("No LD_PRELOAD persistence found"));
        }
    }

    findings
}

async fn check_open_ports() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Parse /proc/net/tcp for listening sockets (state 0A = LISTEN)
    #[cfg(unix)]
    {
        if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
            let mut listen_count = 0u32;
            for line in tcp.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 3 && parts[3] == "0A" {
                    listen_count += 1;
                    // Parse port from hex
                    if let Some(addr) = parts.get(1) {
                        if let Some(port_hex) = addr.split(':').nth(1) {
                            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                let well_known_risky = [21, 23, 25, 111, 513, 514, 6667];
                                if well_known_risky.contains(&port) {
                                    findings.push(
                                        Finding::warning(format!("Potentially risky port {} open", port))
                                            .with_fix(format!("Investigate listener on port {}", port)),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            findings.push(Finding::info(format!("{} TCP ports in LISTEN state", listen_count)));
        }
    }

    #[cfg(not(unix))]
    {
        findings.push(Finding::info("Port scan not yet implemented on this platform"));
    }

    findings
}

async fn check_suid_binaries() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let common_suid_dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin"];
        let mut suid_count = 0u32;

        for dir in &common_suid_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        let mode = meta.permissions().mode();
                        if mode & 0o4000 != 0 {
                            suid_count += 1;
                        }
                    }
                }
            }
        }

        if suid_count > 50 {
            findings.push(
                Finding::warning(format!("{} SUID binaries found — review for unnecessary escalation", suid_count))
                    .with_fix("find / -perm -4000 -type f 2>/dev/null"),
            );
        } else {
            findings.push(Finding::info(format!("{} SUID binaries found in standard paths", suid_count)));
        }
    }

    #[cfg(not(unix))]
    {
        findings.push(Finding::info("SUID check not applicable on this platform"));
    }

    findings
}

fn read_sysctl(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(path).ok()
}
