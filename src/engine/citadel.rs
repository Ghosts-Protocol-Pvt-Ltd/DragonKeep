//! Citadel Engine — System Hardening
//!
//! Kernel parameter hardening, service audits, filesystem security,
//! secure boot status, user/group checks.

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;
use crate::engine::Finding;

/// Audit current system hardening posture
pub async fn audit(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.citadel.enabled {
        findings.push(Finding::info("Citadel engine disabled in config"));
        return Ok(findings);
    }

    if config.citadel.kernel_hardening {
        eprintln!("    {} Auditing kernel hardening...", "→".dimmed());
        findings.extend(audit_kernel().await);
    }

    if config.citadel.fs_hardening {
        eprintln!("    {} Auditing filesystem security...", "→".dimmed());
        findings.extend(audit_filesystem().await);
    }

    if config.citadel.service_audit {
        eprintln!("    {} Auditing running services...", "→".dimmed());
        findings.extend(audit_services().await);
    }

    eprintln!("    {} Checking Secure Boot status...", "→".dimmed());
    findings.extend(check_secure_boot().await);

    eprintln!("    {} Checking user accounts...", "→".dimmed());
    findings.extend(audit_users().await);

    Ok(findings)
}

/// Apply hardening for a given profile
pub async fn harden(_config: &Config, profile: &str, dry_run: bool) -> Result<()> {
    let actions: Vec<(&str, &str, &str)> = match profile {
        "paranoid" => vec![
            ("Disable core dumps", "0", "sysctl -w fs.suid_dumpable=0"),
            ("Enable ASLR (full)", "2", "sysctl -w kernel.randomize_va_space=2"),
            ("Restrict kernel pointers", "2", "sysctl -w kernel.kptr_restrict=2"),
            ("Restrict dmesg", "1", "sysctl -w kernel.dmesg_restrict=1"),
            ("Disable SysRq", "0", "sysctl -w kernel.sysrq=0"),
            ("Enable SYN cookies", "1", "sysctl -w net.ipv4.tcp_syncookies=1"),
            ("Disable IP forwarding", "0", "sysctl -w net.ipv4.ip_forward=0"),
            ("Ignore ICMP broadcast", "1", "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"),
            ("Log martian packets", "1", "sysctl -w net.ipv4.conf.all.log_martians=1"),
            ("Disable source routing", "0", "sysctl -w net.ipv4.conf.all.accept_source_route=0"),
            ("Restrict ptrace", "1", "sysctl -w kernel.yama.ptrace_scope=1"),
        ],
        "server" => vec![
            ("Enable ASLR (full)", "2", "sysctl -w kernel.randomize_va_space=2"),
            ("Restrict kernel pointers", "1", "sysctl -w kernel.kptr_restrict=1"),
            ("Enable SYN cookies", "1", "sysctl -w net.ipv4.tcp_syncookies=1"),
            ("Disable source routing", "0", "sysctl -w net.ipv4.conf.all.accept_source_route=0"),
            ("Ignore ICMP broadcast", "1", "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"),
        ],
        "standard" | _ => vec![
            ("Enable ASLR (full)", "2", "sysctl -w kernel.randomize_va_space=2"),
            ("Restrict kernel pointers", "1", "sysctl -w kernel.kptr_restrict=1"),
            ("Restrict dmesg", "1", "sysctl -w kernel.dmesg_restrict=1"),
            ("Enable SYN cookies", "1", "sysctl -w net.ipv4.tcp_syncookies=1"),
            ("Disable source routing", "0", "sysctl -w net.ipv4.conf.all.accept_source_route=0"),
        ],
    };

    if dry_run {
        eprintln!("  {} Dry run — would apply '{}' hardening:", "→".yellow(), profile);
    } else {
        eprintln!("  {} Applying '{}' hardening profile:", "→".green(), profile);
    }

    for (name, value, command) in &actions {
        if dry_run {
            eprintln!("    {} {} → {} ({})", "[DRY]".yellow(), name, value, command);
        } else {
            eprintln!("    {} {} → {}", "→".dimmed(), name, value);
            let output = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(command)
                .output()
                .await;

            match output {
                Ok(o) if o.status.success() => {
                    eprintln!("      {} Applied", "✓".green());
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    eprintln!("      {} Failed: {}", "✗".red(), stderr.trim());
                    eprintln!("      {} Try: sudo {}", "→".dimmed(), command);
                }
                Err(e) => {
                    eprintln!("      {} Error: {}", "✗".red(), e);
                }
            }
        }
    }

    Ok(())
}

async fn audit_kernel() -> Vec<Finding> {
    let mut findings = Vec::new();

    let checks = vec![
        ("kernel.randomize_va_space", "2", "ASLR", "Full ASLR enabled", "ASLR not fully enabled"),
        ("kernel.kptr_restrict", "1", "Kernel Pointers", "Kernel pointers restricted", "Kernel pointers exposed"),
        ("kernel.dmesg_restrict", "1", "dmesg Restrict", "dmesg restricted", "dmesg accessible to all"),
        ("kernel.yama.ptrace_scope", "1", "Ptrace Scope", "Ptrace restricted", "Ptrace unrestricted"),
        ("kernel.sysrq", "0", "SysRq", "SysRq disabled", "SysRq enabled — may allow dangerous operations"),
        ("net.ipv4.tcp_syncookies", "1", "SYN Cookies", "SYN cookies enabled", "SYN flood protection disabled"),
        ("net.ipv4.conf.all.accept_source_route", "0", "Source Routing", "Source routing disabled", "Source routing enabled"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "ICMP Broadcast", "ICMP broadcast ignored", "ICMP broadcast replies enabled"),
        ("net.ipv4.conf.all.log_martians", "1", "Martian Logging", "Martian packets logged", "Martian packets not logged"),
    ];

    for (key, expected, _label, pass_msg, fail_msg) in checks {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        match std::fs::read_to_string(&path) {
            Ok(val) => {
                let val = val.trim();
                // For >= comparison (e.g., kptr_restrict 2 is also good when expecting 1)
                let actual: i32 = val.parse().unwrap_or(-1);
                let exp: i32 = expected.parse().unwrap_or(-1);

                if actual >= exp {
                    findings.push(Finding::pass(pass_msg));
                } else {
                    findings.push(
                        Finding::warning(format!("{} (current: {})", fail_msg, val))
                            .with_fix(format!("sysctl -w {}={}", key, expected)),
                    );
                }
            }
            Err(_) => {
                findings.push(Finding::info(format!("Could not read {}", key)));
            }
        }
    }

    findings
}

async fn audit_filesystem() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check /tmp mount options
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        // Check for noexec on /tmp
        let tmp_mount = mounts.lines().find(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            parts.get(1) == Some(&"/tmp")
        });

        if let Some(line) = tmp_mount {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let options = parts.get(3).unwrap_or(&"");

            if options.contains("noexec") {
                findings.push(Finding::pass("/tmp mounted with noexec"));
            } else {
                findings.push(
                    Finding::info("/tmp not mounted with noexec")
                        .with_fix("Add 'noexec' to /tmp mount options in /etc/fstab"),
                );
            }

            if options.contains("nosuid") {
                findings.push(Finding::pass("/tmp mounted with nosuid"));
            } else {
                findings.push(
                    Finding::info("/tmp not mounted with nosuid")
                        .with_fix("Add 'nosuid' to /tmp mount options in /etc/fstab"),
                );
            }
        } else {
            findings.push(Finding::info("/tmp is not a separate mount point"));
        }

        // Check for separate /var, /var/log partitions
        let has_var = mounts.lines().any(|l| l.split_whitespace().nth(1) == Some("/var"));
        if has_var {
            findings.push(Finding::pass("/var is a separate mount point"));
        } else {
            findings.push(Finding::info("/var is not a separate mount point"));
        }
    }

    // Check umask
    #[cfg(unix)]
    {
        let umask_val = nix::sys::stat::umask(nix::sys::stat::Mode::empty());
        // Restore it immediately
        nix::sys::stat::umask(umask_val);
        let umask_int = umask_val.bits();
        if umask_int >= 0o022 {
            findings.push(Finding::pass(format!("umask is restrictive ({:04o})", umask_int)));
        } else {
            findings.push(
                Finding::warning(format!("umask is permissive ({:04o})", umask_int))
                    .with_fix("Set umask to 027 or 022 in /etc/profile"),
            );
        }
    }

    findings
}

async fn audit_services() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for unnecessary/risky services
    let risky_services = [
        ("telnet.socket", "Telnet", "Unencrypted remote access"),
        ("rsh.socket", "RSH", "Unencrypted remote shell"),
        ("rlogin.socket", "Rlogin", "Unencrypted remote login"),
        ("vsftpd", "FTP", "Consider SFTP instead"),
        ("rpcbind", "RPCBind", "NFS-related — disable if not using NFS"),
        ("avahi-daemon", "Avahi", "mDNS — disable if not needed on servers"),
    ];

    for (service, name, risk) in &risky_services {
        let status = tokio::process::Command::new("systemctl")
            .args(["is-active", service])
            .output()
            .await;

        if let Ok(output) = status {
            let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if state == "active" {
                findings.push(
                    Finding::warning(format!("{} service is running", name))
                        .with_detail(risk.to_string())
                        .with_fix(format!("systemctl disable --now {}", service)),
                );
            }
        }
    }

    if findings.is_empty() {
        findings.push(Finding::pass("No known risky services running"));
    }

    findings
}

async fn check_secure_boot() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if Secure Boot is enabled via EFI variables
        let sb_path = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
        if std::path::Path::new(sb_path).exists() {
            match std::fs::read(sb_path) {
                Ok(data) => {
                    // Last byte: 1 = enabled, 0 = disabled
                    if data.last() == Some(&1) {
                        findings.push(Finding::pass("Secure Boot is enabled"));
                    } else {
                        findings.push(
                            Finding::info("Secure Boot is disabled")
                                .with_fix("Enable Secure Boot in BIOS/UEFI settings"),
                        );
                    }
                }
                Err(_) => {
                    findings.push(Finding::info("Could not read Secure Boot status"));
                }
            }
        } else if std::path::Path::new("/sys/firmware/efi").exists() {
            findings.push(Finding::info("UEFI boot detected but Secure Boot status unreadable"));
        } else {
            findings.push(Finding::info("Legacy BIOS boot (no Secure Boot support)"));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(Finding::info("Secure Boot check not yet implemented on this platform"));
    }

    findings
}

async fn audit_users() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for users with UID 0 (root equivalents)
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        let root_users: Vec<&str> = passwd.lines()
            .filter(|l| {
                let parts: Vec<&str> = l.split(':').collect();
                parts.get(2) == Some(&"0") && parts.first() != Some(&"root")
            })
            .filter_map(|l| l.split(':').next())
            .collect();

        if root_users.is_empty() {
            findings.push(Finding::pass("No non-root users with UID 0"));
        } else {
            for user in &root_users {
                findings.push(
                    Finding::critical(format!("Non-root user with UID 0: {}", user))
                        .with_detail("This user has equivalent privileges to root")
                        .with_fix(format!("Investigate user '{}' — may be unauthorized", user)),
                );
            }
        }

        // Check for users with no password
        let no_shell_users: Vec<&str> = passwd.lines()
            .filter(|l| {
                let parts: Vec<&str> = l.split(':').collect();
                let shell = parts.get(6).unwrap_or(&"");
                let uid: u32 = parts.get(2).and_then(|u| u.parse().ok()).unwrap_or(0);
                uid >= 1000 && (*shell == "/bin/bash" || *shell == "/bin/zsh" || *shell == "/bin/sh")
            })
            .filter_map(|l| l.split(':').next())
            .collect();

        findings.push(Finding::info(format!("{} interactive user accounts", no_shell_users.len())));
    }

    // Check if root account has a password set
    if let Ok(shadow) = std::fs::read_to_string("/etc/shadow") {
        let root_line = shadow.lines().find(|l| l.starts_with("root:"));
        if let Some(line) = root_line {
            let hash = line.split(':').nth(1).unwrap_or("");
            if hash.starts_with('!') || hash.starts_with('*') {
                findings.push(Finding::pass("Root account is locked (password disabled)"));
            } else if hash.is_empty() {
                findings.push(
                    Finding::critical("Root account has NO password!")
                        .with_fix("Lock root: passwd -l root"),
                );
            } else {
                findings.push(Finding::info("Root account has a password set"));
            }
        }
    }

    findings
}
