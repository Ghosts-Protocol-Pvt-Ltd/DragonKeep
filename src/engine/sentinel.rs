//! Sentinel Engine — Security Scanner
//!
//! Comprehensive system security audit aligned with:
//!   - MITRE ATT&CK for Enterprise (attack.mitre.org)
//!   - Atomic Red Team tests (github.com/redcanaryco/atomic-red-team)
//!   - CIS Benchmarks v8 for Linux (cisecurity.org)
//!   - DISA RHEL 8/9 STIGs (public.cyber.mil)
//!   - NIST SP 800-53 Rev 5 (csrc.nist.gov)
//!   - NSA Cybersecurity Technical Report CTR-U-OO-213547-22
//!
//! Checks: kernel hardening, MAC enforcement, file permissions, SSH config,
//! SUID/SGID binaries, rootkit indicators, credential exposure, open ports,
//! browser/game token theft indicators, USB/DMA attack surface.

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;
use crate::engine::Finding;

/// Run full security scan
pub async fn scan(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.sentinel.enabled {
        findings.push(Finding::info("Sentinel engine disabled in config")
            .with_engine("Sentinel"));
        return Ok(findings);
    }

    eprintln!("    {} Checking kernel security features...", "→".dimmed());
    findings.extend(check_kernel_security().await);

    eprintln!("    {} Checking mandatory access controls...", "→".dimmed());
    findings.extend(check_mac_enforcement().await);

    if config.sentinel.permission_audit {
        eprintln!("    {} Checking file permissions...", "→".dimmed());
        findings.extend(check_permissions().await);
    }

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

        eprintln!("    {} Checking SUID/SGID binaries...", "→".dimmed());
        findings.extend(check_suid_binaries().await);
    }

    eprintln!("    {} Checking credential exposure...", "→".dimmed());
    findings.extend(check_credential_exposure().await);

    eprintln!("    {} Checking USB/DMA attack surface...", "→".dimmed());
    findings.extend(check_dma_attack_surface().await);

    Ok(findings)
}

/// Kernel security parameters
/// Reference: CIS Benchmark Section 1.5, DISA STIG V-230266 through V-230270
/// ATT&CK: Defense Evasion, Privilege Escalation
async fn check_kernel_security() -> Vec<Finding> {
    let mut findings = Vec::new();

    // ASLR — CIS 1.5.3, STIG V-230267, NIST SI-16
    // ATT&CK T1055 (Process Injection — ASLR makes exploitation harder)
    // Atomic Red Team: T1055
    match read_sysctl("kernel.randomize_va_space") {
        Some(val) if val.trim() == "2" => {
            findings.push(Finding::pass("ASLR fully enabled (level 2)")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-001")
                .with_cis("1.5.3")
                .with_stig("RHEL-08-010430")
                .with_nist(vec!["SI-16"]));
        }
        Some(val) => {
            findings.push(
                Finding::high(format!("ASLR not fully enabled (level: {})", val.trim()))
                    .with_detail("Address Space Layout Randomization prevents memory corruption exploits. Level 2 randomizes stack, VDSO, mmap, and heap.")
                    .with_fix("sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space=2' >> /etc/sysctl.d/99-dragonkeep.conf")
                    .with_cvss(7.8)
                    .with_cis("1.5.3")
                    .with_stig("RHEL-08-010430")
                    .with_mitre(vec!["T1055", "T1203"])
                    .with_nist(vec!["SI-16"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-001"),
            );
        }
        None => {
            findings.push(Finding::info("Could not read ASLR status")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-001"));
        }
    }

    // Kernel pointer hiding — CIS 1.5.2, STIG V-230268
    // ATT&CK T1082 (System Information Discovery)
    match read_sysctl("kernel.kptr_restrict") {
        Some(val) if val.trim() == "1" || val.trim() == "2" => {
            findings.push(Finding::pass("Kernel pointers restricted")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-002")
                .with_cis("1.5.2")
                .with_stig("RHEL-08-010375")
                .with_nist(vec!["SI-11"]));
        }
        Some(_) => {
            findings.push(
                Finding::warning("Kernel pointers exposed to unprivileged users")
                    .with_detail("Exposed kernel addresses aid exploit development by defeating KASLR")
                    .with_fix("sysctl -w kernel.kptr_restrict=2")
                    .with_cvss(5.5)
                    .with_cis("1.5.2")
                    .with_stig("RHEL-08-010375")
                    .with_mitre(vec!["T1082"])
                    .with_nist(vec!["SI-11"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-002"),
            );
        }
        None => {}
    }

    // dmesg restrict — CIS 1.5.1, STIG V-230269
    // ATT&CK T1082 (System Information Discovery)
    match read_sysctl("kernel.dmesg_restrict") {
        Some(val) if val.trim() == "1" => {
            findings.push(Finding::pass("dmesg restricted to root")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-003")
                .with_cis("1.5.1")
                .with_stig("RHEL-08-010375")
                .with_nist(vec!["SI-11"]));
        }
        Some(_) => {
            findings.push(
                Finding::warning("dmesg accessible to all users")
                    .with_detail("Kernel ring buffer may leak hardware info, driver versions, and memory addresses useful for exploit development")
                    .with_fix("sysctl -w kernel.dmesg_restrict=1")
                    .with_cvss(3.3)
                    .with_cis("1.5.1")
                    .with_stig("RHEL-08-010375")
                    .with_mitre(vec!["T1082"])
                    .with_nist(vec!["SI-11"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-003"),
            );
        }
        None => {}
    }

    // Core dumps — CIS 1.5.1, STIG V-230310
    // ATT&CK T1003 (OS Credential Dumping)
    match read_sysctl("fs.suid_dumpable") {
        Some(val) if val.trim() == "0" => {
            findings.push(Finding::pass("SUID core dumps disabled")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-004")
                .with_cis("1.5.1")
                .with_stig("RHEL-08-010310")
                .with_nist(vec!["AC-6(1)"]));
        }
        Some(_) => {
            findings.push(
                Finding::warning("SUID processes can dump core (credential leak risk)")
                    .with_detail("Core dumps from SUID programs may contain credentials, keys, or other secrets from privileged memory")
                    .with_fix("sysctl -w fs.suid_dumpable=0")
                    .with_cvss(5.5)
                    .with_cis("1.5.1")
                    .with_stig("RHEL-08-010310")
                    .with_mitre(vec!["T1003"])
                    .with_nist(vec!["AC-6(1)"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-004"),
            );
        }
        None => {}
    }

    // SYN cookies — CIS 3.2.8, STIG V-230510
    // ATT&CK T1498 (Network Denial of Service)
    match read_sysctl("net.ipv4.tcp_syncookies") {
        Some(val) if val.trim() == "1" => {
            findings.push(Finding::pass("SYN cookies enabled")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-005")
                .with_cis("3.2.8")
                .with_stig("RHEL-08-040220")
                .with_nist(vec!["SC-5"]));
        }
        Some(_) => {
            findings.push(
                Finding::warning("SYN flood protection disabled")
                    .with_detail("Without SYN cookies, the system is vulnerable to SYN flood denial-of-service attacks")
                    .with_fix("sysctl -w net.ipv4.tcp_syncookies=1")
                    .with_cvss(5.3)
                    .with_cis("3.2.8")
                    .with_stig("RHEL-08-040220")
                    .with_mitre(vec!["T1498"])
                    .with_nist(vec!["SC-5"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-005"),
            );
        }
        None => {}
    }

    // IP forwarding — CIS 3.1.1, STIG V-230534
    // ATT&CK T1557 (Adversary-in-the-Middle)
    match read_sysctl("net.ipv4.ip_forward") {
        Some(val) if val.trim() == "0" => {
            findings.push(Finding::pass("IP forwarding disabled")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-006")
                .with_cis("3.1.1")
                .with_stig("RHEL-08-040259")
                .with_nist(vec!["CM-7"]));
        }
        Some(_) => {
            findings.push(
                Finding::info("IP forwarding enabled — expected for VMs/containers, risk on workstations")
                    .with_detail("IP forwarding allows the system to route packets between networks, enabling MITM attacks if compromised")
                    .with_fix("sysctl -w net.ipv4.ip_forward=0")
                    .with_cvss(3.7)
                    .with_cis("3.1.1")
                    .with_stig("RHEL-08-040259")
                    .with_mitre(vec!["T1557"])
                    .with_nist(vec!["CM-7"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-006"),
            );
        }
        None => {}
    }

    // Kernel lockdown mode — NSA Linux hardening guide
    // Prevents modification of the running kernel even by root
    if let Ok(content) = std::fs::read_to_string("/sys/kernel/security/lockdown") {
        let trimmed = content.trim();
        if trimmed.contains("[integrity]") || trimmed.contains("[confidentiality]") {
            findings.push(Finding::pass(format!("Kernel lockdown active: {}", trimmed))
                .with_engine("Sentinel")
                .with_rule("DK-SEN-007")
                .with_nist(vec!["SI-7(6)", "SC-34"]));
        } else {
            findings.push(
                Finding::info("Kernel lockdown mode not active")
                    .with_detail("Lockdown restricts root from modifying the running kernel (kexec, /dev/mem, unsigned modules). Recommended by NSA CTR-U-OO-213547-22.")
                    .with_fix("Boot with lockdown=integrity or lockdown=confidentiality kernel parameter")
                    .with_nist(vec!["SI-7(6)", "SC-34"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-007"),
            );
        }
    }

    // Exec-shield / NX bit
    // ATT&CK T1203 (Exploitation for Client Execution)
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        if content.contains(" nx ") || content.contains(" nx\n") {
            findings.push(Finding::pass("NX (No-Execute) bit supported and enabled")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-008")
                .with_nist(vec!["SI-16", "SC-39"]));
        }
    }

    findings
}

/// Check Mandatory Access Control (SELinux / AppArmor)
/// Reference: CIS 1.6, STIG V-230223 through V-230227
/// NSA: CTR-U-OO-213547-22 Section 5
async fn check_mac_enforcement() -> Vec<Finding> {
    let mut findings = Vec::new();

    // SELinux check — STIG V-230223, CIS 1.6.1
    // ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools)
    let selinux_status = std::fs::read_to_string("/sys/fs/selinux/enforce");
    let selinux_config = std::fs::read_to_string("/etc/selinux/config");

    match (&selinux_status, &selinux_config) {
        (Ok(enforce), _) if enforce.trim() == "1" => {
            findings.push(Finding::pass("SELinux is enforcing")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-009")
                .with_cis("1.6.1.2")
                .with_stig("RHEL-08-010170")
                .with_nist(vec!["AC-3(4)", "AU-9"]));
        }
        (Ok(enforce), _) if enforce.trim() == "0" => {
            findings.push(
                Finding::high("SELinux is in permissive mode (not enforcing)")
                    .with_detail("SELinux is loaded but only logging violations, not blocking them. Per NSA hardening guidance, SELinux should be in enforcing mode.")
                    .with_fix("Set SELINUX=enforcing in /etc/selinux/config && setenforce 1")
                    .with_cvss(6.7)
                    .with_cis("1.6.1.2")
                    .with_stig("RHEL-08-010170")
                    .with_mitre(vec!["T1562.001"])
                    .with_nist(vec!["AC-3(4)", "AU-9"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-009"),
            );
        }
        _ => {
            // Check if SELinux is disabled or not present — check AppArmor
            let aa_status = std::fs::read_to_string("/sys/kernel/security/apparmor/profiles");
            match aa_status {
                Ok(profiles) if !profiles.trim().is_empty() => {
                    let enforce_count = profiles.lines().filter(|l| l.contains("(enforce)")).count();
                    let complain_count = profiles.lines().filter(|l| l.contains("(complain)")).count();
                    let total = profiles.lines().count();

                    if enforce_count > 0 {
                        findings.push(Finding::pass(format!("AppArmor active: {} profiles ({} enforce, {} complain)", total, enforce_count, complain_count))
                            .with_engine("Sentinel")
                            .with_rule("DK-SEN-009")
                            .with_cis("1.6.1")
                            .with_nist(vec!["AC-3(4)"]));
                    } else {
                        findings.push(
                            Finding::warning("AppArmor loaded but no profiles in enforce mode")
                                .with_fix("aa-enforce /etc/apparmor.d/*")
                                .with_cvss(4.7)
                                .with_cis("1.6.1")
                                .with_mitre(vec!["T1562.001"])
                                .with_nist(vec!["AC-3(4)"])
                                .with_engine("Sentinel")
                                .with_rule("DK-SEN-009"),
                        );
                    }
                }
                _ => {
                    findings.push(
                        Finding::warning("No Mandatory Access Control active (SELinux/AppArmor)")
                            .with_detail("MAC provides defense-in-depth beyond DAC permissions. NSA recommends SELinux for all DoD systems. CIS requires either SELinux or AppArmor.")
                            .with_fix("Install and enable SELinux or AppArmor for your distribution")
                            .with_cvss(5.3)
                            .with_cis("1.6.1")
                            .with_stig("RHEL-08-010170")
                            .with_mitre(vec!["T1562.001"])
                            .with_nist(vec!["AC-3(4)", "AU-9"])
                            .with_engine("Sentinel")
                            .with_rule("DK-SEN-009"),
                    );
                }
            }
        }
    }

    findings
}

/// File permissions — CIS Section 6.1, STIG V-230258 through V-230265
/// ATT&CK T1222.002 (File and Directory Permissions Modification: Linux)
async fn check_permissions() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Critical file permission checks with full framework mapping
    let sensitive_files: Vec<(&str, u32, &str, &str, &[&str])> = vec![
        // (path, max_mode, CIS ID, STIG ID, NIST controls)
        ("/etc/shadow",  0o640, "6.1.3",  "RHEL-08-010390", &["AC-6(1)"]),
        ("/etc/passwd",  0o644, "6.1.1",  "RHEL-08-010100", &["AC-6(1)"]),
        ("/etc/gshadow", 0o640, "6.1.5",  "RHEL-08-010400", &["AC-6(1)"]),
        ("/etc/sudoers", 0o440, "5.2.1",  "RHEL-08-010380", &["AC-6(1)", "CM-6"]),
        ("/etc/crontab", 0o600, "5.1.2",  "RHEL-08-010660", &["CM-6", "AC-6"]),
        ("/etc/ssh/sshd_config", 0o600, "5.2.1", "RHEL-08-010020", &["AC-6(1)"]),
    ];

    for (path, expected, cis, stig, nist) in &sensitive_files {
        match std::fs::metadata(path) {
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode <= *expected {
                        findings.push(Finding::pass(format!("{} permissions OK ({:o})", path, mode))
                            .with_engine("Sentinel")
                            .with_rule("DK-SEN-010")
                            .with_cis(*cis)
                            .with_stig(*stig)
                            .with_nist(nist.to_vec()));
                    } else {
                        findings.push(
                            Finding::warning(format!("{} permissions too open ({:o}, expected {:o})", path, mode, expected))
                                .with_fix(format!("chmod {:o} {}", expected, path))
                                .with_cvss(5.5)
                                .with_cis(*cis)
                                .with_stig(*stig)
                                .with_mitre(vec!["T1222.002"])
                                .with_nist(nist.to_vec())
                                .with_engine("Sentinel")
                                .with_rule("DK-SEN-010"),
                        );
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = meta;
                    findings.push(Finding::info(format!("{} exists (permission check N/A on this OS)", path))
                        .with_engine("Sentinel")
                        .with_rule("DK-SEN-010"));
                }
            }
            Err(_) => {}
        }
    }

    // World-writable directories — CIS 1.1.21
    // ATT&CK T1222.002
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
                                    .with_fix(format!("chmod o-w {}", entry.path().display()))
                                    .with_cvss(5.3)
                                    .with_cis("1.1.21")
                                    .with_mitre(vec!["T1222.002"])
                                    .with_nist(vec!["AC-6(1)", "CM-6"])
                                    .with_engine("Sentinel")
                                    .with_rule("DK-SEN-011"),
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

/// SSH configuration audit — CIS Section 5.2, STIG V-230340 through V-230380
/// ATT&CK T1021.004 (Remote Services: SSH)
/// Atomic Red Team: T1021.004
async fn check_ssh_config() -> Vec<Finding> {
    let mut findings = Vec::new();

    let sshd_config = match std::fs::read_to_string("/etc/ssh/sshd_config") {
        Ok(c) => c,
        Err(_) => {
            findings.push(Finding::info("SSH server not installed or config not readable")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-012"));
            return findings;
        }
    };

    let get_value = |key: &str| -> Option<String> {
        sshd_config.lines()
            .filter(|l| !l.trim().starts_with('#'))
            .find(|l| l.trim().to_lowercase().starts_with(&key.to_lowercase()))
            .map(|l| l.split_whitespace().nth(1).unwrap_or("").to_string())
    };

    // Root login — CIS 5.2.10, STIG V-230340
    // ATT&CK T1078.003 (Valid Accounts: Local Accounts)
    if get_value("PermitRootLogin").map_or(false, |v| v.to_lowercase() == "yes") {
        findings.push(
            Finding::critical("SSH root login enabled")
                .with_detail("Direct SSH root login violates principle of least privilege and bypasses audit trail of who elevated. Per CIS 5.2.10 and DISA STIG V-230340.")
                .with_fix("Set 'PermitRootLogin no' in /etc/ssh/sshd_config && systemctl restart sshd")
                .with_cvss(7.5)
                .with_cis("5.2.10")
                .with_stig("RHEL-08-010550")
                .with_mitre(vec!["T1078.003", "T1021.004"])
                .with_nist(vec!["AC-6(2)", "IA-2"])
                .with_engine("Sentinel")
                .with_rule("DK-SEN-012"),
        );
    } else {
        findings.push(Finding::pass("SSH root login disabled")
            .with_engine("Sentinel")
            .with_rule("DK-SEN-012")
            .with_cis("5.2.10")
            .with_stig("RHEL-08-010550"));
    }

    // Password authentication — CIS 5.2.12, STIG V-230380
    // ATT&CK T1110 (Brute Force)
    if get_value("PasswordAuthentication").map_or(false, |v| v.to_lowercase() == "yes") {
        findings.push(
            Finding::warning("SSH password authentication enabled")
                .with_detail("Password auth is vulnerable to brute force and credential stuffing. Key-based auth is required by CIS 5.2.12.")
                .with_fix("Set 'PasswordAuthentication no' in /etc/ssh/sshd_config")
                .with_cvss(5.3)
                .with_cis("5.2.12")
                .with_stig("RHEL-08-010380")
                .with_mitre(vec!["T1110", "T1021.004"])
                .with_nist(vec!["IA-2(1)", "IA-5(2)"])
                .with_engine("Sentinel")
                .with_rule("DK-SEN-013"),
        );
    }

    // X11 Forwarding — CIS 5.2.6
    // ATT&CK T1021.004
    if get_value("X11Forwarding").map_or(false, |v| v.to_lowercase() == "yes") {
        findings.push(
            Finding::info("SSH X11 forwarding enabled")
                .with_detail("X11 forwarding can be exploited for keylogging and screen capture on the SSH host")
                .with_fix("Set 'X11Forwarding no' if not needed")
                .with_cis("5.2.6")
                .with_mitre(vec!["T1056.001"])
                .with_nist(vec!["CM-7"])
                .with_engine("Sentinel")
                .with_rule("DK-SEN-014"),
        );
    }

    // Protocol version — ensure only SSHv2
    // MaxAuthTries — CIS 5.2.7, STIG V-230330
    if let Some(max_tries) = get_value("MaxAuthTries") {
        if let Ok(n) = max_tries.parse::<u32>() {
            if n > 4 {
                findings.push(
                    Finding::warning(format!("SSH MaxAuthTries is {} (recommended ≤ 4)", n))
                        .with_fix("Set 'MaxAuthTries 4' in /etc/ssh/sshd_config")
                        .with_cvss(3.7)
                        .with_cis("5.2.7")
                        .with_stig("RHEL-08-010330")
                        .with_mitre(vec!["T1110"])
                        .with_nist(vec!["AC-7"])
                        .with_engine("Sentinel")
                        .with_rule("DK-SEN-015"),
                );
            }
        }
    }

    // Idle timeout — CIS 5.2.16, STIG V-230320
    let timeout = get_value("ClientAliveInterval").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let count_max = get_value("ClientAliveCountMax").and_then(|v| v.parse::<u32>().ok()).unwrap_or(3);
    if timeout == 0 || timeout * count_max > 900 {
        findings.push(
            Finding::info("SSH idle timeout not configured or exceeds 15 minutes")
                .with_detail("CIS and DISA STIG require SSH sessions to timeout after 10-15 minutes of inactivity")
                .with_fix("Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' in /etc/ssh/sshd_config")
                .with_cis("5.2.16")
                .with_stig("RHEL-08-010200")
                .with_mitre(vec!["T1078"])
                .with_nist(vec!["AC-12", "SC-10"])
                .with_engine("Sentinel")
                .with_rule("DK-SEN-016"),
        );
    }

    // Weak ciphers / MACs — CIS 5.2.15, STIG V-230250
    let weak_ciphers = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "arcfour"];
    if let Some(ciphers) = get_value("Ciphers") {
        for wc in &weak_ciphers {
            if ciphers.to_lowercase().contains(wc) {
                findings.push(
                    Finding::high(format!("SSH uses weak cipher: {}", wc))
                        .with_detail("CBC mode ciphers are vulnerable to BEAST-style attacks. Per STIG V-230250, only FIPS 140-2/3 approved ciphers should be used.")
                        .with_fix("Set 'Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr' in sshd_config")
                        .with_cvss(5.9)
                        .with_cis("5.2.15")
                        .with_stig("RHEL-08-010291")
                        .with_mitre(vec!["T1557", "T1040"])
                        .with_nist(vec!["SC-8", "SC-13"])
                        .with_engine("Sentinel")
                        .with_rule("DK-SEN-017"),
                );
                break;
            }
        }
    }

    findings
}

/// Rootkit and malware indicators — ATT&CK Persistence & Defense Evasion
/// Atomic Red Team: T1014 (Rootkit), T1547.006 (Kernel Modules)
async fn check_rootkit_indicators() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Hidden processes — ATT&CK T1014
    #[cfg(unix)]
    {
        let proc_count = std::fs::read_dir("/proc")
            .map(|entries| entries.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_str().map_or(false, |n| n.chars().all(|c| c.is_ascii_digit())))
                .count())
            .unwrap_or(0);

        if proc_count > 0 {
            findings.push(Finding::pass(format!("{} processes visible in /proc", proc_count))
                .with_engine("Sentinel")
                .with_rule("DK-SEN-018"));
        }
    }

    // Suspicious kernel modules — ATT&CK T1547.006, T1014
    // Atomic Red Team: T1547.006
    if let Ok(modules) = std::fs::read_to_string("/proc/modules") {
        let suspicious = [
            ("rootkit",     "Generic rootkit module"),
            ("hideproc",    "Process hiding LKM rootkit"),
            ("diamorphine", "Diamorphine LKM rootkit"),
            ("reptile",     "Reptile LKM rootkit"),
            ("bdvl",        "BDVL userland rootkit"),
            ("suterusu",    "Suterusu LKM rootkit"),
            ("adore",       "Adore-ng LKM rootkit"),
            ("knark",       "Knark LKM rootkit"),
        ];
        let mut found_any = false;
        for (sus, desc) in &suspicious {
            if modules.to_lowercase().contains(sus) {
                found_any = true;
                findings.push(
                    Finding::critical(format!("Rootkit kernel module detected: {} ({})", sus, desc))
                        .with_detail("This module name matches known Linux kernel rootkit indicators. Immediate forensic investigation required.")
                        .with_fix(format!("DO NOT REBOOT — preserve evidence: lsmod | grep {} && modinfo {} && cp /proc/modules /tmp/evidence_modules", sus, sus))
                        .with_cvss(9.8)
                        .with_mitre(vec!["T1014", "T1547.006"])
                        .with_nist(vec!["SI-7", "SI-3"])
                        .with_engine("Sentinel")
                        .with_rule("DK-SEN-019"),
                );
            }
        }
        if !found_any {
            findings.push(Finding::pass("No known rootkit kernel modules detected")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-019"));
        }
    }

    // LD_PRELOAD persistence — ATT&CK T1574.006
    // Atomic Red Team: T1574.006
    match std::fs::read_to_string("/etc/ld.so.preload") {
        Ok(content) if !content.trim().is_empty() => {
            findings.push(
                Finding::high("LD_PRELOAD entries found in /etc/ld.so.preload")
                    .with_detail(format!("Libraries: {} — this file injects shared libraries into every process. Used by rootkits (Jynx2, Azazel, BDVl) for function hooking.", content.trim()))
                    .with_fix("Verify these libraries: cat /etc/ld.so.preload && ldd /usr/bin/ls")
                    .with_cvss(8.4)
                    .with_mitre(vec!["T1574.006", "T1014"])
                    .with_nist(vec!["SI-3", "SI-7"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-020"),
            );
        }
        _ => {
            findings.push(Finding::pass("No LD_PRELOAD persistence found")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-020"));
        }
    }

    // Check /proc/sys/kernel/modules_disabled
    // ATT&CK T1547.006
    if let Ok(val) = std::fs::read_to_string("/proc/sys/kernel/modules_disabled") {
        if val.trim() == "1" {
            findings.push(Finding::pass("Kernel module loading is disabled (post-boot hardening)")
                .with_engine("Sentinel")
                .with_rule("DK-SEN-021")
                .with_nist(vec!["CM-7(2)"]));
        }
    }

    findings
}

/// Open ports and network exposure — CIS 3.4, STIG V-230505
/// ATT&CK T1046 (Network Service Discovery)
async fn check_open_ports() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
            let mut listen_count = 0u32;
            // Well-known risky ports per CIS/DISA guidance
            let risky_ports: Vec<(u16, &str, &str)> = vec![
                (21,   "FTP",    "T1048"),    // Exfiltration over alternative protocol
                (23,   "Telnet", "T1021"),    // Remote Services (unencrypted)
                (25,   "SMTP",   "T1071.003"), // App Layer Protocol: Mail
                (111,  "RPC",    "T1210"),    // Exploitation of Remote Services
                (513,  "Rlogin", "T1021"),    // Remote Services
                (514,  "RSH",    "T1021"),    // Remote Services
                (2049, "NFS",    "T1021.002"), // SMB/Windows Admin Shares
                (3389, "RDP",    "T1021.001"), // Remote Desktop Protocol
                (5900, "VNC",    "T1021.005"), // VNC
                (6667, "IRC",    "T1071.001"), // C2 channel indicator
            ];

            for line in tcp.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 3 && parts[3] == "0A" {
                    listen_count += 1;
                    if let Some(addr) = parts.get(1) {
                        if let Some(port_hex) = addr.split(':').nth(1) {
                            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                for (rp, name, technique) in &risky_ports {
                                    if port == *rp {
                                        let is_external = addr.starts_with("00000000:");
                                        let scope = if is_external { "all interfaces" } else { "localhost" };
                                        let severity = if is_external {
                                            Finding::warning(format!("{} port {} open on {}", name, port, scope))
                                        } else {
                                            Finding::info(format!("{} port {} open on {}", name, port, scope))
                                        };
                                        findings.push(
                                            severity
                                                .with_detail(format!("Port {} ({}) is a high-risk service per CIS/DISA guidance", port, name))
                                                .with_fix(format!("Investigate and disable if unused: ss -tlnp | grep :{}", port))
                                                .with_cvss(if is_external { 5.3 } else { 2.1 })
                                                .with_mitre(vec![technique])
                                                .with_nist(vec!["CM-7", "SC-7"])
                                                .with_engine("Sentinel")
                                                .with_rule("DK-SEN-022"),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            findings.push(Finding::info(format!("{} TCP ports in LISTEN state", listen_count))
                .with_engine("Sentinel")
                .with_rule("DK-SEN-022"));
        }
    }

    #[cfg(not(unix))]
    {
        findings.push(Finding::info("Port scan not yet implemented on this platform")
            .with_engine("Sentinel")
            .with_rule("DK-SEN-022"));
    }

    findings
}

/// SUID/SGID binary audit — CIS 6.1.13, STIG V-230378
/// ATT&CK T1548.001 (Abuse Elevation Control Mechanism: SUID/SGID)
/// Atomic Red Team: T1548.001
async fn check_suid_binaries() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let common_suid_dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"];
        let mut suid_count = 0u32;
        let mut sgid_count = 0u32;

        // Known-dangerous SUID binaries that can be used for privilege escalation
        // Source: GTFOBins (gtfobins.github.io) — authoritative SUID exploitation reference
        let dangerous_suids = [
            "nmap", "vim", "find", "bash", "more", "less", "nano",
            "cp", "mv", "python", "python3", "perl", "ruby", "node",
            "php", "env", "awk", "gawk", "sed", "ed", "tee",
            "docker", "pkexec", "ionice", "strace", "ltrace",
            "taskset", "ip", "aria2c", "wget", "curl",
        ];

        for dir in &common_suid_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        let mode = meta.permissions().mode();
                        let name = entry.file_name().to_string_lossy().to_string();

                        if mode & 0o4000 != 0 {
                            suid_count += 1;
                            // Check against GTFOBins list
                            if dangerous_suids.iter().any(|d| name == *d) {
                                findings.push(
                                    Finding::high(format!("Dangerous SUID binary: {}/{}", dir, name))
                                        .with_detail(format!("This binary with SUID bit can be used for privilege escalation. See: https://gtfobins.github.io/gtfobins/{}/#suid", name))
                                        .with_fix(format!("chmod u-s {}/{}", dir, name))
                                        .with_cvss(7.8)
                                        .with_cis("6.1.13")
                                        .with_stig("RHEL-08-010400")
                                        .with_mitre(vec!["T1548.001"])
                                        .with_nist(vec!["AC-6(1)", "CM-6"])
                                        .with_engine("Sentinel")
                                        .with_rule("DK-SEN-023"),
                                );
                            }
                        }
                        if mode & 0o2000 != 0 {
                            sgid_count += 1;
                        }
                    }
                }
            }
        }

        if suid_count > 50 {
            findings.push(
                Finding::warning(format!("{} SUID + {} SGID binaries — review for unnecessary privilege", suid_count, sgid_count))
                    .with_fix("find / -perm -4000 -type f 2>/dev/null | xargs ls -la")
                    .with_cvss(3.3)
                    .with_cis("6.1.13")
                    .with_mitre(vec!["T1548.001"])
                    .with_nist(vec!["AC-6(1)"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-024"),
            );
        } else {
            findings.push(Finding::info(format!("{} SUID + {} SGID binaries in standard paths", suid_count, sgid_count))
                .with_engine("Sentinel")
                .with_rule("DK-SEN-024"));
        }
    }

    #[cfg(not(unix))]
    {
        findings.push(Finding::info("SUID check not applicable on this platform")
            .with_engine("Sentinel")
            .with_rule("DK-SEN-024"));
    }

    findings
}

/// Credential and token exposure detection — ATT&CK Credential Access
/// Specifically targets gamer and professional workstation threats:
///   - Discord token theft (T1539)
///   - Steam credential exposure
///   - Browser stored credentials
///   - SSH key exposure
async fn check_credential_exposure() -> Vec<Finding> {
    let mut findings = Vec::new();
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() { return findings; }

    // SSH private keys without passphrase protection — CIS 5.2.3
    // ATT&CK T1552.004 (Unsecured Credentials: Private Keys)
    // Atomic Red Team: T1552.004
    let ssh_dir = format!("{}/.ssh", home);
    if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            // Skip public keys and known_hosts
            if name.ends_with(".pub") || name == "known_hosts" || name == "authorized_keys" || name == "config" {
                continue;
            }
            if path.is_file() {
                // Check if it's actually a private key
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if content.contains("PRIVATE KEY") {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Ok(meta) = path.metadata() {
                                let mode = meta.permissions().mode() & 0o777;
                                if mode > 0o600 {
                                    findings.push(
                                        Finding::high(format!("SSH private key too permissive: {} ({:o})", name, mode))
                                            .with_detail("SSH private keys should be 600 or stricter. Over-permissive keys can be read by other users.")
                                            .with_fix(format!("chmod 600 {}", path.display()))
                                            .with_cvss(7.5)
                                            .with_mitre(vec!["T1552.004"])
                                            .with_nist(vec!["IA-5(7)", "SC-12"])
                                            .with_engine("Sentinel")
                                            .with_rule("DK-SEN-025"),
                                    );
                                }
                            }
                        }
                        // Check for unencrypted keys (no passphrase)
                        if !content.contains("ENCRYPTED") && !content.contains("aes") {
                            findings.push(
                                Finding::warning(format!("SSH private key '{}' may lack passphrase encryption", name))
                                    .with_detail("Unencrypted SSH keys provide no protection if the file is exfiltrated")
                                    .with_fix(format!("ssh-keygen -p -f {}", path.display()))
                                    .with_cvss(5.5)
                                    .with_mitre(vec!["T1552.004"])
                                    .with_nist(vec!["IA-5(7)"])
                                    .with_engine("Sentinel")
                                    .with_rule("DK-SEN-026"),
                            );
                        }
                    }
                }
            }
        }
    }

    // Discord token exposure — ATT&CK T1539 (Steal Web Session Cookie)
    // Real-world vector: Discord token grabbers (AnarchyGrabber, TokenStealer)
    let discord_paths = vec![
        format!("{}/.config/discord/Local Storage/leveldb", home),
        format!("{}/.config/discordcanary/Local Storage/leveldb", home),
        format!("{}/.config/discordptb/Local Storage/leveldb", home),
    ];
    for dpath in &discord_paths {
        if std::path::Path::new(dpath).is_dir() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(dpath) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o044 != 0 {
                        findings.push(
                            Finding::warning("Discord token storage is world/group-readable")
                                .with_detail(format!("Path: {} — Discord tokens in LevelDB can be extracted for account takeover. Common malware target for gamers.", dpath))
                                .with_fix(format!("chmod -R 700 {}", dpath.rsplit('/').skip(2).collect::<Vec<&str>>().into_iter().rev().collect::<Vec<&str>>().join("/")))
                                .with_cvss(6.5)
                                .with_mitre(vec!["T1539", "T1555.003"])
                                .with_nist(vec!["IA-5(7)"])
                                .with_engine("Sentinel")
                                .with_rule("DK-SEN-027"),
                        );
                    }
                }
            }
        }
    }

    // Browser credential databases — ATT&CK T1555.003 (Credentials from Web Browsers)
    // Atomic Red Team: T1555.003
    let browser_credential_stores = vec![
        (format!("{}/.config/google-chrome/Default/Login Data", home), "Chrome"),
        (format!("{}/.config/chromium/Default/Login Data", home), "Chromium"),
        (format!("{}/.mozilla/firefox", home), "Firefox"),
        (format!("{}/.config/BraveSoftware/Brave-Browser/Default/Login Data", home), "Brave"),
    ];

    for (cred_path, browser) in &browser_credential_stores {
        let path = std::path::Path::new(cred_path);
        if path.exists() || (path.is_dir() && browser == &"Firefox") {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let check_path = if browser == &"Firefox" {
                    // Firefox stores in profiles — check directory permissions
                    cred_path.clone()
                } else {
                    cred_path.clone()
                };
                if let Ok(meta) = std::fs::metadata(&check_path) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o044 != 0 {
                        findings.push(
                            Finding::warning(format!("{} credential store is group/world-readable", browser))
                                .with_detail("Browser credential databases contain saved passwords. Malware commonly targets these files.")
                                .with_fix(format!("chmod 600 '{}' (or 700 for directories)", check_path))
                                .with_cvss(6.5)
                                .with_mitre(vec!["T1555.003"])
                                .with_nist(vec!["IA-5(7)"])
                                .with_engine("Sentinel")
                                .with_rule("DK-SEN-028"),
                        );
                    }
                }
            }
        }
    }

    // Steam credential exposure
    let steam_path = format!("{}/.steam/steam/config/loginusers.vdf", home);
    if std::path::Path::new(&steam_path).exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&steam_path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o044 != 0 {
                    findings.push(
                        Finding::warning("Steam login credentials file is group/world-readable")
                            .with_detail("loginusers.vdf contains Steam account tokens. Targeted by game account stealers.")
                            .with_fix(format!("chmod 600 '{}'", steam_path))
                            .with_cvss(5.5)
                            .with_mitre(vec!["T1539", "T1552.001"])
                            .with_nist(vec!["IA-5(7)"])
                            .with_engine("Sentinel")
                            .with_rule("DK-SEN-029"),
                    );
                }
            }
        }
    }

    findings
}

/// USB and DMA attack surface — ATT&CK T1200 (Hardware Additions)
/// Reference: NSA CTR-U-OO-213547-22, Thunderbolt/DMA attacks
async fn check_dma_attack_surface() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Thunderbolt security level
    // ATT&CK T1200 (Hardware Additions — Thunderbolt DMA attacks)
    if let Ok(entries) = std::fs::read_dir("/sys/bus/thunderbolt/devices") {
        let has_thunderbolt = entries.count() > 0;
        if has_thunderbolt {
            // Check IOMMU (Intel VT-d / AMD-Vi) — defends against DMA attacks
            if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
                if cmdline.contains("iommu=on") || cmdline.contains("intel_iommu=on") || cmdline.contains("amd_iommu=on") {
                    findings.push(Finding::pass("IOMMU enabled — DMA attack protection active")
                        .with_engine("Sentinel")
                        .with_rule("DK-SEN-030")
                        .with_nist(vec!["SC-43"]));
                } else {
                    findings.push(
                        Finding::warning("Thunderbolt ports present but IOMMU not explicitly enabled")
                            .with_detail("Without IOMMU, Thunderbolt/PCIe devices can directly access system memory (DMA attacks). NSA recommends IOMMU for all systems with external ports.")
                            .with_fix("Add 'intel_iommu=on iommu=pt' (Intel) or 'amd_iommu=on iommu=pt' (AMD) to kernel command line")
                            .with_cvss(6.8)
                            .with_mitre(vec!["T1200"])
                            .with_nist(vec!["SC-43", "AC-25"])
                            .with_engine("Sentinel")
                            .with_rule("DK-SEN-030"),
                    );
                }
            }
        }
    }

    // USB authorized_default — controls whether new USB devices auto-connect
    if let Ok(val) = std::fs::read_to_string("/sys/bus/usb/devices/usb1/authorized_default") {
        if val.trim() == "1" {
            findings.push(
                Finding::info("USB devices auto-authorized on connection")
                    .with_detail("New USB devices are automatically trusted. USB Rubber Ducky and BadUSB attacks exploit this. For high-security: set authorized_default=0.")
                    .with_fix("echo 0 > /sys/bus/usb/devices/usb1/authorized_default (requires manual authorization per device)")
                    .with_mitre(vec!["T1200", "T1091"])
                    .with_nist(vec!["SC-41", "AC-25"])
                    .with_engine("Sentinel")
                    .with_rule("DK-SEN-031"),
            );
        }
    }

    findings
}

fn read_sysctl(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(path).ok()
}
