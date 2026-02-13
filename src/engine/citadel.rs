//! Citadel Engine — System Hardening
//!
//! Deep kernel and OS hardening audit aligned with:
//!   - CIS Benchmarks v8 Sections 1.1–1.6, 3.1–3.3 (cisecurity.org)
//!   - DISA RHEL 8/9 STIGs (public.cyber.mil)
//!   - NIST SP 800-53 Rev 5 CM/SC/AC families (csrc.nist.gov)
//!   - NSA Cybersecurity Technical Report CTR-U-OO-213547-22
//!   - MITRE ATT&CK Defense Evasion & Initial Access tactics
//!
//! Checks: kernel parameters, filesystem security, service audit,
//! Secure Boot, UEFI, GRUB protection, user accounts, audit subsystem.

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;
use crate::engine::Finding;

/// Audit current system hardening posture
pub async fn audit(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.citadel.enabled {
        findings.push(Finding::info("Citadel engine disabled in config")
            .with_engine("Citadel"));
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

    eprintln!("    {} Checking Secure Boot & UEFI...", "→".dimmed());
    findings.extend(check_secure_boot().await);

    eprintln!("    {} Checking user accounts...", "→".dimmed());
    findings.extend(audit_users().await);

    eprintln!("    {} Checking audit subsystem...", "→".dimmed());
    findings.extend(check_audit_subsystem().await);

    eprintln!("    {} Checking bootloader security...", "→".dimmed());
    findings.extend(check_bootloader().await);

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
            ("Restrict ptrace", "3", "sysctl -w kernel.yama.ptrace_scope=3"),
            ("Enable reverse path filter", "1", "sysctl -w net.ipv4.conf.all.rp_filter=1"),
            ("Disable ICMP redirects", "0", "sysctl -w net.ipv4.conf.all.accept_redirects=0"),
        ],
        "server" => vec![
            ("Enable ASLR (full)", "2", "sysctl -w kernel.randomize_va_space=2"),
            ("Restrict kernel pointers", "1", "sysctl -w kernel.kptr_restrict=1"),
            ("Enable SYN cookies", "1", "sysctl -w net.ipv4.tcp_syncookies=1"),
            ("Disable source routing", "0", "sysctl -w net.ipv4.conf.all.accept_source_route=0"),
            ("Ignore ICMP broadcast", "1", "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"),
            ("Enable reverse path filter", "1", "sysctl -w net.ipv4.conf.all.rp_filter=1"),
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

/// Kernel parameter hardening — complementary to Sentinel's checks
/// CIS Sections 1.5, 3.2; DISA STIG V-230269, V-230510
async fn audit_kernel() -> Vec<Finding> {
    let mut findings = Vec::new();

    // (sysctl_key, expected_value, pass_msg, fail_msg, CIS_ID, STIG_ID, MITRE, NIST)
    let checks: Vec<(&str, &str, &str, &str, &str, &str, &[&str], &[&str])> = vec![
        (
            "kernel.yama.ptrace_scope", "1",
            "Ptrace restricted (Yama LSM)",
            "Ptrace unrestricted — process injection possible",
            "1.5.4", "RHEL-08-010370",
            &["T1055.008", "T1003"],
            &["AC-3(4)", "SI-16"],
        ),
        (
            "kernel.sysrq", "0",
            "SysRq key disabled",
            "SysRq key enabled — allows dangerous kernel operations from keyboard",
            "1.5.5", "RHEL-08-010152",
            &["T1529"],
            &["CM-6"],
        ),
        (
            "net.ipv4.conf.all.accept_source_route", "0",
            "Source routing disabled",
            "Source routing enabled — allows packet routing manipulation",
            "3.2.1", "RHEL-08-040240",
            &["T1557"],
            &["SC-7", "CM-7"],
        ),
        (
            "net.ipv4.icmp_echo_ignore_broadcasts", "1",
            "ICMP broadcast replies ignored",
            "ICMP broadcast replies enabled — Smurf attack vector",
            "3.2.5", "RHEL-08-040230",
            &["T1498"],
            &["SC-5"],
        ),
        (
            "net.ipv4.conf.all.log_martians", "1",
            "Martian packets logged",
            "Martian packets not logged — spoofed traffic undetected",
            "3.2.4", "RHEL-08-040250",
            &["T1557"],
            &["AU-3", "SC-7"],
        ),
        (
            "net.ipv4.conf.all.rp_filter", "1",
            "Reverse path filtering enabled",
            "Reverse path filtering disabled — IP spoofing possible",
            "3.2.7", "RHEL-08-040285",
            &["T1557"],
            &["SC-7"],
        ),
        (
            "net.ipv4.conf.all.accept_redirects", "0",
            "ICMP redirects rejected",
            "ICMP redirects accepted — route manipulation possible",
            "3.2.2", "RHEL-08-040270",
            &["T1557"],
            &["SC-7", "CM-7"],
        ),
        (
            "net.ipv4.conf.all.send_redirects", "0",
            "Send redirects disabled",
            "Send redirects enabled — can aid MITM attacks",
            "3.2.1", "RHEL-08-040270",
            &["T1557"],
            &["SC-7", "CM-7"],
        ),
        (
            "net.ipv6.conf.all.accept_redirects", "0",
            "IPv6 ICMP redirects rejected",
            "IPv6 ICMP redirects accepted",
            "3.2.9", "RHEL-08-040280",
            &["T1557"],
            &["SC-7"],
        ),
        (
            "net.ipv4.conf.all.secure_redirects", "0",
            "Secure ICMP redirects rejected",
            "Secure ICMP redirects accepted — still exploitable for route manipulation",
            "3.2.3", "",
            &["T1557"],
            &["SC-7"],
        ),
        (
            "kernel.perf_event_paranoid", "3",
            "perf_event restricted to root",
            "perf_event accessible — side-channel attack surface (Spectre/Meltdown)",
            "", "",
            &["T1082"],
            &["AC-6"],
        ),
        (
            "kernel.unprivileged_bpf_disabled", "1",
            "Unprivileged BPF disabled",
            "Unprivileged BPF enabled — kernel attack surface (CVE-2021-3490, CVE-2021-33200)",
            "", "",
            &["T1068"],
            &["CM-7(2)", "SI-16"],
        ),
    ];

    for (key, expected, pass_msg, fail_msg, cis, stig, mitre, nist) in &checks {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        match std::fs::read_to_string(&path) {
            Ok(val) => {
                let val = val.trim();
                let actual: i32 = val.parse().unwrap_or(-1);
                let exp: i32 = expected.parse().unwrap_or(-1);

                if actual >= exp {
                    let mut f = Finding::pass(*pass_msg)
                        .with_engine("Citadel")
                        .with_rule("DK-CIT-001");
                    if !cis.is_empty() { f = f.with_cis(*cis); }
                    if !stig.is_empty() { f = f.with_stig(*stig); }
                    f = f.with_nist(nist.to_vec());
                    findings.push(f);
                } else {
                    let mut f = Finding::warning(format!("{} (current: {})", fail_msg, val))
                        .with_fix(format!("sysctl -w {}={} && echo '{}={}' >> /etc/sysctl.d/99-dragonkeep.conf", key, expected, key, expected))
                        .with_cvss(5.3)
                        .with_mitre(mitre.to_vec())
                        .with_nist(nist.to_vec())
                        .with_engine("Citadel")
                        .with_rule("DK-CIT-001");
                    if !cis.is_empty() { f = f.with_cis(*cis); }
                    if !stig.is_empty() { f = f.with_stig(*stig); }
                    findings.push(f);
                }
            }
            Err(_) => {
                findings.push(Finding::info(format!("Could not read {}", key))
                    .with_engine("Citadel")
                    .with_rule("DK-CIT-001"));
            }
        }
    }

    findings
}

/// Filesystem security — CIS Section 1.1
/// ATT&CK T1036.005 (Match Legitimate Name or Location)
async fn audit_filesystem() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Mount options checks — CIS 1.1.2-1.1.5
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        let mount_checks: Vec<(&str, &str, &str, &str)> = vec![
            ("/tmp", "noexec", "1.1.4", "RHEL-08-010544"),
            ("/tmp", "nosuid", "1.1.3", "RHEL-08-010543"),
            ("/tmp", "nodev",  "1.1.2", "RHEL-08-010542"),
            ("/var/tmp", "noexec", "1.1.7", ""),
            ("/var/tmp", "nosuid", "1.1.8", ""),
            ("/dev/shm", "noexec", "1.1.16", ""),
            ("/dev/shm", "nosuid", "1.1.17", ""),
            ("/dev/shm", "nodev",  "1.1.15", ""),
        ];

        for (mount_point, option, cis, stig) in &mount_checks {
            let mount_line = mounts.lines().find(|l| {
                l.split_whitespace().nth(1) == Some(mount_point)
            });

            match mount_line {
                Some(line) => {
                    let options = line.split_whitespace().nth(3).unwrap_or("");
                    if options.contains(option) {
                        let mut f = Finding::pass(format!("{} mounted with {}", mount_point, option))
                            .with_engine("Citadel")
                            .with_rule("DK-CIT-002")
                            .with_cis(*cis)
                            .with_nist(vec!["CM-6", "AC-6"]);
                        if !stig.is_empty() { f = f.with_stig(*stig); }
                        findings.push(f);
                    } else {
                        let mut f = Finding::warning(format!("{} not mounted with {}", mount_point, option))
                            .with_fix(format!("Add '{}' to {} mount options in /etc/fstab", option, mount_point))
                            .with_cvss(3.3)
                            .with_cis(*cis)
                            .with_mitre(vec!["T1036.005"])
                            .with_nist(vec!["CM-6", "AC-6"])
                            .with_engine("Citadel")
                            .with_rule("DK-CIT-002");
                        if !stig.is_empty() { f = f.with_stig(*stig); }
                        findings.push(f);
                    }
                }
                None => {
                    if *mount_point == "/tmp" || *mount_point == "/dev/shm" {
                        findings.push(Finding::info(format!("{} is not a separate mount point", mount_point))
                            .with_engine("Citadel")
                            .with_rule("DK-CIT-002")
                            .with_cis(*cis));
                    }
                }
            }
        }

        // Separate /var mount — CIS 1.1.6
        let has_var = mounts.lines().any(|l| l.split_whitespace().nth(1) == Some("/var"));
        if has_var {
            findings.push(Finding::pass("/var is a separate mount point")
                .with_engine("Citadel")
                .with_rule("DK-CIT-003")
                .with_cis("1.1.6")
                .with_nist(vec!["CM-6"]));
        } else {
            findings.push(Finding::info("/var is not a separate mount point")
                .with_engine("Citadel")
                .with_rule("DK-CIT-003")
                .with_cis("1.1.6"));
        }
    }

    // umask — CIS 5.4.4, STIG V-230385
    #[cfg(unix)]
    {
        let umask_val = nix::sys::stat::umask(nix::sys::stat::Mode::empty());
        nix::sys::stat::umask(umask_val);
        let umask_int = umask_val.bits();
        if umask_int >= 0o027 {
            findings.push(Finding::pass(format!("umask is restrictive ({:04o})", umask_int))
                .with_engine("Citadel")
                .with_rule("DK-CIT-004")
                .with_cis("5.4.4")
                .with_stig("RHEL-08-010660")
                .with_nist(vec!["AC-6(1)"]));
        } else if umask_int >= 0o022 {
            findings.push(Finding::pass(format!("umask is acceptable ({:04o})", umask_int))
                .with_engine("Citadel")
                .with_rule("DK-CIT-004")
                .with_cis("5.4.4"));
        } else {
            findings.push(
                Finding::warning(format!("umask is permissive ({:04o})", umask_int))
                    .with_fix("Set umask to 027 in /etc/profile and /etc/bashrc")
                    .with_cvss(3.3)
                    .with_cis("5.4.4")
                    .with_stig("RHEL-08-010660")
                    .with_mitre(vec!["T1222.002"])
                    .with_nist(vec!["AC-6(1)"])
                    .with_engine("Citadel")
                    .with_rule("DK-CIT-004"),
            );
        }
    }

    findings
}

/// Service audit — CIS Section 2, DISA STIG service requirements
/// ATT&CK T1543.002 (Create or Modify System Process: Systemd Service)
async fn audit_services() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Risky services with complete framework mapping
    let risky_services: Vec<(&str, &str, &str, &str, &[&str], &[&str])> = vec![
        // (unit, name, risk, CIS_ID, MITRE, NIST)
        ("telnet.socket", "Telnet", "Unencrypted remote access — transmits credentials in cleartext", "2.1.1", &["T1021", "T1040"], &["CM-7", "SC-8"]),
        ("rsh.socket", "RSH", "Unencrypted remote shell — no authentication mechanism", "2.1.2", &["T1021"], &["CM-7"]),
        ("rlogin.socket", "Rlogin", "Unencrypted remote login — inherently insecure", "2.1.2", &["T1021"], &["CM-7"]),
        ("vsftpd.service", "FTP", "Unencrypted file transfer — use SFTP instead", "2.1.5", &["T1048"], &["CM-7", "SC-8"]),
        ("rpcbind.service", "RPCBind", "NFS prerequisite — disable if NFS unused", "2.1.7", &["T1210"], &["CM-7"]),
        ("avahi-daemon.service", "Avahi", "mDNS — information disclosure on local network", "2.1.3", &["T1046"], &["CM-7"]),
        ("cups.service", "CUPS", "Print service — network-accessible attack surface", "2.1.4", &["T1210"], &["CM-7"]),
        ("xinetd.service", "xinetd", "Legacy inetd — unnecessary on modern systems", "2.1.1", &["T1210"], &["CM-7"]),
    ];

    let mut checked = 0usize;

    for (service, name, risk, cis, mitre, nist) in &risky_services {
        let status = tokio::process::Command::new("systemctl")
            .args(["is-active", service])
            .output()
            .await;

        if let Ok(output) = status {
            checked += 1;
            let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if state == "active" {
                findings.push(
                    Finding::warning(format!("{} service is running", name))
                        .with_detail(risk.to_string())
                        .with_fix(format!("systemctl disable --now {}", service))
                        .with_cvss(3.7)
                        .with_cis(*cis)
                        .with_mitre(mitre.to_vec())
                        .with_nist(nist.to_vec())
                        .with_engine("Citadel")
                        .with_rule("DK-CIT-005"),
                );
            }
        }
    }

    if checked == 0 {
        findings.push(Finding::info("Could not check services (systemctl not available)")
            .with_engine("Citadel")
            .with_rule("DK-CIT-005"));
    } else if findings.is_empty() {
        findings.push(Finding::pass("No known risky services running")
            .with_engine("Citadel")
            .with_rule("DK-CIT-005"));
    }

    findings
}

/// Secure Boot & UEFI — CIS 1.4.1, STIG V-230264
/// ATT&CK T1542 (Pre-OS Boot)
/// Atomic Red Team: T1542.003
async fn check_secure_boot() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let sb_path = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
        if std::path::Path::new(sb_path).exists() {
            match std::fs::read(sb_path) {
                Ok(data) => {
                    if data.last() == Some(&1) {
                        findings.push(Finding::pass("Secure Boot is enabled")
                            .with_engine("Citadel")
                            .with_rule("DK-CIT-006")
                            .with_cis("1.4.1")
                            .with_stig("RHEL-08-010030")
                            .with_nist(vec!["SI-7", "SI-7(1)"]));
                    } else {
                        findings.push(
                            Finding::warning("Secure Boot is disabled")
                                .with_detail("Without Secure Boot, bootkits and unsigned bootloaders can execute. Required by DISA STIG V-230264 and CIS 1.4.1.")
                                .with_fix("Enable Secure Boot in UEFI firmware settings")
                                .with_cvss(6.7)
                                .with_cis("1.4.1")
                                .with_stig("RHEL-08-010030")
                                .with_mitre(vec!["T1542.003", "T1542.001"])
                                .with_nist(vec!["SI-7", "SI-7(1)"])
                                .with_engine("Citadel")
                                .with_rule("DK-CIT-006"),
                        );
                    }
                }
                Err(_) => {
                    findings.push(Finding::info("Could not read Secure Boot status")
                        .with_engine("Citadel")
                        .with_rule("DK-CIT-006"));
                }
            }
        } else if std::path::Path::new("/sys/firmware/efi").exists() {
            findings.push(
                Finding::info("UEFI boot detected but Secure Boot status unreadable")
                    .with_engine("Citadel")
                    .with_rule("DK-CIT-006")
                    .with_cis("1.4.1"),
            );
        } else {
            findings.push(
                Finding::warning("Legacy BIOS boot (no Secure Boot support)")
                    .with_detail("Legacy BIOS provides no boot integrity verification. UEFI with Secure Boot recommended.")
                    .with_cis("1.4.1")
                    .with_mitre(vec!["T1542"])
                    .with_nist(vec!["SI-7"])
                    .with_engine("Citadel")
                    .with_rule("DK-CIT-006"),
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(Finding::info("Secure Boot check not yet implemented on this platform")
            .with_engine("Citadel")
            .with_rule("DK-CIT-006"));
    }

    findings
}

/// User account audit — CIS 6.2, STIG V-230340 through V-230360
/// ATT&CK T1078 (Valid Accounts), T1136 (Create Account)
/// Atomic Red Team: T1078, T1136.001
async fn audit_users() -> Vec<Finding> {
    let mut findings = Vec::new();

    // UID 0 users — CIS 6.2.8, STIG V-230378
    // ATT&CK T1078.003 (Valid Accounts: Local Accounts)
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        let root_users: Vec<&str> = passwd.lines()
            .filter(|l| {
                let parts: Vec<&str> = l.split(':').collect();
                parts.get(2) == Some(&"0") && parts.first() != Some(&"root")
            })
            .filter_map(|l| l.split(':').next())
            .collect();

        if root_users.is_empty() {
            findings.push(Finding::pass("No non-root users with UID 0")
                .with_engine("Citadel")
                .with_rule("DK-CIT-007")
                .with_cis("6.2.8")
                .with_stig("RHEL-08-010373")
                .with_nist(vec!["AC-6(1)"]));
        } else {
            for user in &root_users {
                findings.push(
                    Finding::critical(format!("Non-root user with UID 0: {}", user))
                        .with_detail("This user has equivalent privileges to root — violates principle of least privilege and may indicate compromise")
                        .with_fix(format!("Investigate user '{}' — change UID or remove if unauthorized", user))
                        .with_cvss(9.8)
                        .with_cis("6.2.8")
                        .with_stig("RHEL-08-010373")
                        .with_mitre(vec!["T1078.003", "T1136.001"])
                        .with_nist(vec!["AC-6(1)"])
                        .with_engine("Citadel")
                        .with_rule("DK-CIT-007"),
                );
            }
        }

        // Interactive user count
        let interactive_users: Vec<&str> = passwd.lines()
            .filter(|l| {
                let parts: Vec<&str> = l.split(':').collect();
                let shell = parts.get(6).unwrap_or(&"");
                let uid: u32 = parts.get(2).and_then(|u| u.parse().ok()).unwrap_or(0);
                uid >= 1000 && (*shell == "/bin/bash" || *shell == "/bin/zsh" || *shell == "/bin/sh" || *shell == "/usr/bin/zsh" || *shell == "/usr/bin/bash")
            })
            .filter_map(|l| l.split(':').next())
            .collect();

        findings.push(Finding::info(format!("{} interactive user accounts", interactive_users.len()))
            .with_engine("Citadel")
            .with_rule("DK-CIT-008"));

        // Check for users without password in /etc/shadow — CIS 6.2.1
        // ATT&CK T1078.003
        if let Ok(shadow) = std::fs::read_to_string("/etc/shadow") {
            for user in &interactive_users {
                if let Some(line) = shadow.lines().find(|l| l.starts_with(&format!("{}:", user))) {
                    let hash = line.split(':').nth(1).unwrap_or("");
                    if hash.is_empty() {
                        findings.push(
                            Finding::critical(format!("User '{}' has no password set", user))
                                .with_detail("Passwordless accounts can be accessed by anyone who can reach a login prompt")
                                .with_fix(format!("passwd {} OR usermod -L {}", user, user))
                                .with_cvss(9.8)
                                .with_cis("6.2.1")
                                .with_stig("RHEL-08-010100")
                                .with_mitre(vec!["T1078.003"])
                                .with_nist(vec!["IA-5(1)"])
                                .with_engine("Citadel")
                                .with_rule("DK-CIT-009"),
                        );
                    }
                }
            }

            // Root account status
            let root_line = shadow.lines().find(|l| l.starts_with("root:"));
            if let Some(line) = root_line {
                let hash = line.split(':').nth(1).unwrap_or("");
                if hash.starts_with('!') || hash.starts_with('*') {
                    findings.push(Finding::pass("Root account is locked")
                        .with_engine("Citadel")
                        .with_rule("DK-CIT-010")
                        .with_nist(vec!["AC-6(1)"]));
                } else if hash.is_empty() {
                    findings.push(
                        Finding::critical("Root account has no password!")
                            .with_fix("Set a password: passwd root")
                            .with_cvss(9.8)
                            .with_cis("6.2.1")
                            .with_mitre(vec!["T1078.003"])
                            .with_nist(vec!["IA-5(1)"])
                            .with_engine("Citadel")
                            .with_rule("DK-CIT-010"),
                    );
                }
            }
        }
    }

    // Password aging — CIS 5.4.1, STIG V-230365
    // ATT&CK T1078 (Valid Accounts)
    if let Ok(login_defs) = std::fs::read_to_string("/etc/login.defs") {
        let get_def = |key: &str| -> Option<u32> {
            login_defs.lines()
                .filter(|l| !l.trim().starts_with('#'))
                .find(|l| l.trim().starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        };

        if let Some(max_days) = get_def("PASS_MAX_DAYS") {
            if max_days > 365 || max_days == 99999 {
                findings.push(
                    Finding::warning(format!("Password max age is {} days (recommended ≤ 365)", max_days))
                        .with_fix("Set PASS_MAX_DAYS to 365 in /etc/login.defs")
                        .with_cvss(3.7)
                        .with_cis("5.4.1.1")
                        .with_stig("RHEL-08-020200")
                        .with_mitre(vec!["T1078"])
                        .with_nist(vec!["IA-5(1)"])
                        .with_engine("Citadel")
                        .with_rule("DK-CIT-011"),
                );
            }
        }

        if let Some(min_days) = get_def("PASS_MIN_DAYS") {
            if min_days == 0 {
                findings.push(
                    Finding::info("Password minimum age is 0 — users can change passwords immediately")
                        .with_fix("Set PASS_MIN_DAYS to 1 in /etc/login.defs")
                        .with_cis("5.4.1.2")
                        .with_stig("RHEL-08-020190")
                        .with_nist(vec!["IA-5(1)"])
                        .with_engine("Citadel")
                        .with_rule("DK-CIT-012"),
                );
            }
        }
    }

    findings
}

/// Audit subsystem — CIS 4.1, STIG V-230386 through V-230440
/// ATT&CK T1562.002 (Impair Defenses: Disable Windows Event Logging — applies to Linux auditd)
async fn check_audit_subsystem() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check auditd status — CIS 4.1.1, STIG V-230386
    let auditd = tokio::process::Command::new("systemctl")
        .args(["is-active", "auditd"])
        .output()
        .await;

    match auditd {
        Ok(output) => {
            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if status == "active" {
                findings.push(Finding::pass("auditd is running")
                    .with_engine("Citadel")
                    .with_rule("DK-CIT-013")
                    .with_cis("4.1.1.1")
                    .with_stig("RHEL-08-030181")
                    .with_nist(vec!["AU-3", "AU-12"]));

                // Check if audit rules are configured
                if let Ok(output) = tokio::process::Command::new("auditctl")
                    .args(["-l"])
                    .output()
                    .await
                {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let rule_count = stdout.lines().count();
                        if rule_count < 5 {
                            findings.push(
                                Finding::warning(format!("Only {} audit rules configured — insufficient for compliance", rule_count))
                                    .with_detail("CIS and DISA STIG require audit rules for privileged commands, file access, and user/group modifications")
                                    .with_fix("Install CIS audit rules: augenrules --load")
                                    .with_cis("4.1.3")
                                    .with_stig("RHEL-08-030000")
                                    .with_nist(vec!["AU-3", "AU-12"])
                                    .with_engine("Citadel")
                                    .with_rule("DK-CIT-014"),
                            );
                        } else {
                            findings.push(Finding::pass(format!("{} audit rules configured", rule_count))
                                .with_engine("Citadel")
                                .with_rule("DK-CIT-014")
                                .with_cis("4.1.3"));
                        }
                    }
                }
            } else {
                findings.push(
                    Finding::high("auditd is not running")
                        .with_detail("The Linux Audit daemon provides detailed logging of security-relevant events. Required by CIS 4.1.1.1, DISA STIG V-230386, and NIST AU-3.")
                        .with_fix("systemctl enable --now auditd")
                        .with_cvss(5.3)
                        .with_cis("4.1.1.1")
                        .with_stig("RHEL-08-030181")
                        .with_mitre(vec!["T1562.002"])
                        .with_nist(vec!["AU-3", "AU-12", "AU-14"])
                        .with_engine("Citadel")
                        .with_rule("DK-CIT-013"),
                );
            }
        }
        Err(_) => {
            findings.push(Finding::info("Could not check auditd status")
                .with_engine("Citadel")
                .with_rule("DK-CIT-013"));
        }
    }

    findings
}

/// Bootloader security — CIS 1.4.2, STIG V-230266
/// ATT&CK T1542.003 (Pre-OS Boot: Bootloader)
async fn check_bootloader() -> Vec<Finding> {
    let mut findings = Vec::new();

    // GRUB password protection — CIS 1.4.2
    let grub_configs = vec![
        "/boot/grub2/user.cfg",
        "/boot/grub2/grub.cfg",
        "/boot/grub/grub.cfg",
        "/etc/grub.d/40_custom",
    ];

    let mut grub_password = false;
    for config in &grub_configs {
        if let Ok(content) = std::fs::read_to_string(config) {
            if content.contains("password_pbkdf2") || content.contains("GRUB2_PASSWORD=") {
                grub_password = true;
                break;
            }
        }
    }

    if grub_password {
        findings.push(Finding::pass("GRUB bootloader is password-protected")
            .with_engine("Citadel")
            .with_rule("DK-CIT-015")
            .with_cis("1.4.2")
            .with_stig("RHEL-08-010150")
            .with_nist(vec!["AC-3"]));
    } else {
        findings.push(
            Finding::info("GRUB bootloader is not password-protected")
                .with_detail("Without a GRUB password, anyone with physical access can modify boot parameters (init=/bin/bash) to gain root access")
                .with_fix("grub2-setpassword (RHEL/Fedora) or grub-mkpasswd-pbkdf2 (Debian/Ubuntu)")
                .with_cis("1.4.2")
                .with_stig("RHEL-08-010150")
                .with_mitre(vec!["T1542.003"])
                .with_nist(vec!["AC-3", "PE-3"])
                .with_engine("Citadel")
                .with_rule("DK-CIT-015"),
        );
    }

    // Check GRUB config permissions — CIS 1.4.3
    for config in &["/boot/grub2/grub.cfg", "/boot/grub/grub.cfg"] {
        if let Ok(meta) = std::fs::metadata(config) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o777;
                if mode > 0o600 {
                    findings.push(
                        Finding::warning(format!("GRUB config permissions too open: {:o}", mode))
                            .with_fix(format!("chmod 600 {}", config))
                            .with_cvss(3.3)
                            .with_cis("1.4.3")
                            .with_nist(vec!["AC-6(1)"])
                            .with_engine("Citadel")
                            .with_rule("DK-CIT-016"),
                    );
                }
            }
        }
    }

    findings
}
