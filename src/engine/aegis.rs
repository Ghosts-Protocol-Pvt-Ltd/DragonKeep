//! Aegis Engine — Supply Chain & Integrity Auditor
//!
//! Verifies binary provenance, detects package manager misconfigurations,
//! finds stale/EOL packages, audits container escape vectors,
//! checks systemd unit integrity, and scans for unsigned kernel modules.
//!
//! Standards: MITRE ATT&CK (T1195.002, T1554, T1547.006, T1543.002),
//! NIST SP 800-53 Rev 5 (SI-7, SA-12, SI-2, CM-7), DISA STIG RHEL-08

use crate::config::Config;
use crate::engine::Finding;

use std::path::Path;
use std::process::Command;

/// Critical system binaries that should be verified against package manager
const CRITICAL_BINARIES: &[(&str, &str)] = &[
    ("/usr/sbin/sshd", "openssh-server"),
    ("/usr/bin/sudo", "sudo"),
    ("/usr/bin/su", "util-linux"),
    ("/usr/bin/login", "util-linux"),
    ("/usr/bin/passwd", "passwd"),
    ("/usr/sbin/cron", "cron"),
    ("/usr/sbin/crond", "cronie"),
    ("/usr/bin/gpg", "gnupg2"),
    ("/usr/bin/curl", "curl"),
    ("/usr/bin/wget", "wget"),
    ("/usr/sbin/iptables", "iptables"),
    ("/usr/sbin/nftables", "nftables"),
    ("/lib/systemd/systemd", "systemd"),
];

/// Known EOL distributions
const EOL_DISTROS: &[(&str, &str)] = &[
    ("CentOS Linux 7", "2024-06-30"),
    ("CentOS Linux 8", "2021-12-31"),
    ("Ubuntu 18.04", "2023-05-31"),
    ("Ubuntu 16.04", "2021-04-30"),
    ("Debian 10", "2024-06-30"),
    ("Fedora 37", "2023-12-15"),
    ("Fedora 38", "2024-05-14"),
];

pub async fn scan(config: &Config) -> anyhow::Result<Vec<Finding>> {
    if !config.aegis.enabled {
        return Ok(vec![Finding::info("Aegis engine disabled").with_engine("Aegis")]);
    }

    let mut findings = Vec::new();

    audit_package_manager(&mut findings).await;
    verify_binary_provenance(&mut findings).await;
    check_system_currency(&mut findings).await;
    audit_container_security(&mut findings).await;
    audit_systemd_units(&mut findings).await;
    audit_kernel_modules(&mut findings).await;
    audit_language_packages(&mut findings).await;
    audit_repo_keys(&mut findings).await;

    if findings.is_empty() {
        findings.push(
            Finding::pass("Supply chain integrity verified")
                .with_engine("Aegis")
                .with_rule("DK-AEG-000"),
        );
    }

    Ok(findings)
}

/// Check package manager configurations for security
/// ATT&CK T1195.002 (Compromise Software Supply Chain)
/// DISA STIG V-230264, NIST SI-7
async fn audit_package_manager(findings: &mut Vec<Finding>) {
    // DNF/YUM (RHEL/Fedora)
    if Path::new("/etc/dnf/dnf.conf").exists() {
        if let Ok(content) = std::fs::read_to_string("/etc/dnf/dnf.conf") {
            if content.contains("gpgcheck=0") {
                findings.push(
                    Finding::critical("DNF GPG check disabled — packages not verified")
                        .with_detail("gpgcheck=0 in dnf.conf allows installation of tampered or unsigned packages")
                        .with_fix("Set gpgcheck=1 in /etc/dnf/dnf.conf")
                        .with_cvss(9.1)
                        .with_cis("1.2.3")
                        .with_mitre(vec!["T1195.002"])
                        .with_stig("V-230264")
                        .with_nist(vec!["SI-7", "CM-11(2)"])
                        .with_engine("Aegis")
                        .with_rule("DK-AEG-001"),
                );
            }
            if content.contains("repo_gpgcheck=0") || !content.contains("repo_gpgcheck=1") {
                findings.push(
                    Finding::warning("DNF repo GPG check not enforced")
                        .with_detail("Repository metadata is not cryptographically verified")
                        .with_fix("Add repo_gpgcheck=1 to /etc/dnf/dnf.conf")
                        .with_cvss(6.8)
                        .with_cis("1.2.4")
                        .with_mitre(vec!["T1195.002"])
                        .with_stig("V-230264")
                        .with_nist(vec!["SI-7"])
                        .with_engine("Aegis")
                        .with_rule("DK-AEG-002"),
                );
            }
        }
    }

    // APT (Debian/Ubuntu)
    if Path::new("/etc/apt").is_dir() {
        let apt_configs = glob::glob("/etc/apt/apt.conf.d/*").ok();
        if let Some(paths) = apt_configs {
            for path in paths.flatten() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if content.to_lowercase().contains("allow-unauthenticated")
                        || content.to_lowercase().contains("allow-insecure-repositories")
                    {
                        findings.push(
                            Finding::critical(format!("APT unauthenticated repos allowed in {}", path.display()))
                                .with_detail("Unsigned package repositories enabled — vulnerable to MITM supply chain attacks")
                                .with_fix(format!("Remove allow-unauthenticated from {}", path.display()))
                                .with_cvss(9.1)
                                .with_cis("1.2.1")
                                .with_mitre(vec!["T1195.002", "T1557"])
                                .with_nist(vec!["SI-7", "SA-12"])
                                .with_engine("Aegis")
                                .with_rule("DK-AEG-003"),
                        );
                    }
                }
            }
        }

        if let Ok(content) = std::fs::read_to_string("/etc/apt/sources.list") {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with('#') && trimmed.starts_with("deb http://") {
                    findings.push(
                        Finding::warning("APT repository using HTTP instead of HTTPS")
                            .with_detail(format!("Unencrypted repo: {}", trimmed))
                            .with_fix("Change http:// to https:// in /etc/apt/sources.list")
                            .with_cvss(5.9)
                            .with_mitre(vec!["T1557", "T1195.002"])
                            .with_nist(vec!["SC-8", "SC-23"])
                            .with_engine("Aegis")
                            .with_rule("DK-AEG-004"),
                    );
                    break;
                }
            }
        }
    }

    // Pacman (Arch)
    if let Ok(content) = std::fs::read_to_string("/etc/pacman.conf") {
        if content.contains("SigLevel = Never") {
            findings.push(
                Finding::critical("Pacman signature verification disabled")
                    .with_detail("SigLevel = Never allows installation of unsigned packages")
                    .with_fix("Set SigLevel = Required DatabaseOptional in /etc/pacman.conf")
                    .with_cvss(9.1)
                    .with_mitre(vec!["T1195.002"])
                    .with_nist(vec!["SI-7"])
                    .with_engine("Aegis")
                    .with_rule("DK-AEG-005"),
            );
        }
    }
}

/// Verify critical binaries haven't been tampered with
/// ATT&CK T1554 (Compromise Client Software Binary), DISA STIG V-230221
async fn verify_binary_provenance(findings: &mut Vec<Finding>) {
    for (bin_path, _pkg_name) in CRITICAL_BINARIES {
        if !Path::new(bin_path).exists() { continue; }

        // Try RPM verification
        if let Ok(output) = Command::new("rpm").args(["-Vf", bin_path]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    let changes = stdout.trim();
                    if changes.contains('5') || changes.contains('S') {
                        findings.push(
                            Finding::critical(format!("Binary tampering detected: {}", bin_path))
                                .with_detail(format!("RPM verification failed — checksum/size mismatch: {}", changes))
                                .with_fix(format!("Reinstall the package or investigate the binary: rpm -qf {} && rpm --restore $(rpm -qf {})", bin_path, bin_path))
                                .with_cvss(9.8)
                                .with_mitre(vec!["T1554", "T1036.005"])
                                .with_stig("V-230221")
                                .with_nist(vec!["SI-7", "SI-7(1)"])
                                .with_engine("Aegis")
                                .with_rule("DK-AEG-006"),
                        );
                        continue;
                    }
                }
            }
        }

        // Try dpkg verification
        if let Ok(output) = Command::new("dpkg").args(["--verify", "--verify-format", "rpm"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains(bin_path) && (line.contains('5') || line.contains('S')) {
                        findings.push(
                            Finding::critical(format!("Binary tampering detected: {}", bin_path))
                                .with_detail(format!("dpkg verification failed: {}", line))
                                .with_fix(format!("Reinstall: apt-get install --reinstall $(dpkg -S {} | cut -d: -f1)", bin_path))
                                .with_cvss(9.8)
                                .with_mitre(vec!["T1554", "T1036.005"])
                                .with_nist(vec!["SI-7", "SI-7(1)"])
                                .with_engine("Aegis")
                                .with_rule("DK-AEG-007"),
                        );
                    }
                }
            }
        }
    }
}

/// Check for EOL distro, stale kernel, and system age
/// ATT&CK T1190, T1210 — NIST SI-2
async fn check_system_currency(findings: &mut Vec<Finding>) {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        let pretty_name = content.lines()
            .find(|l| l.starts_with("PRETTY_NAME="))
            .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            .unwrap_or_default();

        for (distro, _eol_date) in EOL_DISTROS {
            if pretty_name.contains(distro) {
                findings.push(
                    Finding::critical(format!("End-of-life distribution: {}", pretty_name))
                        .with_detail("This OS version no longer receives security updates — all unpatched CVEs affect this system")
                        .with_fix("Upgrade to a supported release immediately")
                        .with_cvss(9.8)
                        .with_cis("1.8")
                        .with_mitre(vec!["T1190", "T1210"])
                        .with_nist(vec!["SI-2", "SA-22"])
                        .with_engine("Aegis")
                        .with_rule("DK-AEG-008"),
                );
            }
        }
    }

    if let Ok(output) = Command::new("uname").arg("-r").output() {
        let kernel = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
            if let Some(uptime_secs) = uptime_str.split_whitespace().next() {
                if let Ok(secs) = uptime_secs.parse::<f64>() {
                    let days = (secs / 86400.0) as u64;
                    if days > 90 {
                        findings.push(
                            Finding::warning(format!("System has not been rebooted in {} days (kernel: {})", days, kernel))
                                .with_detail("Long-running systems may miss kernel security patches that require a reboot")
                                .with_fix("Schedule a maintenance window to apply kernel updates and reboot")
                                .with_cvss(5.3)
                                .with_cis("1.9")
                                .with_nist(vec!["SI-2", "CM-3"])
                                .with_engine("Aegis")
                                .with_rule("DK-AEG-009"),
                        );
                    }
                }
            }
        }
    }

    // Check for pending security updates
    if Path::new("/usr/bin/dnf").exists() {
        if let Ok(output) = Command::new("dnf")
            .args(["updateinfo", "list", "--security", "--available", "-q"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let count = stdout.lines().count();
                if count > 0 {
                    findings.push(
                        Finding::high(format!("{} pending security updates available", count))
                            .with_detail("Unpatched security vulnerabilities exist for installed packages")
                            .with_fix("Run: dnf update --security")
                            .with_cvss(7.5)
                            .with_cis("1.9")
                            .with_mitre(vec!["T1190", "T1210"])
                            .with_stig("V-230270")
                            .with_nist(vec!["SI-2", "SI-2(2)"])
                            .with_engine("Aegis")
                            .with_rule("DK-AEG-010"),
                    );
                }
            }
        }
    }
}

/// Check for container escape vectors
/// ATT&CK T1611 (Escape to Host), NIST SC-39
async fn audit_container_security(findings: &mut Vec<Finding>) {
    let in_container = Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|c| c.contains("docker") || c.contains("lxc") || c.contains("kubepods"))
            .unwrap_or(false);

    if in_container {
        if let Ok(status) = std::fs::read_to_string("/proc/1/status") {
            if status.lines().any(|l| l.starts_with("CapEff:") && l.contains("0000003fffffffff")) {
                findings.push(
                    Finding::critical("Container running in privileged mode")
                        .with_detail("Full host capabilities available — trivial container escape via mount, nsenter, or cgroup release_agent")
                        .with_fix("Remove --privileged flag and use specific --cap-add flags instead")
                        .with_cvss(9.9)
                        .with_mitre(vec!["T1611", "T1610"])
                        .with_nist(vec!["SC-39", "AC-6"])
                        .with_engine("Aegis")
                        .with_rule("DK-AEG-011"),
                );
            }
        }

        if Path::new("/var/run/docker.sock").exists() {
            findings.push(
                Finding::critical("Docker socket mounted inside container")
                    .with_detail("Container can control the Docker daemon — full host compromise possible")
                    .with_fix("Remove -v /var/run/docker.sock mount and use Docker-in-Docker or rootless Docker instead")
                    .with_cvss(9.9)
                    .with_mitre(vec!["T1611"])
                    .with_nist(vec!["SC-39", "AC-6"])
                    .with_engine("Aegis")
                    .with_rule("DK-AEG-012"),
            );
        }

        if let Ok(ns_pid) = std::fs::read_link("/proc/1/ns/pid") {
            if let Ok(self_ns) = std::fs::read_link("/proc/self/ns/pid") {
                if ns_pid == self_ns {
                    findings.push(
                        Finding::high("Container shares host PID namespace")
                            .with_detail("--pid=host enables visibility of all host processes and ptrace-based attacks")
                            .with_fix("Remove --pid=host from container run configuration")
                            .with_cvss(7.8)
                            .with_mitre(vec!["T1611", "T1057"])
                            .with_nist(vec!["SC-39", "SC-4"])
                            .with_engine("Aegis")
                            .with_rule("DK-AEG-013"),
                    );
                }
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/etc/containers/registries.conf") {
        if content.contains("insecure = true") || content.contains("[registries.insecure]") {
            findings.push(
                Finding::warning("Insecure container registries configured")
                    .with_detail("HTTP container registries allow MITM attacks on image pulls")
                    .with_fix("Use HTTPS registries and remove insecure registry entries")
                    .with_cvss(6.8)
                    .with_mitre(vec!["T1195.002", "T1557"])
                    .with_nist(vec!["SC-8", "SI-7"])
                    .with_engine("Aegis")
                    .with_rule("DK-AEG-014"),
            );
        }
    }
}

/// Check systemd unit files for tampering
/// ATT&CK T1543.002 (Create or Modify System Process: Systemd Service)
/// DISA STIG V-230312
async fn audit_systemd_units(findings: &mut Vec<Finding>) {
    let suspicious_dirs = vec![
        "/etc/systemd/system",
        "/run/systemd/system",
    ];

    for dir in &suspicious_dirs {
        if !Path::new(dir).is_dir() { continue; }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() { continue; }

            let name = path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            if !name.ends_with(".service") { continue; }

            if let Ok(content) = std::fs::read_to_string(&path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("ExecStart=") || trimmed.starts_with("ExecStartPre=") || trimmed.starts_with("ExecStartPost=") {
                        let exec = trimmed.split('=').nth(1).unwrap_or("");
                        if exec.starts_with("/tmp/") || exec.starts_with("/var/tmp/") || exec.contains("/dev/shm/") {
                            findings.push(
                                Finding::critical(format!("Suspicious systemd service: {} executes from temp directory", name))
                                    .with_detail(format!("ExecStart path: {}", exec))
                                    .with_fix(format!("Investigate and remove if unauthorized: systemctl disable {} && rm {}", name, path.display()))
                                    .with_cvss(8.8)
                                    .with_mitre(vec!["T1543.002", "T1036.005"])
                                    .with_stig("V-230312")
                                    .with_nist(vec!["CM-7", "SI-7"])
                                    .with_engine("Aegis")
                                    .with_rule("DK-AEG-015"),
                            );
                        }

                        if exec.contains("bash -c") || exec.contains("sh -c") || exec.contains("curl ") || exec.contains("wget ") {
                            findings.push(
                                Finding::warning(format!("Systemd service '{}' uses shell commands in ExecStart", name))
                                    .with_detail(format!("Command: {}", exec))
                                    .with_fix("Use direct binary paths instead of shell commands in systemd units")
                                    .with_cvss(5.3)
                                    .with_mitre(vec!["T1543.002", "T1059.004"])
                                    .with_nist(vec!["CM-7"])
                                    .with_engine("Aegis")
                                    .with_rule("DK-AEG-016"),
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Check for unsigned or out-of-tree kernel modules
/// ATT&CK T1547.006 (Kernel Modules and Extensions), DISA STIG V-230268
async fn audit_kernel_modules(findings: &mut Vec<Finding>) {
    if let Ok(output) = Command::new("lsmod").output() {
        if !output.status.success() { return; }
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let module_name = match line.split_whitespace().next() {
                Some(n) => n,
                None => continue,
            };

            if let Ok(modinfo) = Command::new("modinfo").arg(module_name).output() {
                let info = String::from_utf8_lossy(&modinfo.stdout);

                let has_sig = info.lines().any(|l| l.starts_with("sig_id:") || l.starts_with("signer:"));
                let is_intree = info.lines().any(|l| l.starts_with("intree:") && l.contains("Y"));

                if !has_sig && !is_intree {
                    findings.push(
                        Finding::warning(format!("Out-of-tree unsigned kernel module: {}", module_name))
                            .with_detail("Unsigned kernel modules can be used for rootkits or system compromise")
                            .with_fix(format!("Investigate module origin: modinfo {} && consider removing with: modprobe -r {}", module_name, module_name))
                            .with_cvss(6.7)
                            .with_mitre(vec!["T1547.006", "T1014"])
                            .with_stig("V-230268")
                            .with_nist(vec!["SI-7", "CM-7"])
                            .with_engine("Aegis")
                            .with_rule("DK-AEG-017"),
                    );
                }
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/modules_disabled") {
        if content.trim() == "0" {
            findings.push(
                Finding::info("Kernel module loading is unrestricted")
                    .with_detail("New kernel modules can be loaded at runtime (modules_disabled=0)")
                    .with_fix("After system is fully booted: echo 1 > /proc/sys/kernel/modules_disabled (irreversible until reboot)")
                    .with_cis("1.4.2")
                    .with_nist(vec!["CM-6", "CM-7"])
                    .with_engine("Aegis")
                    .with_rule("DK-AEG-018"),
            );
        }
    }
}

/// Audit globally installed language packages (pip, npm)
/// ATT&CK T1195.002, NIST SA-12
async fn audit_language_packages(findings: &mut Vec<Finding>) {
    if let Ok(output) = Command::new("pip3")
        .args(["list", "--format=json", "--path=/usr/lib/python3/dist-packages"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(packages) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
                if packages.len() > 50 {
                    findings.push(
                        Finding::info(format!("{} system-level pip packages installed", packages.len()))
                            .with_detail("Large number of system pip packages increases supply chain attack surface")
                            .with_fix("Use virtual environments (python -m venv) instead of system-wide pip install")
                            .with_cvss(3.7)
                            .with_mitre(vec!["T1195.002"])
                            .with_nist(vec!["SA-12", "CM-7"])
                            .with_engine("Aegis")
                            .with_rule("DK-AEG-019"),
                    );
                }
            }
        }
    }

    if let Ok(output) = Command::new("npm").args(["list", "-g", "--json", "--depth=0"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(deps) = data.get("dependencies").and_then(|d| d.as_object()) {
                    if deps.len() > 20 {
                        findings.push(
                            Finding::info(format!("{} global npm packages installed", deps.len()))
                                .with_detail("Global npm packages run with user privileges and auto-execute post-install scripts")
                                .with_fix("Use npx for one-off tools and local installs for project dependencies")
                                .with_cvss(3.7)
                                .with_mitre(vec!["T1195.002"])
                                .with_nist(vec!["SA-12", "CM-7"])
                                .with_engine("Aegis")
                                .with_rule("DK-AEG-020"),
                        );
                    }
                }
            }
        }
    }
}

/// Check for expired or soon-to-expire repo signing keys
async fn audit_repo_keys(findings: &mut Vec<Finding>) {
    if let Ok(output) = Command::new("rpm").args(["-qa", "gpg-pubkey*"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let key_count = stdout.lines().count();
            if key_count == 0 {
                findings.push(
                    Finding::warning("No GPG signing keys installed for RPM")
                        .with_detail("Package signature verification cannot work without trusted keys")
                        .with_fix("Import distribution GPG keys: rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-*")
                        .with_cvss(6.5)
                        .with_mitre(vec!["T1195.002"])
                        .with_nist(vec!["SI-7"])
                        .with_engine("Aegis")
                        .with_rule("DK-AEG-021"),
                );
            }
        }
    }

    if Path::new("/usr/bin/apt-key").exists() {
        if let Ok(output) = Command::new("apt-key").args(["list", "--with-colons"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains(":e:") {
                    findings.push(
                        Finding::warning("Expired APT signing keys detected")
                            .with_detail("Expired keys may prevent security updates from being verified")
                            .with_fix("Update expired keys: apt-key adv --refresh-keys --keyserver keyserver.ubuntu.com")
                            .with_cvss(5.3)
                            .with_mitre(vec!["T1195.002"])
                            .with_nist(vec!["SI-7"])
                            .with_engine("Aegis")
                            .with_rule("DK-AEG-022"),
                    );
                }
            }
        }
    }
}
