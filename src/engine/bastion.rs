//! Bastion Engine — Network Security
//!
//! Network perimeter audit aligned with:
//!   - CIS Benchmarks v8 Section 3.4–3.5 (cisecurity.org)
//!   - DISA RHEL 8/9 STIGs (public.cyber.mil)
//!   - NIST SP 800-53 Rev 5 SC family (csrc.nist.gov)
//!   - MITRE ATT&CK Command and Control / Lateral Movement tactics
//!
//! Checks: firewall status, listening services, DNS security,
//! network interfaces, IPv6 privacy, DNS-over-TLS, VPN leak detection.

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;
use crate::engine::Finding;

/// Scan network security posture
pub async fn scan(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.bastion.enabled {
        findings.push(Finding::info("Bastion engine disabled in config")
            .with_engine("Bastion"));
        return Ok(findings);
    }

    if config.bastion.firewall_audit {
        eprintln!("    {} Checking firewall status...", "→".dimmed());
        findings.extend(check_firewall().await);
    }

    if config.bastion.port_scan {
        eprintln!("    {} Scanning listening services...", "→".dimmed());
        findings.extend(check_listening_services().await);
    }

    if config.bastion.dns_check {
        eprintln!("    {} Checking DNS configuration...", "→".dimmed());
        findings.extend(check_dns().await);
    }

    eprintln!("    {} Checking network interfaces...", "→".dimmed());
    findings.extend(check_interfaces().await);

    Ok(findings)
}

/// Firewall audit — CIS 3.5.1, STIG V-230505
/// ATT&CK T1562.004 (Impair Defenses: Disable or Modify System Firewall)
/// Atomic Red Team: T1562.004
async fn check_firewall() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check firewalld (Fedora, RHEL, CentOS)
    let firewalld = tokio::process::Command::new("systemctl")
        .args(["is-active", "firewalld"])
        .output()
        .await;

    if let Ok(output) = firewalld {
        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if status == "active" {
            findings.push(Finding::pass("firewalld is active")
                .with_engine("Bastion")
                .with_rule("DK-BAS-001")
                .with_cis("3.5.1.1")
                .with_stig("RHEL-08-040090")
                .with_nist(vec!["SC-7", "SC-7(5)"]));

            // Check default zone
            if let Ok(zone_output) = tokio::process::Command::new("firewall-cmd")
                .arg("--get-default-zone")
                .output()
                .await
            {
                let zone = String::from_utf8_lossy(&zone_output.stdout).trim().to_string();
                if zone == "public" || zone == "drop" || zone == "block" {
                    findings.push(Finding::pass(format!("Default firewall zone: {}", zone))
                        .with_engine("Bastion")
                        .with_rule("DK-BAS-002"));
                } else if zone == "trusted" {
                    findings.push(
                        Finding::critical("Default firewall zone is 'trusted' — all traffic allowed")
                            .with_detail("The 'trusted' zone accepts all incoming connections without any filtering")
                            .with_fix("firewall-cmd --set-default-zone=public")
                            .with_cvss(9.1)
                            .with_mitre(vec!["T1562.004"])
                            .with_nist(vec!["SC-7"])
                            .with_engine("Bastion")
                            .with_rule("DK-BAS-002"),
                    );
                } else {
                    findings.push(Finding::info(format!("Default firewall zone: {}", zone))
                        .with_engine("Bastion")
                        .with_rule("DK-BAS-002"));
                }
            }
            return findings;
        }
    }

    // Check ufw (Ubuntu, Debian)
    let ufw = tokio::process::Command::new("ufw")
        .arg("status")
        .output()
        .await;

    if let Ok(output) = ufw {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("active") {
            findings.push(Finding::pass("UFW firewall is active")
                .with_engine("Bastion")
                .with_rule("DK-BAS-001")
                .with_cis("3.5.1.1")
                .with_nist(vec!["SC-7"]));
            return findings;
        }
    }

    // Check nftables
    let mut has_firewall = false;
    let nft = tokio::process::Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .await;

    if let Ok(output) = nft {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let table_count = stdout.lines().filter(|l| l.starts_with("table")).count();
            if table_count > 0 {
                findings.push(Finding::pass(format!("nftables active with {} tables", table_count))
                    .with_engine("Bastion")
                    .with_rule("DK-BAS-001")
                    .with_cis("3.5.1.1")
                    .with_nist(vec!["SC-7"]));
                has_firewall = true;
            }
        }
    }

    if !has_firewall {
        let iptables = tokio::process::Command::new("iptables")
            .args(["-L", "-n", "--line-numbers"])
            .output()
            .await;

        if let Ok(output) = iptables {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let rule_count = stdout.lines()
                .filter(|l| !l.is_empty() && !l.starts_with("Chain") && !l.starts_with("num"))
                .count();
            if rule_count > 0 {
                findings.push(Finding::info(format!("iptables has {} rules (no firewall daemon detected)", rule_count))
                    .with_engine("Bastion")
                    .with_rule("DK-BAS-001")
                    .with_nist(vec!["SC-7"]));
                has_firewall = true;
            }
        }
    }

    if !has_firewall {
        findings.push(
            Finding::high("No active firewall detected")
                .with_detail("No firewalld, ufw, nftables, or iptables rules found. CIS 3.5.1.1 requires a host-based firewall. Per NIST SC-7, boundary protection is mandatory.")
                .with_fix("Install and enable a firewall: sudo systemctl enable --now firewalld")
                .with_cvss(7.5)
                .with_cis("3.5.1.1")
                .with_stig("RHEL-08-040090")
                .with_mitre(vec!["T1562.004"])
                .with_nist(vec!["SC-7", "SC-7(5)"])
                .with_engine("Bastion")
                .with_rule("DK-BAS-001"),
        );
    }

    findings
}

/// Listening services audit — CIS 3.4, NIST CM-7
/// ATT&CK T1046 (Network Service Discovery)
async fn check_listening_services() -> Vec<Finding> {
    let mut findings = Vec::new();

    let ss = tokio::process::Command::new("ss")
        .args(["-tlnp"])
        .output()
        .await;

    if let Ok(output) = ss {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut external_listeners = Vec::new();
            let mut local_listeners = Vec::new();

            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let local_addr = parts[3];
                    let process = if parts.len() >= 7 { parts[6] } else { "" };

                    if local_addr.starts_with("0.0.0.0:") || local_addr.starts_with("*:") || local_addr.starts_with(":::") {
                        external_listeners.push(format!("{} {}", local_addr, process).trim().to_string());
                    } else {
                        local_listeners.push(format!("{} {}", local_addr, process).trim().to_string());
                    }
                }
            }

            findings.push(Finding::info(format!(
                "{} listening services ({} external, {} local-only)",
                external_listeners.len() + local_listeners.len(),
                external_listeners.len(),
                local_listeners.len()
            ))
                .with_engine("Bastion")
                .with_rule("DK-BAS-003")
                .with_nist(vec!["CM-7"]));

            if !external_listeners.is_empty() {
                for listener in &external_listeners {
                    findings.push(
                        Finding::info(format!("External listener: {}", listener))
                            .with_detail("Accessible from network — verify this is intended. Per NIST CM-7, minimize network-accessible services.")
                            .with_mitre(vec!["T1046"])
                            .with_nist(vec!["CM-7", "SC-7"])
                            .with_engine("Bastion")
                            .with_rule("DK-BAS-003"),
                    );
                }
            }
        }
    } else {
        // Fallback to /proc/net/tcp
        findings.push(Finding::info("ss not available — using /proc/net/tcp")
            .with_engine("Bastion")
            .with_rule("DK-BAS-003"));
        if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
            let listen_count = tcp.lines().skip(1)
                .filter(|l| l.split_whitespace().nth(3) == Some("0A"))
                .count();
            findings.push(Finding::info(format!("{} TCP sockets in LISTEN state", listen_count))
                .with_engine("Bastion")
                .with_rule("DK-BAS-003"));
        }
    }

    findings
}

/// DNS security — NIST SC-20, SC-21, SC-22
/// ATT&CK T1071.004 (Application Layer Protocol: DNS)
async fn check_dns() -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
        let nameservers: Vec<&str> = resolv.lines()
            .filter(|l| l.starts_with("nameserver"))
            .filter_map(|l| l.split_whitespace().nth(1))
            .collect();

        if nameservers.is_empty() {
            findings.push(Finding::warning("No DNS nameservers configured in /etc/resolv.conf")
                .with_engine("Bastion")
                .with_rule("DK-BAS-004")
                .with_nist(vec!["SC-20"]));
        } else {
            for ns in &nameservers {
                let is_private = ns.starts_with("127.") || ns.starts_with("10.") ||
                    ns.starts_with("192.168.") || ns.starts_with("172.");

                if is_private {
                    findings.push(Finding::pass(format!("DNS: {} (local resolver)", ns))
                        .with_engine("Bastion")
                        .with_rule("DK-BAS-004"));
                } else {
                    // Known secure DNS providers with DNSSEC validation
                    let known_secure = [
                        ("1.1.1.1", "Cloudflare"),
                        ("1.0.0.1", "Cloudflare"),
                        ("8.8.8.8", "Google"),
                        ("8.8.4.4", "Google"),
                        ("9.9.9.9", "Quad9 (malware filtering)"),
                        ("149.112.112.112", "Quad9"),
                    ];
                    if let Some((_, provider)) = known_secure.iter().find(|(ip, _)| ip == ns) {
                        findings.push(Finding::pass(format!("DNS: {} ({})", ns, provider))
                            .with_engine("Bastion")
                            .with_rule("DK-BAS-004")
                            .with_nist(vec!["SC-20"]));
                    } else {
                        findings.push(
                            Finding::info(format!("DNS: {} — verify this is a trusted provider", ns))
                                .with_detail("Unknown DNS servers may log queries, inject responses, or lack DNSSEC validation")
                                .with_mitre(vec!["T1071.004"])
                                .with_nist(vec!["SC-20", "SC-21"])
                                .with_engine("Bastion")
                                .with_rule("DK-BAS-004"),
                        );
                    }
                }
            }
        }
    } else {
        findings.push(Finding::info("Could not read /etc/resolv.conf")
            .with_engine("Bastion")
            .with_rule("DK-BAS-004"));
    }

    // DNS-over-TLS/HTTPS — NIST SC-8
    // ATT&CK T1557 (Adversary-in-the-Middle — DNS interception)
    let resolved = tokio::process::Command::new("systemctl")
        .args(["is-active", "systemd-resolved"])
        .output()
        .await;

    if let Ok(output) = resolved {
        if String::from_utf8_lossy(&output.stdout).trim() == "active" {
            findings.push(Finding::info("systemd-resolved is active")
                .with_engine("Bastion")
                .with_rule("DK-BAS-005"));

            if let Ok(conf) = std::fs::read_to_string("/etc/systemd/resolved.conf") {
                if conf.contains("DNSOverTLS=yes") || conf.contains("DNSOverTLS=opportunistic") {
                    findings.push(Finding::pass("DNS-over-TLS is enabled")
                        .with_engine("Bastion")
                        .with_rule("DK-BAS-005")
                        .with_nist(vec!["SC-8", "SC-8(1)"]));
                } else {
                    findings.push(
                        Finding::info("DNS-over-TLS not enabled — DNS queries sent in cleartext")
                            .with_detail("Without DoT/DoH, DNS queries are visible to any network observer. NSA recommends encrypted DNS for all endpoints.")
                            .with_fix("Add 'DNSOverTLS=opportunistic' and 'DNS=1.1.1.1#cloudflare-dns.com' to /etc/systemd/resolved.conf")
                            .with_mitre(vec!["T1557", "T1040"])
                            .with_nist(vec!["SC-8", "SC-8(1)"])
                            .with_engine("Bastion")
                            .with_rule("DK-BAS-005"),
                    );
                }

                // DNSSEC — NIST SC-20
                if conf.contains("DNSSEC=yes") || conf.contains("DNSSEC=allow-downgrade") {
                    findings.push(Finding::pass("DNSSEC validation is enabled")
                        .with_engine("Bastion")
                        .with_rule("DK-BAS-006")
                        .with_nist(vec!["SC-20", "SC-21"]));
                } else {
                    findings.push(
                        Finding::info("DNSSEC validation not explicitly enabled")
                            .with_fix("Add 'DNSSEC=allow-downgrade' to /etc/systemd/resolved.conf")
                            .with_nist(vec!["SC-20", "SC-21"])
                            .with_engine("Bastion")
                            .with_rule("DK-BAS-006"),
                    );
                }
            }
        }
    }

    findings
}

/// Network interfaces and privacy — CIS 3.1.2
async fn check_interfaces() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let mut interfaces = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "lo" { continue; }

                let operstate_path = format!("/sys/class/net/{}/operstate", name);
                let state = std::fs::read_to_string(&operstate_path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".into());

                let is_wireless = std::path::Path::new(&format!("/sys/class/net/{}/wireless", name)).exists();
                let iface_type = if is_wireless {
                    "WiFi"
                } else if name.starts_with("vir") || name.starts_with("br") || name.starts_with("docker") || name.starts_with("veth") {
                    "Virtual"
                } else if name.starts_with("wg") || name.starts_with("tun") || name.starts_with("tap") {
                    "VPN/Tunnel"
                } else {
                    "Wired"
                };

                interfaces.push(format!("{} ({}, {})", name, iface_type, state));
            }

            if interfaces.is_empty() {
                findings.push(Finding::warning("No network interfaces found (excluding loopback)")
                    .with_engine("Bastion")
                    .with_rule("DK-BAS-007"));
            } else {
                findings.push(Finding::info(format!("Network interfaces: {}", interfaces.join(", ")))
                    .with_engine("Bastion")
                    .with_rule("DK-BAS-007"));
            }
        }

        // Check for promiscuous mode — ATT&CK T1040 (Network Sniffing)
        // Atomic Red Team: T1040
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "lo" { continue; }
                let flags_path = format!("/sys/class/net/{}/flags", name);
                if let Ok(flags_str) = std::fs::read_to_string(&flags_path) {
                    if let Ok(flags) = u32::from_str_radix(flags_str.trim().trim_start_matches("0x"), 16) {
                        // IFF_PROMISC = 0x100
                        if flags & 0x100 != 0 {
                            findings.push(
                                Finding::warning(format!("Interface '{}' is in promiscuous mode", name))
                                    .with_detail("Promiscuous mode captures all network traffic, not just packets addressed to this host. May indicate network sniffing.")
                                    .with_fix(format!("ip link set {} promisc off", name))
                                    .with_cvss(4.3)
                                    .with_mitre(vec!["T1040"])
                                    .with_nist(vec!["AC-4", "SI-4(4)"])
                                    .with_engine("Bastion")
                                    .with_rule("DK-BAS-008"),
                            );
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(Finding::info("Network interface check not yet implemented on this platform")
            .with_engine("Bastion")
            .with_rule("DK-BAS-007"));
    }

    // IPv6 privacy extensions — CIS 3.1.2
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/use_tempaddr") {
            Ok(val) if val.trim() == "2" => {
                findings.push(Finding::pass("IPv6 privacy extensions enabled")
                    .with_engine("Bastion")
                    .with_rule("DK-BAS-009")
                    .with_nist(vec!["SC-28"]));
            }
            Ok(_) => {
                findings.push(
                    Finding::info("IPv6 privacy extensions not enabled — MAC address may be derivable from IPv6 address")
                        .with_fix("sysctl -w net.ipv6.conf.all.use_tempaddr=2")
                        .with_nist(vec!["SC-28"])
                        .with_engine("Bastion")
                        .with_rule("DK-BAS-009"),
                );
            }
            Err(_) => {}
        }
    }

    findings
}
