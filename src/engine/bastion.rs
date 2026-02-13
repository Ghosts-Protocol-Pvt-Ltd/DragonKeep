//! Bastion Engine — Network Security
//!
//! Checks: firewall status, open ports, listening services,
//! DNS configuration, network interfaces.

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;
use crate::engine::Finding;

/// Scan network security posture
pub async fn scan(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.bastion.enabled {
        findings.push(Finding::info("Bastion engine disabled in config"));
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
            findings.push(Finding::pass("firewalld is active"));

            // Check default zone
            if let Ok(zone_output) = tokio::process::Command::new("firewall-cmd")
                .arg("--get-default-zone")
                .output()
                .await
            {
                let zone = String::from_utf8_lossy(&zone_output.stdout).trim().to_string();
                if zone == "public" || zone == "drop" || zone == "block" {
                    findings.push(Finding::pass(format!("Default firewall zone: {}", zone)));
                } else if zone == "trusted" {
                    findings.push(
                        Finding::critical("Default firewall zone is 'trusted' — all traffic allowed")
                            .with_fix("firewall-cmd --set-default-zone=public"),
                    );
                } else {
                    findings.push(Finding::info(format!("Default firewall zone: {}", zone)));
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
            findings.push(Finding::pass("UFW firewall is active"));
            return findings;
        }
    }

    // Check iptables as fallback
    let mut has_firewall = false;

    // Check nftables first (modern replacement for iptables)
    let nft = tokio::process::Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .await;

    if let Ok(output) = nft {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let table_count = stdout.lines().filter(|l| l.starts_with("table")).count();
            if table_count > 0 {
                findings.push(Finding::pass(format!("nftables active with {} tables", table_count)));
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
            let rule_count = stdout.lines().filter(|l| !l.is_empty() && !l.starts_with("Chain") && !l.starts_with("num")).count();
            if rule_count > 0 {
                findings.push(Finding::info(format!("iptables has {} rules (no firewall daemon detected)", rule_count)));
                has_firewall = true;
            }
        }
    }

    if !has_firewall {
        findings.push(
            Finding::warning("No active firewall detected (no firewalld, ufw, iptables, or nftables rules)")
                .with_fix("Install and enable a firewall: sudo systemctl enable --now firewalld"),
        );
    }

    findings
}

async fn check_listening_services() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try ss first (modern)
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
                    // Process info is the last column, may be absent without root
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
            )));

            if !external_listeners.is_empty() {
                for listener in &external_listeners {
                    findings.push(
                        Finding::info(format!("External listener: {}", listener))
                            .with_detail("Accessible from network — verify this is intended"),
                    );
                }
            }
        }
    } else {
        // Fallback to /proc/net/tcp
        findings.push(Finding::info("ss not available — using /proc/net/tcp"));
        if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
            let listen_count = tcp.lines().skip(1)
                .filter(|l| l.split_whitespace().nth(3) == Some("0A"))
                .count();
            findings.push(Finding::info(format!("{} TCP sockets in LISTEN state", listen_count)));
        }
    }

    findings
}

async fn check_dns() -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
        let nameservers: Vec<&str> = resolv.lines()
            .filter(|l| l.starts_with("nameserver"))
            .filter_map(|l| l.split_whitespace().nth(1))
            .collect();

        if nameservers.is_empty() {
            findings.push(Finding::warning("No DNS nameservers configured in /etc/resolv.conf"));
        } else {
            for ns in &nameservers {
                let is_private = ns.starts_with("127.") || ns.starts_with("10.") ||
                    ns.starts_with("192.168.") || ns.starts_with("172.");

                if is_private {
                    findings.push(Finding::pass(format!("DNS: {} (local resolver)", ns)));
                } else {
                    // Known secure DNS providers
                    let known_secure = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"];
                    if known_secure.contains(ns) {
                        findings.push(Finding::pass(format!("DNS: {} (known provider)", ns)));
                    } else {
                        findings.push(Finding::info(format!("DNS: {} — verify this is a trusted provider", ns)));
                    }
                }
            }
        }
    } else {
        findings.push(Finding::info("Could not read /etc/resolv.conf"));
    }

    // Check if DNS-over-HTTPS/TLS is configured (systemd-resolved)
    let resolved = tokio::process::Command::new("systemctl")
        .args(["is-active", "systemd-resolved"])
        .output()
        .await;

    if let Ok(output) = resolved {
        if String::from_utf8_lossy(&output.stdout).trim() == "active" {
            findings.push(Finding::info("systemd-resolved is active — may support DNS-over-TLS"));

            if let Ok(conf) = std::fs::read_to_string("/etc/systemd/resolved.conf") {
                if conf.contains("DNSOverTLS=yes") || conf.contains("DNSOverTLS=opportunistic") {
                    findings.push(Finding::pass("DNS-over-TLS is enabled"));
                } else {
                    findings.push(
                        Finding::info("DNS-over-TLS not explicitly enabled")
                            .with_fix("Add 'DNSOverTLS=opportunistic' to /etc/systemd/resolved.conf"),
                    );
                }
            }
        }
    }

    findings
}

async fn check_interfaces() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let mut interfaces = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "lo" {
                    continue;
                }

                let operstate_path = format!("/sys/class/net/{}/operstate", name);
                let state = std::fs::read_to_string(&operstate_path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".into());

                let is_wireless = std::path::Path::new(&format!("/sys/class/net/{}/wireless", name)).exists();
                let iface_type = if is_wireless { "WiFi" } else if name.starts_with("vir") || name.starts_with("br") || name.starts_with("docker") || name.starts_with("veth") { "Virtual" } else { "Wired" };

                interfaces.push(format!("{} ({}, {})", name, iface_type, state));
            }

            if interfaces.is_empty() {
                findings.push(Finding::warning("No network interfaces found (excluding loopback)"));
            } else {
                findings.push(Finding::info(format!("Network interfaces: {}", interfaces.join(", "))));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(Finding::info("Network interface check not yet implemented on this platform"));
    }

    // IPv6 privacy extensions
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/use_tempaddr") {
            Ok(val) if val.trim() == "2" => {
                findings.push(Finding::pass("IPv6 privacy extensions enabled"));
            }
            Ok(_) => {
                findings.push(
                    Finding::info("IPv6 privacy extensions not enabled")
                        .with_fix("sysctl -w net.ipv6.conf.all.use_tempaddr=2"),
                );
            }
            Err(_) => {}
        }
    }

    findings
}
