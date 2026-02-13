//! Forge Engine — Performance Tuning & Analysis
//!
//! Profiles: gaming, ai, creative, workstation, server, balanced
//! Checks: CPU governor, I/O scheduler, GPU state, memory pressure,
//! swap config, transparent hugepages, disk utilization.

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;
use crate::engine::Finding;

/// Analyze current system performance characteristics
pub async fn analyze(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.forge.enabled {
        findings.push(Finding::info("Forge engine disabled in config"));
        return Ok(findings);
    }

    eprintln!("    {} Checking CPU governor...", "→".dimmed());
    findings.extend(check_cpu_governor().await);

    eprintln!("    {} Checking I/O schedulers...", "→".dimmed());
    findings.extend(check_io_scheduler().await);

    eprintln!("    {} Checking memory pressure...", "→".dimmed());
    findings.extend(check_memory().await);

    eprintln!("    {} Checking swap configuration...", "→".dimmed());
    findings.extend(check_swap().await);

    eprintln!("    {} Checking transparent hugepages...", "→".dimmed());
    findings.extend(check_thp().await);

    if config.forge.gpu_tuning {
        eprintln!("    {} Checking GPU status...", "→".dimmed());
        findings.extend(check_gpu().await);
    }

    Ok(findings)
}

/// Apply performance tuning for a specific profile
pub async fn tune(_config: &Config, profile: &str, dry_run: bool) -> Result<()> {
    let actions = match profile {
        "gaming" => vec![
            ("CPU governor", "performance", "cpupower frequency-set -g performance"),
            ("Swappiness", "10", "sysctl -w vm.swappiness=10"),
            ("THP", "madvise", "echo madvise > /sys/kernel/mm/transparent_hugepage/enabled"),
            ("I/O scheduler", "none/noop", "echo none > /sys/block/*/queue/scheduler"),
        ],
        "ai" | "ml" => vec![
            ("CPU governor", "performance", "cpupower frequency-set -g performance"),
            ("Swappiness", "10", "sysctl -w vm.swappiness=10"),
            ("THP", "always", "echo always > /sys/kernel/mm/transparent_hugepage/enabled"),
            ("Max map count", "1048576", "sysctl -w vm.max_map_count=1048576"),
        ],
        "creative" => vec![
            ("CPU governor", "performance", "cpupower frequency-set -g performance"),
            ("Swappiness", "20", "sysctl -w vm.swappiness=20"),
            ("Dirty ratio", "40", "sysctl -w vm.dirty_ratio=40"),
        ],
        "workstation" => vec![
            ("CPU governor", "ondemand", "cpupower frequency-set -g ondemand"),
            ("Swappiness", "30", "sysctl -w vm.swappiness=30"),
        ],
        "server" => vec![
            ("CPU governor", "performance", "cpupower frequency-set -g performance"),
            ("Swappiness", "10", "sysctl -w vm.swappiness=10"),
            ("Somaxconn", "65535", "sysctl -w net.core.somaxconn=65535"),
            ("TCP fin timeout", "15", "sysctl -w net.ipv4.tcp_fin_timeout=15"),
        ],
        "balanced" | _ => vec![
            ("CPU governor", "schedutil", "cpupower frequency-set -g schedutil"),
            ("Swappiness", "60", "sysctl -w vm.swappiness=60"),
        ],
    };

    if dry_run {
        eprintln!("  {} Dry run — would apply:", "→".yellow());
    } else {
        eprintln!("  {} Applying tuning profile: {}", "→".green(), profile.bold());
    }

    for (name, value, command) in &actions {
        if dry_run {
            eprintln!("    {} {} → {} ({})", "[DRY]".yellow(), name, value, command);
        } else {
            eprintln!("    {} {} → {}", "→".dimmed(), name, value);
            // Actually apply via command
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
                    eprintln!("      {} May need root: sudo {}", "→".dimmed(), command);
                }
                Err(e) => {
                    eprintln!("      {} Error: {}", "✗".red(), e);
                }
            }
        }
    }

    Ok(())
}

async fn check_cpu_governor() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor";
        match std::fs::read_to_string(path) {
            Ok(gov) => {
                let gov = gov.trim().to_string();
                let detail = format!("Current: {}", gov);
                match gov.as_str() {
                    "performance" => {
                        findings.push(Finding::pass("CPU governor: performance").with_detail(detail));
                    }
                    "powersave" => {
                        findings.push(
                            Finding::info("CPU governor: powersave — may limit performance")
                                .with_detail(detail)
                                .with_fix("cpupower frequency-set -g performance"),
                        );
                    }
                    _ => {
                        findings.push(Finding::info(format!("CPU governor: {}", gov)).with_detail(detail));
                    }
                }
            }
            Err(_) => {
                findings.push(Finding::info("Could not read CPU governor (cpufreq not available)"));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(Finding::info("CPU governor check not available on this platform"));
    }

    findings
}

async fn check_io_scheduler() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Skip loop/ram devices
                if name.starts_with("loop") || name.starts_with("ram") {
                    continue;
                }

                let sched_path = format!("/sys/block/{}/queue/scheduler", name);
                if let Ok(sched) = std::fs::read_to_string(&sched_path) {
                    let active = sched
                        .split_whitespace()
                        .find(|s| s.starts_with('['))
                        .map(|s| s.trim_matches(|c| c == '[' || c == ']').to_string())
                        .unwrap_or_else(|| "unknown".into());

                    let rotational_path = format!("/sys/block/{}/queue/rotational", name);
                    let is_ssd = std::fs::read_to_string(&rotational_path)
                        .map(|v| v.trim() == "0")
                        .unwrap_or(false);

                    if is_ssd && active != "none" && active != "mq-deadline" {
                        findings.push(
                            Finding::info(format!("SSD {} using '{}' scheduler — 'none' is optimal", name, active))
                                .with_fix(format!("echo none > /sys/block/{}/queue/scheduler", name)),
                        );
                    } else {
                        findings.push(Finding::pass(format!("{}: {} scheduler ({})", name, active, if is_ssd { "SSD" } else { "HDD" })));
                    }
                }
            }
        }
    }

    findings
}

async fn check_memory() -> Vec<Finding> {
    let mut findings = Vec::new();

    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_memory();

    let total = sys.total_memory() / 1024 / 1024;
    let used = sys.used_memory() / 1024 / 1024;
    let pct = if total > 0 { (used as f64 / total as f64 * 100.0) as u64 } else { 0 };

    if pct > 90 {
        findings.push(
            Finding::critical(format!("Memory pressure critical: {}% used ({}/{} MB)", pct, used, total))
                .with_fix("Close unused applications or add more RAM"),
        );
    } else if pct > 75 {
        findings.push(
            Finding::warning(format!("Memory pressure elevated: {}% used ({}/{} MB)", pct, used, total)),
        );
    } else {
        findings.push(Finding::pass(format!("Memory usage healthy: {}% ({}/{} MB)", pct, used, total)));
    }

    findings
}

async fn check_swap() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/sys/vm/swappiness") {
            Ok(val) => {
                let swappiness: u32 = val.trim().parse().unwrap_or(60);
                if swappiness > 60 {
                    findings.push(
                        Finding::info(format!("Swappiness is high ({}), may swap too aggressively", swappiness))
                            .with_fix("sysctl -w vm.swappiness=30 for desktop use"),
                    );
                } else {
                    findings.push(Finding::pass(format!("Swappiness: {}", swappiness)));
                }
            }
            Err(_) => {
                findings.push(Finding::info("Could not read swappiness"));
            }
        }
    }

    findings
}

async fn check_thp() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let path = "/sys/kernel/mm/transparent_hugepage/enabled";
        if let Ok(content) = std::fs::read_to_string(path) {
            let active = content
                .split_whitespace()
                .find(|s| s.starts_with('['))
                .map(|s| s.trim_matches(|c| c == '[' || c == ']').to_string())
                .unwrap_or_else(|| "unknown".into());

            match active.as_str() {
                "always" => {
                    findings.push(
                        Finding::info("Transparent Hugepages: always — good for AI/ML, may cause latency spikes for gaming")
                            .with_fix("echo madvise > /sys/kernel/mm/transparent_hugepage/enabled"),
                    );
                }
                "madvise" => {
                    findings.push(Finding::pass("Transparent Hugepages: madvise (optimal for most workloads)"));
                }
                "never" => {
                    findings.push(Finding::info("Transparent Hugepages disabled — may reduce performance for large workloads"));
                }
                _ => {
                    findings.push(Finding::info(format!("Transparent Hugepages: {}", active)));
                }
            }
        }
    }

    findings
}

async fn check_gpu() -> Vec<Finding> {
    let mut findings = Vec::new();

    // NVIDIA GPU check
    let nvidia = tokio::process::Command::new("nvidia-smi")
        .arg("--query-gpu=name,temperature.gpu,power.draw,utilization.gpu,memory.used,memory.total")
        .arg("--format=csv,noheader,nounits")
        .output()
        .await;

    match nvidia {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 6 {
                    let name = parts[0];
                    let temp: f32 = parts[1].parse().unwrap_or(0.0);
                    let power = parts[2];
                    let util = parts[3];
                    let mem_used = parts[4];
                    let mem_total = parts[5];

                    findings.push(Finding::info(
                        format!("GPU: {} | {}°C | {} W | {}% util | {}/{} MB VRAM", name, temp, power, util, mem_used, mem_total),
                    ));

                    if temp > 85.0 {
                        findings.push(
                            Finding::warning(format!("GPU temperature high: {}°C", temp))
                                .with_fix("Check GPU cooling, reduce workload, or adjust fan curve"),
                        );
                    } else {
                        findings.push(Finding::pass(format!("GPU temperature OK: {}°C", temp)));
                    }
                }
            }
        }
        _ => {
            // Check for AMD GPU
            let amd_path = "/sys/class/drm/card0/device/gpu_busy_percent";
            if std::path::Path::new(amd_path).exists() {
                let util = std::fs::read_to_string(amd_path).unwrap_or_default();
                findings.push(Finding::info(format!("AMD GPU utilization: {}%", util.trim())));
            } else {
                findings.push(Finding::info("No NVIDIA/AMD GPU detected or drivers not loaded"));
            }
        }
    }

    findings
}
