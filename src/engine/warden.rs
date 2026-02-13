//! Warden Engine — Process Monitor & Security
//!
//! Advanced process threat detection aligned with:
//!   - MITRE ATT&CK Execution, Resource Hijacking, Defense Evasion tactics
//!   - NIST SP 800-53 Rev 5 SI/AU families
//!   - Gamer/professional threat vectors: cryptominers, credential stealers,
//!     anti-cheat bypass tools, token grabbers
//!
//! Live TUI monitoring dashboard with ratatui.

use anyhow::Result;
use crate::config::Config;
use crate::engine::Finding;

/// Known cryptocurrency miners — ATT&CK T1496 (Resource Hijacking)
/// Source: Common miner binaries from incident response reports
const CRYPTO_MINERS: &[(&str, &str)] = &[
    ("xmrig", "XMRig Monero miner"),
    ("minerd", "cpuminer"),
    ("ethminer", "Ethereum miner"),
    ("phoenixminer", "PhoenixMiner"),
    ("t-rex", "T-Rex GPU miner"),
    ("lolminer", "lolMiner"),
    ("nbminer", "NBMiner"),
    ("gminer", "GMiner"),
    ("trex", "T-Rex miner variant"),
    ("ccminer", "ccminer CUDA miner"),
    ("bfgminer", "BFGMiner"),
    ("cgminer", "CGMiner"),
    ("minergate", "MinerGate"),
    ("nicehash", "NiceHash miner"),
    ("kryptex", "Kryptex miner"),
    ("claymore", "Claymore miner"),
    ("xmr-stak", "XMR-Stak"),
    ("randomx", "RandomX miner"),
];

/// Known credential stealers and info-stealers targeting gamers
/// Source: Malware analysis reports, MITRE ATT&CK T1555, T1539
const CREDENTIAL_STEALERS: &[(&str, &str)] = &[
    ("vidar", "Vidar Stealer"),
    ("redline", "RedLine Stealer"),
    ("raccoon", "Raccoon Stealer"),
    ("azorult", "AZORult"),
    ("predator", "Predator the Thief"),
    ("kpot", "KPOT Stealer"),
    ("arkei", "Arkei Stealer"),
    ("mars", "Mars Stealer"),
    ("stealc", "StealC"),
    ("lumma", "Lumma Stealer"),
    ("rhadamanthys", "Rhadamanthys"),
    ("aurora", "Aurora Stealer"),
];

/// Suspicious network/hacking tools
const SUSPICIOUS_TOOLS: &[(&str, &str, &str)] = &[
    ("nc", "Netcat", "T1059"),
    ("ncat", "Ncat", "T1059"),
    ("socat", "Socat", "T1059"),
    ("tcpdump", "tcpdump", "T1040"),
    ("wireshark", "Wireshark", "T1040"),
    ("tshark", "TShark", "T1040"),
    ("ettercap", "Ettercap", "T1557"),
    ("mitmproxy", "mitmproxy", "T1557"),
    ("bettercap", "Bettercap", "T1557"),
    ("responder", "Responder", "T1557.001"),
    ("hashcat", "Hashcat", "T1110.002"),
    ("john", "John the Ripper", "T1110.002"),
    ("hydra", "Hydra", "T1110"),
    ("nmap", "Nmap", "T1046"),
    ("masscan", "Masscan", "T1046"),
    ("sqlmap", "SQLmap", "T1190"),
];

/// Scan processes for suspicious activity and resource abuse
pub async fn scan(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.warden.enabled {
        findings.push(Finding::info("Warden engine disabled in config")
            .with_engine("Warden"));
        return Ok(findings);
    }

    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    sys.refresh_all();

    let total_mem = sys.total_memory() as f64;
    let proc_count = sys.processes().len();
    findings.push(Finding::info(format!("{} processes running", proc_count))
        .with_engine("Warden")
        .with_rule("DK-WAR-001"));

    // === Resource abuse detection ===
    let mut high_cpu: Vec<(String, u32, f32)> = Vec::new();
    let mut high_mem: Vec<(String, u32, f64)> = Vec::new();

    for (pid, proc_info) in sys.processes() {
        let name = proc_info.name().to_string_lossy().to_string();
        let cpu = proc_info.cpu_usage();
        let mem_pct = proc_info.memory() as f64 / total_mem * 100.0;

        if cpu > config.warden.cpu_threshold {
            high_cpu.push((name.clone(), pid.as_u32(), cpu));
        }
        if mem_pct > config.warden.memory_threshold as f64 {
            high_mem.push((name.clone(), pid.as_u32(), mem_pct));
        }
    }

    // Report high CPU — ATT&CK T1496 (Resource Hijacking)
    if high_cpu.is_empty() {
        findings.push(Finding::pass(format!(
            "No processes exceeding {}% CPU threshold",
            config.warden.cpu_threshold
        ))
            .with_engine("Warden")
            .with_rule("DK-WAR-002"));
    } else {
        for (name, pid, cpu) in &high_cpu {
            findings.push(
                Finding::warning(format!("High CPU: {} (PID {}) — {:.1}%", name, pid, cpu))
                    .with_detail("Sustained high CPU may indicate cryptomining, compilation, or compromised process")
                    .with_fix(format!("Investigate: ps aux | grep {} && cat /proc/{}/cmdline | tr '\\0' ' '", pid, pid))
                    .with_cvss(3.7)
                    .with_mitre(vec!["T1496"])
                    .with_nist(vec!["SI-4(2)"])
                    .with_engine("Warden")
                    .with_rule("DK-WAR-002"),
            );
        }
    }

    // Report high memory
    if high_mem.is_empty() {
        findings.push(Finding::pass(format!(
            "No processes exceeding {}% memory threshold",
            config.warden.memory_threshold
        ))
            .with_engine("Warden")
            .with_rule("DK-WAR-003"));
    } else {
        for (name, pid, mem) in &high_mem {
            findings.push(
                Finding::warning(format!("High memory: {} (PID {}) — {:.1}%", name, pid, mem))
                    .with_fix(format!("Investigate: ps aux | grep {}", pid))
                    .with_nist(vec!["SI-4(2)"])
                    .with_engine("Warden")
                    .with_rule("DK-WAR-003"),
            );
        }
    }

    // === Cryptominer detection ===
    // ATT&CK T1496 (Resource Hijacking)
    // Atomic Red Team: T1496
    let mut miner_found = false;
    for (pid, proc_info) in sys.processes() {
        let name = proc_info.name().to_string_lossy().to_lowercase();
        let exe = proc_info.exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "unknown".into());

        for (miner_name, miner_desc) in CRYPTO_MINERS {
            if name.contains(miner_name) || exe.to_lowercase().contains(miner_name) {
                miner_found = true;
                findings.push(
                    Finding::critical(format!("Cryptocurrency miner detected: {} — {} (PID {})", miner_desc, name, pid.as_u32()))
                        .with_detail(format!("Executable: {} | CPU: {:.1}% — unauthorized crypto mining hijacks GPU/CPU resources", exe, proc_info.cpu_usage()))
                        .with_fix(format!("kill -9 {} && find / -name '{}' -delete 2>/dev/null", pid.as_u32(), miner_name))
                        .with_cvss(7.5)
                        .with_mitre(vec!["T1496"])
                        .with_nist(vec!["SI-3", "SI-4"])
                        .with_engine("Warden")
                        .with_rule("DK-WAR-004"),
                );
            }
        }
    }
    if !miner_found {
        findings.push(Finding::pass("No known cryptocurrency miners detected")
            .with_engine("Warden")
            .with_rule("DK-WAR-004"));
    }

    // === Credential stealer detection ===
    // ATT&CK T1555.003 (Credentials from Web Browsers), T1539 (Steal Web Session Cookie)
    let mut stealer_found = false;
    for (pid, proc_info) in sys.processes() {
        let name = proc_info.name().to_string_lossy().to_lowercase();
        let exe = proc_info.exe()
            .map(|p| p.display().to_string().to_lowercase())
            .unwrap_or_default();

        for (stealer_name, stealer_desc) in CREDENTIAL_STEALERS {
            if name.contains(stealer_name) || exe.contains(stealer_name) {
                stealer_found = true;
                findings.push(
                    Finding::critical(format!("Credential stealer detected: {} (PID {})", stealer_desc, pid.as_u32()))
                        .with_detail(format!("Process '{}' matches known info-stealer malware. These target browser credentials, Discord tokens, and game accounts.", name))
                        .with_fix(format!("kill -9 {} && quarantine binary: cp /proc/{}/exe /tmp/quarantine_{} && investigate", pid.as_u32(), pid.as_u32(), pid.as_u32()))
                        .with_cvss(9.1)
                        .with_mitre(vec!["T1555.003", "T1539", "T1005"])
                        .with_nist(vec!["SI-3", "IR-4"])
                        .with_engine("Warden")
                        .with_rule("DK-WAR-005"),
                );
            }
        }
    }
    if !stealer_found {
        findings.push(Finding::pass("No known credential stealers detected")
            .with_engine("Warden")
            .with_rule("DK-WAR-005"));
    }

    // === Suspicious tool detection ===
    // Context-dependent — these tools are legitimate when run by the system owner
    for (pid, proc_info) in sys.processes() {
        let name = proc_info.name().to_string_lossy().to_lowercase();
        for (tool_name, tool_desc, technique) in SUSPICIOUS_TOOLS {
            if name == *tool_name {
                let exe = proc_info.exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".into());
                findings.push(
                    Finding::info(format!("Security tool running: {} — {} (PID {})", tool_desc, name, pid.as_u32()))
                        .with_detail(format!("Executable: {} — legitimate if run by operator, suspicious if unexpected", exe))
                        .with_mitre(vec![technique])
                        .with_nist(vec!["SI-4"])
                        .with_engine("Warden")
                        .with_rule("DK-WAR-006"),
                );
            }
        }
    }

    // === Zombie processes ===
    let zombie_count = sys.processes().values()
        .filter(|p| matches!(p.status(), sysinfo::ProcessStatus::Zombie))
        .count();

    if zombie_count > 0 {
        findings.push(
            Finding::warning(format!("{} zombie processes detected", zombie_count))
                .with_detail("Zombie processes indicate parent process issues — may mask crashed malware or broken daemons")
                .with_fix("ps aux | grep 'Z' — investigate parent processes")
                .with_nist(vec!["SI-4"])
                .with_engine("Warden")
                .with_rule("DK-WAR-007"),
        );
    } else {
        findings.push(Finding::pass("No zombie processes")
            .with_engine("Warden")
            .with_rule("DK-WAR-007"));
    }

    // === Processes running from suspicious locations ===
    // ATT&CK T1036.005 (Match Legitimate Name or Location)
    for (pid, proc_info) in sys.processes() {
        if let Some(exe_path) = proc_info.exe() {
            let exe_str = exe_path.display().to_string();
            let suspicious_paths = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];
            for sp in &suspicious_paths {
                if exe_str.starts_with(sp) {
                    let name = proc_info.name().to_string_lossy().to_string();
                    findings.push(
                        Finding::high(format!("Process running from {}: {} (PID {})", sp.trim_end_matches('/'), name, pid.as_u32()))
                            .with_detail(format!("Binary: {} — world-writable directories are common malware staging locations", exe_str))
                            .with_fix(format!("Investigate: file {} && kill {} if unauthorized", exe_str, pid.as_u32()))
                            .with_cvss(7.8)
                            .with_mitre(vec!["T1036.005", "T1059"])
                            .with_nist(vec!["SI-3", "CM-6"])
                            .with_engine("Warden")
                            .with_rule("DK-WAR-008"),
                    );
                }
            }
        }
    }

    Ok(findings)
}

/// Launch interactive TUI monitor
pub async fn monitor_tui() -> Result<()> {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
        execute,
    };
    use ratatui::{
        prelude::*,
        widgets::*,
    };
    use sysinfo::System;
    use std::io;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    let mut sys = System::new_all();
    let tick_rate = std::time::Duration::from_secs(1);
    let mut last_tick = std::time::Instant::now();

    loop {
        sys.refresh_all();

        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(5),
                    Constraint::Min(10),
                    Constraint::Length(3),
                ])
                .split(frame.area());

            let title = Block::default()
                .borders(Borders::ALL)
                .title(" 🏰 DragonKeep — Warden Monitor ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Rounded);
            frame.render_widget(title, chunks[0]);

            let total_mem = sys.total_memory() / 1024 / 1024;
            let used_mem = sys.used_memory() / 1024 / 1024;
            let cpu_avg: f32 = if sys.cpus().is_empty() {
                0.0
            } else {
                sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32
            };
            let uptime = System::uptime();

            let sys_info = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled("CPU: ", Style::default().fg(Color::Cyan)),
                    Span::raw(format!("{:.1}%  ", cpu_avg)),
                    Span::styled("RAM: ", Style::default().fg(Color::Green)),
                    Span::raw(format!("{}/{} MB  ", used_mem, total_mem)),
                    Span::styled("Procs: ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("{}  ", sys.processes().len())),
                    Span::styled("Up: ", Style::default().fg(Color::Magenta)),
                    Span::raw(format!("{}h {}m", uptime / 3600, (uptime % 3600) / 60)),
                ]),
            ])
            .block(Block::default().borders(Borders::ALL).title(" System "));
            frame.render_widget(sys_info, chunks[1]);

            let mut procs: Vec<_> = sys.processes().iter().collect();
            procs.sort_by(|a, b| b.1.cpu_usage().partial_cmp(&a.1.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));

            let rows: Vec<Row> = procs.iter().take(20).map(|(pid, proc_info)| {
                let mem_mb = proc_info.memory() / 1024 / 1024;
                Row::new(vec![
                    Cell::from(pid.as_u32().to_string()),
                    Cell::from(proc_info.name().to_string_lossy().to_string()),
                    Cell::from(format!("{:.1}%", proc_info.cpu_usage())),
                    Cell::from(format!("{} MB", mem_mb)),
                    Cell::from(format!("{:?}", proc_info.status())),
                ])
            }).collect();

            let table = Table::new(
                rows,
                [
                    Constraint::Length(8),
                    Constraint::Min(20),
                    Constraint::Length(10),
                    Constraint::Length(12),
                    Constraint::Length(12),
                ],
            )
            .header(Row::new(vec!["PID", "Name", "CPU", "Memory", "Status"])
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
            .block(Block::default().borders(Borders::ALL).title(" Processes (Top 20 by CPU) "));
            frame.render_widget(table, chunks[2]);

            let footer = Paragraph::new("  Press 'q' to quit")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(footer, chunks[3]);
        })?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
