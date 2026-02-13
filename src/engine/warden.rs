//! Warden Engine — Process Monitor & Security
//!
//! Live TUI monitoring dashboard with ratatui.
//! Suspicious process detection, resource tracking, anomaly alerts.

use anyhow::Result;
use crate::config::Config;
use crate::engine::Finding;

/// Scan processes for suspicious activity and resource abuse
pub async fn scan(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.warden.enabled {
        findings.push(Finding::info("Warden engine disabled in config"));
        return Ok(findings);
    }

    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    // Wait for accurate CPU readings
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    sys.refresh_all();

    let total_mem = sys.total_memory() as f64;
    let proc_count = sys.processes().len();
    findings.push(Finding::info(format!("{} processes running", proc_count)));

    // Find resource-heavy processes
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

    // Report high CPU
    if high_cpu.is_empty() {
        findings.push(Finding::pass(format!(
            "No processes exceeding {}% CPU threshold",
            config.warden.cpu_threshold
        )));
    } else {
        for (name, pid, cpu) in &high_cpu {
            findings.push(
                Finding::warning(format!("High CPU: {} (PID {}) — {:.1}%", name, pid, cpu))
                    .with_fix(format!("Investigate: ps aux | grep {}", pid)),
            );
        }
    }

    // Report high memory
    if high_mem.is_empty() {
        findings.push(Finding::pass(format!(
            "No processes exceeding {}% memory threshold",
            config.warden.memory_threshold
        )));
    } else {
        for (name, pid, mem) in &high_mem {
            findings.push(
                Finding::warning(format!("High memory: {} (PID {}) — {:.1}%", name, pid, mem))
                    .with_fix(format!("Investigate: ps aux | grep {}", pid)),
            );
        }
    }

    // Check for suspicious process names
    let suspicious_names = [
        "nc", "ncat", "socat", "cryptominer", "xmrig", "minerd",
        "kworker/u:0",  // Fake kworker
    ];

    for (pid, proc_info) in sys.processes() {
        let name = proc_info.name().to_string_lossy().to_lowercase();
        for sus in &suspicious_names {
            if name == *sus {
                let exe = proc_info.exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".into());
                findings.push(
                    Finding::warning(format!("Potentially suspicious process: {} (PID {})", name, pid.as_u32()))
                        .with_detail(format!("Executable: {}", exe))
                        .with_fix(format!("Verify legitimacy: ls -la /proc/{}/exe", pid.as_u32())),
                );
            }
        }
    }

    // Zombie processes
    let zombie_count = sys.processes().values()
        .filter(|p| matches!(p.status(), sysinfo::ProcessStatus::Zombie))
        .count();

    if zombie_count > 0 {
        findings.push(
            Finding::warning(format!("{} zombie processes detected", zombie_count))
                .with_fix("ps aux | grep 'Z' — parent process may need investigation"),
        );
    } else {
        findings.push(Finding::pass("No zombie processes"));
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

    let mut sys = System::new_all();
    let tick_rate = std::time::Duration::from_secs(1);
    let mut last_tick = std::time::Instant::now();

    loop {
        sys.refresh_all();

        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),  // Title
                    Constraint::Length(5),  // System info
                    Constraint::Min(10),    // Process table
                    Constraint::Length(3),  // Footer
                ])
                .split(frame.area());

            // Title
            let title = Block::default()
                .borders(Borders::ALL)
                .title(" 🏰 DragonKeep — Warden Monitor ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Rounded);
            frame.render_widget(title, chunks[0]);

            // System info
            let total_mem = sys.total_memory() / 1024 / 1024;
            let used_mem = sys.used_memory() / 1024 / 1024;
            let cpu_avg: f32 = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32;
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

            // Process table — top 20 by CPU
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

            // Footer
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
