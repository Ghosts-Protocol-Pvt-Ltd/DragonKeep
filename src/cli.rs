use clap::{Parser, Subcommand};
use colored::Colorize;

use crate::config::Config;
use crate::engine::{sentinel, forge, warden, bastion, citadel, spectre, aegis, phantom};
use crate::report::Reporter;

#[derive(Parser)]
#[command(
    name = "dragonkeep",
    about = "Next-gen system security, performance & stability platform",
    version,
    after_help = "Examples:\n  dragonkeep scan                Full security + performance audit\n  dragonkeep scan spectre,aegis  Scan specific engines\n  dragonkeep harden              Apply security hardening\n  dragonkeep tune gaming         Optimize for gaming performance\n  dragonkeep monitor             Live system monitoring dashboard\n  dragonkeep firewall            Network security audit\n  dragonkeep report              Generate full system report\n  dragonkeep report -o out.sarif Export as SARIF (GitHub/Azure compatible)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Suppress banner output
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Output format
    #[arg(long, global = true, default_value = "pretty")]
    pub format: OutputFormat,

    /// Config file path
    #[arg(long, global = true)]
    pub config: Option<String>,

    /// Dry run — show what would change without applying
    #[arg(long, global = true)]
    pub dry_run: bool,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
    Minimal,
    Sarif,
}

#[derive(Subcommand)]
pub enum Command {
    /// Full security + performance scan
    Scan {
        /// Specific modules to scan (comma-separated: sentinel,forge,spectre,aegis,phantom,warden,bastion,citadel)
        #[arg(value_delimiter = ',')]
        modules: Option<Vec<String>>,
    },

    /// Security hardening — apply safe defaults
    Harden {
        /// Hardening profile
        #[arg(default_value = "standard")]
        profile: String,
    },

    /// Performance tuning — optimize for a workload
    Tune {
        /// Workload profile: gaming, ai, creative, workstation, server, balanced
        profile: String,
    },

    /// Live system monitoring dashboard (TUI)
    Monitor,

    /// Network security audit + firewall check
    Firewall,

    /// Process security — find suspicious or resource-heavy processes
    Processes,

    /// AI/ML threat surface scan
    Ai,

    /// Supply chain & integrity audit
    Supply,

    /// Runtime anomaly detection
    Anomaly,

    /// Generate comprehensive system report
    Report {
        /// Output file (use .sarif extension for SARIF format)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Show current system status
    Status,

    /// Initialize DragonKeep config
    Init,
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        let config = match &self.config {
            Some(path) => Config::load_from(path)?,
            None => Config::load_or_default()?,
        };

        match self.command {
            Some(Command::Scan { ref modules }) => {
                self.cmd_scan(&config, modules.clone()).await
            }
            Some(Command::Harden { ref profile }) => {
                self.cmd_harden(&config, profile).await
            }
            Some(Command::Tune { ref profile }) => {
                self.cmd_tune(&config, profile).await
            }
            Some(Command::Monitor) => {
                self.cmd_monitor(&config).await
            }
            Some(Command::Firewall) => {
                self.cmd_firewall(&config).await
            }
            Some(Command::Processes) => {
                self.cmd_processes(&config).await
            }
            Some(Command::Ai) => {
                self.cmd_ai(&config).await
            }
            Some(Command::Supply) => {
                self.cmd_supply(&config).await
            }
            Some(Command::Anomaly) => {
                self.cmd_anomaly(&config).await
            }
            Some(Command::Report { ref output }) => {
                self.cmd_report(&config, output.clone()).await
            }
            Some(Command::Status) => {
                self.cmd_status(&config).await
            }
            Some(Command::Init) => {
                self.cmd_init().await
            }
            None => {
                // Default: quick status
                self.cmd_status(&config).await
            }
        }
    }

    async fn cmd_scan(&self, config: &Config, modules: Option<Vec<String>>) -> anyhow::Result<()> {
        let run_all = modules.is_none();
        let mods: Vec<String> = modules.unwrap_or_default();
        let should_run = |name: &str| run_all || mods.iter().any(|m| m == name);

        let mut reporter = Reporter::new();

        if should_run("sentinel") || should_run("security") {
            eprintln!("{}", "  ── Sentinel: Security Scanner ──".cyan().bold());
            let findings = sentinel::scan(config).await?;
            reporter.add_section("Security", findings);
        }

        if should_run("forge") || should_run("performance") {
            eprintln!("{}", "  ── Forge: Performance Analysis ──".yellow().bold());
            let findings = forge::analyze(config).await?;
            reporter.add_section("Performance", findings);
        }

        if should_run("warden") || should_run("processes") {
            eprintln!("{}", "  ── Warden: Process Monitor ──".magenta().bold());
            let findings = warden::scan(config).await?;
            reporter.add_section("Processes", findings);
        }

        if should_run("bastion") || should_run("network") {
            eprintln!("{}", "  ── Bastion: Network Security ──".blue().bold());
            let findings = bastion::scan(config).await?;
            reporter.add_section("Network", findings);
        }

        if should_run("citadel") || should_run("hardening") {
            eprintln!("{}", "  ── Citadel: System Hardening ──".red().bold());
            let findings = citadel::audit(config).await?;
            reporter.add_section("Hardening", findings);
        }

        if should_run("spectre") || should_run("ai") {
            eprintln!("{}", "  ── Spectre: AI/ML Threat Surface ──".truecolor(255, 100, 0).bold());
            let findings = spectre::scan(config).await?;
            reporter.add_section("AI/ML Threats", findings);
        }

        if should_run("aegis") || should_run("supply") || should_run("supply-chain") {
            eprintln!("{}", "  ── Aegis: Supply Chain Integrity ──".truecolor(0, 200, 150).bold());
            let findings = aegis::scan(config).await?;
            reporter.add_section("Supply Chain", findings);
        }

        if should_run("phantom") || should_run("anomaly") || should_run("runtime") {
            eprintln!("{}", "  ── Phantom: Runtime Anomaly Detection ──".truecolor(180, 0, 255).bold());
            let findings = phantom::scan(config).await?;
            reporter.add_section("Runtime Anomalies", findings);
        }

        reporter.print(&self.format);
        Ok(())
    }

    async fn cmd_harden(&self, config: &Config, profile: &str) -> anyhow::Result<()> {
        eprintln!("{}", format!("  ── Citadel: Applying '{}' hardening ──", profile).red().bold());
        citadel::harden(config, profile, self.dry_run).await
    }

    async fn cmd_tune(&self, config: &Config, profile: &str) -> anyhow::Result<()> {
        eprintln!("{}", format!("  ── Forge: Tuning for '{}' ──", profile).yellow().bold());
        forge::tune(config, profile, self.dry_run).await
    }

    async fn cmd_monitor(&self, _config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Warden: Live Monitor ──".magenta().bold());
        warden::monitor_tui().await
    }

    async fn cmd_firewall(&self, config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Bastion: Network Audit ──".blue().bold());
        let mut reporter = Reporter::new();
        let findings = bastion::scan(config).await?;
        reporter.add_section("Network", findings);
        reporter.print(&self.format);
        Ok(())
    }

    async fn cmd_processes(&self, config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Warden: Process Scan ──".magenta().bold());
        let mut reporter = Reporter::new();
        let findings = warden::scan(config).await?;
        reporter.add_section("Processes", findings);
        reporter.print(&self.format);
        Ok(())
    }

    async fn cmd_ai(&self, config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Spectre: AI/ML Threat Surface ──".truecolor(255, 100, 0).bold());
        let mut reporter = Reporter::new();
        let findings = spectre::scan(config).await?;
        reporter.add_section("AI/ML Threats", findings);
        reporter.print(&self.format);
        Ok(())
    }

    async fn cmd_supply(&self, config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Aegis: Supply Chain Integrity ──".truecolor(0, 200, 150).bold());
        let mut reporter = Reporter::new();
        let findings = aegis::scan(config).await?;
        reporter.add_section("Supply Chain", findings);
        reporter.print(&self.format);
        Ok(())
    }

    async fn cmd_anomaly(&self, config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Phantom: Runtime Anomaly Detection ──".truecolor(180, 0, 255).bold());
        let mut reporter = Reporter::new();
        let findings = phantom::scan(config).await?;
        reporter.add_section("Runtime Anomalies", findings);
        reporter.print(&self.format);
        Ok(())
    }

    async fn cmd_report(&self, config: &Config, output: Option<String>) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Full System Report ──".green().bold());
        let mut reporter = Reporter::new();

        reporter.add_section("Security", sentinel::scan(config).await?);
        reporter.add_section("Performance", forge::analyze(config).await?);
        reporter.add_section("Processes", warden::scan(config).await?);
        reporter.add_section("Network", bastion::scan(config).await?);
        reporter.add_section("Hardening", citadel::audit(config).await?);
        reporter.add_section("AI/ML Threats", spectre::scan(config).await?);
        reporter.add_section("Supply Chain", aegis::scan(config).await?);
        reporter.add_section("Runtime Anomalies", phantom::scan(config).await?);

        if let Some(path) = output {
            if path.ends_with(".sarif") || path.ends_with(".sarif.json") {
                reporter.save_sarif(&path)?;
                eprintln!("  {} SARIF report saved: {}", "✓".green(), path);
            } else {
                reporter.save_json(&path)?;
                eprintln!("  {} Report saved: {}", "✓".green(), path);
            }
        } else {
            reporter.print(&self.format);
        }
        Ok(())
    }

    async fn cmd_status(&self, _config: &Config) -> anyhow::Result<()> {
        use sysinfo::System;

        let mut sys = System::new_all();
        sys.refresh_all();
        // sysinfo requires two refreshes with a delay for accurate CPU readings
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        sys.refresh_all();

        eprintln!("{}", "  ── System Status ──".green().bold());

        // OS
        let os_name = System::name().unwrap_or_else(|| "Unknown".into());
        let os_version = System::os_version().unwrap_or_else(|| "?".into());
        let kernel = System::kernel_version().unwrap_or_else(|| "?".into());
        let hostname = System::host_name().unwrap_or_else(|| "?".into());
        eprintln!("  {} {}", "Host:".dimmed(), hostname);
        eprintln!("  {} {} {}", "OS:".dimmed(), os_name, os_version);
        eprintln!("  {} {}", "Kernel:".dimmed(), kernel);

        // CPU
        let cpu_count = sys.cpus().len();
        let cpu_name = sys.cpus().first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "Unknown".into());
        let cpu_usage: f32 = if cpu_count > 0 {
            sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / cpu_count as f32
        } else {
            0.0
        };
        eprintln!("  {} {} ({} threads, {:.0}% avg)", "CPU:".dimmed(), cpu_name, cpu_count, cpu_usage);

        // Memory
        let total_mem = sys.total_memory() / 1024 / 1024;
        let used_mem = sys.used_memory() / 1024 / 1024;
        let mem_pct = if total_mem > 0 { (used_mem as f64 / total_mem as f64 * 100.0) as u64 } else { 0 };
        eprintln!("  {} {} / {} MB ({}%)", "RAM:".dimmed(), used_mem, total_mem, mem_pct);

        // Swap
        let total_swap = sys.total_swap() / 1024 / 1024;
        let used_swap = sys.used_swap() / 1024 / 1024;
        eprintln!("  {} {} / {} MB", "Swap:".dimmed(), used_swap, total_swap);

        // Uptime
        let uptime = System::uptime();
        let hours = uptime / 3600;
        let mins = (uptime % 3600) / 60;
        eprintln!("  {} {}h {}m", "Uptime:".dimmed(), hours, mins);

        // Process count
        let proc_count = sys.processes().len();
        eprintln!("  {} {}", "Processes:".dimmed(), proc_count);

        eprintln!();
        eprintln!("  {} Run {} for a full audit", "→".green(), "dragonkeep scan".bold());

        Ok(())
    }

    async fn cmd_init(&self) -> anyhow::Result<()> {
        let config = Config::default();
        let path = Config::default_path();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let toml_str = toml::to_string_pretty(&config)?;
        std::fs::write(&path, &toml_str)?;
        eprintln!("  {} Config created: {}", "✓".green(), path.display());
        Ok(())
    }
}
