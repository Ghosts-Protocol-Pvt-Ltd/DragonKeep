use clap::{Parser, Subcommand};
use colored::Colorize;

use crate::config::Config;
use crate::engine::{sentinel, forge, warden, bastion, citadel, spectre, aegis, phantom, hydra, drake, talon};
use crate::report::Reporter;
use crate::community;

#[derive(Parser)]
#[command(
    name = "dragonkeep",
    about = "Next-gen system security, performance & stability platform — Community Edition",
    version,
    after_help = "Examples:\n  dragonkeep scan                Full security + performance audit\n  dragonkeep scan --profile quick Quick security check\n  dragonkeep malware             Malware detection & defense\n  dragonkeep ransomware          Ransomware defense scan\n  dragonkeep hunt                Proactive threat hunting\n  dragonkeep remediate           Auto-remediate threats\n  dragonkeep score               Security score & grade\n  dragonkeep harden              Apply security hardening\n  dragonkeep monitor             Live system monitoring dashboard\n  dragonkeep report -o out.sarif Export as SARIF format"
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
        /// Specific modules to scan (comma-separated: sentinel,forge,spectre,aegis,phantom,warden,bastion,citadel,hydra,drake,talon)
        #[arg(value_delimiter = ',')]
        modules: Option<Vec<String>>,

        /// Use a community scan profile (quick, standard, deep, malware, threat-hunt, compliance, server, workstation)
        #[arg(long)]
        profile: Option<String>,
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

    /// Malware detection & defense (Hydra engine)
    Malware,

    /// Ransomware defense & recovery (Drake engine)
    Ransomware,

    /// Proactive threat hunting (Talon engine)
    Hunt,

    /// Auto-remediate detected threats (safe mode by default)
    Remediate {
        /// Target: malware, ransomware, or all
        #[arg(default_value = "all")]
        target: String,
    },

    /// Calculate and display security score
    Score,

    /// Show available community scan profiles
    Profiles,

    /// Fetch and check community threat intelligence feeds
    Feeds,

    /// Deploy ransomware canary files
    Canary,

    /// Show DragonKeep Community Edition info
    Community,
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        let config = match &self.config {
            Some(path) => Config::load_from(path)?,
            None => Config::load_or_default()?,
        };

        match self.command {
            Some(Command::Scan { ref modules, ref profile }) => {
                self.cmd_scan(&config, modules.clone(), profile.clone()).await
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
            Some(Command::Malware) => {
                self.cmd_malware(&config).await
            }
            Some(Command::Ransomware) => {
                self.cmd_ransomware(&config).await
            }
            Some(Command::Hunt) => {
                self.cmd_hunt(&config).await
            }
            Some(Command::Remediate { ref target }) => {
                self.cmd_remediate(&config, target).await
            }
            Some(Command::Score) => {
                self.cmd_score(&config).await
            }
            Some(Command::Profiles) => {
                self.cmd_profiles().await
            }
            Some(Command::Feeds) => {
                self.cmd_feeds(&config).await
            }
            Some(Command::Canary) => {
                self.cmd_canary().await
            }
            Some(Command::Community) => {
                self.cmd_community().await
            }
            None => {
                // Default: quick status
                self.cmd_status(&config).await
            }
        }
    }

    async fn cmd_scan(&self, config: &Config, modules: Option<Vec<String>>, profile: Option<String>) -> anyhow::Result<()> {
        // Resolve profile into module list
        let effective_modules = if let Some(profile_name) = profile {
            let profiles = community::default_profiles();
            if let Some(p) = profiles.iter().find(|p| p.name == profile_name) {
                Some(p.engines.clone())
            } else {
                eprintln!("  {} Unknown profile '{}'. Use 'dragonkeep profiles' to see available profiles.", "✗".red(), profile_name);
                return Ok(());
            }
        } else {
            modules
        };

        let run_all = effective_modules.is_none();
        let mods: Vec<String> = effective_modules.unwrap_or_default();
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

        if should_run("hydra") || should_run("malware") {
            eprintln!("{}", "  ── Hydra: Malware Detection & Defense ──".truecolor(255, 50, 50).bold());
            let findings = hydra::scan(config).await?;
            reporter.add_section("Malware Defense", findings);
        }

        if should_run("drake") || should_run("ransomware") {
            eprintln!("{}", "  ── Drake: Ransomware Defense ──".truecolor(255, 0, 100).bold());
            let findings = drake::scan(config).await?;
            reporter.add_section("Ransomware Defense", findings);
        }

        if should_run("talon") || should_run("hunt") || should_run("threat-hunt") {
            eprintln!("{}", "  ── Talon: Threat Hunting ──".truecolor(200, 50, 255).bold());
            let findings = talon::hunt(config).await?;
            reporter.add_section("Threat Hunting", findings);
        }

        // Calculate and display security score for full scans
        if run_all {
            let all_findings: Vec<_> = reporter.all_findings();
            let score = community::calculate_security_score(&all_findings);
            community::print_security_score(&score);
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
        reporter.add_section("Malware Defense", hydra::scan(config).await?);
        reporter.add_section("Ransomware Defense", drake::scan(config).await?);
        reporter.add_section("Threat Hunting", talon::hunt(config).await?);

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

    async fn cmd_malware(&self, config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Hydra: Malware Detection & Defense ──".truecolor(255, 50, 50).bold());
        let mut reporter = Reporter::new();
        let findings = hydra::scan(config).await?;
        reporter.add_section("Malware Defense", findings);
        reporter.print(&self.format);
        Ok(())
    }

    async fn cmd_ransomware(&self, config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Drake: Ransomware Defense & Recovery ──".truecolor(255, 0, 100).bold());
        let mut reporter = Reporter::new();
        let findings = drake::scan(config).await?;
        reporter.add_section("Ransomware Defense", findings);
        reporter.print(&self.format);
        Ok(())
    }

    async fn cmd_hunt(&self, config: &Config) -> anyhow::Result<()> {
        talon::interactive_hunt(config).await
    }

    async fn cmd_remediate(&self, config: &Config, target: &str) -> anyhow::Result<()> {
        eprintln!("{}", "  ── DragonKeep: Threat Remediation ──".red().bold());
        eprintln!();

        match target {
            "malware" => {
                hydra::remediate(config, self.dry_run).await?;
            }
            "ransomware" => {
                drake::remediate(config, self.dry_run).await?;
            }
            "all" | _ => {
                hydra::remediate(config, self.dry_run).await?;
                eprintln!();
                drake::remediate(config, self.dry_run).await?;
            }
        }
        Ok(())
    }

    async fn cmd_score(&self, config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Running Full Security Assessment ──".green().bold());

        let mut all_findings = Vec::new();

        eprintln!("    {} Sentinel...", "→".dimmed());
        all_findings.extend(sentinel::scan(config).await?);
        eprintln!("    {} Warden...", "→".dimmed());
        all_findings.extend(warden::scan(config).await?);
        eprintln!("    {} Bastion...", "→".dimmed());
        all_findings.extend(bastion::scan(config).await?);
        eprintln!("    {} Citadel...", "→".dimmed());
        all_findings.extend(citadel::audit(config).await?);
        eprintln!("    {} Phantom...", "→".dimmed());
        all_findings.extend(phantom::scan(config).await?);
        eprintln!("    {} Hydra...", "→".dimmed());
        all_findings.extend(hydra::scan(config).await?);
        eprintln!("    {} Drake...", "→".dimmed());
        all_findings.extend(drake::scan(config).await?);
        eprintln!("    {} Talon...", "→".dimmed());
        all_findings.extend(talon::hunt(config).await?);

        let score = community::calculate_security_score(&all_findings);
        community::print_security_score(&score);

        Ok(())
    }

    async fn cmd_profiles(&self) -> anyhow::Result<()> {
        community::print_profiles();
        Ok(())
    }

    async fn cmd_feeds(&self, config: &Config) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Community Threat Intelligence ──".cyan().bold());
        let mut reporter = Reporter::new();
        let findings = community::check_against_feeds(config).await?;
        reporter.add_section("Threat Intelligence", findings);
        reporter.print(&self.format);
        Ok(())
    }

    async fn cmd_canary(&self) -> anyhow::Result<()> {
        eprintln!("{}", "  ── Drake: Deploying Ransomware Canaries ──".truecolor(255, 0, 100).bold());
        drake::deploy_canaries(self.dry_run).await
    }

    async fn cmd_community(&self) -> anyhow::Result<()> {
        community::print_community_status();
        Ok(())
    }
}
