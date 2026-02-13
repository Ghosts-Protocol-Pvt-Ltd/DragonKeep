mod cli;
mod engine;
mod config;
mod report;
mod community;

use clap::Parser;
use cli::Cli;
use colored::Colorize;

const BANNER: &str = r#"
  ╔══════════════════════════════════════════════╗
  ║            🏰 DragonKeep                     ║
  ║    System Security & Performance Platform    ║
  ╚══════════════════════════════════════════════╝
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    if !cli.quiet {
        eprintln!("{}", BANNER.green());
    }

    cli.run().await
}
