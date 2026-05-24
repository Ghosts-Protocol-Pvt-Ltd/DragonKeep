mod cli;
mod engine;
mod config;
mod report;
mod community;
pub mod compliance;
mod license;
pub mod dashboard;
pub mod scheduler;
pub mod queue;

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
    // SECURITY: Harden PATH to prevent PATH injection/hijacking attacks
    // Only allow standard system directories for subprocess execution
    // SAFETY: Called at startup before any threads are spawned, so no data races
    unsafe {
        std::env::set_var("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    }

    // SECURITY (spec 013 · self-protect): mark this process non-dumpable so
    // ptrace + core-dumps can't pull credentials / IOC store / quarantine
    // contents out of memory. Idempotent. Linux-only via prctl; macOS uses
    // a separate codesigned entitlement path; Windows has DEP+ASLR by default.
    #[cfg(target_os = "linux")]
    {
        // PR_SET_DUMPABLE = 4; SUID_DUMP_DISABLE = 0
        unsafe { libc::prctl(4, 0, 0, 0, 0); }
        // PR_SET_NAME = 15 (cosmetic but signals intent to ps/htop)
        let name = b"dragonkeep-secured\0";
        unsafe { libc::prctl(15, name.as_ptr() as libc::c_ulong, 0, 0, 0); }
    }

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
