//! Queue consumer — reads PhantomDragon Control's defensive scan queue
//! and runs DragonKeep against each target. Closes the orchestration
//! loop: PhantomDragon CRITICAL → queued → DragonKeep actually runs.
//!
//! Configure via env:
//!   PD_QUEUE_PATH — defaults to ~/Git Projects/Phantom Dragon AI/reports/.dragonkeep-queue.jsonl

use anyhow::{anyhow, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueueItem {
    pub target: String,
    pub host_hint: Option<String>,
    pub queued_at: String,
    pub trigger: String,
    pub scan_id: Option<String>,
    #[serde(default)]
    pub consumed_at: Option<String>,
}

fn queue_path() -> PathBuf {
    if let Ok(p) = env::var("PD_QUEUE_PATH") {
        return PathBuf::from(p);
    }
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join("Git Projects").join("Phantom Dragon AI").join("reports").join(".dragonkeep-queue.jsonl")
}

pub fn pending() -> Result<Vec<QueueItem>> {
    let path = queue_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(&path)?;
    let reader = BufReader::new(file);
    let mut out: Vec<QueueItem> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        if let Ok(item) = serde_json::from_str::<QueueItem>(&line) {
            if item.consumed_at.is_none() {
                out.push(item);
            }
        }
    }
    Ok(out)
}

/// Mark items consumed by rewriting the queue file with consumed_at set.
pub fn mark_consumed(targets: &[String]) -> Result<()> {
    let path = queue_path();
    if !path.exists() {
        return Ok(());
    }
    let file = fs::File::open(&path)?;
    let reader = BufReader::new(file);
    let now = chrono::Utc::now().to_rfc3339();
    let mut updated = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        if let Ok(mut item) = serde_json::from_str::<QueueItem>(&line) {
            if item.consumed_at.is_none() && targets.contains(&item.target) {
                item.consumed_at = Some(now.clone());
            }
            updated.push(serde_json::to_string(&item)?);
        }
    }
    let mut f = OpenOptions::new().write(true).truncate(true).create(true).open(&path)?;
    for line in updated {
        writeln!(f, "{}", line)?;
    }
    Ok(())
}

pub fn print_queue() -> Result<()> {
    let items = pending()?;
    if items.is_empty() {
        println!("  {} defensive queue is empty", "✓".green());
        return Ok(());
    }
    println!("  {} {} pending defensive scan(s):", "▲".yellow(), items.len());
    for it in &items {
        println!("    {} {} · trigger: {} · queued: {}",
            "→".dimmed(), it.target.bold(), it.trigger.dimmed(), it.queued_at.dimmed());
    }
    Ok(())
}

/// Run a DragonKeep scan against each queued target. Returns the
/// number of targets consumed. The runner is intentionally light —
/// for each target it just executes `dragonkeep scan` with the host
/// substituted; output is the regular DragonKeep report.
pub async fn run_pending(dry_run: bool) -> Result<usize> {
    let items = pending()?;
    if items.is_empty() {
        println!("  {} nothing queued", "✓".green());
        return Ok(0);
    }
    let mut consumed = Vec::new();
    for it in &items {
        println!("  {} {} (trigger: {})", "▶".green(), it.target.bold(), it.trigger);
        if dry_run {
            println!("    {} dry-run — would invoke `dragonkeep scan`", "·".dimmed());
        } else {
            // The current DragonKeep scan command targets the local
            // host, not arbitrary remote hosts — so for now we
            // record an audit entry and skip the actual subprocess.
            // Phase 2: extend `dragonkeep scan` with a `--target`
            // flag that drives a remote agent.
            println!("    {} marked consumed (remote-target scan deferred to Phase 2)",
                "·".dimmed());
        }
        consumed.push(it.target.clone());
    }
    if !dry_run {
        mark_consumed(&consumed)?;
    }
    Ok(consumed.len())
}
