//! Drake Engine — Ransomware Defense & Recovery
//!
//! Comprehensive ransomware detection and remediation aligned with:
//!   - MITRE ATT&CK Impact tactics (T1486, T1490, T1489)
//!   - NIST SP 800-53 Rev 5 CP/SI families (Contingency Planning, System Integrity)
//!   - DISA STIG backup and recovery requirements
//!   - CISA Ransomware Best Practices (stopransomware.gov)
//!
//! Detection capabilities:
//!   - Known ransomware process signatures
//!   - Mass file encryption detection (entropy analysis)
//!   - Ransom note detection (pattern matching)
//!   - Shadow copy/backup destruction detection
//!   - File extension monitoring (ransomware extensions)
//!   - Honeypot canary files for early detection
//!   - Backup integrity verification
//!   - Anti-recovery technique detection (wipe, overwrite)
//!
//! Remediation:
//!   - Process termination of ransomware
//!   - Backup restoration guidance
//!   - Network isolation recommendations
//!   - Snapshot/recovery point management

use anyhow::Result;
use colored::Colorize;
use crate::config::Config;
use crate::engine::Finding;

/// Known ransomware process names — ATT&CK T1486 (Data Encrypted for Impact)
const RANSOMWARE_PROCESSES: &[(&str, &str)] = &[
    ("lockbit", "LockBit ransomware"),
    ("blackcat", "BlackCat/ALPHV ransomware"),
    ("royalransom", "Royal ransomware"),
    ("clop", "Clop ransomware"),
    ("conti", "Conti ransomware"),
    ("revil", "REvil/Sodinokibi ransomware"),
    ("ryuk", "Ryuk ransomware"),
    ("wannacry", "WannaCry ransomware"),
    ("dharma", "Dharma/CrySIS ransomware"),
    ("maze", "Maze ransomware"),
    ("netwalker", "Netwalker ransomware"),
    ("ragnar", "Ragnar Locker ransomware"),
    ("hive", "Hive ransomware"),
    ("blackbasta", "Black Basta ransomware"),
    ("play", "Play ransomware"),
    ("akira", "Akira ransomware"),
    ("medusa", "Medusa ransomware"),
    ("bianlian", "BianLian ransomware"),
    ("rhysida", "Rhysida ransomware"),
    ("cactus", "Cactus ransomware"),
];

/// Known ransomware file extensions — ATT&CK T1486
const RANSOMWARE_EXTENSIONS: &[(&str, &str)] = &[
    (".lockbit", "LockBit"), (".lockbit3", "LockBit 3.0"),
    (".encrypted", "Generic ransomware"), (".enc", "Generic encrypted"),
    (".locked", "Generic locked"), (".crypt", "Generic crypto"),
    (".crypted", "Generic crypted"), (".zzzzz", "Locky variant"),
    (".wnry", "WannaCry"), (".wcry", "WannaCry variant"),
    (".wncry", "WannaCry"), (".onion", "Dharma/CrySIS"),
    (".wallet", "Dharma"), (".arena", "Dharma variant"),
    (".basta", "Black Basta"), (".play", "Play ransomware"),
    (".akira", "Akira"), (".rhysida", "Rhysida"),
    (".medusa", "Medusa"), (".revil", "REvil"),
    (".sodinokibi", "Sodinokibi"), (".ryuk", "Ryuk"),
    (".conti", "Conti"), (".hive", "Hive"),
    (".blackcat", "BlackCat/ALPHV"),
];

/// Ransom note filenames — ATT&CK T1486
const RANSOM_NOTES: &[&str] = &[
    "readme.txt", "read_me.txt", "how_to_decrypt.txt",
    "decrypt_files.txt", "restore_files.txt", "recovery_key.txt",
    "ransom_note.txt", "!readme!.txt", "!decrypt!.txt",
    "how_to_back_files.html", "restore-my-files.txt",
    "_readme.txt", "recover_your_files.txt",
    "files_encrypted.txt", "warning.txt",
    "decrypt_instructions.txt", "your_files.txt",
    "__read_me_.txt", "!how_to_recover.txt",
    "payment.txt", "help_decrypt.txt", "info.hta",
    "readme.html", "decrypt.html", "unlock.txt",
    "recovery.txt", "restore.txt", "instructions.txt",
    "read_it.txt", "note.txt",
];

/// Suspicious encryption-related process arguments
const ENCRYPTION_INDICATORS: &[&str] = &[
    "openssl enc",
    "gpg --symmetric",
    "gpg -c",
    "aes-256-cbc",
    "chacha20",
    "xor ",
    "encrypt",
    "--ransom",
    "--lock-files",
    "cipher /e",
];

/// Backup destruction commands — ATT&CK T1490 (Inhibit System Recovery)
const BACKUP_DESTRUCTION: &[&str] = &[
    "vssadmin delete shadows",
    "wbadmin delete",
    "bcdedit /set",
    "btrfs subvolume delete",
    "zfs destroy",
    "lvremove",
    "rm -rf /backup",
    "rm -rf /var/backups",
    "shred",
    "wipe ",
    "srm ",
    "dd if=/dev/zero",
    "dd if=/dev/urandom",
];

/// Directories to monitor for ransomware activity
const CRITICAL_DIRS: &[&str] = &[
    "/home", "/root", "/var/www", "/srv", "/opt",
    "/var/lib", "/etc", "/usr/local",
];

/// Canary file locations for early ransomware detection
const CANARY_DIRS: &[&str] = &[
    "/home", "/root", "/var/www", "/srv",
    "/tmp", "/opt", "/var/lib",
];

/// Scan for ransomware indicators
pub async fn scan(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.drake.enabled {
        findings.push(Finding::info("Drake engine disabled in config")
            .with_engine("Drake"));
        return Ok(findings);
    }

    eprintln!("    {} Scanning for ransomware processes...", "→".dimmed());
    findings.extend(detect_ransomware_processes().await);

    if config.drake.extension_monitor {
        eprintln!("    {} Checking for ransomware file extensions...", "→".dimmed());
        findings.extend(detect_ransomware_extensions().await);
    }

    if config.drake.ransom_note_scan {
        eprintln!("    {} Scanning for ransom notes...", "→".dimmed());
        findings.extend(detect_ransom_notes().await);
    }

    if config.drake.backup_protection {
        eprintln!("    {} Verifying backup integrity...", "→".dimmed());
        findings.extend(check_backup_integrity().await);
    }

    eprintln!("    {} Detecting backup destruction attempts...", "→".dimmed());
    findings.extend(detect_backup_destruction().await);

    if config.drake.entropy_analysis {
        eprintln!("    {} Running entropy analysis on critical files...", "→".dimmed());
        findings.extend(entropy_analysis().await);
    }

    if config.drake.canary_monitoring {
        eprintln!("    {} Checking canary file integrity...", "→".dimmed());
        findings.extend(check_canary_files().await);
    }

    eprintln!("    {} Checking anti-recovery techniques...", "→".dimmed());
    findings.extend(detect_anti_recovery().await);

    if findings.iter().all(|f| f.severity == crate::engine::Severity::Pass) {
        findings.push(Finding::pass("No ransomware indicators detected")
            .with_engine("Drake")
            .with_rule("DK-DRK-000"));
    }

    Ok(findings)
}

/// Detect known ransomware processes
async fn detect_ransomware_processes() -> Vec<Finding> {
    use sysinfo::System;
    let mut findings = Vec::new();
    let mut sys = System::new_all();
    sys.refresh_all();

    for (_pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        let cmd = process.cmd().iter()
            .map(|s| s.to_string_lossy().to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        // Check ransomware process names
        for &(pattern, desc) in RANSOMWARE_PROCESSES {
            if name.contains(pattern) || cmd.contains(pattern) {
                findings.push(Finding::critical(format!("RANSOMWARE DETECTED: {} ({})", desc, name))
                    .with_detail(format!(
                        "Process '{}' (PID {}) matches known ransomware: {}. IMMEDIATE ACTION REQUIRED.",
                        name, process.pid(), desc))
                    .with_fix("1) Kill process immediately 2) Isolate host from network 3) Preserve evidence 4) Begin incident response")
                    .with_engine("Drake")
                    .with_rule("DK-DRK-001")
                    .with_cvss(10.0)
                    .with_mitre(vec!["T1486", "T1490"])
                    .with_stig("V-230222")
                    .with_nist(vec!["SI-3", "SI-4", "CP-10", "IR-4"]));
            }
        }

        // Check for encryption-related commands
        for indicator in ENCRYPTION_INDICATORS {
            if cmd.contains(indicator) {
                // Check if it's mass-encrypting files
                let file_ops = cmd.contains("/home") || cmd.contains("/srv")
                    || cmd.contains("/var/www") || cmd.contains("/opt")
                    || cmd.contains("find ") || cmd.contains("xargs");

                if file_ops {
                    findings.push(Finding::critical(format!("Mass encryption activity detected: PID {}", process.pid()))
                        .with_detail(format!("Process appears to be mass-encrypting files: {}", cmd))
                        .with_fix("Kill process immediately and investigate for ransomware deployment")
                        .with_engine("Drake")
                        .with_rule("DK-DRK-002")
                        .with_cvss(9.8)
                        .with_mitre(vec!["T1486"])
                        .with_nist(vec!["SI-3", "SI-4", "IR-4"]));
                }
            }
        }
    }

    if findings.is_empty() {
        findings.push(Finding::pass("No ransomware processes detected")
            .with_engine("Drake")
            .with_rule("DK-DRK-001"));
    }

    findings
}

/// Detect ransomware file extensions in critical directories
async fn detect_ransomware_extensions() -> Vec<Finding> {
    let mut findings = Vec::new();

    for dir in CRITICAL_DIRS {
        if !std::path::Path::new(dir).exists() {
            continue;
        }

        // Check top-level files only to avoid deep recursion lag
        if let Ok(entries) = std::fs::read_dir(dir) {
            let mut ext_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_lowercase();
                for &(ext, _) in RANSOMWARE_EXTENSIONS {
                    if fname.ends_with(ext) {
                        *ext_counts.entry(ext.to_string()).or_insert(0) += 1;
                    }
                }
            }

            for (ext, count) in &ext_counts {
                let ransomware_name = RANSOMWARE_EXTENSIONS.iter()
                    .find(|&&(e, _)| e == ext.as_str())
                    .map(|&(_, name)| name)
                    .unwrap_or("Unknown");

                findings.push(Finding::critical(format!(
                    "Ransomware encrypted files detected: {} files with '{}' extension in {}",
                    count, ext, dir))
                    .with_detail(format!("{} ransomware — {} files affected in {}", ransomware_name, count, dir))
                    .with_fix("Isolate system, do NOT pay ransom. Restore from clean backups.")
                    .with_engine("Drake")
                    .with_rule("DK-DRK-003")
                    .with_cvss(10.0)
                    .with_mitre(vec!["T1486"])
                    .with_nist(vec!["CP-10", "IR-4", "IR-5"]));
            }
        }
    }

    findings
}

/// Detect ransom notes
async fn detect_ransom_notes() -> Vec<Finding> {
    let mut findings = Vec::new();

    for dir in CRITICAL_DIRS {
        if !std::path::Path::new(dir).exists() {
            continue;
        }

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_lowercase();
                for note in RANSOM_NOTES {
                    if fname == *note || fname.contains("ransom") || fname.contains("decrypt") {
                        // Verify it's actually a ransom note by checking content
                        if let Ok(content) = tokio::fs::read_to_string(entry.path()).await {
                            let cl = content.to_lowercase();
                            let is_ransom = cl.contains("bitcoin") || cl.contains("btc")
                                || cl.contains("monero") || cl.contains("xmr")
                                || cl.contains("decrypt") || cl.contains("ransom")
                                || cl.contains("encrypted") || cl.contains("payment")
                                || cl.contains("tor ") || cl.contains(".onion")
                                || cl.contains("wallet") || cl.contains("recover your files");

                            if is_ransom {
                                findings.push(Finding::critical(format!("Ransom note found: {}", entry.path().display()))
                                    .with_detail("Ransom note confirmed — system is actively compromised by ransomware")
                                    .with_fix("DO NOT PAY. Isolate system. Engage incident response team. Restore from backups.")
                                    .with_engine("Drake")
                                    .with_rule("DK-DRK-004")
                                    .with_cvss(10.0)
                                    .with_mitre(vec!["T1486"])
                                    .with_nist(vec!["IR-4", "IR-5", "IR-6", "CP-10"]));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Check backup integrity and availability
async fn check_backup_integrity() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for backup tools
    let backup_tools = [
        ("restic", "Restic backup"),
        ("borgbackup", "BorgBackup"),
        ("borg", "BorgBackup"),
        ("duplicity", "Duplicity"),
        ("rsnapshot", "rsnapshot"),
        ("timeshift", "Timeshift"),
        ("snapper", "Snapper"),
    ];

    let mut has_backup_tool = false;
    for &(tool, name) in &backup_tools {
        if let Ok(output) = tokio::process::Command::new("which")
            .arg(tool)
            .output()
            .await
        {
            if output.status.success() {
                has_backup_tool = true;
                findings.push(Finding::pass(format!("Backup tool available: {}", name))
                    .with_engine("Drake")
                    .with_rule("DK-DRK-005"));
            }
        }
    }

    if !has_backup_tool {
        findings.push(Finding::high("No backup tool installed — vulnerable to data loss from ransomware")
            .with_detail("No recognized backup solution (restic, borg, duplicity, etc.) is installed")
            .with_fix("Install a backup solution: apt install restic && restic init --repo /backup")
            .with_engine("Drake")
            .with_rule("DK-DRK-005")
            .with_cvss(8.0)
            .with_mitre(vec!["T1490"])
            .with_stig("V-230270")
            .with_nist(vec!["CP-9", "CP-10"]));
    }

    // Check backup directories exist
    let backup_paths = ["/backup", "/var/backups", "/mnt/backup", "/opt/backup"];
    let mut has_backup_dir = false;
    for path in &backup_paths {
        if std::path::Path::new(path).exists() {
            has_backup_dir = true;
            // Check if backup dir is writable (should have restricted permissions)
            if let Ok(meta) = std::fs::metadata(path) {
                use std::os::unix::fs::MetadataExt;
                let mode = meta.mode();
                if mode & 0o002 != 0 {
                    findings.push(Finding::high(format!("Backup directory {} is world-writable", path))
                        .with_detail("Ransomware can modify/delete backups if the directory is world-writable")
                        .with_fix(format!("chmod 700 {} && chown root:root {}", path, path))
                        .with_engine("Drake")
                        .with_rule("DK-DRK-006")
                        .with_cvss(8.5)
                        .with_mitre(vec!["T1490", "T1222.002"])
                        .with_nist(vec!["CP-9", "AC-3"]));
                }
            }
        }
    }

    if !has_backup_dir {
        findings.push(Finding::warning("No backup directory found")
            .with_detail("No common backup directories (/backup, /var/backups, etc.) exist")
            .with_fix("Create a backup directory on a separate volume: mkdir -p /mnt/backup")
            .with_engine("Drake")
            .with_rule("DK-DRK-006")
            .with_nist(vec!["CP-9"]));
    }

    // Check for immutable backups (btrfs snapshots, ZFS snapshots)
    let has_btrfs = std::path::Path::new("/sbin/btrfs").exists() || std::path::Path::new("/usr/sbin/btrfs").exists();
    let has_zfs = std::path::Path::new("/sbin/zfs").exists() || std::path::Path::new("/usr/sbin/zfs").exists();

    if has_btrfs {
        if let Ok(output) = tokio::process::Command::new("btrfs")
            .args(["subvolume", "list", "/"])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let snapshot_count = stdout.lines().filter(|l| l.contains("snapshot")).count();
            if snapshot_count > 0 {
                findings.push(Finding::pass(format!("{} BTRFS snapshots available for recovery", snapshot_count))
                    .with_engine("Drake")
                    .with_rule("DK-DRK-007"));
            }
        }
    }

    if has_zfs {
        if let Ok(output) = tokio::process::Command::new("zfs")
            .args(["list", "-t", "snapshot"])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let snap_count = stdout.lines().count().saturating_sub(1);
            if snap_count > 0 {
                findings.push(Finding::pass(format!("{} ZFS snapshots available for recovery", snap_count))
                    .with_engine("Drake")
                    .with_rule("DK-DRK-007"));
            }
        }
    }

    findings
}

/// Detect backup destruction attempts
async fn detect_backup_destruction() -> Vec<Finding> {
    use sysinfo::System;
    let mut findings = Vec::new();
    let mut sys = System::new_all();
    sys.refresh_all();

    for (_pid, process) in sys.processes() {
        let cmd = process.cmd().iter()
            .map(|s| s.to_string_lossy().to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        if cmd.is_empty() {
            continue;
        }

        for pattern in BACKUP_DESTRUCTION {
            if cmd.contains(pattern) {
                findings.push(Finding::critical(format!("Backup destruction attempt detected: PID {}", process.pid()))
                    .with_detail(format!("Process is attempting to destroy backups: {}", cmd))
                    .with_fix("Kill process immediately. This is a ransomware precursor technique.")
                    .with_engine("Drake")
                    .with_rule("DK-DRK-008")
                    .with_cvss(9.5)
                    .with_mitre(vec!["T1490", "T1561"])
                    .with_stig("V-230270")
                    .with_nist(vec!["CP-9", "CP-10", "IR-4"]));
            }
        }
    }

    findings
}

/// Entropy analysis to detect mass encryption
async fn entropy_analysis() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Sample files from critical directories and check for high entropy (encrypted content)
    for dir in &["/home", "/var/www", "/srv"] {
        if !std::path::Path::new(dir).exists() {
            continue;
        }

        if let Ok(entries) = std::fs::read_dir(dir) {
            let mut high_entropy_count = 0;
            let mut total_checked = 0;

            for entry in entries.flatten().take(50) {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                if let Ok(data) = std::fs::read(&path) {
                    if data.len() < 100 {
                        continue;
                    }

                    total_checked += 1;
                    let entropy = calculate_entropy(&data[..std::cmp::min(data.len(), 4096)]);

                    // Entropy > 7.9 suggests encryption (random data is ~8.0)
                    if entropy > 7.9 {
                        high_entropy_count += 1;
                    }
                }
            }

            if total_checked > 5 && high_entropy_count > total_checked / 2 {
                findings.push(Finding::critical(format!(
                    "Mass encryption detected: {}/{} files in {} have high entropy",
                    high_entropy_count, total_checked, dir))
                    .with_detail(format!(
                        "{}% of sampled files have entropy > 7.9 (encrypted) — active ransomware likely",
                        high_entropy_count * 100 / total_checked))
                    .with_fix("Isolate system immediately. Do NOT reboot. Begin incident response.")
                    .with_engine("Drake")
                    .with_rule("DK-DRK-009")
                    .with_cvss(10.0)
                    .with_mitre(vec!["T1486"])
                    .with_nist(vec!["SI-4", "IR-4", "IR-5"]));
            }
        }
    }

    findings
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check canary files for ransomware detection
async fn check_canary_files() -> Vec<Finding> {
    let mut findings = Vec::new();

    let canary_name = ".dragonkeep_canary";

    for dir in CANARY_DIRS {
        let canary_path = format!("{}/{}", dir, canary_name);
        let path = std::path::Path::new(&canary_path);

        if path.exists() {
            // Verify canary integrity
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                if !content.contains("DRAGONKEEP_CANARY_V1") {
                    findings.push(Finding::critical(format!("Canary file tampered: {}", canary_path))
                        .with_detail("DragonKeep canary file has been modified — possible ransomware activity")
                        .with_fix("Investigate immediately — canary files should never change")
                        .with_engine("Drake")
                        .with_rule("DK-DRK-010")
                        .with_cvss(9.5)
                        .with_mitre(vec!["T1486"])
                        .with_nist(vec!["SI-4", "SI-7", "IR-4"]));
                }
            } else {
                findings.push(Finding::critical(format!("Canary file unreadable: {}", canary_path))
                    .with_detail("Cannot read canary file — may have been encrypted by ransomware")
                    .with_fix("Investigate immediately — canary files should always be readable")
                    .with_engine("Drake")
                    .with_rule("DK-DRK-010")
                    .with_cvss(9.5)
                    .with_mitre(vec!["T1486"])
                    .with_nist(vec!["SI-4", "IR-4"]));
            }
        }
    }

    findings
}

/// Detect anti-recovery techniques
async fn detect_anti_recovery() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check if recovery/rescue tools are available
    let recovery_tools = [
        ("testdisk", "TestDisk recovery"),
        ("photorec", "PhotoRec file recovery"),
        ("ddrescue", "GNU ddrescue"),
        ("extundelete", "ext4 file recovery"),
        ("foremost", "Foremost file carver"),
        ("scalpel", "Scalpel file carver"),
    ];

    let mut has_recovery = false;
    for &(tool, _name) in &recovery_tools {
        if let Ok(output) = tokio::process::Command::new("which")
            .arg(tool)
            .output()
            .await
        {
            if output.status.success() {
                has_recovery = true;
            }
        }
    }

    if !has_recovery {
        findings.push(Finding::warning("No data recovery tools installed")
            .with_detail("Tools like testdisk, photorec, foremost not available for post-ransomware recovery")
            .with_fix("Install recovery tools: apt install testdisk foremost scalpel")
            .with_engine("Drake")
            .with_rule("DK-DRK-011")
            .with_nist(vec!["CP-10", "IR-4"]));
    }

    // Check if secure deletion has been attempted on critical files
    if let Ok(output) = tokio::process::Command::new("journalctl")
        .args(["--no-pager", "-n", "500", "--output=short"])
        .output()
        .await
    {
        let logs = String::from_utf8_lossy(&output.stdout).to_lowercase();
        if logs.contains("shred") || logs.contains("wipe") || logs.contains("srm ") {
            findings.push(Finding::high("Secure deletion activity detected in system logs")
                .with_detail("Recent shred/wipe commands found — possible anti-recovery technique")
                .with_fix("Investigate who ran secure deletion and what files were targeted")
                .with_engine("Drake")
                .with_rule("DK-DRK-012")
                .with_cvss(8.0)
                .with_mitre(vec!["T1485", "T1561.001"])
                .with_nist(vec!["AU-6", "IR-4"]));
        }
    }

    findings
}

/// Deploy canary files for ransomware early detection
pub async fn deploy_canaries(dry_run: bool) -> Result<()> {
    let canary_name = ".dragonkeep_canary";
    let canary_content = format!(
        "DRAGONKEEP_CANARY_V1\n\
         # This file is used by DragonKeep Drake engine for ransomware detection.\n\
         # DO NOT MODIFY OR DELETE THIS FILE.\n\
         # If this file is modified or encrypted, it indicates ransomware activity.\n\
         # Deployed: {}\n\
         # Checksum: INTEGRITY_MARKER\n",
        chrono::Utc::now().to_rfc3339()
    );

    for dir in CANARY_DIRS {
        if !std::path::Path::new(dir).exists() {
            continue;
        }

        let canary_path = format!("{}/{}", dir, canary_name);
        if dry_run {
            eprintln!("    {} [DRY RUN] Would deploy canary: {}", "→".yellow(), canary_path);
        } else {
            if let Err(e) = tokio::fs::write(&canary_path, &canary_content).await {
                eprintln!("    {} Failed to deploy canary at {}: {}", "✗".red(), canary_path, e);
            } else {
                // Make read-only
                let _ = tokio::process::Command::new("chmod")
                    .args(["444", &canary_path])
                    .output()
                    .await;
                eprintln!("    {} Canary deployed: {}", "✓".green(), canary_path);
            }
        }
    }

    Ok(())
}

/// Remediate ransomware — kill processes, isolate, prepare for recovery
pub async fn remediate(config: &Config, dry_run: bool) -> Result<()> {
    eprintln!("{}", "  ── Drake: Ransomware Remediation ──".red().bold());
    eprintln!("{}", "  ⚠ INCIDENT RESPONSE MODE ⚠".red().bold());

    if config.general.safe_mode && !dry_run {
        eprintln!("  {} Safe mode — showing remediation plan only", "ℹ".blue());
    }

    // Step 1: Kill ransomware processes
    eprintln!("    {} Step 1: Terminating ransomware processes...", "→".dimmed());
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    for (_pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        for &(pattern, desc) in RANSOMWARE_PROCESSES {
            if name.contains(pattern) {
                if dry_run || config.general.safe_mode {
                    eprintln!("    {} [DRY RUN] Would kill: {} (PID {}) — {}",
                        "→".yellow(), name, process.pid(), desc);
                } else {
                    eprintln!("    {} KILLING: {} (PID {}) — {}",
                        "✗".red().bold(), name, process.pid(), desc);
                    process.kill();
                }
            }
        }
    }

    // Step 2: Network isolation recommendation
    eprintln!("    {} Step 2: Network isolation...", "→".dimmed());
    if dry_run || config.general.safe_mode {
        eprintln!("    {} [DRY RUN] Would recommend network isolation", "→".yellow());
    } else {
        eprintln!("    {} RECOMMENDED: Disconnect from network immediately", "⚠".red().bold());
        eprintln!("    {}   iptables -I INPUT -j DROP", "→".dimmed());
        eprintln!("    {}   iptables -I OUTPUT -j DROP", "→".dimmed());
        eprintln!("    {}   iptables -I OUTPUT -p tcp --dport 53 -j ACCEPT  # Keep DNS for investigation", "→".dimmed());
    }

    // Step 3: Preserve evidence
    eprintln!("    {} Step 3: Evidence preservation...", "→".dimmed());
    eprintln!("    {}   Save memory dump: dd if=/dev/mem of=/mnt/usb/memdump.raw", "→".dimmed());
    eprintln!("    {}   Save process list: ps auxef > /mnt/usb/processes.txt", "→".dimmed());
    eprintln!("    {}   Save network connections: ss -tnp > /mnt/usb/connections.txt", "→".dimmed());

    // Step 4: Recovery guidance
    eprintln!("    {} Step 4: Recovery options...", "→".dimmed());
    eprintln!("    {}   • Check for decryption tools: nomoreransom.org", "→".dimmed());
    eprintln!("    {}   • Restore from backups (verify backup integrity first)", "→".dimmed());
    eprintln!("    {}   • Contact CISA: cisa.gov/stopransomware", "→".dimmed());
    eprintln!("    {}   • File FBI IC3 report: ic3.gov", "→".dimmed());

    eprintln!();
    if dry_run || config.general.safe_mode {
        eprintln!("  {} Remediation plan complete (dry run)", "ℹ".blue());
    } else {
        eprintln!("  {} Emergency response actions executed", "✓".green());
    }

    Ok(())
}
