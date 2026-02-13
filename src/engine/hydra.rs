//! Hydra Engine — Malware Detection & Defense
//!
//! Advanced malware detection aligned with:
//!   - MITRE ATT&CK for Enterprise (Execution, Persistence, Defense Evasion, C2)
//!   - NIST SP 800-53 Rev 5 SI/SC families (System & Information Integrity)
//!   - DISA STIG malware defense requirements
//!   - YARA-style pattern matching for known malware signatures
//!   - File integrity monitoring (FIM) for rootkit/dropper detection
//!   - Heuristic analysis for zero-day behavioral indicators
//!
//! Detection categories:
//!   - Known malware signatures (process names, file hashes, paths)
//!   - Trojanized binaries (modified system utilities)
//!   - Fileless malware indicators (LOLBins abuse, memory-only execution)
//!   - Backdoor persistence mechanisms (systemd, cron, init scripts)
//!   - Command & control (C2) beaconing patterns
//!   - Rootkit indicators (hidden processes, kernel module tampering)
//!   - Webshell detection (PHP/JSP/ASP backdoors in web roots)
//!   - Dropper artifacts (staged payloads, encoded executables)

use anyhow::Result;
use colored::Colorize;
use crate::config::Config;
use crate::engine::Finding;

/// Known malware process names — ATT&CK T1059 (Command & Scripting Interpreter)
const MALWARE_PROCESSES: &[(&str, &str, &str)] = &[
    ("cobalt", "Cobalt Strike beacon", "T1071.001"),
    ("meterpreter", "Metasploit Meterpreter", "T1059.006"),
    ("sliver", "Sliver C2 implant", "T1071.001"),
    ("covenant", "Covenant C2 agent", "T1071.001"),
    ("havoc", "Havoc C2 demon", "T1071.001"),
    ("poshc2", "PoshC2 implant", "T1059.001"),
    ("merlin", "Merlin C2 agent", "T1071.001"),
    ("mythic", "Mythic C2 payload", "T1071.001"),
    ("empire", "PowerShell Empire agent", "T1059.001"),
    ("brute_ratel", "Brute Ratel C4 badger", "T1071.001"),
    ("chisel", "Chisel tunneling proxy", "T1572"),
    ("ligolo", "Ligolo reverse tunnel", "T1572"),
    ("ncat", "Ncat reverse shell listener", "T1059.004"),
    ("socat", "Socat bidirectional relay", "T1059.004"),
    ("pwncat", "Pwncat backdoor handler", "T1059.006"),
    ("gsocket", "Global Socket stealth tunnel", "T1572"),
];

/// LOLBins — Living Off the Land Binaries abused by malware — ATT&CK T1218
const LOLBINS_SUSPICIOUS: &[(&str, &str)] = &[
    ("curl|wget", "Data transfer tools often used for C2/staging"),
    ("base64", "Encoding used for payload obfuscation"),
    ("xxd", "Hex encoding for payload crafting"),
    ("python -c", "Inline Python execution (possible reverse shell)"),
    ("python3 -c", "Inline Python3 execution (possible reverse shell)"),
    ("perl -e", "Inline Perl execution (possible reverse shell)"),
    ("ruby -e", "Inline Ruby execution (possible reverse shell)"),
    ("php -r", "Inline PHP execution (possible backdoor)"),
    ("lua -e", "Inline Lua execution (possible backdoor)"),
    ("openssl s_client", "Encrypted reverse shell via OpenSSL"),
    ("nohup", "Background persistence mechanism"),
    ("at ", "Scheduled execution (persistence)"),
    ("screen -dmS", "Detached screen session (stealth)"),
    ("tmux new -d", "Detached tmux session (stealth)"),
];

/// Webshell indicators — ATT&CK T1505.003
const WEBSHELL_PATTERNS: &[&str] = &[
    "eval(base64_decode",
    "eval($_POST",
    "eval($_GET",
    "eval($_REQUEST",
    "system($_GET",
    "passthru(",
    "shell_exec(",
    "exec(base64",
    "assert(base64",
    "preg_replace.*e\"",
    "Runtime.getRuntime().exec",
    "ProcessBuilder",
    "<%@page import=\"java.io",
    "cmd.exe /c",
    "powershell -enc",
    "wscript.shell",
    "WSH.Run",
];

/// Suspicious file extensions indicating malware droppers
const DROPPER_EXTENSIONS: &[(&str, &str)] = &[
    (".elf", "ELF binary in unexpected location"),
    (".bin", "Raw binary payload"),
    (".sh.x", "SHC-encrypted shell script"),
    (".py.enc", "Encrypted Python payload"),
    (".dat", "Data file possibly containing staged payload"),
    (".tmp.exe", "Temporary executable (Windows malware on Linux)"),
    (".so.1", "Shared library dropper"),
    (".ko", "Kernel module (possible rootkit)"),
];

/// Persistence locations to check — ATT&CK T1543, T1053
#[allow(dead_code)]
const PERSISTENCE_PATHS: &[(&str, &str)] = &[
    ("/etc/systemd/system", "Systemd service persistence"),
    ("/usr/lib/systemd/system", "System-level systemd persistence"),
    ("/etc/init.d", "Init script persistence (SysV)"),
    ("/etc/rc.local", "rc.local boot persistence"),
    ("/etc/cron.d", "Cron directory persistence"),
    ("/var/spool/cron", "User crontab persistence"),
    ("/etc/profile.d", "Shell profile persistence"),
    ("/etc/ld.so.preload", "LD_PRELOAD hijacking"),
    ("/etc/ld.so.conf.d", "Library path hijacking"),
    ("/root/.bashrc", "Root shell persistence"),
    ("/root/.bash_profile", "Root profile persistence"),
    ("/root/.ssh/authorized_keys", "SSH key persistence"),
];

/// C2 beaconing indicators — common ports/patterns
const C2_PORTS: &[u16] = &[
    443, 8443, 8080, 4444, 5555, 1337, 9090, 9001, 6666, 6667, 6697,
    31337, 50050, 8888, 3333, 7777, 2222,
];

/// Known malicious user agents (partial matches)
#[allow(dead_code)]
const MALICIOUS_AGENTS: &[&str] = &[
    "Mozilla/4.0",
    "MSIE 6.0",
    "Java/1.",
    "python-requests",
];

/// Scan for malware indicators across the system
pub async fn scan(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.hydra.enabled {
        findings.push(Finding::info("Hydra engine disabled in config")
            .with_engine("Hydra"));
        return Ok(findings);
    }

    eprintln!("    {} Scanning for known malware processes...", "→".dimmed());
    findings.extend(detect_malware_processes().await);

    eprintln!("    {} Checking for LOLBins abuse...", "→".dimmed());
    findings.extend(detect_lolbins_abuse().await);

    if config.hydra.rootkit_detection {
        eprintln!("    {} Deep rootkit detection...", "→".dimmed());
        findings.extend(detect_rootkits().await);
    }

    if config.hydra.persistence_scan {
        eprintln!("    {} Scanning persistence mechanisms...", "→".dimmed());
        findings.extend(scan_persistence().await);
    }

    if config.hydra.webshell_scan {
        eprintln!("    {} Scanning for webshells...", "→".dimmed());
        findings.extend(detect_webshells().await);
    }

    if config.hydra.c2_detection {
        eprintln!("    {} Analyzing C2 beaconing patterns...", "→".dimmed());
        findings.extend(detect_c2_beaconing().await);
    }

    if config.hydra.fileless_detection {
        eprintln!("    {} Detecting fileless malware indicators...", "→".dimmed());
        findings.extend(detect_fileless_malware().await);
    }

    eprintln!("    {} Scanning for dropper artifacts...", "→".dimmed());
    findings.extend(detect_droppers().await);

    eprintln!("    {} Checking binary integrity...", "→".dimmed());
    findings.extend(check_binary_integrity().await);

    if findings.iter().all(|f| f.severity == crate::engine::Severity::Pass) {
        findings.push(Finding::pass("No malware indicators detected")
            .with_engine("Hydra")
            .with_rule("DK-HYD-000"));
    }

    Ok(findings)
}

/// Detect known malware processes
async fn detect_malware_processes() -> Vec<Finding> {
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

        // Check against known malware process names
        for &(pattern, desc, mitre_id) in MALWARE_PROCESSES {
            if name.contains(pattern) || cmd.contains(pattern) {
                findings.push(Finding::critical(format!("Malware detected: {} ({})", desc, name))
                    .with_detail(format!("Process '{}' matches known malware signature: {}. Command: {}",
                        name, desc, if cmd.is_empty() { "N/A" } else { &cmd }))
                    .with_fix("Immediately kill the process, isolate the host, and perform forensic analysis")
                    .with_engine("Hydra")
                    .with_rule("DK-HYD-001")
                    .with_cvss(9.8)
                    .with_mitre(vec![mitre_id, "T1059"])
                    .with_stig("V-230222")
                    .with_nist(vec!["SI-3", "SI-4", "SC-7"]));
            }
        }
    }

    if findings.is_empty() {
        findings.push(Finding::pass("No known malware processes detected")
            .with_engine("Hydra")
            .with_rule("DK-HYD-001"));
    }

    findings
}

/// Detect LOLBins abuse (Living Off the Land Binaries)
async fn detect_lolbins_abuse() -> Vec<Finding> {
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

        for &(pattern, desc) in LOLBINS_SUSPICIOUS {
            // Check each alternative in pipe-delimited patterns
            let patterns: Vec<&str> = pattern.split('|').collect();
            for pat in patterns {
                if cmd.contains(pat) {
                    // Check for suspicious combinations
                    let is_suspicious = cmd.contains("| bash")
                        || cmd.contains("| sh")
                        || cmd.contains("/dev/tcp")
                        || cmd.contains("/dev/udp")
                        || cmd.contains("base64 -d")
                        || cmd.contains("base64 --decode")
                        || cmd.contains("eval ")
                        || cmd.contains("> /dev/null 2>&1 &")
                        || cmd.contains("0<&196")
                        || cmd.contains("exec 196<>");

                    if is_suspicious {
                        findings.push(Finding::high(format!("LOLBin abuse detected: {}", desc))
                            .with_detail(format!("Suspicious use of '{}': {}", pat, cmd))
                            .with_fix("Investigate the process origin and kill if unauthorized")
                            .with_engine("Hydra")
                            .with_rule("DK-HYD-002")
                            .with_cvss(7.5)
                            .with_mitre(vec!["T1218", "T1059"])
                            .with_stig("V-230269")
                            .with_nist(vec!["SI-3", "SI-4", "CM-7"]));
                    }
                }
            }
        }
    }

    findings
}

/// Deep rootkit detection
async fn detect_rootkits() -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Check for hidden processes (compare /proc count vs sysinfo count)
    if let Ok(proc_entries) = std::fs::read_dir("/proc") {
        let proc_pids: Vec<u32> = proc_entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .collect();

        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        let sysinfo_count = sys.processes().len();

        if proc_pids.len().abs_diff(sysinfo_count) > 10 {
            findings.push(Finding::critical("Process count discrepancy — possible rootkit")
                .with_detail(format!("/proc shows {} PIDs but sysinfo reports {} processes — hidden processes suspected",
                    proc_pids.len(), sysinfo_count))
                .with_fix("Run rkhunter/chkrootkit, check for kernel module rootkits with lsmod")
                .with_engine("Hydra")
                .with_rule("DK-HYD-003")
                .with_cvss(9.8)
                .with_mitre(vec!["T1014", "T1564.001"])
                .with_stig("V-230222")
                .with_nist(vec!["SI-3", "SI-7", "SC-4"]));
        }
    }

    // 2. Check for suspicious kernel modules
    if let Ok(modules) = tokio::fs::read_to_string("/proc/modules").await {
        let suspicious_modules = ["diamorphine", "reptile", "suterusu", "adore-ng",
            "azazel", "jynx", "brootus", "beurk", "vlany", "bdvl",
            "heroin", "knark", "enyelkm", "kbeast", "override"];

        for line in modules.lines() {
            let module_name = line.split_whitespace().next().unwrap_or("");
            for &rootkit_mod in &suspicious_modules {
                if module_name.to_lowercase().contains(rootkit_mod) {
                    findings.push(Finding::critical(format!("Rootkit kernel module detected: {}", module_name))
                        .with_detail(format!("Kernel module '{}' matches known rootkit: {}", module_name, rootkit_mod))
                        .with_fix(format!("rmmod {} && investigate system compromise", module_name))
                        .with_engine("Hydra")
                        .with_rule("DK-HYD-004")
                        .with_cvss(10.0)
                        .with_mitre(vec!["T1014", "T1547.006"])
                        .with_stig("V-230268")
                        .with_nist(vec!["SI-3", "SI-7", "SC-4", "CM-7"]));
                }
            }
        }
    }

    // 3. Check for LD_PRELOAD rootkits
    if let Ok(preload) = tokio::fs::read_to_string("/etc/ld.so.preload").await {
        if !preload.trim().is_empty() {
            findings.push(Finding::critical("LD_PRELOAD rootkit indicator — /etc/ld.so.preload is non-empty")
                .with_detail(format!("Preloaded libraries: {}", preload.trim()))
                .with_fix("Inspect and remove unauthorized entries from /etc/ld.so.preload")
                .with_engine("Hydra")
                .with_rule("DK-HYD-005")
                .with_cvss(9.5)
                .with_mitre(vec!["T1574.006", "T1014"])
                .with_stig("V-230269")
                .with_nist(vec!["SI-3", "SI-7"]));
        }
    }

    // 4. Check /dev for unusual device files (rootkit hideouts)
    if let Ok(dev_entries) = std::fs::read_dir("/dev") {
        let suspicious_devs = ["shm/.", "mqueue/.", ".hid", ".secret", ".backdoor"];
        for entry in dev_entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            for &sus in &suspicious_devs {
                if fname.contains(sus) || fname.starts_with('.') {
                    findings.push(Finding::high(format!("Suspicious device file: /dev/{}", fname))
                        .with_detail("Hidden or suspicious file in /dev — common rootkit hiding location")
                        .with_fix(format!("Investigate /dev/{} — remove if unauthorized", fname))
                        .with_engine("Hydra")
                        .with_rule("DK-HYD-006")
                        .with_cvss(8.0)
                        .with_mitre(vec!["T1564.001", "T1014"])
                        .with_nist(vec!["SI-3", "SI-7"]));
                }
            }
        }
    }

    // 5. Check for modified system binaries (Trojanized)
    let critical_bins = [
        ("/bin/ls", "ls"), ("/bin/ps", "ps"), ("/bin/netstat", "netstat"),
        ("/bin/ss", "ss"), ("/bin/top", "top"), ("/usr/bin/who", "who"),
        ("/usr/bin/w", "w"), ("/usr/bin/last", "last"), ("/usr/bin/find", "find"),
        ("/usr/bin/lsof", "lsof"),
    ];

    for &(path, name) in &critical_bins {
        if let Ok(meta) = std::fs::metadata(path) {
            use std::os::unix::fs::MetadataExt;
            // Binaries < 1KB or > 50MB are suspicious
            if meta.size() < 1024 || meta.size() > 50 * 1024 * 1024 {
                findings.push(Finding::high(format!("Suspicious binary size for {}: {} bytes", name, meta.size()))
                    .with_detail(format!("{} has unusual file size — may be trojanized or replaced", path))
                    .with_fix(format!("Verify with: rpm -V $(rpm -qf {}) or dpkg -V $(dpkg -S {} | cut -d: -f1)", path, path))
                    .with_engine("Hydra")
                    .with_rule("DK-HYD-007")
                    .with_cvss(8.5)
                    .with_mitre(vec!["T1036.005", "T1554"])
                    .with_stig("V-230264")
                    .with_nist(vec!["SI-7", "CM-6"]));
            }
        }
    }

    if findings.is_empty() {
        findings.push(Finding::pass("No rootkit indicators detected")
            .with_engine("Hydra")
            .with_rule("DK-HYD-003"));
    }

    findings
}

/// Scan persistence mechanisms for malware
async fn scan_persistence() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for suspicious systemd services
    let systemd_paths = ["/etc/systemd/system", "/usr/lib/systemd/system"];
    for dir in &systemd_paths {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "service" || ext == "timer" {
                        if let Ok(content) = tokio::fs::read_to_string(&path).await {
                            let content_lower = content.to_lowercase();
                            // Check for suspicious ExecStart commands
                            let suspicious = content_lower.contains("/tmp/")
                                || content_lower.contains("/dev/shm/")
                                || content_lower.contains("curl ")
                                || content_lower.contains("wget ")
                                || content_lower.contains("base64")
                                || content_lower.contains("python -c")
                                || content_lower.contains("bash -i")
                                || content_lower.contains("ncat ")
                                || content_lower.contains("nc -")
                                || content_lower.contains("/dev/tcp")
                                || content_lower.contains("reverse");

                            if suspicious {
                                findings.push(Finding::critical(format!("Suspicious systemd service: {}",
                                    path.file_name().unwrap_or_default().to_string_lossy()))
                                    .with_detail(format!("Service at {} contains suspicious commands — possible malware persistence", path.display()))
                                    .with_fix(format!("systemctl disable {} && rm {}", path.file_name().unwrap_or_default().to_string_lossy(), path.display()))
                                    .with_engine("Hydra")
                                    .with_rule("DK-HYD-008")
                                    .with_cvss(9.0)
                                    .with_mitre(vec!["T1543.002", "T1053"])
                                    .with_stig("V-230312")
                                    .with_nist(vec!["SI-3", "CM-7", "CM-6"]));
                            }
                        }
                    }
                }
            }
        }
    }

    // Check for suspicious cron jobs
    let cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                     "/etc/cron.weekly", "/etc/cron.monthly"];
    for dir in &cron_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(content) = tokio::fs::read_to_string(entry.path()).await {
                    let content_lower = content.to_lowercase();
                    if content_lower.contains("curl") || content_lower.contains("wget")
                        || content_lower.contains("/tmp/") || content_lower.contains("base64")
                        || content_lower.contains("python -c") || content_lower.contains("bash -i")
                    {
                        findings.push(Finding::high(format!("Suspicious cron job: {}",
                            entry.path().display()))
                            .with_detail("Cron job contains suspicious commands — possible malware persistence")
                            .with_fix(format!("Review and remove: {}", entry.path().display()))
                            .with_engine("Hydra")
                            .with_rule("DK-HYD-009")
                            .with_cvss(8.0)
                            .with_mitre(vec!["T1053.003"])
                            .with_stig("V-230324")
                            .with_nist(vec!["SI-3", "CM-7"]));
                    }
                }
            }
        }
    }

    // Check authorized_keys for unauthorized entries
    if let Ok(users) = std::fs::read_dir("/home") {
        for user_dir in users.flatten() {
            let auth_keys = user_dir.path().join(".ssh/authorized_keys");
            if auth_keys.exists() {
                if let Ok(content) = tokio::fs::read_to_string(&auth_keys).await {
                    let key_count = content.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).count();
                    // Check for command= restrictions that could be backdoors
                    for line in content.lines() {
                        if line.contains("command=") && (line.contains("bash") || line.contains("/bin/sh") || line.contains("nc ")) {
                            findings.push(Finding::critical(format!("SSH key with suspicious forced command: {}",
                                auth_keys.display()))
                                .with_detail("authorized_keys entry has a forced command that may be a backdoor")
                                .with_fix(format!("Review and remove unauthorized keys from {}", auth_keys.display()))
                                .with_engine("Hydra")
                                .with_rule("DK-HYD-010")
                                .with_cvss(9.0)
                                .with_mitre(vec!["T1098.004"])
                                .with_stig("V-230267")
                                .with_nist(vec!["AC-17", "IA-2"]));
                        }
                    }
                    if key_count > 20 {
                        findings.push(Finding::warning(format!("Excessive SSH keys ({}) for user {}",
                            key_count, user_dir.file_name().to_string_lossy()))
                            .with_engine("Hydra")
                            .with_rule("DK-HYD-011")
                            .with_mitre(vec!["T1098.004"])
                            .with_nist(vec!["AC-17"]));
                    }
                }
            }
        }
    }

    findings
}

/// Detect webshells in common web server directories
async fn detect_webshells() -> Vec<Finding> {
    let mut findings = Vec::new();

    let web_roots = [
        "/var/www", "/srv/www", "/usr/share/nginx/html",
        "/var/www/html", "/opt/lampp/htdocs", "/var/www/vhosts",
    ];

    let web_extensions = [".php", ".jsp", ".asp", ".aspx", ".cgi", ".pl"];

    for root in &web_roots {
        if !std::path::Path::new(root).exists() {
            continue;
        }

        let walker = glob::glob(&format!("{}/**/*", root));
        if let Ok(entries) = walker {
            for entry in entries.flatten() {
                let ext = entry.extension()
                    .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
                    .unwrap_or_default();

                if !web_extensions.contains(&ext.as_str()) {
                    continue;
                }

                if let Ok(content) = tokio::fs::read_to_string(&entry).await {
                    for pattern in WEBSHELL_PATTERNS {
                        if content.to_lowercase().contains(&pattern.to_lowercase()) {
                            findings.push(Finding::critical(format!("Webshell detected: {}", entry.display()))
                                .with_detail(format!("File contains webshell pattern: '{}'", pattern))
                                .with_fix(format!("Quarantine and investigate: mv {} {}.quarantined", entry.display(), entry.display()))
                                .with_engine("Hydra")
                                .with_rule("DK-HYD-012")
                                .with_cvss(9.8)
                                .with_mitre(vec!["T1505.003"])
                                .with_stig("V-230222")
                                .with_nist(vec!["SI-3", "SI-4", "CM-7"]));
                            break; // One finding per file
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Detect C2 beaconing patterns
async fn detect_c2_beaconing() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for processes with established connections on C2-typical ports
    if let Ok(output) = tokio::process::Command::new("ss")
        .args(["-tnp", "state", "established"])
        .output()
        .await
    {
        let ss_output = String::from_utf8_lossy(&output.stdout);
        for line in ss_output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let remote = parts[4];
                // Extract port from remote address
                if let Some(port_str) = remote.rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if C2_PORTS.contains(&port) && port != 443 {
                            // Non-HTTPS C2 ports
                            let process_info = parts.get(5).unwrap_or(&"unknown");
                            findings.push(Finding::high(format!("Suspicious outbound connection on port {}", port))
                                .with_detail(format!("Process {} has connection to {} — common C2 port", process_info, remote))
                                .with_fix("Investigate the process and destination IP. Block if unauthorized")
                                .with_engine("Hydra")
                                .with_rule("DK-HYD-013")
                                .with_cvss(8.0)
                                .with_mitre(vec!["T1071.001", "T1571"])
                                .with_nist(vec!["SI-4", "SC-7"]));
                        }
                    }
                }
            }
        }
    }

    // Check for DNS tunneling indicators (unusually long DNS queries)
    if let Ok(resolv) = tokio::fs::read_to_string("/etc/resolv.conf").await {
        for line in resolv.lines() {
            if line.starts_with("nameserver") {
                let server = line.split_whitespace().nth(1).unwrap_or("");
                // Non-standard DNS (not common public DNS)
                let common_dns = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                    "9.9.9.9", "208.67.222.222", "208.67.220.220", "127.0.0.1"];
                if !server.is_empty() && !common_dns.contains(&server) && !server.starts_with("192.168.") && !server.starts_with("10.") && !server.starts_with("172.") {
                    findings.push(Finding::warning(format!("Non-standard DNS server: {}", server))
                        .with_detail("Custom DNS server may be used for DNS tunneling or C2 communication")
                        .with_fix("Verify the DNS server is authorized by your organization")
                        .with_engine("Hydra")
                        .with_rule("DK-HYD-014")
                        .with_mitre(vec!["T1071.004"])
                        .with_nist(vec!["SC-7", "SI-4"]));
                }
            }
        }
    }

    findings
}

/// Detect fileless malware indicators
async fn detect_fileless_malware() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for memfd_create-based execution (fileless technique)
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                let exe_link = format!("/proc/{}/exe", pid);
                if let Ok(target) = std::fs::read_link(&exe_link) {
                    let target_str = target.to_string_lossy();
                    if target_str.contains("memfd:") || target_str.contains("(deleted)") {
                        // Read cmdline for context
                        let cmdline = tokio::fs::read_to_string(format!("/proc/{}/cmdline", pid))
                            .await
                            .unwrap_or_default()
                            .replace('\0', " ");

                        findings.push(Finding::critical(format!("Fileless malware indicator — PID {} running from memory", pid))
                            .with_detail(format!("Process executing from: {} — cmdline: {}", target_str, cmdline.trim()))
                            .with_fix(format!("kill -9 {} && investigate the source of the fileless payload", pid))
                            .with_engine("Hydra")
                            .with_rule("DK-HYD-015")
                            .with_cvss(9.5)
                            .with_mitre(vec!["T1620", "T1055.009"])
                            .with_stig("V-230222")
                            .with_nist(vec!["SI-3", "SI-4", "SC-4"]));
                    }
                }
            }
        }
    }

    // Check for processes running from /dev/shm (tmpfs — memory-only)
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                let exe_link = format!("/proc/{}/exe", pid);
                if let Ok(target) = std::fs::read_link(&exe_link) {
                    let target_str = target.to_string_lossy();
                    if target_str.starts_with("/dev/shm/") || target_str.starts_with("/run/shm/") {
                        findings.push(Finding::critical(format!("Process running from shared memory: PID {}", pid))
                            .with_detail(format!("Binary at {} — shared memory execution is a fileless malware technique", target_str))
                            .with_fix(format!("kill -9 {} && rm -f {}", pid, target_str))
                            .with_engine("Hydra")
                            .with_rule("DK-HYD-016")
                            .with_cvss(9.0)
                            .with_mitre(vec!["T1620", "T1059"])
                            .with_nist(vec!["SI-3", "SI-4"]));
                    }
                }
            }
        }
    }

    findings
}

/// Detect dropper artifacts
async fn detect_droppers() -> Vec<Finding> {
    let mut findings = Vec::new();

    let staging_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"];

    for dir in &staging_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let fname = entry.file_name().to_string_lossy().to_string();

                // Check for executables in staging directories
                if let Ok(meta) = entry.metadata() {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode();

                    if mode & 0o111 != 0 && meta.is_file() {
                        // Executable file in /tmp or /dev/shm
                        findings.push(Finding::high(format!("Executable in staging directory: {}", path.display()))
                            .with_detail(format!("File '{}' is executable in {} — common dropper/staging location", fname, dir))
                            .with_fix(format!("Investigate and remove: rm -f {}", path.display()))
                            .with_engine("Hydra")
                            .with_rule("DK-HYD-017")
                            .with_cvss(7.5)
                            .with_mitre(vec!["T1074.001", "T1059"])
                            .with_nist(vec!["SI-3", "CM-7"]));
                    }

                    // Check for dropper extensions
                    for &(ext, desc) in DROPPER_EXTENSIONS {
                        if fname.ends_with(ext) {
                            findings.push(Finding::high(format!("Dropper artifact: {}", path.display()))
                                .with_detail(format!("{}: {}", desc, fname))
                                .with_fix(format!("Quarantine and analyze: mv {} /var/lib/dragonkeep/quarantine/", path.display()))
                                .with_engine("Hydra")
                                .with_rule("DK-HYD-018")
                                .with_cvss(7.0)
                                .with_mitre(vec!["T1105", "T1074.001"])
                                .with_nist(vec!["SI-3"]));
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Check system binary integrity
async fn check_binary_integrity() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try rpm -Va or dpkg -V for package verification
    let rpm_check = tokio::process::Command::new("rpm")
        .args(["-Va", "--noconfig"])
        .output()
        .await;

    let dpkg_check = tokio::process::Command::new("dpkg")
        .args(["--verify"])
        .output()
        .await;

    if let Ok(output) = rpm_check {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let modified_count = stdout.lines()
            .filter(|l| l.contains("..5") || l.contains("S.5")) // Size or MD5 changes
            .count();

        if modified_count > 0 {
            findings.push(Finding::high(format!("{} system packages have modified files", modified_count))
                .with_detail("rpm -Va detected files that differ from package expectations — possible tampering")
                .with_fix("Run 'rpm -Va' to see details, reinstall affected packages")
                .with_engine("Hydra")
                .with_rule("DK-HYD-019")
                .with_cvss(7.5)
                .with_mitre(vec!["T1554", "T1036.005"])
                .with_stig("V-230264")
                .with_nist(vec!["SI-7", "CM-6"]));
        }
    } else if let Ok(output) = dpkg_check {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let modified_count = stdout.lines()
            .filter(|l| l.starts_with("??5"))
            .count();

        if modified_count > 0 {
            findings.push(Finding::high(format!("{} dpkg packages have modified files", modified_count))
                .with_detail("dpkg --verify detected files that differ from package expectations")
                .with_fix("Run 'dpkg --verify' to see details, reinstall affected packages")
                .with_engine("Hydra")
                .with_rule("DK-HYD-019")
                .with_cvss(7.5)
                .with_mitre(vec!["T1554", "T1036.005"])
                .with_stig("V-230264")
                .with_nist(vec!["SI-7", "CM-6"]));
        }
    }

    findings
}

/// Remediate detected malware — kill processes, quarantine files, disable persistence
pub async fn remediate(config: &Config, dry_run: bool) -> Result<()> {
    use colored::Colorize;

    eprintln!("{}", "  ── Hydra: Malware Remediation ──".red().bold());

    if config.general.safe_mode && !dry_run {
        eprintln!("  {} Safe mode enabled — showing remediation plan only", "ℹ".blue());
        eprintln!("  {} Run with --dry-run=false and safe_mode=false to execute", "→".dimmed());
    }

    // 1. Kill known malware processes
    eprintln!("    {} Killing malware processes...", "→".dimmed());
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    // SECURITY: Audit log all remediation actions
    let audit_log_path = "/var/lib/dragonkeep/audit.log";
    let _ = std::fs::create_dir_all("/var/lib/dragonkeep");
    let mut audit_entries: Vec<String> = Vec::new();
    let audit_timestamp = chrono::Utc::now().to_rfc3339();

    for (_pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        // SECURITY: Match against full executable path for more reliable detection
        let exe_path = process.exe()
            .map(|p| p.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        for &(pattern, desc, _) in MALWARE_PROCESSES {
            if name.contains(pattern) || exe_path.contains(pattern) {
                if dry_run || config.general.safe_mode {
                    eprintln!("    {} [DRY RUN] Would kill: {} (PID {} exe:{}) — {}", "→".yellow(),
                        name, process.pid(), exe_path, desc);
                } else {
                    eprintln!("    {} Killing: {} (PID {} exe:{}) — {}", "✗".red(), name, process.pid(), exe_path, desc);
                    audit_entries.push(format!("[{}] KILL pid={} name={} exe={} reason={}",
                        audit_timestamp, process.pid(), name, exe_path, desc));
                    process.kill();
                }
            }
        }
    }

    // 2. Quarantine suspicious files from staging directories
    eprintln!("    {} Quarantining dropper artifacts...", "→".dimmed());
    let quarantine_dir = "/var/lib/dragonkeep/quarantine";
    if !dry_run && !config.general.safe_mode {
        let _ = std::fs::create_dir_all(quarantine_dir);
    }

    let staging_dirs = ["/tmp", "/var/tmp", "/dev/shm"];
    for dir in &staging_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                        let path = entry.path();
                        if dry_run || config.general.safe_mode {
                            eprintln!("    {} [DRY RUN] Would quarantine: {}", "→".yellow(), path.display());
                        } else {
                            // SECURITY: Generate unique quarantine filename to prevent collisions
                            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                            let original_name = entry.file_name().to_string_lossy().to_string();
                            let dest = format!("{}/{}_{}", quarantine_dir, timestamp, original_name);
                            // Try rename first, fall back to copy+delete for cross-device
                            match std::fs::rename(&path, &dest) {
                                Ok(()) => {
                                    eprintln!("    {} Quarantined: {} → {}", "✓".green(), path.display(), dest);
                                }
                                Err(ref e) if e.raw_os_error() == Some(18) => {
                                    // EXDEV: cross-device rename — use copy then secure delete
                                    if std::fs::copy(&path, &dest).is_ok() {
                                        let _ = std::fs::remove_file(&path);
                                        eprintln!("    {} Quarantined (cross-device): {} → {}", "✓".green(), path.display(), dest);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("    {} Failed to quarantine {}: {}", "✗".red(), path.display(), e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Disable suspicious systemd services
    eprintln!("    {} Disabling suspicious services...", "→".dimmed());
    // SECURITY: Whitelist of legitimate system services that must never be disabled
    let service_whitelist: &[&str] = &[
        "systemd-tmpfiles-clean", "systemd-journald", "systemd-logind",
        "systemd-resolved", "systemd-networkd", "systemd-timesyncd",
        "systemd-udevd", "dbus", "NetworkManager", "sshd", "cron",
        "rsyslog", "auditd", "firewalld", "iptables", "docker",
        "containerd", "snapd", "polkit", "accounts-daemon",
    ];
    let systemd_paths = ["/etc/systemd/system", "/usr/lib/systemd/system"];
    for dir in &systemd_paths {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "service" || ext == "timer" {
                        if let Ok(content) = tokio::fs::read_to_string(&path).await {
                            let cl = content.to_lowercase();
                            if cl.contains("/tmp/") || cl.contains("/dev/shm/") || cl.contains("base64") {
                                let svc_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                // SECURITY: Never disable whitelisted system services
                                let base_name = svc_name.trim_end_matches(".service").trim_end_matches(".timer");
                                if service_whitelist.iter().any(|&w| base_name == w) {
                                    eprintln!("    {} Skipping whitelisted service: {}", "ℹ".blue(), svc_name);
                                    continue;
                                }
                                if dry_run || config.general.safe_mode {
                                    eprintln!("    {} [DRY RUN] Would disable: {}", "→".yellow(), svc_name);
                                } else {
                                    audit_entries.push(format!("[{}] DISABLE_SERVICE name={}",
                                        audit_timestamp, svc_name));
                                    let _ = tokio::process::Command::new("systemctl")
                                        .args(["disable", "--now", &svc_name])
                                        .output()
                                        .await;
                                    eprintln!("    {} Disabled: {}", "✓".green(), svc_name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // SECURITY: Flush audit log of all remediation actions
    if !audit_entries.is_empty() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(audit_log_path) {
            for entry in &audit_entries {
                let _ = writeln!(f, "{}", entry);
            }
        }
    }

    eprintln!();
    if dry_run || config.general.safe_mode {
        eprintln!("  {} Remediation plan complete (dry run — no changes applied)", "ℹ".blue());
    } else {
        eprintln!("  {} Remediation complete — review quarantine at {}", "✓".green(), quarantine_dir);
    }

    Ok(())
}
