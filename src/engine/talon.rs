//! Talon Engine — Threat Hunting & Advanced Threat Protection
//!
//! Proactive threat hunting aligned with:
//!   - MITRE ATT&CK Threat Hunting methodology
//!   - NIST SP 800-53 Rev 5 SI/AU/IR families
//!   - DISA STIG audit and monitoring requirements
//!   - MITRE D3FEND defensive technique taxonomy
//!   - Sigma rule logic (generic detection patterns)
//!   - Threat hunting hypothesis-driven approach
//!
//! Capabilities:
//!   - IOC (Indicators of Compromise) scanning
//!   - Behavioral anomaly detection (process trees, user sessions)
//!   - ATT&CK technique hunting (specific TTP detection)
//!   - Log analysis and correlation
//!   - Lateral movement detection
//!   - Privilege escalation hunting
//!   - Data exfiltration indicators
//!   - Living-off-the-land technique detection
//!   - Scheduled task abuse detection
//!   - Timeline analysis and event correlation

use anyhow::Result;
use std::collections::HashMap;
use colored::Colorize;
use crate::config::Config;
use crate::engine::Finding;

/// SECURITY: Read only the tail of a log file with a size cap to prevent OOM on large logs.
/// Reads at most `max_bytes` from the end of the file, returning lines.
async fn read_log_tail(path: &str, max_bytes: u64) -> std::io::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path).await?;
    let meta = file.metadata().await?;
    let len = meta.len();
    if len > max_bytes {
        file.seek(std::io::SeekFrom::End(-(max_bytes as i64))).await?;
    }
    let mut buf = String::with_capacity(std::cmp::min(len, max_bytes) as usize);
    file.read_to_string(&mut buf).await?;
    // If we seeked into the middle of a line, drop the first partial line
    if len > max_bytes {
        if let Some(pos) = buf.find('\n') {
            buf.drain(..=pos);
        }
    }
    Ok(buf)
}

/// IOC types for threat hunting
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum IocType {
    IpAddress(String),
    Domain(String),
    FileHash(String),
    FilePath(String),
    ProcessName(String),
    UserAgent(String),
    Registry(String),
    Mutex(String),
}

/// Known threat actor TTPs — mapped to ATT&CK
const LATERAL_MOVEMENT_INDICATORS: &[(&str, &str, &str)] = &[
    ("ssh -o StrictHostKeyChecking=no", "SSH with host key check disabled", "T1021.004"),
    ("sshpass", "Automated SSH credential injection", "T1021.004"),
    ("psexec", "PsExec lateral movement", "T1021.002"),
    ("wmic ", "WMI lateral movement", "T1047"),
    ("winrm", "WinRM lateral movement", "T1021.006"),
    ("rdp", "RDP session", "T1021.001"),
    ("rdesktop", "RDP client", "T1021.001"),
    ("xfreerdp", "FreeRDP client", "T1021.001"),
    ("smbclient", "SMB share access", "T1021.002"),
    ("rpcclient", "RPC enumeration", "T1021.002"),
    ("crackmapexec", "CrackMapExec attack tool", "T1021"),
    ("evil-winrm", "Evil-WinRM attack tool", "T1021.006"),
    ("impacket", "Impacket attack framework", "T1021"),
    ("proxychains", "Proxied connection (pivoting)", "T1090"),
    ("chisel", "Tunnel/pivot tool", "T1572"),
    ("ligolo", "Reverse tunnel pivoting", "T1572"),
    ("sshuttle", "SSH-based VPN tunnel", "T1572"),
];

/// Privilege escalation indicators — ATT&CK TA0004
const PRIVESC_INDICATORS: &[(&str, &str, &str)] = &[
    ("sudo -l", "Sudo enumeration", "T1548.003"),
    ("find / -perm -4000", "SUID binary search", "T1548.001"),
    ("find / -perm -u=s", "SUID binary search variant", "T1548.001"),
    ("getcap -r /", "Linux capability enumeration", "T1548"),
    ("linpeas", "LinPEAS privilege escalation scanner", "T1059.004"),
    ("linenum", "LinEnum enumeration script", "T1059.004"),
    ("pspy", "Process spy (unprivileged process monitor)", "T1057"),
    ("les.sh", "Linux Exploit Suggester", "T1068"),
    ("linux-exploit-suggester", "Exploit suggester", "T1068"),
    ("dirtypipe", "Dirty Pipe exploit (CVE-2022-0847)", "T1068"),
    ("dirtycow", "Dirty COW exploit (CVE-2016-5195)", "T1068"),
    ("pwnkit", "PwnKit exploit (CVE-2021-4034)", "T1068"),
    ("looney", "Looney Tunables exploit (CVE-2023-4911)", "T1068"),
    ("pkexec", "Polkit pkexec (potential exploit target)", "T1548.001"),
];

/// Data exfiltration indicators — ATT&CK TA0010
const EXFILTRATION_INDICATORS: &[(&str, &str, &str)] = &[
    ("tar czf", "Creating compressed archive (potential exfil staging)", "T1560.001"),
    ("zip -r", "Creating zip archive (potential exfil staging)", "T1560.001"),
    ("7z a", "7-Zip archive creation", "T1560.001"),
    ("scp ", "SCP file transfer", "T1048.002"),
    ("rsync ", "Rsync data sync (potential exfil)", "T1048"),
    ("rclone", "Rclone cloud storage transfer", "T1567.002"),
    ("mega-", "MEGA cloud transfer", "T1567.002"),
    ("aws s3 cp", "AWS S3 upload", "T1537"),
    ("az storage blob", "Azure blob upload", "T1537"),
    ("gsutil cp", "GCP storage upload", "T1537"),
    ("curl -X POST", "HTTP POST data exfil", "T1048.003"),
    ("curl --upload-file", "HTTP file upload exfil", "T1048.003"),
    ("nc -w", "Netcat data transfer", "T1048"),
    ("certutil -encode", "Base64 encoding for exfil", "T1132.001"),
    ("split -b", "File splitting for staged exfil", "T1030"),
];

/// Reconnaissance indicators — ATT&CK TA0007
const RECON_INDICATORS: &[(&str, &str, &str)] = &[
    ("whoami", "Identity discovery", "T1033"),
    ("id ", "User/group enumeration", "T1033"),
    ("uname -a", "System information discovery", "T1082"),
    ("cat /etc/passwd", "User account enumeration", "T1087.001"),
    ("cat /etc/shadow", "Password hash access attempt", "T1003.008"),
    ("cat /etc/hosts", "Network configuration discovery", "T1016"),
    ("ifconfig", "Network interface enumeration", "T1016"),
    ("ip addr", "IP address enumeration", "T1016"),
    ("netstat -", "Network connection enumeration", "T1049"),
    ("ss -", "Socket statistics enumeration", "T1049"),
    ("arp -", "ARP table enumeration", "T1016"),
    ("route -n", "Routing table enumeration", "T1016"),
    ("nmap", "Network scanner", "T1046"),
    ("masscan", "Mass port scanner", "T1046"),
    ("enum4linux", "SMB enumeration", "T1135"),
    ("ldapsearch", "LDAP enumeration", "T1087.002"),
    ("bloodhound", "Active Directory mapper", "T1087.002"),
    ("sharphound", "BloodHound collector", "T1087.002"),
];

/// Credential access indicators — ATT&CK TA0006
const CREDENTIAL_ACCESS_INDICATORS: &[(&str, &str, &str)] = &[
    ("mimikatz", "Mimikatz credential dumper", "T1003"),
    ("lazagne", "LaZagne password recovery", "T1555"),
    ("john ", "John the Ripper password cracker", "T1110.002"),
    ("hashcat", "Hashcat password cracker", "T1110.002"),
    ("hydra ", "THC-Hydra brute forcer", "T1110"),
    ("medusa ", "Medusa brute forcer", "T1110"),
    ("patator", "Patator brute forcer", "T1110"),
    ("responder", "LLMNR/NBT-NS responder", "T1557.001"),
    ("tcpdump", "Packet capture (credential sniffing)", "T1040"),
    ("tshark", "Network capture", "T1040"),
    ("ettercap", "MITM/ARP poisoning", "T1557"),
    ("bettercap", "Network attack framework", "T1557"),
    ("secretsdump", "Impacket secrets dumper", "T1003"),
    ("dcsync", "DCSync replication attack", "T1003.006"),
    ("kerbrute", "Kerberos brute force", "T1110"),
    ("rubeus", "Kerberos ticket manipulation", "T1558"),
];

/// Run comprehensive threat hunt
pub async fn hunt(config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if !config.talon.enabled {
        findings.push(Finding::info("Talon engine disabled in config")
            .with_engine("Talon"));
        return Ok(findings);
    }

    eprintln!("    {} Hunting lateral movement...", "→".dimmed());
    findings.extend(hunt_lateral_movement().await);

    if config.talon.privesc_hunting {
        eprintln!("    {} Hunting privilege escalation...", "→".dimmed());
        findings.extend(hunt_privilege_escalation().await);
    }

    if config.talon.exfil_detection {
        eprintln!("    {} Hunting data exfiltration...", "→".dimmed());
        findings.extend(hunt_exfiltration().await);
    }

    eprintln!("    {} Hunting reconnaissance activity...", "→".dimmed());
    findings.extend(hunt_reconnaissance().await);

    if config.talon.credential_hunting {
        eprintln!("    {} Hunting credential access...", "→".dimmed());
        findings.extend(hunt_credential_access().await);
    }

    if config.talon.log_analysis {
        eprintln!("    {} Analyzing system logs...", "→".dimmed());
        findings.extend(analyze_logs().await);
    }

    eprintln!("    {} Hunting suspicious user sessions...", "→".dimmed());
    findings.extend(hunt_suspicious_sessions().await);

    eprintln!("    {} Hunting process tree anomalies...", "→".dimmed());
    findings.extend(hunt_process_tree_anomalies().await);

    if config.talon.ioc_scan {
        eprintln!("    {} Scanning for IOCs...", "→".dimmed());
        findings.extend(scan_iocs().await);
    }

    if findings.iter().all(|f| f.severity == crate::engine::Severity::Pass || f.severity == crate::engine::Severity::Info) {
        findings.push(Finding::pass("Threat hunt complete — no active threats detected")
            .with_engine("Talon")
            .with_rule("DK-TAL-000"));
    }

    Ok(findings)
}

/// Hunt for lateral movement indicators
async fn hunt_lateral_movement() -> Vec<Finding> {
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

        for &(pattern, desc, mitre_id) in LATERAL_MOVEMENT_INDICATORS {
            if cmd.contains(pattern) {
                findings.push(Finding::high(format!("Lateral movement indicator: {}", desc))
                    .with_detail(format!("Process PID {} executing: {}", process.pid(), cmd))
                    .with_fix("Investigate whether this lateral movement is authorized")
                    .with_engine("Talon")
                    .with_rule("DK-TAL-001")
                    .with_cvss(8.0)
                    .with_mitre(vec![mitre_id])
                    .with_nist(vec!["SI-4", "AC-17", "IR-4"]));
            }
        }
    }

    // Check SSH logs for lateral movement
    let ssh_log_paths = ["/var/log/auth.log", "/var/log/secure"];
    for log_path in &ssh_log_paths {
        // SECURITY: Bounded read — max 10MB tail to prevent OOM on large log files
        if let Ok(content) = read_log_tail(log_path, 10 * 1024 * 1024).await {
            let lines: Vec<&str> = content.lines().collect();
            let recent_lines = &lines[lines.len().saturating_sub(500)..];

            let failed_ssh: Vec<&&str> = recent_lines.iter()
                .filter(|l| l.contains("Failed password") || l.contains("Invalid user"))
                .collect();

            if failed_ssh.len() > 20 {
                // Count unique source IPs
                let mut ips: HashMap<String, usize> = HashMap::new();
                for line in &failed_ssh {
                    if let Some(ip) = extract_ip(line) {
                        *ips.entry(ip).or_insert(0) += 1;
                    }
                }

                for (ip, count) in &ips {
                    if *count > 10 {
                        findings.push(Finding::high(format!("SSH brute force from {}: {} failed attempts", ip, count))
                            .with_detail(format!("Source IP {} has {} failed SSH login attempts", ip, count))
                            .with_fix(format!("Block IP: iptables -I INPUT -s {} -j DROP", ip))
                            .with_engine("Talon")
                            .with_rule("DK-TAL-002")
                            .with_cvss(7.5)
                            .with_mitre(vec!["T1110", "T1021.004"])
                            .with_stig("V-230222")
                            .with_nist(vec!["SI-4", "AC-7", "IR-4"]));
                    }
                }
            }
        }
    }

    findings
}

/// Hunt for privilege escalation indicators
async fn hunt_privilege_escalation() -> Vec<Finding> {
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

        for &(pattern, desc, mitre_id) in PRIVESC_INDICATORS {
            if cmd.contains(pattern) {
                findings.push(Finding::high(format!("Privilege escalation indicator: {}", desc))
                    .with_detail(format!("PID {} running: {}", process.pid(), cmd))
                    .with_fix("Verify this is authorized security testing, not attacker reconnaissance")
                    .with_engine("Talon")
                    .with_rule("DK-TAL-003")
                    .with_cvss(8.5)
                    .with_mitre(vec![mitre_id])
                    .with_nist(vec!["AC-6", "SI-4", "AU-6"]));
            }
        }
    }

    // Check for recently modified SUID binaries
    if let Ok(output) = tokio::process::Command::new("find")
        .args(["/usr", "-perm", "-4000", "-mtime", "-1", "-type", "f"])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if !line.trim().is_empty() {
                findings.push(Finding::critical(format!("Recently modified SUID binary: {}", line.trim()))
                    .with_detail("SUID binary modified in the last 24 hours — possible privilege escalation implant")
                    .with_fix(format!("Investigate: ls -la {} && rpm -Vf {} 2>/dev/null || dpkg -S {}", line.trim(), line.trim(), line.trim()))
                    .with_engine("Talon")
                    .with_rule("DK-TAL-004")
                    .with_cvss(9.0)
                    .with_mitre(vec!["T1548.001"])
                    .with_stig("V-230267")
                    .with_nist(vec!["AC-6(1)", "SI-7"]));
            }
        }
    }

    // Check sudo logs for suspicious commands
    // SECURITY: Bounded read — max 10MB tail to prevent OOM
    if let Ok(content) = read_log_tail("/var/log/auth.log", 10 * 1024 * 1024).await {
        let lines: Vec<&str> = content.lines().collect();
        let recent = &lines[lines.len().saturating_sub(200)..];

        for line in recent {
            if line.contains("sudo") && line.contains("COMMAND=") {
                let lower = line.to_lowercase();
                if lower.contains("chmod 4") || lower.contains("chown root") || lower.contains("setuid") {
                    findings.push(Finding::high("Suspicious sudo command — SUID/ownership change")
                        .with_detail(format!("Log entry: {}", line))
                        .with_fix("Verify this sudo command was authorized")
                        .with_engine("Talon")
                        .with_rule("DK-TAL-005")
                        .with_cvss(8.0)
                        .with_mitre(vec!["T1548.001", "T1222.002"])
                        .with_nist(vec!["AC-6", "AU-6"]));
                }
            }
        }
    }

    findings
}

/// Hunt for data exfiltration indicators
async fn hunt_exfiltration() -> Vec<Finding> {
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

        for &(pattern, desc, mitre_id) in EXFILTRATION_INDICATORS {
            if cmd.contains(pattern) {
                // Filter out legitimate uses
                let is_suspicious = cmd.contains("/etc/") || cmd.contains("/home/")
                    || cmd.contains("/var/") || cmd.contains("/root/")
                    || cmd.contains("pass") || cmd.contains("secret")
                    || cmd.contains("credential") || cmd.contains("key");

                if is_suspicious {
                    findings.push(Finding::high(format!("Data exfiltration indicator: {}", desc))
                        .with_detail(format!("PID {} executing: {}", process.pid(), cmd))
                        .with_fix("Investigate data transfer — verify it's authorized")
                        .with_engine("Talon")
                        .with_rule("DK-TAL-006")
                        .with_cvss(8.0)
                        .with_mitre(vec![mitre_id])
                        .with_nist(vec!["SI-4", "SC-7", "AC-4"]));
                }
            }
        }
    }

    // Check for large outbound transfers
    if let Ok(output) = tokio::process::Command::new("ss")
        .args(["-tnp", "state", "established"])
        .output()
        .await
    {
        let ss_output = String::from_utf8_lossy(&output.stdout);
        for line in ss_output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                // Check send queue size
                if let Ok(send_q) = parts[1].parse::<u64>() {
                    if send_q > 1_000_000 { // > 1MB in send queue
                        let remote = parts.get(4).unwrap_or(&"unknown");
                        let process_info = parts.get(5).unwrap_or(&"");
                        findings.push(Finding::warning(format!("Large outbound data transfer: {} bytes to {}", send_q, remote))
                            .with_detail(format!("Process {} sending large data volume", process_info))
                            .with_fix("Verify this data transfer is authorized")
                            .with_engine("Talon")
                            .with_rule("DK-TAL-007")
                            .with_mitre(vec!["T1048"])
                            .with_nist(vec!["SI-4", "SC-7"]));
                    }
                }
            }
        }
    }

    findings
}

/// Hunt for internal reconnaissance
async fn hunt_reconnaissance() -> Vec<Finding> {
    use sysinfo::System;
    let mut findings = Vec::new();
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut recon_count = 0;
    let mut recon_details = Vec::new();

    for (_pid, process) in sys.processes() {
        let cmd = process.cmd().iter()
            .map(|s| s.to_string_lossy().to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        if cmd.is_empty() {
            continue;
        }

        for &(pattern, desc, mitre_id) in RECON_INDICATORS {
            if cmd.contains(pattern) {
                recon_count += 1;
                recon_details.push((desc, mitre_id, process.pid()));
            }
        }
    }

    // Multiple recon commands from same system = likely attacker
    if recon_count >= 3 {
        findings.push(Finding::high(format!("Active reconnaissance detected: {} indicators", recon_count))
            .with_detail(format!("Multiple recon commands running simultaneously: {}",
                recon_details.iter().map(|(d, _, pid)| format!("{} (PID {})", d, pid)).collect::<Vec<_>>().join(", ")))
            .with_fix("Investigate user activity — this pattern indicates active enumeration")
            .with_engine("Talon")
            .with_rule("DK-TAL-008")
            .with_cvss(7.5)
            .with_mitre(vec!["T1082", "T1016", "T1033"])
            .with_nist(vec!["SI-4", "AU-6", "IR-4"]));
    } else if recon_count > 0 {
        for (desc, mitre_id, pid) in &recon_details {
            findings.push(Finding::info(format!("Reconnaissance command: {}", desc))
                .with_detail(format!("PID {} running recon command", pid))
                .with_engine("Talon")
                .with_rule("DK-TAL-008")
                .with_mitre(vec![mitre_id]));
        }
    }

    findings
}

/// Hunt for credential access
async fn hunt_credential_access() -> Vec<Finding> {
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

        for &(pattern, desc, mitre_id) in CREDENTIAL_ACCESS_INDICATORS {
            if name.contains(pattern) || cmd.contains(pattern) {
                findings.push(Finding::critical(format!("Credential access tool detected: {}", desc))
                    .with_detail(format!("PID {} running: {}", process.pid(), if cmd.is_empty() { &name } else { &cmd }))
                    .with_fix("This tool should not be running unless authorized penetration testing is in progress")
                    .with_engine("Talon")
                    .with_rule("DK-TAL-009")
                    .with_cvss(9.0)
                    .with_mitre(vec![mitre_id])
                    .with_stig("V-230222")
                    .with_nist(vec!["IA-5", "AC-6", "SI-4"]));
            }
        }
    }

    // Check for credential files in world-readable locations
    let cred_files = [
        "/tmp/.credentials", "/tmp/passwords", "/tmp/hashes",
        "/var/tmp/.creds", "/dev/shm/dump",
    ];

    for path in &cred_files {
        if std::path::Path::new(path).exists() {
            findings.push(Finding::critical(format!("Credential dump file found: {}", path))
                .with_detail("Credential file in temporary directory — likely from attacker dumping credentials")
                .with_fix(format!("Preserve as evidence, then remove: cp {} /evidence/ && rm -f {}", path, path))
                .with_engine("Talon")
                .with_rule("DK-TAL-010")
                .with_cvss(9.5)
                .with_mitre(vec!["T1003"])
                .with_nist(vec!["IA-5", "SI-4"]));
        }
    }

    findings
}

/// Analyze system logs for indicators of compromise
async fn analyze_logs() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for failed login bursts (brute force)
    if let Ok(output) = tokio::process::Command::new("journalctl")
        .args(["--no-pager", "-n", "1000", "--output=short", "-p", "warning..err"])
        .output()
        .await
    {
        let logs = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = logs.lines().collect();

        // Count authentication failures
        let auth_failures = lines.iter()
            .filter(|l| l.contains("authentication failure") || l.contains("auth.*fail"))
            .count();

        if auth_failures > 50 {
            findings.push(Finding::high(format!("High authentication failure rate: {} failures in recent logs", auth_failures))
                .with_detail("Excessive authentication failures may indicate brute-force attack or misconfiguration")
                .with_fix("Review auth logs, implement account lockout, consider fail2ban")
                .with_engine("Talon")
                .with_rule("DK-TAL-011")
                .with_cvss(7.0)
                .with_mitre(vec!["T1110"])
                .with_stig("V-230222")
                .with_nist(vec!["AC-7", "SI-4", "AU-6"]));
        }

        // Check for segfaults (potential exploit attempts)
        let segfaults = lines.iter()
            .filter(|l| l.contains("segfault") || l.contains("SEGV"))
            .count();

        if segfaults > 10 {
            findings.push(Finding::warning(format!("{} segfault events in recent logs — possible exploit attempts", segfaults))
                .with_detail("Multiple segfaults may indicate buffer overflow exploitation attempts")
                .with_fix("Investigate affected processes. Ensure ASLR and stack protector are enabled.")
                .with_engine("Talon")
                .with_rule("DK-TAL-012")
                .with_cvss(6.5)
                .with_mitre(vec!["T1068", "T1203"])
                .with_nist(vec!["SI-4", "SI-16"]));
        }

        // Check for OOM kills (DoS or crypto mining)
        let oom_kills = lines.iter()
            .filter(|l| l.contains("Out of memory") || l.contains("oom-kill"))
            .count();

        if oom_kills > 5 {
            findings.push(Finding::warning(format!("{} OOM kill events — possible DoS or resource abuse", oom_kills))
                .with_detail("Frequent out-of-memory kills may indicate cryptomining or denial-of-service")
                .with_fix("Investigate memory-hungry processes. Check for unauthorized workloads.")
                .with_engine("Talon")
                .with_rule("DK-TAL-013")
                .with_mitre(vec!["T1496", "T1499"])
                .with_nist(vec!["SI-4", "SC-5"]));
        }
    }

    // Check for audit log tampering
    let audit_logs = ["/var/log/audit/audit.log", "/var/log/syslog", "/var/log/messages"];
    for log_path in &audit_logs {
        if let Ok(meta) = std::fs::metadata(log_path) {
            if meta.len() == 0 {
                findings.push(Finding::critical(format!("Audit log truncated: {}", log_path))
                    .with_detail("Empty audit log indicates possible log tampering by an attacker")
                    .with_fix("Investigate log tampering. Enable remote syslog forwarding.")
                    .with_engine("Talon")
                    .with_rule("DK-TAL-014")
                    .with_cvss(9.0)
                    .with_mitre(vec!["T1070.002"])
                    .with_stig("V-230270")
                    .with_nist(vec!["AU-9", "AU-6", "SI-4"]));
            }
        }
    }

    findings
}

/// Hunt for suspicious user sessions
async fn hunt_suspicious_sessions() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for users logged in from unusual sources
    if let Ok(output) = tokio::process::Command::new("who")
        .output()
        .await
    {
        let who_output = String::from_utf8_lossy(&output.stdout);
        for line in who_output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let user = parts[0];
                let source = parts.last().unwrap_or(&"");

                // Check for root login
                if user == "root" {
                    findings.push(Finding::warning("Direct root login session active")
                        .with_detail(format!("Root is logged in from: {}", source))
                        .with_fix("Use non-root user with sudo instead of direct root login")
                        .with_engine("Talon")
                        .with_rule("DK-TAL-015")
                        .with_cvss(6.0)
                        .with_mitre(vec!["T1078.003"])
                        .with_stig("V-230222")
                        .with_nist(vec!["AC-6(2)", "IA-2"]));
                }
            }
        }
    }

    // Check for recently created user accounts
    if let Ok(content) = tokio::fs::read_to_string("/etc/passwd").await {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 7 {
                let user = fields[0];
                let uid: u32 = fields[2].parse().unwrap_or(0);
                let shell = fields[6];

                // UID 0 accounts (besides root)
                if uid == 0 && user != "root" {
                    findings.push(Finding::critical(format!("Non-root account with UID 0: {}", user))
                        .with_detail("Account with UID 0 has root-level privileges — possible backdoor account")
                        .with_fix(format!("Investigate and remove: userdel {}", user))
                        .with_engine("Talon")
                        .with_rule("DK-TAL-016")
                        .with_cvss(9.5)
                        .with_mitre(vec!["T1136.001"])
                        .with_stig("V-230222")
                        .with_nist(vec!["AC-6", "IA-2"]));
                }

                // Accounts with login shell that shouldn't have one
                if (user.starts_with("ftp") || user.starts_with("mail") || user.starts_with("news")
                    || user.starts_with("games") || user.starts_with("nobody"))
                    && (shell.contains("bash") || shell.contains("sh") || shell.contains("zsh"))
                    && !shell.contains("nologin") && !shell.contains("false")
                {
                    findings.push(Finding::warning(format!("Service account '{}' has login shell: {}", user, shell))
                        .with_detail("Service accounts should have /sbin/nologin or /bin/false as their shell")
                        .with_fix(format!("usermod -s /sbin/nologin {}", user))
                        .with_engine("Talon")
                        .with_rule("DK-TAL-017")
                        .with_mitre(vec!["T1078.001"])
                        .with_nist(vec!["AC-6", "CM-6"]));
                }
            }
        }
    }

    findings
}

/// Hunt for process tree anomalies
async fn hunt_process_tree_anomalies() -> Vec<Finding> {
    use sysinfo::System;
    let mut findings = Vec::new();
    let mut sys = System::new_all();
    sys.refresh_all();

    for (_pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        let exe = process.exe()
            .map(|p| p.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        // Shell spawned by web server (web shell indicator)
        if let Some(parent_pid) = process.parent() {
            if let Some(parent) = sys.process(parent_pid) {
                let parent_name = parent.name().to_string_lossy().to_lowercase();

                // Web server spawning shells
                if (parent_name.contains("apache") || parent_name.contains("nginx")
                    || parent_name.contains("httpd") || parent_name.contains("tomcat")
                    || parent_name.contains("php-fpm"))
                    && (name.contains("bash") || name.contains("sh") || name == "python"
                    || name == "python3" || name == "perl" || name == "ruby")
                {
                    findings.push(Finding::critical(format!("Web server spawned shell: {} → {}", parent_name, name))
                        .with_detail(format!("Web server process '{}' spawned '{}' — strong web shell indicator",
                            parent_name, name))
                        .with_fix("Investigate web server for uploaded webshells. Kill the shell process.")
                        .with_engine("Talon")
                        .with_rule("DK-TAL-018")
                        .with_cvss(9.5)
                        .with_mitre(vec!["T1505.003", "T1059"])
                        .with_nist(vec!["SI-3", "SI-4", "IR-4"]));
                }

                // Database spawning shells
                if (parent_name.contains("mysql") || parent_name.contains("postgres")
                    || parent_name.contains("mongo") || parent_name.contains("redis"))
                    && (name.contains("bash") || name.contains("sh") || name == "python"
                    || name == "python3")
                {
                    findings.push(Finding::critical(format!("Database spawned shell: {} → {}", parent_name, name))
                        .with_detail("Database process spawning a shell — possible SQL injection or database exploitation")
                        .with_fix("Investigate database for exploitation. Kill the shell. Review DB logs.")
                        .with_engine("Talon")
                        .with_rule("DK-TAL-019")
                        .with_cvss(9.5)
                        .with_mitre(vec!["T1190", "T1059"])
                        .with_nist(vec!["SI-3", "SI-10", "IR-4"]));
                }
            }
        }

        // Process running from unusual location
        if !exe.is_empty()
            && (exe.starts_with("/tmp/") || exe.starts_with("/dev/shm/")
            || exe.starts_with("/var/tmp/") || exe.contains("/."))
        {
            findings.push(Finding::high(format!("Process in suspicious location: {} ({})", name, exe))
                .with_detail(format!("Binary at {} — processes should not run from temporary or hidden directories", exe))
                .with_fix(format!("Investigate process origin and kill if unauthorized"))
                .with_engine("Talon")
                .with_rule("DK-TAL-020")
                .with_cvss(7.5)
                .with_mitre(vec!["T1036", "T1059"])
                .with_nist(vec!["SI-3", "CM-7"]));
        }
    }

    findings
}

/// Scan for IOCs (Indicators of Compromise)
async fn scan_iocs() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for known malicious IP connections
    if let Ok(output) = tokio::process::Command::new("ss")
        .args(["-tnp", "state", "established"])
        .output()
        .await
    {
        let ss_output = String::from_utf8_lossy(&output.stdout);

        // Check for connections to TOR exit nodes (common C2)
        for line in ss_output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let remote = parts[4];
                // Common malicious port patterns
                if remote.ends_with(":4444") || remote.ends_with(":31337")
                    || remote.ends_with(":6667") || remote.ends_with(":6697")
                    || remote.ends_with(":1337") || remote.ends_with(":5555")
                {
                    findings.push(Finding::high(format!("Suspicious outbound connection: {}", remote))
                        .with_detail(format!("Connection to {} on known malicious port", remote))
                        .with_fix("Investigate the destination and block if unauthorized")
                        .with_engine("Talon")
                        .with_rule("DK-TAL-021")
                        .with_cvss(7.5)
                        .with_mitre(vec!["T1071", "T1571"])
                        .with_nist(vec!["SC-7", "SI-4"]));
                }
            }
        }
    }

    // Check /tmp and /dev/shm for IOC artifacts
    let ioc_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm"];
    for dir in &ioc_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();

                // Suspicious filenames
                if fname.contains("payload") || fname.contains("exploit")
                    || fname.contains("shell") || fname.contains("beacon")
                    || fname.contains("agent") || fname.contains("implant")
                    || fname.contains("dropper") || fname.contains("stager")
                    || fname.contains("loader") || fname.contains("injector")
                {
                    findings.push(Finding::critical(format!("IOC artifact found: {}/{}", dir, fname))
                        .with_detail(format!("File '{}' in {} has a name matching known attack tool patterns", fname, dir))
                        .with_fix(format!("Quarantine: mv {}/{} /var/lib/dragonkeep/quarantine/", dir, fname))
                        .with_engine("Talon")
                        .with_rule("DK-TAL-022")
                        .with_cvss(9.0)
                        .with_mitre(vec!["T1105", "T1059"])
                        .with_nist(vec!["SI-3", "SI-4"]));
                }
            }
        }
    }

    findings
}

/// Extract IP address from a log line
fn extract_ip(line: &str) -> Option<String> {
    // Simple IP extraction using regex-like approach
    let words: Vec<&str> = line.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if *word == "from" {
            if let Some(next) = words.get(i + 1) {
                let ip = next.trim_end_matches(':');
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

/// Interactive threat hunting mode — guided hypothesis-driven hunt
pub async fn interactive_hunt(config: &Config) -> Result<()> {
    eprintln!("{}", "  ── Talon: Interactive Threat Hunt ──".red().bold());
    eprintln!();
    eprintln!("  {} Running comprehensive threat hunt across all categories...", "→".dimmed());
    eprintln!();

    let findings = hunt(config).await?;

    let critical = findings.iter().filter(|f| f.severity == crate::engine::Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == crate::engine::Severity::High).count();
    let _warning = findings.iter().filter(|f| f.severity == crate::engine::Severity::Warning).count();

    let mut reporter = crate::report::Reporter::new();
    reporter.add_section("Threat Hunting Results", findings);
    reporter.print(&crate::cli::OutputFormat::Pretty);

    if critical > 0 {
        eprintln!();
        eprintln!("  {} {} CRITICAL threats require immediate attention!", "⚠".red().bold(), critical);
        eprintln!("  {} Recommended: Isolate host and begin incident response", "→".red());
    } else if high > 0 {
        eprintln!();
        eprintln!("  {} {} HIGH findings require investigation", "!".yellow().bold(), high);
    } else {
        eprintln!();
        eprintln!("  {} No active threats detected — system appears clean", "✓".green());
    }

    Ok(())
}
