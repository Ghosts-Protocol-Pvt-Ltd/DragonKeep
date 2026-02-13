//! Phantom Engine — Runtime Anomaly Detector
//!
//! Deep inspection of running processes for indicators of compromise:
//!   - Reverse shell detection (ATT&CK T1059, Atomic Red Team T1059.004)
//!   - LD_PRELOAD injection (ATT&CK T1574.006, DISA STIG V-230222)
//!   - Fileless malware via memfd_create (ATT&CK T1620)
//!   - Ptrace-based process injection (ATT&CK T1055.008, STIG V-230269)
//!   - Crontab backdoor detection (ATT&CK T1053.003, STIG V-230324)
//!   - Process masquerading & hidden artifacts
//!   - Namespace manipulation / container escape vectors
//!
//! Standards: MITRE ATT&CK, NIST SP 800-53 Rev 5, DISA STIG RHEL-08

use crate::config::Config;
use crate::engine::Finding;

use std::collections::HashSet;
use std::path::Path;

/// Known reverse shell command patterns
const REVERSE_SHELL_PATTERNS: &[&str] = &[
    "bash -i >& /dev/tcp/",
    "bash -i >& /dev/udp/",
    "nc -e /bin/",
    "ncat -e /bin/",
    "socat exec:",
    "python -c 'import socket,subprocess,os",
    "python3 -c 'import socket,subprocess,os",
    "perl -e 'use Socket",
    "ruby -rsocket -e",
    "php -r '$sock=fsockopen",
    "mkfifo /tmp/",
    "0<&196;exec 196<>/dev/tcp/",
    "/dev/tcp/",
    "exec 5<>/dev/tcp/",
];

/// Suspicious cron patterns
const SUSPICIOUS_CRON_PATTERNS: &[&str] = &[
    "curl ", "wget ", "python -c", "python3 -c",
    "base64 -d", "eval ", "exec ", "/dev/tcp/",
    "/dev/shm/", "/tmp/.", "bash -i",
    "nc -", "ncat -", "|sh", "| sh", "|bash", "| bash",
    "chmod +s", "chmod u+s", "chmod 4",
];

pub async fn scan(config: &Config) -> anyhow::Result<Vec<Finding>> {
    if !config.phantom.enabled {
        return Ok(vec![Finding::info("Phantom engine disabled").with_engine("Phantom")]);
    }

    let mut findings = Vec::new();

    scan_process_cmdlines(&mut findings).await;
    scan_ld_preload_injection(&mut findings).await;
    scan_deleted_executables(&mut findings).await;
    scan_ptrace_attachment(&mut findings).await;
    scan_memfd_abuse(&mut findings).await;
    scan_crontab_backdoors(&mut findings).await;
    scan_outbound_connections(&mut findings).await;
    scan_process_masquerading(&mut findings).await;
    scan_hidden_artifacts(&mut findings).await;
    scan_namespace_anomalies(&mut findings).await;

    if findings.is_empty() {
        findings.push(
            Finding::pass("No runtime anomalies detected")
                .with_engine("Phantom")
                .with_rule("DK-PHA-000"),
        );
    }

    Ok(findings)
}

/// Scan all process command lines for reverse shell indicators
/// ATT&CK T1059.004 (Unix Shell), Atomic Red Team T1059.004
async fn scan_process_cmdlines(findings: &mut Vec<Finding>) {
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) { continue; }

        let cmdline_path = format!("/proc/{}/cmdline", name);
        if let Ok(cmdline_raw) = std::fs::read(&cmdline_path) {
            let cmdline = cmdline_raw.iter()
                .map(|&b| if b == 0 { b' ' } else { b })
                .collect::<Vec<u8>>();
            let cmdline_str = String::from_utf8_lossy(&cmdline).to_lowercase();

            for pattern in REVERSE_SHELL_PATTERNS {
                if cmdline_str.contains(&pattern.to_lowercase()) {
                    let exe = std::fs::read_link(format!("/proc/{}/exe", name))
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| "unknown".into());

                    findings.push(
                        Finding::critical(format!("Reverse shell detected — PID {} ({})", name, exe))
                            .with_detail(format!("Pattern: '{}' in command: {}", pattern, cmdline_str.trim()))
                            .with_fix(format!("Kill immediately: kill -9 {} && investigate compromise vector", name))
                            .with_cvss(9.8)
                            .with_mitre(vec!["T1059.004", "T1071.001", "T1572"])
                            .with_stig("V-230223")
                            .with_nist(vec!["SI-4", "IR-4", "SI-3"])
                            .with_engine("Phantom")
                            .with_rule("DK-PHA-001"),
                    );
                    break;
                }
            }
        }
    }
}

/// Check all processes for LD_PRELOAD injection
/// ATT&CK T1574.006 (Dynamic Linker Hijacking), DISA STIG V-230222
async fn scan_ld_preload_injection(findings: &mut Vec<Finding>) {
    // Check global /etc/ld.so.preload
    if let Ok(content) = std::fs::read_to_string("/etc/ld.so.preload") {
        let libraries: Vec<&str> = content.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

        if !libraries.is_empty() {
            findings.push(
                Finding::critical(format!("System-wide LD_PRELOAD active: {}", libraries.join(", ")))
                    .with_detail("Libraries in /etc/ld.so.preload are injected into EVERY process — common rootkit technique")
                    .with_fix("Investigate and remove: cat /etc/ld.so.preload && > /etc/ld.so.preload")
                    .with_cvss(9.8)
                    .with_mitre(vec!["T1574.006", "T1014"])
                    .with_stig("V-230222")
                    .with_nist(vec!["SI-7", "SI-3"])
                    .with_engine("Phantom")
                    .with_rule("DK-PHA-002"),
            );
        }
    }

    // Check per-process LD_PRELOAD in /proc/*/environ
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    let mut preloaded_pids: Vec<(String, String, String)> = Vec::new();

    for entry in proc_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) { continue; }

        let environ_path = format!("/proc/{}/environ", name);
        if let Ok(environ) = std::fs::read(&environ_path) {
            let environ_str = String::from_utf8_lossy(&environ);
            for env_var in environ_str.split('\0') {
                if env_var.starts_with("LD_PRELOAD=") {
                    let lib = env_var.trim_start_matches("LD_PRELOAD=").to_string();
                    if !lib.is_empty() {
                        let exe = std::fs::read_link(format!("/proc/{}/exe", name))
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "unknown".into());
                        preloaded_pids.push((name.clone(), lib, exe));
                    }
                }
            }
        }
    }

    if !preloaded_pids.is_empty() {
        for (pid, lib, exe) in &preloaded_pids {
            findings.push(
                Finding::high(format!("LD_PRELOAD injection on PID {} ({})", pid, exe))
                    .with_detail(format!("Preloaded library: {}", lib))
                    .with_fix(format!("Investigate: ls -la {} && kill {} if unauthorized", lib, pid))
                    .with_cvss(8.4)
                    .with_mitre(vec!["T1574.006", "T1055.009"])
                    .with_stig("V-230222")
                    .with_nist(vec!["SI-7"])
                    .with_engine("Phantom")
                    .with_rule("DK-PHA-003"),
            );
        }
    }
}

/// Check for processes running from deleted executables
/// ATT&CK T1070.004 (Indicator Removal: File Deletion)
async fn scan_deleted_executables(findings: &mut Vec<Finding>) {
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) { continue; }

        let exe_link = format!("/proc/{}/exe", name);
        if let Ok(target) = std::fs::read_link(&exe_link) {
            let target_str = target.to_string_lossy().to_string();
            if target_str.contains(" (deleted)") {
                let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", name))
                    .unwrap_or_default()
                    .replace('\0', " ");

                findings.push(
                    Finding::high(format!("Process {} running from deleted executable", name))
                        .with_detail(format!("Deleted binary: {} | Command: {}", target_str, cmdline.trim()))
                        .with_fix(format!("Investigate: cat /proc/{}/maps && kill {} if suspicious", name, name))
                        .with_cvss(7.8)
                        .with_mitre(vec!["T1070.004", "T1059"])
                        .with_nist(vec!["SI-4", "AU-6"])
                        .with_engine("Phantom")
                        .with_rule("DK-PHA-004"),
                );
            }
        }
    }
}

/// Detect ptrace attachment (debugging/injection)
/// ATT&CK T1055.008 (Ptrace System Calls), DISA STIG V-230269
async fn scan_ptrace_attachment(findings: &mut Vec<Finding>) {
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) { continue; }

        let status_path = format!("/proc/{}/status", name);
        if let Ok(status) = std::fs::read_to_string(&status_path) {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let tracer_pid = line.split_whitespace()
                        .nth(1)
                        .unwrap_or("0")
                        .trim();

                    if tracer_pid != "0" {
                        let process_name = status.lines()
                            .find(|l| l.starts_with("Name:"))
                            .map(|l| l.split_whitespace().nth(1).unwrap_or("unknown"))
                            .unwrap_or("unknown");

                        let tracer_exe = std::fs::read_link(format!("/proc/{}/exe", tracer_pid))
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "unknown".into());

                        if tracer_exe.contains("gdb") || tracer_exe.contains("lldb")
                            || tracer_exe.contains("strace") || tracer_exe.contains("ltrace") {
                            continue;
                        }

                        findings.push(
                            Finding::warning(format!("Process '{}' (PID {}) is being traced by PID {} ({})", process_name, name, tracer_pid, tracer_exe))
                                .with_detail("Ptrace attachment may indicate process injection, credential theft, or debugging-based evasion")
                                .with_fix(format!("Investigate tracer: ls -la /proc/{}/exe && kill {} if unauthorized", tracer_pid, tracer_pid))
                                .with_cvss(6.5)
                                .with_mitre(vec!["T1055.008", "T1003"])
                                .with_stig("V-230269")
                                .with_nist(vec!["AC-3", "SI-4"])
                                .with_engine("Phantom")
                                .with_rule("DK-PHA-005"),
                        );
                    }
                }
            }
        }
    }
}

/// Detect memfd_create abuse (fileless malware)
/// ATT&CK T1620 (Reflective Code Loading)
async fn scan_memfd_abuse(findings: &mut Vec<Finding>) {
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) { continue; }

        let fd_dir = format!("/proc/{}/fd", name);
        if let Ok(fds) = std::fs::read_dir(&fd_dir) {
            for fd_entry in fds.flatten() {
                if let Ok(target) = std::fs::read_link(fd_entry.path()) {
                    let target_str = target.to_string_lossy().to_string();
                    if target_str.contains("memfd:") {
                        let exe = std::fs::read_link(format!("/proc/{}/exe", name))
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "unknown".into());

                        if exe.contains("memfd:") || exe.contains("(deleted)") {
                            findings.push(
                                Finding::critical(format!("Fileless malware indicator — PID {} executing from memfd", name))
                                    .with_detail(format!("Executable: {} | memfd descriptor: {}", exe, target_str))
                                    .with_fix(format!("Dump process memory for forensics: cp /proc/{}/exe /tmp/suspicious_binary && kill -9 {}", name, name))
                                    .with_cvss(9.1)
                                    .with_mitre(vec!["T1620", "T1055.009"])
                                    .with_nist(vec!["SI-7", "SI-3", "IR-4"])
                                    .with_engine("Phantom")
                                    .with_rule("DK-PHA-006"),
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Audit all crontab entries for backdoors
/// ATT&CK T1053.003 (Scheduled Task: Cron), DISA STIG V-230324
async fn scan_crontab_backdoors(findings: &mut Vec<Finding>) {
    let cron_dirs = vec![
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ];

    for file in &["/etc/crontab"] {
        check_cron_file(file, findings);
    }

    for dir in &cron_dirs {
        if !Path::new(dir).is_dir() { continue; }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    check_cron_file(&path.to_string_lossy(), findings);
                }
            }
        }
    }

    if Path::new("/var/spool/at").is_dir() {
        if let Ok(entries) = std::fs::read_dir("/var/spool/at") {
            let at_jobs: Vec<_> = entries.flatten().collect();
            if !at_jobs.is_empty() {
                findings.push(
                    Finding::info(format!("{} pending 'at' jobs found", at_jobs.len()))
                        .with_detail("at jobs execute once at a specified time — review for unauthorized scheduled tasks")
                        .with_fix("List jobs: atq && inspect: at -c <job_id>")
                        .with_mitre(vec!["T1053.002"])
                        .with_nist(vec!["CM-7"])
                        .with_engine("Phantom")
                        .with_rule("DK-PHA-007"),
                );
            }
        }
    }
}

fn check_cron_file(path: &str, findings: &mut Vec<Finding>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }

        for pattern in SUSPICIOUS_CRON_PATTERNS {
            if trimmed.contains(pattern) {
                findings.push(
                    Finding::high(format!("Suspicious cron entry in {} (line {})", path, line_num + 1))
                        .with_detail(format!("Pattern '{}' found: {}", pattern, trimmed))
                        .with_fix(format!("Review and remove if unauthorized: edit {} line {}", path, line_num + 1))
                        .with_cvss(7.8)
                        .with_mitre(vec!["T1053.003", "T1059.004"])
                        .with_stig("V-230324")
                        .with_nist(vec!["CM-7", "AU-2"])
                        .with_engine("Phantom")
                        .with_rule("DK-PHA-008"),
                );
                break;
            }
        }
    }
}

/// Detect unusual outbound connections to non-standard ports
/// ATT&CK T1071.001 (Web Protocols), T1041 (Exfiltration Over C2)
async fn scan_outbound_connections(findings: &mut Vec<Finding>) {
    let tcp_data = match std::fs::read_to_string("/proc/net/tcp") {
        Ok(d) => d,
        Err(_) => return,
    };

    let mut suspicious_conns: Vec<(String, u16, String)> = Vec::new();

    let tcp6_data = std::fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
    let all_data = format!("{}\n{}", tcp_data, tcp6_data);

    for line in all_data.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 { continue; }
        if fields[3] != "01" { continue; } // ESTABLISHED

        let remote = fields[2];
        let parts: Vec<&str> = remote.split(':').collect();
        if parts.len() != 2 { continue; }

        let port = match u16::from_str_radix(parts[1], 16) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let ip_hex = parts[0];
        let remote_ip = if ip_hex.len() == 8 {
            let bytes: Vec<u8> = (0..4)
                .filter_map(|i| u8::from_str_radix(&ip_hex[i*2..i*2+2], 16).ok())
                .collect();
            if bytes.len() == 4 {
                format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
            } else {
                continue;
            }
        } else {
            continue;
        };

        if remote_ip.starts_with("127.") || remote_ip.starts_with("10.")
            || remote_ip.starts_with("192.168.") || remote_ip.starts_with("172.")
            || remote_ip == "0.0.0.0" {
            continue;
        }

        let standard_ports: HashSet<u16> = [
            22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
            8080, 8443, 3306, 5432, 6379, 27017,
        ].into_iter().collect();

        if !standard_ports.contains(&port) {
            let pid = if fields.len() >= 10 { fields[9].to_string() } else { "?".into() };
            suspicious_conns.push((remote_ip.clone(), port, pid));
        }
    }

    let shown = suspicious_conns.len().min(10);
    for (ip, port, _pid) in suspicious_conns.iter().take(shown) {
        findings.push(
            Finding::warning(format!("Outbound connection to {}:{} (non-standard port)", ip, port))
                .with_detail("Connection to an external IP on an unusual port — may indicate C2 communication or data exfiltration")
                .with_fix(format!("Investigate: ss -tnp | grep {} && block if unauthorized: iptables -A OUTPUT -d {} -j DROP", port, ip))
                .with_cvss(5.3)
                .with_mitre(vec!["T1071.001", "T1041", "T1572"])
                .with_nist(vec!["SC-7", "SI-4", "AC-17"])
                .with_engine("Phantom")
                .with_rule("DK-PHA-009"),
        );
    }

    if suspicious_conns.len() > shown {
        findings.push(
            Finding::info(format!("... and {} more non-standard outbound connections", suspicious_conns.len() - shown))
                .with_engine("Phantom")
                .with_rule("DK-PHA-009"),
        );
    }
}

/// Detect process name masquerading (kworker mimics, bracket tricks)
/// ATT&CK T1036.004 (Masquerade Task or Service)
async fn scan_process_masquerading(findings: &mut Vec<Finding>) {
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) { continue; }

        let status_path = format!("/proc/{}/status", name);
        let comm_path = format!("/proc/{}/comm", name);

        let comm = match std::fs::read_to_string(&comm_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };

        let kernel_thread_names = ["kworker", "kthreadd", "ksoftirqd", "migration", "watchdog", "rcu_"];
        let looks_like_kernel = kernel_thread_names.iter().any(|k| comm.starts_with(k));

        if looks_like_kernel {
            match std::fs::read_link(format!("/proc/{}/exe", name)) {
                Ok(exe) => {
                    findings.push(
                        Finding::critical(format!("Process masquerading as kernel thread: '{}' (PID {})", comm, name))
                            .with_detail(format!("Real executable: {} — legitimate kernel threads have no exe link", exe.display()))
                            .with_fix(format!("Kill immediately: kill -9 {} && investigate binary: file {}", name, exe.display()))
                            .with_cvss(8.8)
                            .with_mitre(vec!["T1036.004", "T1014"])
                            .with_nist(vec!["SI-4", "SI-7"])
                            .with_engine("Phantom")
                            .with_rule("DK-PHA-010"),
                    );
                }
                Err(_) => {}
            }
        }

        if comm.starts_with('[') && comm.ends_with(']') {
            if let Ok(_exe) = std::fs::read_link(format!("/proc/{}/exe", name)) {
                if let Ok(status) = std::fs::read_to_string(&status_path) {
                    let is_userspace = status.lines()
                        .any(|l| l.starts_with("Uid:") && !l.contains("0\t0\t0\t0"));

                    if is_userspace {
                        findings.push(
                            Finding::high(format!("Bracket-name process masquerading: '{}' (PID {})", comm, name))
                                .with_detail("Process using bracket-enclosed name to mimic kernel threads")
                                .with_fix(format!("Investigate: cat /proc/{}/cmdline | tr '\\0' ' '", name))
                                .with_cvss(7.5)
                                .with_mitre(vec!["T1036.004"])
                                .with_nist(vec!["SI-4"])
                                .with_engine("Phantom")
                                .with_rule("DK-PHA-011"),
                        );
                    }
                }
            }
        }
    }
}

/// Detect hidden files in world-writable directories
/// ATT&CK T1564.001 (Hidden Files and Directories)
async fn scan_hidden_artifacts(findings: &mut Vec<Finding>) {
    let suspicious_dirs = vec![
        "/tmp", "/var/tmp", "/dev/shm", "/run/shm",
    ];

    for dir in &suspicious_dirs {
        if !Path::new(dir).is_dir() { continue; }

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();

                if name.starts_with('.') && name != "." && name != ".." {
                    let path = entry.path();
                    let is_dir = path.is_dir();
                    let size = if path.is_file() {
                        path.metadata().map(|m| m.len()).unwrap_or(0)
                    } else { 0 };

                    if name == ".X11-unix" || name == ".ICE-unix" || name == ".font-unix" || name == ".XIM-unix" {
                        continue;
                    }

                    let file_type = if is_dir { "directory" } else { "file" };
                    let detail = if size > 0 {
                        format!("Hidden {} ({} bytes)", file_type, size)
                    } else {
                        format!("Hidden {}", file_type)
                    };

                    findings.push(
                        Finding::warning(format!("Hidden {} in {}: {}", file_type, dir, name))
                            .with_detail(detail)
                            .with_fix(format!("Inspect: ls -la {}/{} && file {}/{}", dir, name, dir, name))
                            .with_cvss(4.3)
                            .with_mitre(vec!["T1564.001"])
                            .with_nist(vec!["CM-6", "SI-4"])
                            .with_engine("Phantom")
                            .with_rule("DK-PHA-012"),
                    );
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(meta) = path.metadata() {
                            let mode = meta.permissions().mode();
                            if mode & 0o111 != 0 && meta.len() > 0 {
                                findings.push(
                                    Finding::warning(format!("Executable in {}: {}", dir, name))
                                        .with_detail(format!("Size: {} bytes | Permissions: {:o}", meta.len(), mode & 0o7777))
                                        .with_fix(format!("Inspect: file {}/{} && strings {}/{} | head", dir, name, dir, name))
                                        .with_cvss(4.3)
                                        .with_mitre(vec!["T1059", "T1036.005"])
                                        .with_nist(vec!["CM-6", "SI-3"])
                                        .with_engine("Phantom")
                                        .with_rule("DK-PHA-013"),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Check for namespace manipulation indicators
/// ATT&CK T1611 (Escape to Host), NIST SC-39
async fn scan_namespace_anomalies(findings: &mut Vec<Finding>) {
    if let Ok(content) = std::fs::read_to_string("/proc/sys/user/max_user_namespaces") {
        let max_ns: u64 = content.trim().parse().unwrap_or(0);
        if max_ns > 0 {
            findings.push(
                Finding::info(format!("User namespaces enabled (max: {})", max_ns))
                    .with_detail("User namespaces allow unprivileged namespace creation — used by containers but also exploitable")
                    .with_fix("If not needed: echo 0 > /proc/sys/user/max_user_namespaces")
                    .with_cis("1.6.4")
                    .with_stig("V-230267")
                    .with_nist(vec!["CM-6", "SC-39"])
                    .with_engine("Phantom")
                    .with_rule("DK-PHA-014"),
            );
        }
    }

    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if content.trim() == "1" {
            findings.push(
                Finding::info("Unprivileged user namespace cloning enabled")
                    .with_detail("Any user can create namespaces — increases kernel attack surface (CVE-2022-0185, CVE-2023-2640)")
                    .with_fix("If not needed: sysctl kernel.unprivileged_userns_clone=0")
                    .with_cvss(5.3)
                    .with_cve(vec!["CVE-2022-0185", "CVE-2023-2640"])
                    .with_nist(vec!["CM-6", "SC-39"])
                    .with_engine("Phantom")
                    .with_rule("DK-PHA-015"),
            );
        }
    }
}
