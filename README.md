# 🏰 DragonKeep — Community Edition

**Next-gen system security, threat defense & performance platform.**

A command-line tool built in Rust that scans, defends, hunts, hardens, tunes, and monitors your system — from gaming rigs to AI workstations to production servers. 11 specialized engines cover malware defense, ransomware protection, threat hunting, security auditing, AI/ML threat detection, supply chain integrity, runtime anomaly detection, performance tuning, process monitoring, and network hardening.

## Why DragonKeep?

Most security tools do one thing. DragonKeep runs 11 engines in a single binary with zero runtime dependencies, producing findings mapped to 6 industry frameworks:

- **MITRE ATT&CK** — Technique IDs from [attack.mitre.org](https://attack.mitre.org) (150+ technique mappings)
- **Atomic Red Team** — Test procedures from [Red Canary](https://github.com/redcanaryco/atomic-red-team) (ATT&CK technique IDs double as test references)
- **NIST SP 800-53 Rev 5** — Security controls (SI, AC, CM, SC, AU, IR, CP, IA families)
- **DISA STIG** — Defense Information Systems Agency STIGs (RHEL-08 V-230xxx series)
- **CIS Benchmarks v8** — Center for Internet Security hardening benchmarks
- **CVSS v3.1** — Common Vulnerability Scoring System base scores (0.0–10.0)

Output in SARIF v2.1.0 for GitHub Code Scanning, Azure DevOps, and CI/CD integration.

| Feature | DragonKeep | lynis | Wazuh | CrowdStrike |
|---------|-----------|-------|-------|-------------|
| Security scanning | ✅ | ✅ | ✅ | ✅ |
| Malware detection & defense | ✅ | ❌ | ✅ | ✅ |
| Ransomware defense | ✅ | ❌ | Partial | ✅ |
| Threat hunting | ✅ | ❌ | Partial | ✅ |
| Automated remediation | ✅ | ❌ | ✅ | ✅ |
| AI/ML threat surface | ✅ | ❌ | ❌ | Partial |
| Supply chain audit | ✅ | ❌ | Partial | ✅ |
| Runtime anomaly detection | ✅ | ❌ | ✅ | ✅ |
| Performance tuning | ✅ | ❌ | ❌ | ❌ |
| Live TUI monitor | ✅ | ❌ | ❌ | ❌ |
| Security score & grading | ✅ | ❌ | ❌ | Partial |
| Community threat feeds | ✅ | ❌ | ✅ | N/A |
| Scan profiles | ✅ | ❌ | ❌ | ❌ |
| Ransomware canary files | ✅ | ❌ | ❌ | ❌ |
| SARIF output | ✅ | ❌ | ❌ | ❌ |
| CVSS scoring | ✅ | ❌ | ✅ | ✅ |
| MITRE ATT&CK mapping | ✅ | ❌ | ✅ | ✅ |
| CIS Benchmark IDs | ✅ | ✅ | ✅ | ✅ |
| DISA STIG mapping | ✅ | ❌ | Partial | ✅ |
| NIST SP 800-53 mapping | ✅ | ❌ | ❌ | ❌ |
| GPU awareness | ✅ | ❌ | ❌ | ❌ |
| Single binary | ✅ | ❌ | ❌ | ❌ |
| Zero agent overhead | ✅ | ✅ | ❌ | ❌ |

## Engines

DragonKeep runs 11 specialized engines:

### 🛡️ Sentinel — Security Scanner
- Kernel security (ASLR, kptr_restrict, dmesg_restrict, core dumps, SYN cookies, NX bit, kernel lockdown)
- MAC enforcement verification (SELinux/AppArmor status)
- File permission audits (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, SUID binaries via GTFOBins)
- SSH hardening audit (root login, password auth, X11, MaxAuthTries, idle timeout, weak ciphers)
- Rootkit detection (Diamorphine, Reptile, bdvl, Suterusu, Adore-ng, Knark, LD_PRELOAD)
- Credential exposure (Discord tokens, Steam tokens, browser credential stores, SSH private keys)
- USB/DMA attack surface (Thunderbolt IOMMU, USB auto-authorization)
- Open port analysis (10 risky port categories)

### ⚡ Forge — Performance Tuner
- CPU governor optimization
- I/O scheduler selection (SSD vs HDD aware)
- Memory pressure analysis & swap/swappiness configuration
- Transparent hugepages management
- GPU status (NVIDIA/AMD)
- Workload profiles: `gaming`, `ai`, `creative`, `workstation`, `server`, `balanced`

### 👁️ Warden — Process Monitor & Threat Detector
- Real-time TUI dashboard (ratatui)
- CPU/memory threshold alerts with ATT&CK T1496 mapping
- Cryptocurrency miner detection (18 known miners: xmrig, ethminer, phoenixminer, t-rex, etc.)
- Credential stealer detection (12 known stealers: RedLine, Vidar, Raccoon, Lumma, etc.)
- Suspicious tool runtime detection (nmap, hashcat, responder, bettercap)
- Zombie process detection & process binary location analysis
- Processes executing from world-writable directories (/tmp, /dev/shm)

### 🏯 Bastion — Network Security
- Firewall audit (firewalld, ufw, iptables, nftables)
- Listening service enumeration (local vs external binding)
- DNS configuration audit (DoT/DoH detection)
- Network interface analysis & IPv6 privacy extension check

### 🏰 Citadel — System Hardener
- Kernel parameter hardening (sysctl, ptrace_scope, sysrq)
- Secure Boot status verification
- Filesystem mount options (/tmp noexec/nosuid)
- Service audit (risky services: telnet, rsh, ftp, rpcbind)
- User account security (UID 0 users, root password)
- Hardening profiles: `standard`, `server`, `paranoid`

### 🔮 Spectre — AI/ML Threat Surface Scanner
- Exposed AI inference ports (Ollama, Jupyter, TensorFlow, vLLM, Gradio, Triton)
- Dangerous model files (pickle-based .pt/.pkl with code execution risk)
- Leaked API keys (OpenAI, Anthropic, HuggingFace, Azure, Cohere, Mistral)
- GPU memory residuals (data leakage after AI workloads)
- Unsafe deserialization in Python ML pipelines (torch.load, pickle.load)
- Jupyter authentication audit (disabled tokens, network exposure)
- Container-based AI service exposure (Ollama/vLLM containers on 0.0.0.0)
- Prompt injection vectors in LLM configurations

### 🛡️ Aegis — Supply Chain & Integrity Auditor
- Package manager security (GPG verification: dnf, apt, pacman)
- Critical binary provenance (RPM/dpkg verification of sshd, sudo, login, su)
- EOL distribution detection & stale kernel warnings
- Container escape vectors (privileged mode, Docker socket mount, PID namespace)
- Systemd unit file tampering (temp directory exec, shell command injection)
- Unsigned/out-of-tree kernel module detection
- Language package audit (pip/npm global installs)
- Repository signing key expiration checks

### 👻 Phantom — Runtime Anomaly Detector
- Reverse shell pattern detection across all running processes
- System-wide LD_PRELOAD injection (rootkit technique detection)
- Deleted executable detection (processes running from removed binaries)
- Ptrace attachment monitoring (process injection/credential theft)
- Fileless malware indicators (memfd_create abuse)
- Crontab backdoor detection (suspicious scheduled tasks)
- Unusual outbound connections (non-standard ports to external IPs)
- Process name masquerading (fake kernel threads: kworker mimics)
- Hidden file detection in world-writable directories (/tmp, /dev/shm)
- Namespace manipulation analysis (user namespace escape vectors)

### 🐉 Hydra — Malware Detection & Defense
- Known malware process detection (16 C2/implant signatures: Cobalt Strike, Meterpreter, Sliver, Havoc, etc.)
- LOLBins abuse detection (curl|wget piping to shell, base64 obfuscation, openssl reverse shells)
- Deep rootkit detection (hidden processes, kernel module rootkits: Diamorphine, Reptile, Suterusu, etc.)
- LD_PRELOAD rootkit scanning
- Persistence mechanism audit (systemd, cron, SSH keys, init scripts, shell profiles)
- Webshell detection (PHP/JSP/ASP backdoors with 17 pattern signatures)
- C2 beaconing pattern analysis (suspicious port connections, DNS tunneling)
- Fileless malware detection (memfd_create, /dev/shm execution)
- Dropper artifact scanning in staging directories
- System binary integrity verification (rpm -Va / dpkg --verify)
- **Automated remediation:** Kill processes, quarantine files, disable services

### 🔥 Drake — Ransomware Defense & Recovery
- Known ransomware process detection (20 families: LockBit, BlackCat, Conti, REvil, Ryuk, Akira, etc.)
- Mass encryption activity detection (file operation monitoring)
- Ransomware file extension monitoring (30+ known extensions)
- Ransom note detection (30+ filename patterns with content validation)
- Backup integrity verification (restic, borg, duplicity, timeshift, BTRFS/ZFS snapshots)
- Backup destruction detection (vssadmin, wbadmin, zfs destroy, lvremove)
- Shannon entropy analysis for mass encryption detection
- Ransomware canary file deployment & monitoring
- Anti-recovery technique detection (shred, wipe, secure deletion)
- Recovery tool availability check (testdisk, photorec, foremost)
- **Automated remediation:** Kill ransomware, network isolation, evidence preservation, recovery guidance

### 🦅 Talon — Threat Hunting & Advanced Threat Protection
- Lateral movement detection (SSH brute force, PsExec, WMI, RDP, tunneling tools)
- Privilege escalation hunting (SUID abuse, LinPEAS, kernel exploits: DirtyPipe, PwnKit, Looney Tunables)
- Data exfiltration indicator detection (cloud uploads, archive creation, large transfers)
- Internal reconnaissance detection (nmap, masscan, bloodhound, enum4linux)
- Credential access tool detection (mimikatz, hashcat, john, responder, lazagne)
- System log analysis (auth failures, segfaults, OOM kills, audit log tampering)
- Suspicious user session detection (root login, UID 0 backdoor accounts)
- Process tree anomaly detection (web server → shell, database → shell)
- IOC artifact scanning (payloads, exploits, implants in temp directories)
- Suspicious connection monitoring (malicious port patterns)
- **Interactive threat hunting mode** with hypothesis-driven approach

## Installation

### From source
```bash
git clone https://github.com/Ghosts-Protocol-Pvt-Ltd/DragonKeep.git
cd DragonKeep
cargo build --release
sudo cp target/release/dragonkeep /usr/local/bin/
```

### Requirements
- Rust 1.85+ (edition 2024)
- Linux (primary target)

## Usage

```bash
# Full system audit (all 11 engines)
dragonkeep scan

# Use community scan profiles
dragonkeep scan --profile quick         # Fast essential check (~30s)
dragonkeep scan --profile standard       # Balanced audit (~2min)
dragonkeep scan --profile deep           # All 11 engines (~5min)
dragonkeep scan --profile malware        # Malware & ransomware focus
dragonkeep scan --profile threat-hunt    # Active threat detection
dragonkeep scan --profile compliance     # STIG/NIST/CIS compliance
dragonkeep scan --profile server         # Production server check
dragonkeep scan --profile workstation    # Desktop security check

# Scan specific engines
dragonkeep scan sentinel,forge
dragonkeep scan hydra,drake,talon

# Malware & ransomware defense
dragonkeep malware                       # Malware scan (Hydra engine)
dragonkeep ransomware                    # Ransomware defense (Drake engine)
dragonkeep hunt                          # Proactive threat hunting (Talon engine)

# Threat remediation (safe mode by default)
dragonkeep remediate                     # Remediate all threats
dragonkeep remediate malware             # Remediate malware only
dragonkeep remediate ransomware          # Ransomware incident response

# Community features
dragonkeep score                         # Security score & grade
dragonkeep feeds                         # Community threat intel feeds
dragonkeep canary                        # Deploy ransomware canary files
dragonkeep profiles                      # Show scan profiles
dragonkeep community                     # Community edition info

# Individual engine commands
dragonkeep ai                            # AI/ML threat surface scan
dragonkeep supply                        # Supply chain integrity audit
dragonkeep anomaly                       # Runtime anomaly detection
dragonkeep firewall                      # Network security audit
dragonkeep processes                     # Process analysis

# Show system status
dragonkeep status

# Tune for gaming / AI / server
dragonkeep tune gaming
dragonkeep tune ai

# Apply security hardening
dragonkeep harden
dragonkeep harden paranoid

# Live system monitor (TUI)
dragonkeep monitor

# Generate full report (all 11 engines)
dragonkeep report
dragonkeep report --output report.json
dragonkeep report --output scan.sarif

# Output formats
dragonkeep scan --format sarif
dragonkeep scan --format json
dragonkeep scan --format minimal

# Dry run — see what would change
dragonkeep harden paranoid --dry-run
dragonkeep remediate --dry-run

# Initialize config
dragonkeep init
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Pretty | `--format pretty` | Human-readable terminal output (default) |
| JSON | `--format json` | Machine-parseable, CI/CD pipelines |
| Minimal | `--format minimal` | One-line-per-finding, grep-friendly |
| SARIF | `--format sarif` | GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer |

### SARIF Integration

DragonKeep outputs SARIF v2.1.0, the industry standard for security tool interoperability:

```bash
# Upload to GitHub Code Scanning
dragonkeep report -o results.sarif
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -F sarif=@results.sarif -F ref=refs/heads/main
```

Each finding includes:
- **CVSS v3.1 base score** (0.0–10.0) mapped to `security-severity`
- **MITRE ATT&CK technique IDs** (e.g., T1059, T1195.002) — [attack.mitre.org](https://attack.mitre.org)
- **DISA STIG IDs** (e.g., V-230264, V-230324) — [DoD Cyber Exchange](https://public.cyber.mil/stigs/)
- **NIST SP 800-53 controls** (e.g., SI-7, AC-6, CM-7) — [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- **CIS Benchmark IDs** (e.g., 1.1.1.1, 5.2.4) — [cisecurity.org](https://www.cisecurity.org/cis-benchmarks)
- **CVE identifiers** where applicable
- **Unique rule IDs** (e.g., DK-SPE-001) for suppression/deduplication

### Framework Sources & References

| Framework | Authority | URL |
|-----------|-----------|-----|
| MITRE ATT&CK | The MITRE Corporation | https://attack.mitre.org |
| Atomic Red Team | Red Canary | https://github.com/redcanaryco/atomic-red-team |
| NIST SP 800-53 Rev 5 | National Institute of Standards and Technology | https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final |
| DISA STIGs | Defense Information Systems Agency | https://public.cyber.mil/stigs/ |
| CIS Benchmarks v8 | Center for Internet Security | https://www.cisecurity.org/cis-benchmarks |
| CVSS v3.1 | FIRST.org | https://www.first.org/cvss/v3.1/specification-document |
| GTFOBins | community | https://gtfobins.github.io |
| NSA Hardening Guides | National Security Agency | https://www.nsa.gov/cybersecurity-guidance/ |

## Configuration

DragonKeep stores config at `~/.config/dragonkeep/config.toml`. Generate defaults with:

```bash
dragonkeep init
```

Config structure:
```toml
[general]
safe_mode = true
log_level = "info"

[sentinel]
enabled = true
cve_check = true
rootkit_scan = true

[forge]
enabled = true
default_profile = "balanced"
gpu_tuning = true

[warden]
enabled = true
cpu_threshold = 90.0
memory_threshold = 85.0

[bastion]
enabled = true
firewall_audit = true

[citadel]
enabled = true
kernel_hardening = true

[spectre]
enabled = true
port_scan = true
key_scan = true
model_scan = true
gpu_check = true
deserialization_scan = true

[aegis]
enabled = true
binary_verification = true
package_audit = true
currency_check = true
container_audit = true
systemd_audit = true
module_audit = true

[phantom]
enabled = true
shell_detection = true
preload_scan = true
deleted_exe_scan = true
cron_audit = true
connection_scan = true
masquerade_detection = true

[hydra]
enabled = true
rootkit_detection = true
persistence_scan = true
webshell_scan = true
c2_detection = true
fileless_detection = true

[drake]
enabled = true
extension_monitor = true
ransom_note_scan = true
backup_protection = true
entropy_analysis = true
canary_monitoring = true

[talon]
enabled = true
privesc_hunting = true
exfil_detection = true
credential_hunting = true
log_analysis = true
ioc_scan = true
```

## Safety

DragonKeep is designed to **never break your system**:

- **`--dry-run`** flag shows all changes before applying
- **`safe_mode = true`** in config prevents destructive operations by default
- All tuning operations use standard `sysctl` calls that revert on reboot
- No files are deleted, no services are stopped without user confirmation
- Scan operations are read-only — they only report findings

## Architecture

```
dragonkeep
├── src/
│   ├── main.rs          # Entry point, banner, tokio runtime
│   ├── cli.rs           # clap CLI parser, command dispatch (20+ commands)
│   ├── config.rs        # TOML config (serde, 11 engine configs)
│   ├── report.rs        # Report generation (JSON/SARIF/pretty/minimal)
│   ├── community.rs     # Community features (profiles, scoring, feeds)
│   └── engine/
│       ├── mod.rs       # Finding/Severity types (CVSS, CIS, MITRE, STIG, NIST)
│       ├── sentinel.rs  # Security scanner
│       ├── forge.rs     # Performance tuner
│       ├── warden.rs    # Process monitor + TUI
│       ├── bastion.rs   # Network security
│       ├── citadel.rs   # System hardener
│       ├── spectre.rs   # AI/ML threat surface scanner
│       ├── aegis.rs     # Supply chain integrity auditor
│       ├── phantom.rs   # Runtime anomaly detector
│       ├── hydra.rs     # Malware detection & defense
│       ├── drake.rs     # Ransomware defense & recovery
│       └── talon.rs     # Threat hunting & advanced threat protection
├── Cargo.toml
├── LICENSE              # MIT
└── README.md
```

## License

MIT — [Ghost Protocol (Pvt) Ltd](https://ghosts.lk)
