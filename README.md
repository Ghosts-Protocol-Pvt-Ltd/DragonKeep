# 🏰 DragonKeep

**Next-gen system security, performance & stability platform.**

A cross-platform command-line tool built in Rust that scans, hardens, tunes, and monitors your system — from gaming rigs to AI workstations to production servers.

## Why DragonKeep?

Most system tools do one thing. DragonKeep does everything — security auditing, performance tuning, process monitoring, network hardening, and system optimization — in a single binary with zero runtime dependencies.

| Feature | DragonKeep | lynis | htop | sysctl tuning scripts |
|---------|-----------|-------|------|----------------------|
| Security scanning | ✅ | ✅ | ❌ | ❌ |
| Performance tuning | ✅ | ❌ | ❌ | ✅ |
| Live TUI monitor | ✅ | ❌ | ✅ | ❌ |
| Network audit | ✅ | Partial | ❌ | ❌ |
| GPU awareness | ✅ | ❌ | ❌ | ❌ |
| Workload profiles | ✅ | ❌ | ❌ | ❌ |
| Dry run mode | ✅ | ❌ | N/A | ❌ |
| Single binary | ✅ | ❌ | ✅ | N/A |

## Engines

DragonKeep runs 5 specialized engines:

### 🛡️ Sentinel — Security Scanner
- Kernel security features (ASLR, kptr_restrict, dmesg_restrict)
- File permission audits (`/etc/shadow`, `/etc/passwd`, SUID binaries)
- SSH configuration audit (root login, password auth, X11)
- Rootkit indicator detection (suspicious modules, LD_PRELOAD)
- Open port analysis

### ⚡ Forge — Performance Tuner
- CPU governor optimization
- I/O scheduler selection (SSD vs HDD aware)
- Memory pressure analysis
- Swap/swappiness configuration
- Transparent hugepages management
- GPU status (NVIDIA/AMD)
- Workload profiles: `gaming`, `ai`, `creative`, `workstation`, `server`, `balanced`

### 👁️ Warden — Process Monitor
- Real-time TUI dashboard (ratatui)
- CPU/memory threshold alerts
- Suspicious process detection (cryptominers, reverse shells)
- Zombie process detection
- Top-N process ranking

### 🏯 Bastion — Network Security
- Firewall audit (firewalld, ufw, iptables, nftables)
- Listening service enumeration
- DNS configuration audit (DoT/DoH detection)
- Network interface analysis
- IPv6 privacy extension check

### 🏰 Citadel — System Hardener
- Kernel parameter hardening (sysctl)
- Secure Boot status
- Filesystem mount options (/tmp noexec)
- Service audit (risky services detection)
- User account security (UID 0, root password)
- Hardening profiles: `standard`, `server`, `paranoid`

## Installation

### From source
```bash
# Clone
git clone https://github.com/Ghosts-Protocol-Pvt-Ltd/DragonKeep.git
cd DragonKeep

# Build release binary
cargo build --release

# Install
sudo cp target/release/dragonkeep /usr/local/bin/
```

### Requirements
- Rust 1.85+ (edition 2024)
- Linux (primary), macOS/Windows (partial support)

## Usage

```bash
# Full system audit
dragonkeep scan

# Scan specific engines only
dragonkeep scan sentinel,forge

# Show system status
dragonkeep status

# Tune for gaming
dragonkeep tune gaming

# Tune for AI/ML workloads
dragonkeep tune ai

# Apply security hardening (standard profile)
dragonkeep harden

# Paranoid hardening
dragonkeep harden paranoid

# Live system monitor (TUI)
dragonkeep monitor

# Network security audit
dragonkeep firewall

# Process analysis
dragonkeep processes

# Generate full report
dragonkeep report

# Save report to file
dragonkeep report --output report.json

# Dry run — see what would change
dragonkeep harden paranoid --dry-run
dragonkeep tune gaming --dry-run

# JSON output
dragonkeep scan --format json

# Initialize config
dragonkeep init
```

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
│   ├── cli.rs           # clap CLI parser, command dispatch
│   ├── config.rs        # TOML config (serde)
│   ├── report.rs        # Report generation (JSON/pretty/minimal)
│   └── engine/
│       ├── mod.rs       # Finding/Severity types
│       ├── sentinel.rs  # Security scanner
│       ├── forge.rs     # Performance tuner
│       ├── warden.rs    # Process monitor + TUI
│       ├── bastion.rs   # Network security
│       └── citadel.rs   # System hardener
├── Cargo.toml
├── LICENSE              # MIT
└── README.md
```

## License

MIT — [Ghost Protocol (Pvt) Ltd](https://ghosts.lk)
