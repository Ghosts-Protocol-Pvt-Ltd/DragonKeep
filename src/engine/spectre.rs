//! Spectre Engine — AI/ML Threat Surface Scanner
//!
//! Detects exposed ML model endpoints, unprotected inference services,
//! prompt injection vectors, GPU memory residuals, unsafe deserialization,
//! leaked API keys, and AI framework vulnerabilities.
//!
//! Standards: MITRE ATT&CK (T1190, T1059.006, T1195.002, T1552.001),
//! NIST SP 800-53 Rev 5 (SC-7, SI-7, IA-5, SC-28), OWASP ML Top 10

use crate::config::Config;
use crate::engine::Finding;

use std::collections::HashSet;
use std::path::Path;

/// Well-known AI/ML inference ports and their services
const AI_PORTS: &[(u16, &str)] = &[
    (8888, "Jupyter Notebook"),
    (8889, "Jupyter Lab (alt)"),
    (8080, "TorchServe / Triton HTTP"),
    (8081, "TorchServe management"),
    (8501, "TensorFlow Serving REST"),
    (8500, "TensorFlow Serving gRPC"),
    (11434, "Ollama"),
    (5000, "MLflow / Flask inference"),
    (3000, "LiteLLM / OpenWebUI"),
    (7860, "Gradio"),
    (7861, "Gradio (variant)"),
    (9090, "Prometheus (model metrics)"),
    (4000, "LiteLLM proxy"),
    (6333, "Qdrant vector DB"),
    (19530, "Milvus vector DB"),
    (8983, "Solr (embedding search)"),
];

/// Dangerous model file extensions that may contain executable payloads
const DANGEROUS_MODEL_EXTS: &[&str] = &[
    ".pkl", ".pickle",  // Python pickle — arbitrary code execution
    ".pt", ".pth",      // PyTorch — uses pickle internally
    ".joblib",          // scikit-learn — pickle variant
];

/// Model files that are safe but should still be access-controlled
const SENSITIVE_MODEL_EXTS: &[&str] = &[
    ".onnx",            // ONNX — safe format but proprietary IP
    ".safetensors",     // HuggingFace safe format
    ".gguf", ".ggml",   // llama.cpp quantized models
    ".bin",             // Generic model weights
    ".h5", ".hdf5",     // Keras / TF models
    ".tflite",          // TensorFlow Lite
    ".mlmodel",         // CoreML
    ".pb",              // TensorFlow protobuf
];

/// API key patterns to search for in environment / config files
const KEY_PATTERNS: &[(&str, &str)] = &[
    ("OPENAI_API_KEY", "OpenAI"),
    ("ANTHROPIC_API_KEY", "Anthropic"),
    ("HF_TOKEN", "Hugging Face"),
    ("HUGGING_FACE_HUB_TOKEN", "Hugging Face"),
    ("COHERE_API_KEY", "Cohere"),
    ("REPLICATE_API_TOKEN", "Replicate"),
    ("GOOGLE_API_KEY", "Google AI"),
    ("MISTRAL_API_KEY", "Mistral AI"),
    ("TOGETHER_API_KEY", "Together AI"),
    ("GROQ_API_KEY", "Groq"),
    ("WANDB_API_KEY", "Weights & Biases"),
    ("NEPTUNE_API_TOKEN", "Neptune.ai"),
    ("AWS_SECRET_ACCESS_KEY", "AWS (SageMaker)"),
    ("AZURE_OPENAI_API_KEY", "Azure OpenAI"),
];

/// Suspicious Python patterns indicating unsafe model loading
const UNSAFE_LOAD_PATTERNS: &[&str] = &[
    "pickle.load",
    "pickle.loads",
    "torch.load",          // Without weights_only=True
    "joblib.load",
    "dill.load",
    "cloudpickle.load",
    "shelve.open",
    "yaml.load",           // Without Loader=SafeLoader
    "marshal.loads",
];

pub async fn scan(config: &Config) -> anyhow::Result<Vec<Finding>> {
    if !config.spectre.enabled {
        return Ok(vec![Finding::info("Spectre engine disabled").with_engine("Spectre")]);
    }

    let mut findings = Vec::new();

    scan_ai_ports(&mut findings).await;
    scan_model_files(&mut findings).await;
    scan_api_keys(&mut findings).await;
    scan_gpu_memory(&mut findings).await;
    scan_unsafe_deserialization(&mut findings).await;
    scan_jupyter_config(&mut findings).await;
    scan_container_ai_exposure(&mut findings).await;
    scan_prompt_injection_vectors(&mut findings).await;

    if findings.is_empty() {
        findings.push(
            Finding::pass("No AI/ML threat surface detected")
                .with_engine("Spectre")
                .with_rule("DK-SPE-000"),
        );
    }

    Ok(findings)
}

/// Check if common AI inference ports are listening and externally accessible
/// ATT&CK T1190 (Exploit Public-Facing Application)
async fn scan_ai_ports(findings: &mut Vec<Finding>) {
    let tcp_data = match std::fs::read_to_string("/proc/net/tcp") {
        Ok(data) => data,
        Err(_) => return,
    };

    let listening_ports: HashSet<u16> = tcp_data
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 { return None; }
            if fields[3] != "0A" { return None; }
            let addr = fields[1];
            let port_hex = addr.split(':').nth(1)?;
            u16::from_str_radix(port_hex, 16).ok()
        })
        .collect();

    for (port, service) in AI_PORTS {
        if listening_ports.contains(port) {
            let is_external = tcp_data.lines().skip(1).any(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 || fields[3] != "0A" { return false; }
                let addr = fields[1];
                addr.starts_with("00000000:")
                    && addr.ends_with(&format!("{:04X}", port))
            });

            if is_external {
                findings.push(
                    Finding::critical(format!("{} exposed on port {} (all interfaces)", service, port))
                        .with_detail("AI inference endpoint bound to 0.0.0.0 — accessible from any network")
                        .with_fix(format!("Bind {} to 127.0.0.1 or use a reverse proxy with authentication", service))
                        .with_cvss(9.1)
                        .with_mitre(vec!["T1190", "T1071.001"])
                        .with_nist(vec!["SC-7", "AC-17", "IA-2"])
                        .with_engine("Spectre")
                        .with_rule("DK-SPE-001"),
                );
            } else {
                findings.push(
                    Finding::info(format!("{} listening on port {} (localhost only)", service, port))
                        .with_engine("Spectre")
                        .with_rule("DK-SPE-002"),
                );
            }
        }
    }
}

/// Find world-readable or dangerous model files
/// ATT&CK T1195.002 (Supply Chain: Compromise Software Supply Chain)
async fn scan_model_files(findings: &mut Vec<Finding>) {
    let search_dirs = vec![
        "/home", "/opt", "/srv", "/var/lib", "/tmp",
        "/root",
    ];

    let mut dangerous_found = Vec::new();
    let mut world_readable = Vec::new();

    for dir in &search_dirs {
        if !Path::new(dir).exists() { continue; }
        scan_dir_for_models(dir, &mut dangerous_found, &mut world_readable, 0);
    }

    for path in &dangerous_found {
        findings.push(
            Finding::high(format!("Dangerous model file: {}", path))
                .with_detail("Pickle-based model files can execute arbitrary code when loaded. An attacker who replaces this file gains code execution.")
                .with_fix("Convert to SafeTensors (.safetensors) format or use torch.load(weights_only=True)")
                .with_cvss(8.8)
                .with_mitre(vec!["T1059.006", "T1195.002"])
                .with_nist(vec!["SI-7", "SA-12"])
                .with_engine("Spectre")
                .with_rule("DK-SPE-003"),
        );
    }

    for path in &world_readable {
        findings.push(
            Finding::warning(format!("World-readable model file: {}", path))
                .with_detail("Model files with open permissions can be read (IP theft) or replaced (supply chain attack)")
                .with_fix(format!("chmod 640 '{}' && chown root:ml-team '{}'", path, path))
                .with_cvss(5.3)
                .with_mitre(vec!["T1005", "T1195.002"])
                .with_nist(vec!["SC-28", "AC-3"])
                .with_engine("Spectre")
                .with_rule("DK-SPE-004"),
        );
    }
}

fn scan_dir_for_models(dir: &str, dangerous: &mut Vec<String>, world_readable: &mut Vec<String>, depth: u32) {
    if depth > 5 { return; }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        // SECURITY: Skip symlinks to prevent traversal outside scan scope
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                continue;
            }
        }
        if path.is_dir() {
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if name.starts_with('.') || name == "node_modules" || name == "__pycache__" {
                continue;
            }
            scan_dir_for_models(&path.to_string_lossy(), dangerous, world_readable, depth + 1);
        } else if let Some(ext) = path.extension() {
            let ext_str = format!(".{}", ext.to_string_lossy().to_lowercase());
            let path_str = path.to_string_lossy().to_string();

            if DANGEROUS_MODEL_EXTS.contains(&ext_str.as_str()) {
                dangerous.push(path_str.clone());
            }

            let all_model_exts: Vec<&str> = DANGEROUS_MODEL_EXTS.iter()
                .chain(SENSITIVE_MODEL_EXTS.iter())
                .copied()
                .collect();

            if all_model_exts.contains(&ext_str.as_str()) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = path.metadata() {
                        let mode = meta.permissions().mode();
                        if mode & 0o004 != 0 {
                            world_readable.push(path_str);
                        }
                    }
                }
            }
        }
    }
}

/// Check for AI/ML API keys leaked in environment variables or config files
/// ATT&CK T1552.001 (Unsecured Credentials: Credentials in Files)
async fn scan_api_keys(findings: &mut Vec<Finding>) {
    for (key, service) in KEY_PATTERNS {
        if std::env::var(key).is_ok() {
            findings.push(
                Finding::warning(format!("{} API key found in environment: {}", service, key))
                    .with_detail("API keys in environment variables may leak via /proc, logs, or child processes")
                    .with_fix(format!("Use a secrets manager (Vault, SOPS) instead of env var {}", key))
                    .with_cvss(6.5)
                    .with_mitre(vec!["T1552.001"])
                    .with_nist(vec!["IA-5(7)", "SC-28"])
                    .with_engine("Spectre")
                    .with_rule("DK-SPE-005"),
            );
        }
    }

    let config_files = vec![
        format!("{}/.bashrc", std::env::var("HOME").unwrap_or_default()),
        format!("{}/.zshrc", std::env::var("HOME").unwrap_or_default()),
        format!("{}/.profile", std::env::var("HOME").unwrap_or_default()),
        format!("{}/.env", std::env::var("HOME").unwrap_or_default()),
        "/etc/environment".to_string(),
    ];

    for file_path in &config_files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for (key, service) in KEY_PATTERNS {
                if content.contains(key) {
                    // SECURITY: Report file and key name only — never include line content
                    // to prevent leaking actual secret values in scan output
                    let line_num = content.lines().enumerate()
                        .find(|(_, l)| l.contains(key))
                        .map(|(i, _)| i + 1)
                        .unwrap_or(0);
                    findings.push(
                        Finding::high(format!("{} API key hardcoded in {}", service, file_path))
                            .with_detail(format!("API key '{}' found at line {} — hardcoded keys persist across sessions and may be committed to version control", key, line_num))
                            .with_fix(format!("Remove {} from {} and use a secrets manager", key, file_path))
                            .with_cvss(7.5)
                            .with_mitre(vec!["T1552.001", "T1552.004"])
                            .with_nist(vec!["IA-5(7)", "SC-28"])
                            .with_engine("Spectre")
                            .with_rule("DK-SPE-006"),
                    );
                }
            }
        }
    }
}

/// Check GPU memory state
/// ATT&CK T1005 (Data from Local System)
async fn scan_gpu_memory(findings: &mut Vec<Finding>) {
    if let Ok(output) = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=index,memory.used,memory.total,compute-mode", "--format=csv,noheader,nounits"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split(", ").collect();
                if parts.len() >= 4 {
                    let gpu_idx = parts[0].trim();
                    let mem_used: f64 = parts[1].trim().parse().unwrap_or(0.0);
                    let mem_total: f64 = parts[2].trim().parse().unwrap_or(1.0);
                    let compute_mode = parts[3].trim();

                    if mem_used > 100.0 {
                        let pct = (mem_used / mem_total * 100.0) as u32;
                        let procs = std::process::Command::new("nvidia-smi")
                            .args(["--query-compute-apps=pid", "--format=csv,noheader", &format!("--id={}", gpu_idx)])
                            .output();

                        let active_procs = procs.map(|o| {
                            String::from_utf8_lossy(&o.stdout).lines().count()
                        }).unwrap_or(0);

                        if active_procs == 0 && mem_used > 256.0 {
                            findings.push(
                                Finding::warning(format!("GPU {} has {:.0}MB ({:.0}%) memory residual with no active processes", gpu_idx, mem_used, pct))
                                    .with_detail("Residual GPU memory may contain model weights, training data, or inference results")
                                    .with_fix("Run 'nvidia-smi --gpu-reset' or explicitly free CUDA memory in your application")
                                    .with_cvss(4.0)
                                    .with_mitre(vec!["T1005"])
                                    .with_nist(vec!["SC-4", "SC-28"])
                                    .with_engine("Spectre")
                                    .with_rule("DK-SPE-007"),
                            );
                        }
                    }

                    if compute_mode == "Default" {
                        findings.push(
                            Finding::info(format!("GPU {} in Default compute mode — shared access enabled", gpu_idx))
                                .with_detail("Multiple processes/users can access this GPU simultaneously")
                                .with_fix("Set compute mode to Exclusive_Process for single-tenant ML workloads: nvidia-smi -c EXCLUSIVE_PROCESS")
                                .with_nist(vec!["AC-3", "SC-4"])
                                .with_engine("Spectre")
                                .with_rule("DK-SPE-008"),
                        );
                    }
                }
            }
        }
    }
}

/// Scan Python files for unsafe deserialization patterns
/// ATT&CK T1059.006 (Python), T1203 (Exploitation for Client Execution)
async fn scan_unsafe_deserialization(findings: &mut Vec<Finding>) {
    let search_dirs = vec!["/home", "/opt", "/srv"];
    let mut unsafe_files: Vec<(String, String)> = Vec::new();

    for dir in &search_dirs {
        find_unsafe_python_loads(dir, &mut unsafe_files, 0);
    }

    for (path, pattern) in &unsafe_files {
        findings.push(
            Finding::high(format!("Unsafe deserialization in {}", path))
                .with_detail(format!("Found '{}' — loading untrusted serialized data enables arbitrary code execution (CVE-2019-6446, CVE-2022-45907)", pattern))
                .with_fix(match pattern.as_str() {
                    p if p.contains("torch.load") => String::from("Use torch.load(path, weights_only=True) or convert to safetensors format"),
                    p if p.contains("pickle") => String::from("Use json, msgpack, or safetensors instead of pickle for model data"),
                    p if p.contains("yaml.load") => String::from("Use yaml.safe_load() instead of yaml.load()"),
                    _ => String::from("Replace with a safe serialization format (JSON, MessagePack, SafeTensors)"),
                })
                .with_cvss(8.1)
                .with_mitre(vec!["T1059.006", "T1203"])
                .with_cve(vec!["CVE-2019-6446", "CVE-2022-45907"])
                .with_nist(vec!["SI-7", "SI-10"])
                .with_engine("Spectre")
                .with_rule("DK-SPE-009"),
        );
    }
}

fn find_unsafe_python_loads(dir: &str, results: &mut Vec<(String, String)>, depth: u32) {
    if depth > 4 { return; }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        // SECURITY: Skip symlinks to prevent traversal outside scan scope
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                continue;
            }
        }
        if path.is_dir() {
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if name.starts_with('.') || name == "node_modules" || name == "__pycache__" || name == "venv" || name == ".venv" {
                continue;
            }
            find_unsafe_python_loads(&path.to_string_lossy(), results, depth + 1);
        } else if path.extension().is_some_and(|ext| ext == "py") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                for pattern in UNSAFE_LOAD_PATTERNS {
                    if content.contains(pattern) {
                        let safe = match *pattern {
                            "torch.load" => content.contains("weights_only=True") || content.contains("weights_only = True"),
                            "yaml.load" => content.contains("SafeLoader") || content.contains("safe_load"),
                            _ => false,
                        };
                        if !safe {
                            results.push((path.to_string_lossy().to_string(), pattern.to_string()));
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Check for exposed / insecure Jupyter configurations
/// ATT&CK T1190, NIST AC-3/IA-2
async fn scan_jupyter_config(findings: &mut Vec<Finding>) {
    let home = std::env::var("HOME").unwrap_or_default();
    let jupyter_configs = vec![
        format!("{}/.jupyter/jupyter_notebook_config.py", home),
        format!("{}/.jupyter/jupyter_server_config.py", home),
        format!("{}/.jupyter/jupyter_lab_config.py", home),
    ];

    for config_path in &jupyter_configs {
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if content.contains("NotebookApp.token = ''")
                || content.contains("ServerApp.token = ''")
                || content.contains("NotebookApp.password = ''")
                || content.contains("c.NotebookApp.disable_check_xsrf = True")
            {
                findings.push(
                    Finding::critical(format!("Jupyter authentication disabled in {}", config_path))
                        .with_detail("Jupyter without authentication allows arbitrary code execution by any network-reachable attacker")
                        .with_fix("Set a token or password: jupyter notebook --generate-config && jupyter notebook password")
                        .with_cvss(9.8)
                        .with_mitre(vec!["T1190", "T1059.006"])
                        .with_nist(vec!["AC-3", "IA-2", "SC-7"])
                        .with_engine("Spectre")
                        .with_rule("DK-SPE-010"),
                );
            }

            if content.contains("ip = '0.0.0.0'") || content.contains("ip = '*'") {
                findings.push(
                    Finding::high(format!("Jupyter bound to all interfaces in {}", config_path))
                        .with_detail("Jupyter server accessible from all network interfaces")
                        .with_fix("Set c.ServerApp.ip = '127.0.0.1' to bind to localhost only")
                        .with_cvss(7.5)
                        .with_mitre(vec!["T1190"])
                        .with_nist(vec!["SC-7", "AC-17"])
                        .with_engine("Spectre")
                        .with_rule("DK-SPE-011"),
                );
            }
        }
    }
}

/// Check for container-based AI service exposure
/// ATT&CK T1611 (Escape to Host), T1610 (Deploy Container)
async fn scan_container_ai_exposure(findings: &mut Vec<Finding>) {
    if Path::new("/var/run/docker.sock").exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata("/var/run/docker.sock") {
                let mode = meta.permissions().mode();
                if mode & 0o006 != 0 {
                    findings.push(
                        Finding::critical("Docker socket world-accessible — container escape possible")
                            .with_detail("An attacker with Docker socket access can mount the host filesystem and escalate to root")
                            .with_fix("Restrict /var/run/docker.sock to the docker group: chmod 660 /var/run/docker.sock")
                            .with_cvss(9.9)
                            .with_mitre(vec!["T1611", "T1610"])
                            .with_stig("V-230353")
                            .with_nist(vec!["AC-6", "SC-39"])
                            .with_engine("Spectre")
                            .with_rule("DK-SPE-012"),
                    );
                }
            }
        }
    }

    if let Ok(output) = std::process::Command::new("docker")
        .args(["ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let ai_images = ["ollama", "vllm", "triton", "tensorrt", "text-generation", "huggingface", "jupyter", "mlflow"];

            for line in stdout.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 2 {
                    let image = parts[1].to_lowercase();
                    if ai_images.iter().any(|ai| image.contains(ai)) {
                        let ports = if parts.len() >= 3 { parts[2] } else { "" };
                        if ports.contains("0.0.0.0") {
                            findings.push(
                                Finding::warning(format!("AI container '{}' exposed on all interfaces", parts[0]))
                                    .with_detail(format!("Image: {} | Ports: {}", parts[1], ports))
                                    .with_fix("Use Docker's -p 127.0.0.1:<port>:<port> to bind to localhost only")
                                    .with_cvss(6.5)
                                    .with_mitre(vec!["T1190", "T1610"])
                                    .with_nist(vec!["SC-7", "AC-17"])
                                    .with_engine("Spectre")
                                    .with_rule("DK-SPE-013"),
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Check for prompt injection vectors in LLM configurations
async fn scan_prompt_injection_vectors(findings: &mut Vec<Finding>) {
    let home = std::env::var("HOME").unwrap_or_default();

    let prompt_patterns = vec![
        format!("{}/.ollama", home),
        format!("{}/.config/lmstudio", home),
        format!("{}/.continue", home),
        format!("{}/.tabby", home),
        format!("{}/.local/share/ollama", home),
    ];

    for dir in &prompt_patterns {
        if Path::new(dir).is_dir() {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
                        if name.contains("model") || name.contains("prompt") || name.contains("system") {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                if let Ok(meta) = path.metadata() {
                                    let mode = meta.permissions().mode();
                                    if mode & 0o004 != 0 {
                                        findings.push(
                                            Finding::warning(format!("World-readable AI config: {}", path.display()))
                                                .with_detail("System prompts and model configs may contain sensitive instructions or guardrail bypasses")
                                                .with_fix(format!("chmod 600 '{}'", path.display()))
                                                .with_cvss(4.3)
                                                .with_mitre(vec!["T1552.001"])
                                                .with_nist(vec!["AC-3", "SC-28"])
                                                .with_engine("Spectre")
                                                .with_rule("DK-SPE-014"),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
