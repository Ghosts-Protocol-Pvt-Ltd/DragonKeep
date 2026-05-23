//! Smoke-test the Phantom Memory bridge with a synthetic finding.
//! Run with: `cargo run --example test_bridge`
//! Requires DRAGONKEEP_MEMORY_BRIDGE env var.

use dragonkeep::engine::{memory_bridge, Finding};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let f = Finding::high("Smoke-test: bridge connectivity check")
        .with_detail("Synthetic finding emitted by examples/test_bridge.rs")
        .with_engine("Shield")
        .with_rule("DK-SMOKE-001")
        .with_mitre(vec!["T1059".to_string()]);

    println!("Bridge endpoint: {:?}", memory_bridge::bridge_endpoint());
    println!("Host target: {}", memory_bridge::host_target());

    match memory_bridge::check_bridge().await {
        Ok(msg) => println!("✓ bridge ok: {msg}"),
        Err(e) => {
            eprintln!("✗ bridge unreachable: {e}");
            std::process::exit(1);
        }
    }

    match memory_bridge::push_finding(&f).await {
        Ok(_) => println!("✓ pushed finding to Phantom Memory"),
        Err(e) => {
            eprintln!("✗ push failed: {e}");
            std::process::exit(2);
        }
    }
    Ok(())
}
