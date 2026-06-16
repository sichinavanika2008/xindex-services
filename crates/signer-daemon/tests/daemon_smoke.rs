#![expect(
    clippy::expect_used,
    reason = "integration test: panics on failed fixtures are the correct failure mode"
)]
//! Binary smoke test ("drill 0"): boot the real `xindex-signer-daemon`
//! binary in `--dev` with a software-key config on an ephemeral loopback
//! port and assert it serves `GET /api/v1/health` → 200. Proves the
//! entrypoint's config parse → state build → serve path end-to-end (the
//! coordinator↔daemon wire itself is covered by `loopback.rs`).

use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Grab an ephemeral free loopback port (bind :0, read it back, release).
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("local_addr").port()
}

/// Minimal `--dev` software-key config — enough to boot and serve health
/// (no UTXO role, no mTLS, in-memory store). `/health` does not sign, so
/// `eth_address` need not match the software key here.
fn write_dev_config(port: u16) -> std::path::PathBuf {
    let cfg = serde_json::json!({
        "chain_id": 31337,
        "verifying_contract": format!("0x{}", "ab".repeat(20)),
        "eth_address": format!("0x{}", "cd".repeat(20)),
        "intent_policy": {
            "signer_whitelist": [format!("0x{}", "01".repeat(20))],
            "intent_quorum": 1,
            "ric_max_age_secs": 7200
        },
        "cert_volume": { "window_secs": 86_400, "caps": {} },
        "hsm": {
            "kind": "software",
            "software": {
                "eth_secret_key": format!("0x{}", "22".repeat(32)),
                "btc_secret_key": format!("0x{}", "11".repeat(32))
            }
        },
        "bind": format!("127.0.0.1:{port}")
    });
    let path = std::env::temp_dir().join(format!("xindex-daemon-smoke-{port}.json"));
    let mut f = std::fs::File::create(&path).expect("create config");
    f.write_all(
        serde_json::to_string_pretty(&cfg)
            .expect("serialize config")
            .as_bytes(),
    )
    .expect("write config");
    path
}

#[tokio::test]
async fn daemon_binary_boots_and_serves_health_in_dev() {
    let port = free_port();
    let config = write_dev_config(port);

    // Spawn the real compiled binary; inherit stderr so a boot error
    // (anyhow `Err` from main, or the software-key gate) surfaces here.
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_xindex-signer-daemon"))
        .arg(&config)
        .arg("--dev")
        .env("XINDEX_ALLOW_SOFTWARE_KEYS", "1")
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn daemon binary");

    let url = format!("http://127.0.0.1:{port}/api/v1/health");
    let client = reqwest::Client::new();
    let mut last_err = String::from("never responded");
    let mut ok = false;
    for _ in 0..50 {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.expect("health json");
                assert_eq!(body["ok"], serde_json::Value::Bool(true), "health ok=true");
                ok = true;
                break;
            }
            Ok(resp) => last_err = format!("status {}", resp.status()),
            Err(e) => last_err = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&config);

    assert!(ok, "daemon did not serve /health within ~5s: {last_err}");
}

/// The software-key gate must hold at the binary boundary too: without
/// `XINDEX_ALLOW_SOFTWARE_KEYS=1`, a `software` config must fail to boot
/// (the daemon exits non-zero) rather than silently run with in-memory keys.
#[tokio::test]
async fn daemon_refuses_software_keys_without_optout() {
    let port = free_port();
    let config = write_dev_config(port);

    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_xindex-signer-daemon"))
        .arg(&config)
        .arg("--dev")
        .env_remove("XINDEX_ALLOW_SOFTWARE_KEYS")
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn daemon binary");

    // The gate must make it EXIT promptly. Poll rather than block on
    // `.output()` so a regressed gate (daemon keeps serving) fails fast
    // instead of hanging the suite.
    let mut status = None;
    for _ in 0..30 {
        if let Some(s) = child.try_wait().expect("try_wait") {
            status = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = std::fs::remove_file(&config);

    let status =
        status.expect("daemon must EXIT when software keys are not opted in, not keep serving");
    assert!(
        !status.success(),
        "daemon must exit non-zero without XINDEX_ALLOW_SOFTWARE_KEYS"
    );
}
