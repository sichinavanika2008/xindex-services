#![expect(
    clippy::print_stdout,
    reason = "rehearsal config generator: writes a summary to stdout for the operator"
)]
//! Generate the one-box testnet-rehearsal config set: five
//! `xindex-signer-daemon` `--dev` configs sharing one 3-of-5 Set-B
//! whitelist + one 3-of-5 P2WSH custody descriptor, each with its own
//! port, software keys, and replay DB. DEV / TESTNET ONLY.
//!
//! Keys are DETERMINISTIC per operator index (keccak of a fixed label) so a
//! rehearsal is reproducible and its evidence bundle is regenerable — they
//! are NOT the e2e test trio and NEVER touch mainnet (the daemon's
//! `XINDEX_ALLOW_SOFTWARE_KEYS` gate + production-safety check block that).
//!
//! Run (after the testnet deploy, passing the deployed `AttestationOracle`):
//!
//! ```text
//! cargo run -p xindex-signer-daemon --example rehearsal_gen -- \
//!     <out_dir> <oracle_address> [chain_id=31337] [network=signet]
//! ```

use std::error::Error;

use alloy_primitives::{hex, keccak256, Address};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::PublicKey;
use k256::ecdsa::SigningKey;
use serde_json::json;

const OPERATORS: usize = 5;
const QUORUM: usize = 3;
/// Per-chain BTC certification cap (sats) — small, so drill D6 (volume cap)
/// is reachable in a short rehearsal. Tune per the runbook.
const BTC_CAP_SATS: u128 = 100_000_000;
const BASE_PORT: u16 = 8551;

/// Deterministic 32-byte secret for `(label, operator)` — keccak of a fixed
/// preimage. Distinct per role + operator; reproducible across runs.
fn secret(label: &str, op: usize) -> [u8; 32] {
    keccak256(format!("xindex-rehearsal-{label}-{op}").as_bytes()).0
}

/// EOA address from a k256 signing key (keccak of the uncompressed pubkey).
fn eth_address(sk: &SigningKey) -> Address {
    let encoded = sk.verifying_key().to_encoded_point(false);
    Address::from_slice(&keccak256(&encoded.as_bytes()[1..])[12..])
}

fn main() -> Result<(), Box<dyn Error>> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let signers_only = argv.first().is_some_and(|s| s == "--signers-only");

    let secp = Secp256k1::new();
    let mut eth_secrets = Vec::with_capacity(OPERATORS);
    let mut btc_secrets = Vec::with_capacity(OPERATORS);
    let mut eth_addrs = Vec::with_capacity(OPERATORS);
    let mut btc_pubkeys = Vec::with_capacity(OPERATORS);
    for op in 0..OPERATORS {
        let eth_sk_bytes = secret("eth", op);
        let btc_sk_bytes = secret("btc", op);
        let eth_sk = SigningKey::from_slice(&eth_sk_bytes)?;
        let btc_sk = SecretKey::from_slice(&btc_sk_bytes)?;
        eth_addrs.push(eth_address(&eth_sk));
        btc_pubkeys.push(PublicKey::new(btc_sk.public_key(&secp)));
        eth_secrets.push(eth_sk_bytes);
        btc_secrets.push(btc_sk_bytes);
    }

    let whitelist: Vec<String> = eth_addrs.iter().map(|a| format!("{a:#x}")).collect();
    let pubkeys_hex: Vec<String> = btc_pubkeys.iter().map(ToString::to_string).collect();

    // `--signers-only`: print the 5 deterministic Set-B addresses (which are
    // oracle-independent) so the on-chain deploy can set the AttestationOracle
    // signer set BEFORE the oracle address exists (chicken-and-egg).
    if signers_only {
        println!("{}", whitelist.join(","));
        return Ok(());
    }

    let out_dir = argv.first().ok_or(
        "usage: rehearsal_gen <out_dir> <oracle_address> [chain_id=31337] [network=signet]",
    )?;
    let oracle: Address = argv.get(1).ok_or("missing <oracle_address>")?.parse()?;
    let chain_id: u64 = argv.get(2).map_or(Ok(31337), |s| s.parse())?;
    let network = argv.get(3).map_or("signet", String::as_str);

    std::fs::create_dir_all(out_dir)?;
    for op in 0..OPERATORS {
        // The BTC key routes under a distinct alias address (≠ this
        // operator's Set-B eth_address) so the software HSM picks the BTC
        // key for PSBT signing.
        let hsm_alias = Address::repeat_byte(0xC0 + u8::try_from(op)?);
        let port = BASE_PORT + u16::try_from(op)?;
        let cfg = json!({
            "chain_id": chain_id,
            "verifying_contract": format!("{oracle:#x}"),
            "eth_address": whitelist[op],
            "intent_policy": {
                "signer_whitelist": whitelist,
                "intent_quorum": QUORUM,
                "ric_max_age_secs": 7200
            },
            "cert_volume": {
                "window_secs": 86_400,
                "caps": { "btc": BTC_CAP_SATS }
            },
            "hsm": {
                "kind": "software",
                "software": {
                    "eth_secret_key": format!("0x{}", hex::encode(eth_secrets[op])),
                    "btc_secret_key": format!("0x{}", hex::encode(btc_secrets[op]))
                }
            },
            "utxo": {
                "chain": "btc",
                "network": network,
                "threshold": QUORUM,
                "pubkeys": pubkeys_hex,
                "my_pubkey": pubkeys_hex[op],
                "hsm_address": format!("{hsm_alias:#x}")
            },
            "bind": format!("127.0.0.1:{port}")
        });
        let path = format!("{out_dir}/daemon-{op}.json");
        std::fs::write(&path, serde_json::to_string_pretty(&cfg)?)?;
        println!("wrote {path}  (Set-B {})  port {port}", whitelist[op]);
    }

    println!("\nSet-B whitelist (quorum {QUORUM}-of-{OPERATORS}):");
    for (op, a) in whitelist.iter().enumerate() {
        println!("  operator {op}: {a}");
    }
    println!("\nNext: run each daemon with --dev + XINDEX_ALLOW_SOFTWARE_KEYS=1 (see up.sh).");
    Ok(())
}
