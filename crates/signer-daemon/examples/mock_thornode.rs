#![expect(
    clippy::print_stdout,
    reason = "mock server: prints its THORNODE_URLS line for the operator"
)]
//! Mock `THORNode` for the one-box rehearsal: serves a fixed BTC
//! `inbound_addresses` Asgard entry on TWO loopback ports (the observer's
//! `AsgardAgreement` requires ≥2 distinct sources that AGREE — a single
//! shared source collapses 5 observers into 1). DEV / TESTNET ONLY: it
//! returns whatever Asgard address you pass, with all halt flags false, so
//! the observer resolves it and certifies.
//!
//! The JSON shape is byte-faithful to what `xindex_chain_thor::ThorClient`
//! deserializes from `GET /thorchain/inbound_addresses`.
//!
//! Run:
//!
//! ```text
//! cargo run -p xindex-signer-daemon --example mock_thornode -- \
//!     <btc_asgard_address> [port0=26659] [port1=26660]
//! ```

use std::future::IntoFuture;
use std::net::SocketAddr;

use anyhow::Result;
use axum::{routing::get, Json, Router};
use serde_json::{json, Value};

/// One mock router serving the fixed `inbound_addresses` body.
fn app(asgard: Value) -> Router {
    Router::new().route(
        "/thorchain/inbound_addresses",
        get(move || {
            let body = asgard.clone();
            async move { Json(body) }
        }),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let asgard_addr = args.next().ok_or_else(|| {
        anyhow::anyhow!("usage: mock_thornode <btc_asgard_address> [port0=26659] [port1=26660]")
    })?;
    let port0: u16 = args.next().map_or(Ok(26659), |s| s.parse())?;
    let port1: u16 = args.next().map_or(Ok(26660), |s| s.parse())?;

    // ≥2 sources must agree on `address` + report no halt flags, or the
    // observer's AsgardAgreement refuses to certify.
    let body = json!([{
        "chain": "BTC",
        "pub_key": "thorpub1rehearsalmockonly",
        "address": asgard_addr,
        "halted": false,
        "global_trading_paused": false,
        "chain_trading_paused": false,
        "chain_lp_actions_paused": false
    }]);

    let l0 = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port0))).await?;
    let l1 = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port1))).await?;
    println!("mock THORNode — BTC Asgard inbound = {asgard_addr}");
    println!("THORNODE_URLS=http://127.0.0.1:{port0},http://127.0.0.1:{port1}");

    let (r0, r1) = tokio::join!(
        axum::serve(l0, app(body.clone())).into_future(),
        axum::serve(l1, app(body)).into_future(),
    );
    r0?;
    r1?;
    Ok(())
}
