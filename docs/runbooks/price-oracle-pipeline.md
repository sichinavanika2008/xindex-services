# NAV price quorum pipeline

This runbook wires the self-driven `xindex-price-signer` producers to the
untrusted `xindex-price-collector`, which recover-verifies an exact k-of-n tuple
and permissionlessly posts `PriceAttestationOracle.attestPrice`.

The collector is not a price authority. Each operator independently sources,
aggregates, TWAPs, canonicalizes, and signs its own tuple. The collector never
averages close observations: all four signed fields `(assetId, priceWad,
supply, timestamp)` must match exactly.

## Signer configuration

Every signer uses the same oracle domain, asset ids, cadence, TWAP policy, and
canonicalization digits, but its own HSM key, durable state file, and independent
venue connectivity. Example shape (values are development placeholders):

```json
{
  "oracle_chain_id": 31337,
  "oracle_contract": "0x0000000000000000000000000000000000000001",
  "signer_address": "0x0000000000000000000000000000000000000002",
  "hsm_url": "http://127.0.0.1:9000",
  "min_venues": 3,
  "max_deviation_bps": 5000,
  "supply_min_venues": 1,
  "twap_window_secs": 1800,
  "twap_min_samples": 10,
  "twap_max_gap_secs": 300,
  "interval_secs": 60,
  "epoch_secs": 60,
  "price_significant_digits": 4,
  "supply_significant_digits": 6,
  "state_file": "/var/lib/xindex/price-signer-last-epoch.json",
  "collector_urls": ["http://127.0.0.1:9191"],
  "publish_attempts": 3,
  "publish_timeout_secs": 5,
  "binance_base": "https://api.binance.com",
  "coinbase_base": "https://api.coinbase.com",
  "kraken_base": "https://api.kraken.com",
  "coingecko_base": "https://api.coingecko.com",
  "assets": [
    {
      "asset_id": "0x_______________________________________________",
      "decimals": 8,
      "binance": "BTCUSDT",
      "coinbase": "BTC-USD",
      "kraken": "XBTUSD",
      "coingecko": "bitcoin"
    }
  ]
}
```

`epoch_secs` must equal `interval_secs`; this makes every signer commit to the
same floored unix epoch instead of its arbitrary observation second. Four price
significant digits bounds deterministic flooring below 10 bps. A corrupt
anti-equivocation state file refuses startup. Persist the state directory on a
durable volume.

Run one producer per independent signer:

```sh
cargo run -p xindex-signer-daemon --bin xindex-price-signer -- /etc/xindex/price-signer.json
```

Stdout remains a complete JSON-lines audit stream and includes supply and the
recovered signer address. Collector delivery retries only transient HTTP
failures; alert on an exhausted publish or a deterministic 4xx rejection.

## Collector/poster

Keep the default loopback bind unless an authenticated private service mesh is
in front of the endpoint. Do not put the poster key in argv or a config file.

```sh
export ETH_RPC_URL=http://127.0.0.1:8545
export PRICE_ORACLE_ADDR=0x________________________________________
export PRICE_POSTER_KEY=0x________________________________________
export PRICE_SIGNER_ADDRESSES=0xSigner1,0xSigner2,0xSigner3
export PRICE_THRESHOLD=2

cargo run -p xindex-relayer --bin xindex-price-collector
```

Startup reads `threshold()`, `signerCount()`, and `isSigner(address)` and refuses
any roster mismatch. Signer rotation therefore requires a collector restart
with the complete new set. The HTTP endpoint is
`POST /api/v1/price-signature` with `SignedPriceMessage` JSON.

Posting is nonce-serialized and idempotence-checks `pendingQuote` before every
attempt. Transport, rate-limit, server, receipt, and short-reorg failures receive
bounded exponential retries. Bounds, Chainlink divergence, pause, stale epoch,
and bad-quorum reverts are deterministic for a signed tuple and are not retried.
If the poster worker exits, the HTTP server terminates fail-closed rather than
accepting a quorum it can no longer enqueue.

## Release gates still required

- The ignored Anvil/Forge on-chain integration test passed locally on
  2026-07-11; rerun it from a clean release/CI environment.
- Rehearse a real Sepolia quorum with independent signer hosts and a dedicated
  poster EOA, including one signer down, split exact tuples, RPC outage, receipt
  timeout, signer rotation, pause, bounds rejection, and restart recovery.
- Configure production L1 bounds, Chainlink gates, heartbeat, challenge window,
  and alerts before the first price.
- Include the final pipeline and operating configuration in external audit.
