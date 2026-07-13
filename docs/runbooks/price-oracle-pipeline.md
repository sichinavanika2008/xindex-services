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
  "supply_min_venues": 2,
  "twap_window_secs": 1800,
  "twap_min_samples": 10,
  "twap_max_gap_secs": 300,
  "interval_secs": 60,
  "epoch_secs": 60,
  "price_significant_digits": 4,
  "supply_significant_digits": 6,
  "state_file": "/var/lib/xindex/price-signer-last-epoch.json",
  "evidence_dir": "/var/lib/xindex/price-evidence",
  "evidence_operator_id": "operator-01",
  "anomaly_failure_threshold": 12,
  "collector_urls": [
    "https://collector-a.internal:9191",
    "https://collector-b.internal:9191"
  ],
  "publish_attempts": 3,
  "publish_timeout_secs": 5,
  "metrics_address": "127.0.0.1:9095",
  "collector_client_identity_pem": "/etc/xindex/tls/price-signer-client.pem",
  "collector_server_ca_pems": [
    "/etc/xindex/tls/collector-a-ca.pem",
    "/etc/xindex/tls/collector-b-ca.pem"
  ],
  "binance_base": "https://api.binance.com",
  "coinbase_base": "https://api.coinbase.com",
  "kraken_base": "https://api.kraken.com",
  "coingecko_base": "https://api.coingecko.com",
  "coincap_base": "https://api.coincap.io",
  "assets": [
    {
      "asset_id": "0x_______________________________________________",
      "decimals": 8,
      "binance": "BTCUSDT",
      "coinbase": "BTC-USD",
      "kraken": "XBTUSD",
      "coingecko": "bitcoin",
      "coincap": "bitcoin"
    }
  ]
}
```

`epoch_secs` must equal `interval_secs`; this makes every signer commit to the
same floored unix epoch instead of its arbitrary observation second. Four price
significant digits bounds deterministic flooring below 10 bps. The build
requires exactly three distinct price-provider origins, two distinct supply
origins, and at least two distinct collector origins. A corrupt
anti-equivocation state file refuses startup. Both paths must be absolute and
live on durable storage; create the evidence directory ahead of time with mode
`0700` (group/world access is rejected).

For every asset/epoch, the signer writes one create-new, mode-`0600` evidence
file and a Keccak-256 sidecar containing each exact raw provider response,
normalized value and response hash, then fsyncs both and the directory before
asking the HSM to sign. The fixed identity is also the crash-safe pre-HSM
reservation: a restart cannot overwrite or produce a second observation for
the same asset/epoch. It signs the values from those persisted observations,
not a second fetch. A persistence failure stops publication. Repeated
observation failures latch the process shut at `anomaly_failure_threshold`; the threshold must be at least
`twap_min_samples + 2`. If every collector is unavailable, the signer exits.
Collector delivery uses a client identity and explicit CA pins with system
roots disabled. The metrics task and producer loop are supervised together.

Run one producer per independent signer:

```sh
cargo run -p xindex-signer-daemon --bin xindex-price-signer -- /etc/xindex/price-signer.json
```

Stdout emits the signed wire tuple and includes supply and the recovered signer
address; the raw audit record is the locked evidence file. Collector delivery
retries only transient HTTP failures. Alert on an exhausted publish, a
deterministic 4xx rejection, any evidence/state persistence error, source
disagreement, or the anomaly latch exiting the process.

## Collector/poster

The collector API always requires pinned mutual TLS. Its only private key is an
owner-only transport key; it has no price-signing or poster private-key input.
Its connected RPC must delegate `eth_sendTransaction` signing for the
configured address to a node-managed external signer such as Clef/HSM.

```sh
export ETH_RPC_URL=http://127.0.0.1:8545
export PRICE_ORACLE_ADDR=0x________________________________________
export PRICE_POSTER_ADDRESS=0x____________________________________
export PRICE_SIGNER_ADDRESSES=0xSigner1,...,0xSigner11
export PRICE_THRESHOLD=7
export EXPECTED_ETH_CHAIN_ID=1
export PRICE_SERVER_CERT_PEM=/etc/xindex/tls/price-collector.pem
export PRICE_SERVER_KEY_PEM=/etc/xindex/tls/price-collector.key
export PRICE_PINNED_CLIENT_CERT_PEMS=/etc/xindex/tls/p01.pem,...,/etc/xindex/tls/p11.pem
export METRICS_ADDRESS=127.0.0.1:9192

cargo run -p xindex-relayer --bin xindex-price-collector
```

Production startup requires exactly the approved 7-of-11 topology, pins the
chain id, reads `threshold()`, `signerCount()`, and `isSigner(address)`, and
refuses any roster mismatch. Signer rotation therefore requires a collector
restart with the complete new set. The mTLS endpoint is
`POST /api/v1/price-signature` with `SignedPriceMessage` JSON.

Posting is nonce-serialized and idempotence-checks `pendingQuote` before every
attempt. Transport, rate-limit, server, receipt, and short-reorg failures receive
bounded exponential retries. Bounds, Chainlink divergence, pause, stale epoch,
and bad-quorum reverts are deterministic for a signed tuple and are not retried.
If the poster worker, mTLS API, or metrics server exits, the process terminates
fail-closed rather than accepting a quorum it can no longer enqueue or monitor.

## Release gates still required

- The ignored Anvil/Forge on-chain integration test passed locally on
  2026-07-11; rerun it from a clean release/CI environment.
- Rehearse a real Sepolia quorum with independent signer hosts and a dedicated
  poster EOA, including one signer down, split exact tuples, RPC outage, receipt
  timeout, signer rotation, pause, bounds rejection, and restart recovery.
- Configure production L1 bounds, Chainlink gates, heartbeat, challenge window,
  and alerts before the first price.
- Include the final pipeline and operating configuration in external audit.
- Demonstrate the checked-in Prometheus rules, dual alert routes, evidence
  inventory/WORM retention, and incident procedures in
  [`gate3-operations.md`](gate3-operations.md). Code is not operational
  evidence.
