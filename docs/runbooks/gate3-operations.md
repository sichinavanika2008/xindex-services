# Gate 3 signer-service operations and incident runbook

This runbook defines the release evidence required around the Gate-3 service
code. It does not claim that operators, HSMs, alerts, drills, or a deployment
exist. Populate and review the records outside the repository; never replace
missing production facts with example identities.

## Release inputs

One owner-only topology registry must describe every production operator and
the exact `7-of-11` price, `3-of-5` registry, `3-of-5` settlement-observer and
`3-of-5` custody roles. It contains public key fingerprints and immutable
evidence hashes only—no private key, PIN, credential, recovery share, client
identity PEM, or bearer token.

Validate it before a release candidate is tagged:

```sh
chmod 0600 /secure/release/gate3-topology.json
RUSTUP_TOOLCHAIN=1.95.0-aarch64-apple-darwin \
  cargo run --offline --locked -p xindex-ops \
  --bin xindex-topology-check -- \
  /secure/release/gate3-topology.json
```

The validator requires that path itself—not only its target—to be an absolute,
owner-only, non-symlink regular file with exactly one hard link.

The validator rejects incomplete/placeholder rows, duplicate operators,
shared legal entities, cloud accounts, regions, host/HSM/network/RPC/data
administration domains, public-key or HSM-key reuse, unsafe quorum/provider
concentration, missing dual review, mutable evidence references, non-HTTPS
origins, and shared primary Ethereum/Bitcoin/owned-THOR sources inside a role.
All operator evidence is addressed by SHA-256 in the registry and reviewed by
at least two named reviewers.

The required JSON fields are:

- top level: `schema_version`, `environment`, `reviewed_at_utc`, `reviewers`,
  `operators`, and `roles`;
- operator: public identity, legal entity, cloud/provider/account/region,
  host/HSM/network/RPC/market-data failure domains, dual reviewers, evidence
  SHA-256 hashes, and source origins;
- sources: one Ethereum and Bitcoin RPC origin, at least three THORNode,
  three CometBFT, three price-venue, two supply and two collector origins; and
- role member: `operator_id`, opaque public `hsm_key_id`, and a
  `sha256:<64 hex>` public-key fingerprint.

## Monitoring and alert routing

Load [`gate3-alerts.yml`](../../ops/prometheus/gate3-alerts.yml) and validate it
with the same Prometheus release that will evaluate it:

```sh
promtool check rules ops/prometheus/gate3-alerts.yml
```

Use these exact scrape job names so the availability rule matches:

- `xindex-signer`, `xindex-price-signer`, `xindex-price-collector`;
- `xindex-registry-signer`, `xindex-registry-coordinator`;
- `xindex-finalized-observer`, `xindex-settlement-collector`; and
- `xindex-redeem`.

Metrics endpoints bind loopback and are exposed only through the operator's
authenticated monitoring agent. The API/event loop, metrics server, producer,
poster and custody rebroadcast worker are supervised together; an unexpected
exit terminates the process. Configure the process supervisor to page on a
restart loop, not to mask it indefinitely.

Critical alerts page two independent on-call operators and the security lead.
Warnings create an incident ticket and page if unresolved for 15 minutes. An
acknowledgement is not resolution: preserve the alert start/end timestamps,
all matching metric series, the immutable log segment, and the evidence
inventory roots in the incident bundle.

Before enabling value flow, demonstrate every checked-in rule with synthetic
metrics or an isolated monitoring staging stack. Record the exact Prometheus
and Alertmanager versions, rule-file SHA-256, fired alert, delivery timestamps,
acknowledgement and escalation. Do not fire a drill by submitting a real
signature or transaction.

## Evidence retention and reconciliation

Each service gets a separate absolute directory, mode `0700`, on durable local
storage. Evidence files and digest sidecars are mode `0600`. Never mix roles or
operators in one directory. No service credential or private key may appear in
raw evidence.

Run the verifier at least hourly and immediately before/after an incident:

```sh
RUSTUP_TOOLCHAIN=1.95.0-aarch64-apple-darwin \
  cargo run --offline --locked -p xindex-shared \
  --bin xindex-evidence-check -- \
  /var/lib/xindex/evidence/ROLE
```

The report checks JSON syntax, owner-only regular single-link files, bounded
record size, content-addressed filenames or `.keccak256` sidecars, and returns
one Keccak-256 inventory root over sorted filename/content hashes. To reconcile
against a prior root, pass it as the second argument; any mismatch fails.

Every five minutes, copy closed records and the verifier report to an
independently administered, versioned object store with retention lock. Keep
30 days locally and seven years in immutable storage unless a longer legal
hold applies. The off-site writer may create objects but may not delete or
shorten retention. The service host must not hold the object-lock
administrator credential.

Daily reconciliation compares local inventory, WORM object inventory, durable
SQLite checkpoints/reservations, on-chain accepted reports and custody txids.
Two reviewers sign the reconciliation report. Missing, extra, renamed,
rewritten, hash-mismatched or out-of-order evidence is a critical incident;
never "repair" it by deleting a reservation or regenerating evidence.

## Incident procedures

### Service or monitoring loss

1. Stop new mint/custody coordination at the external traffic and scheduler
   layer; do not weaken thresholds to restore availability.
2. Confirm the metrics endpoint, process supervisor and log/evidence volumes
   independently. A dead metrics task is a process failure by design.
3. Snapshot logs, metrics, database files and evidence inventory roots before
   restart. Preserve owner/mode metadata.
4. Restart only after identifying the dependency failure. Verify durable
   checkpoints and pending reservations before reopening traffic.

### Signer or HSM incident

1. Quarantine the affected signer endpoint and stop its HSM frontend. Do not
   export a key or substitute a software key.
2. Inspect request outcome metrics, anti-equivocation rows, HSM audit records,
   mTLS peer identity and evidence hashes. A pending reservation after a crash
   is a safety stop, not permission to sign again.
3. If compromise is possible, use the separately governed on-chain pause and
   signer-rotation process. Retain the old key identity in the incident record.
4. Resume only after the remaining independent domains still meet the original
   threshold and the rotation has been dual-reviewed.

### Price source or anomaly incident

1. Leave the anomaly latch closed. Do not widen deviation, freshness, TWAP or
   canonicalization bounds during an incident.
2. Compare all three venue bodies, both supply bodies, epochs, inventory roots
   and independent operators. Separate provider disagreement from transport
   failure and HSM recovery mismatch.
3. Verify the on-chain pending quote/reference bounds before restoring price
   publication. A collector conflict or deterministic revert requires review,
   not retry amplification.

### Registry source or publication incident

1. Stop quote issuance and new cross-chain dispatch while any pause flag,
   source disagreement, stale tip, evidence failure or publication gap exists.
2. Compare each operator's three THORNode and CometBFT responses, Mimir/pool
   state, owned fullnode tip, on-chain sequence/nonce, and raw evidence.
3. Never majority-vote away an omitted halt/LP field or reuse a quote nonce.

### Observer finality or source incident

1. Stop settlement collection and custody dispatch. Preserve the finalized
   head response, block/log bodies and durable checkpoint database.
2. On any finalized-hash change, keep the service unavailable until the common
   ancestor and rollback evidence are independently reviewed.
3. Reconcile logical/physical consumed inflows, native inflow rows, settlement
   attestations and on-chain state before restoring readiness.

### Custody or broadcast incident

1. Stop new dispatches but keep the exact-byte watcher and chain observation
   available unless they are themselves suspected.
2. A reservation without exact transaction bytes requires manual review. Do
   not release it or select another UTXO. A persisted transaction may only be
   rebroadcast byte-for-byte.
3. Reconcile dispatch id, redemption id, RIC, PSBT inputs/outputs/memo/change,
   txid, F2 record, broadcast registry and confirmation block.
4. A one-shot conflict is a security incident. Preserve both attempted
   payloads and all peer identities; do not retry with a modified transaction.

## Required Gate-3 drill record

The release bundle must show, without protocol-key use, that alerts and
procedures were exercised for: service/metrics loss, signer/HSM refusal,
source disagreement/staleness, evidence write and integrity failure, finalized
checkpoint rollback, logical/physical inflow reuse, quote-nonce contention,
custody crash after reservation, ambiguous broadcast and exact rebroadcast.
For each drill record trigger, expected fail-closed state, actual alert route,
operator response time, recovery decision, evidence inventory roots and two
review approvals.

Code and synthetic checks cannot supply real operator independence, HSM
ceremonies, alert delivery, WORM retention, incident response, or an
independent audit. Those remain release evidence, not repository assertions.
