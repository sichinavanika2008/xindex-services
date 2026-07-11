# Cobo custody development gate

> **Status: OPEN.** Cobo is a candidate custody provider; this gate does not
> replace or enable the current Turnkey production path. The gate binary is
> read-only: live mode authenticates only `GET` requests against
> `https://api.dev.cobo.com/v2`. It never creates, signs, or broadcasts a
> transaction.

## What the gate proves

`xindex-cobo-dev-gate` emits one JSON result with `pass`, `fail`, or `blocked`
for:

- the exact Cobo Go SDK **1.39** OpenAPI snapshot at commit
  `e14ea77ae07daa15e4f77b5e978b0a0a00f2b2bd`, SHA-256
  `25e9d81a68eabd1754e036b2997ea8d9616261d50d4374ba19817f616952cd5f`;
- all 15 Xindex chain assets from `chain_registry.rs` against the authenticated
  Organization-Controlled `enabled_chains` response;
- a live Organization-Controlled 2-of-2 wallet/signing group;
- a confirmed BTC signet transaction whose exact signed output set includes
  one payout, one zero-value payload-exact THORChain `OP_RETURN`, and only
  custody change;
- callback binding from Cobo `biz_task_id` and `msg_hash_list` to independently
  reconstructed BIP-143/EIP-1559 signing hashes;
- an EIP-1559 Sepolia `BuildOnly -> Built -> Completed` contract call; and
- live callback rejection, with no signature or broadcast, for destination,
  amount/calldata, callback-hash, replay, and excessive-fee mutations.

The schema check also records the decisive current limitation: both public
UTXO output objects contain only `address` and `amount`, and
`Raw_Message_Signature` is marked deprecated, no longer allowed, and must not
be used. Therefore BTC remains blocked unless Cobo can produce the native
`OP_RETURN` transaction and callback evidence despite the public schema.

## Local implementation validation

On 2026-07-11, `xindex-cobo-dev-gate` compiled and its focused test suite
passed **5/5** using an isolated non-Spotlight Cargo target. This validates the
gate implementation only. It does not satisfy any live provider requirement or
change this runbook's `OPEN` status.

## 1. Run the safe offline check now

From `xindex-services`:

```sh
cargo run --offline -p xindex-cobo-dev-gate -- \
  --openapi /tmp/cobo-waas2-go-sdk/api/openapi.yaml \
  --output /private/tmp/cobo-gate-offline.json
```

The command intentionally exits `2` and reports `overall: blocked` without
credentials and live transaction evidence. A schema mismatch is `fail`, not a
fallback to hard-coded assumptions.

## 2. Provision and execute the tests

Founder/operator actions in the Cobo development organization:

1. Create an Organization-Controlled MPC wallet and an active signing group
   with `threshold=2`, `participants=2`. Record the wallet, vault, and signing
   group IDs.
2. Configure the Cobo TSS callback using its real RSA/JWT verification keys.
   Store the complete callback securely, verify its transport signature, and
   verify the signed callback response. Put only the parsed `request_detail`,
   parsed `extra_info`, signature-verification results, and SHA-256 of the
   verified JWT in the evidence file. Do not place private keys or API secrets
   in evidence.
3. Attempt a native BTC signet transfer containing the payout and exact memo
   `OP_RETURN`. It is not enough to submit two normal address outputs. Capture
   the Cobo transaction/request IDs and KeySign callback. After confirmation,
   obtain the raw transaction and reconstruct a PSBT with `witness_utxo` for
   every input so the gate can recompute every BIP-143 sighash.
4. Use Cobo's official SDK to create a Sepolia contract call with
   `transaction_process_type=BuildOnly`. Observe `Built`, invoke the normal
   Cobo sign-and-broadcast flow, then capture `Completed`, raw EIP-1559 bytes,
   successful receipt, block hash, and KeySign callback.
5. Repeat the EVM flow with each required mutation. The verified callback must
   return `REJECT`; Cobo must record `Rejected`/`Failed`, with no transaction
   hash, signature, or broadcast.

Copy [the evidence template](cobo-gate-evidence.example.json) to a private
working location and replace every `REPLACE_...` value. The validator rejects
unknown fields and malformed artifacts.

## 3. Corroborate against the live dev API

Export the API secret only in the process environment. It must be the 32-byte
Ed25519 seed as 64 hex characters; the binary never prints it or includes it in
the report.

```sh
export COBO_API_SECRET='<dev-only-secret>'
cargo run --offline -p xindex-cobo-dev-gate -- \
  --live \
  --openapi /tmp/cobo-waas2-go-sdk/api/openapi.yaml \
  --evidence /private/tmp/cobo-gate-evidence.json \
  --output /private/tmp/cobo-gate-live.json
```

Live mode authenticates the enabled-chain, wallet, signing-group, and
transaction lookups. It is hard-coded to the development host; there is no
production URL option. Exit `0` means every required result passed. Any failed
or blocked requirement exits `2`, and the JSON report is the audit artifact.

## Decision

- `overall: pass`: Cobo may proceed to a separately reviewed wire adapter. Do
  not replace Turnkey or lift a production gate from this result alone.
- `overall: blocked`: missing credentials/evidence or a temporarily unavailable
  dev dependency; complete the named item and rerun.
- `overall: fail`: the captured behavior contradicts a required invariant. In
  particular, if native BTC `OP_RETURN` fails, the prohibited raw-message path
  is not an acceptable fallback; Cobo does not qualify for BTC v1.
