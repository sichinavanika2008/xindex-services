# BitGo BTC custody development qualification

> **Selected for future BTC custody; Testnet4 runtime capability-closed and
> production/mainnet disabled.** This
> runbook tests whether BitGo can preserve the exact Xindex/THORChain Bitcoin
> transaction shape. Selection is a design decision, not a live integration or
> production approval. This document authorizes no account, wallet, key,
> funding, signing, approval, or broadcast action.

## Decisive product constraints

BitGo's current Bitcoin matrix supports self-custody **hot multisignature** but
does not support Bitcoin MPC hot wallets. The compatible Bitcoin topology is
therefore native on-chain 2-of-3 multisig (user key, backup key, BitGo key), not
MPC 2-of-3. This can satisfy a two-signature control objective, but it does not
satisfy a literal requirement that the BTC key itself use MPC/TSS.

BitGo's documented Bitcoin test asset is Testnet4 (`tbtc4`); no Bitcoin signet
asset is documented. THORChain's public stagenet uses real external-chain
assets, so a `tbtc4` transaction cannot be represented as a completed public
stagenet swap. The safe qualification below therefore proves BitGo wallet and
transaction compatibility against a controlled Testnet4 payout. A true
non-mainnet BitGo-to-THORChain execution would require a separately operated
THORChain devnet/mocknet wired to Bitcoin Testnet4. A mainnet pilot is a
different, value-bearing gate and is not authorized here.

Current official references:

- [BitGo Bitcoin support and `tbtc4`](https://developers.bitgo.com/docs/bitcoin)
- [BitGo wallet types and 2-of-3 key ownership](https://developers.bitgo.com/docs/wallet-types)
- [BitGo UTXO address types](https://developers.bitgo.com/coins/chain-codes)
- [BitGo transaction builder](https://developers.bitgo.com/reference/v2wallettxbuild)
- [BitGo manual self-custody multisig withdrawal](https://developers.bitgo.com/docs/withdraw-wallet-type-self-custody-multisig-manual)
- [BitGo HMAC request/response authentication](https://developers.bitgo.com/docs/hmac)
- [THORChain UTXO transaction requirements](https://dev.thorchain.org/concepts/sending-transactions.html)

## Required transaction profile

The qualification wallet and UTXO must use native P2WSH. BitGo currently
documents Taproot MuSig2 as the default Bitcoin address type, while the reviewed
Xindex BTC signer is P2WSH/BIP-143. Create or select a native P2WSH address
(external chain code 20), fund that address, and spend an explicit UTXO from it.
Do not silently qualify a Taproot or wrapped-SegWit path.

The unsigned transaction must contain exactly:

1. `VOUT0`: controlled Testnet4 payout standing in for the current Asgard
   inbound, with the exact authorized amount.
2. `VOUT1`: one non-zero change output to the exact P2WSH address represented by
   `VIN0`.
3. `VOUT2`: one zero-value `OP_RETURN` containing the exact <=80-byte
   THORChain memo.

The build request must pin `txFormat=psbt`, `noSplitChange=true`,
`changeAddressType=p2wsh`, `isReplaceableByFee=false`, the complete ordered
`unspents` list, and `changeAddress=VIN0`. BitGo documents all of these
controls. It also documents `sequenceId` as the idempotent request correlation;
use a unique value and retain it in evidence. BitGo documents an `OP_RETURN`
recipient as `scriptPubKey:<HEX_ENCODED_OP_RETURN_SCRIPT>`. Its API
documentation does not promise the resulting VOUT order, so the returned PSBT
must be inspected; API parameters alone are not evidence.

## What the offline validator checks

`xindex-bitgo-dev-gate` performs no HTTP request and never creates a wallet,
generates a key, decrypts a key, signs, or broadcasts. Given caller-supplied
evidence, it checks internal consistency:

- the claimed BitGo test identity and self-custody/hot/on-chain 2-of-3 topology,
  native P2WSH address type, external chain code 20, and distinct compressed
  user, backup and BitGo public keys;
- the exact build controls, explicit input set, and recipient order;
- every PSBT input's outpoint, value, non-RBF sequence, native P2WSH script,
  exact 2-of-3 role-key witness script, and witness-script commitment against
  independently collected evidence;
- `VIN0` identity and the exact THORChain VOUT layout;
- implied miner fee against a fixed satoshi cap;
- byte-for-byte preservation of the unsigned transaction plus a valid
  `SIGHASH_ALL` signature from the captured user key after user signing;
- preservation of the unsigned skeleton after BitGo finalization, exact valid
  user + BitGo `SIGHASH_ALL` signatures in descriptor order, and final txid;
  and
- presence and correlation of claimed live wallet/build/finalization
  identifiers.

The validator proves cryptographic consistency only relative to the role keys
inside the same input file. It cannot authenticate that those keys, responses,
or identifiers came from BitGo. Missing artifacts and complete-looking live
claims therefore both produce `overall: blocked`; the current binary cannot
produce a qualification pass. The generated report binds the wallet ID and
SHA-256 of the exact evidence file for review, not as origin authentication.

## Reusable adapter core

`xindex-bitgo-adapter` is the shared, key-free request/policy boundary used by
the gate. It generates the exact typed `tx/build` payload and endpoint path,
including string-encoded base-unit amounts, explicit inputs, P2WSH change,
non-RBF, PSBT format and idempotent `sequenceId`. It validates the returned
unsigned PSBT, a user-signed PSBT or raw half-signed transaction, and a final
transaction with exact user + BitGo signature roles. It can generate a retained
`tx/send` JSON body only after the raw half-signed transaction passes.

The adapter intentionally has no HTTP client, access token, private-key input,
approval operation or broadcast method. The separate `xindex-bitgo-client`
crate owns fixed official test/production origins, explicit BitGo Auth V2/V3
HMAC request construction, hashed bearer-token transport, HMAC and freshness
verification of every response, bounded response reads, exact `200`/`202`
decoding, and a SQLite write-ahead workflow. Request JSON is serialized once;
the identical bytes are authenticated and transmitted. Each retained response
is a versioned envelope containing the method, path, status, timestamp, HMAC,
body hash and exact bounded body. Its `tx/send` transport is private to
`BitGoCoordinator`: the
coordinator revalidates the stored unsigned and user-signed artifacts, reserves
the irreversible call atomically, and permits only that reservation holder to
POST. Build completion first retains the exact wallet response and one
canonical hot/on-chain 2-of-3 topology snapshot. Before user-signature capture,
`authorize_redeem` passes that exact retained PSBT through the provider-neutral
RIC/output gate, consumes the durable `(BTC, redemptionId, legIndex)` one-shot,
and retains a canonical authorization receipt plus its certificate expiry.
Only `intent_authorized` may transition to `user_signed`; an expired receipt
fails closed. A send-reserved retry performs only an exact `sequenceId` lookup.
A pending approval never releases the reservation: the coordinator uses only
read-only approval and
transfer-by-approval GETs, makes rejection terminal, and accepts an approved
final transaction only after approval/transfer/sequence/txid correlation and
the original exact policy plus user/BitGo signature checks. A direct `200`
send response is accepted only in `signed`, `unconfirmed` or `confirmed`
state; terminal failure states do not become `broadcast`.

The client accepts no private key and exposes no approval mutation. It also
builds a schema-v2 canonical SHA-256 manifest over the content-addressed
workflow artifacts and binds the selected HMAC version. Response HMAC prevents
an untrusted transport from silently changing BitGo traffic, but it is a
symmetric proof under the access token: the token holder could reproduce it,
so it is not independent provider attestation or non-repudiation. The manifest
remains unsigned; without separately pinned reviewer trust anchors, signatures
and independent raw-chain/provider corroboration it is not closure provenance.

The separate `xindex-bitgo-custody` runtime now activates this coordinator only
for the staged Testnet4 workflow. It refuses `production`, accepts no private
key, reads secrets and configuration only from absolute owner-only single-link
files, requires a durable owner-only workflow database, and requires a matching
authorization ID plus an unexpired satoshi cap and explicit per-operation
capability. Final sign-and-broadcast additionally requires the exact sequence
ID on the command line. The historical `xindex-redeem` binary remains unchanged.
This is a runnable qualification seam, not permission to use a BitGo token or
perform any external action.

## Current key-free verification

From this nested Rust repository:

```sh
RUSTUP_TOOLCHAIN=1.95.0 cargo test --offline --locked \
  -p xindex-bitgo-dev-gate

RUSTUP_TOOLCHAIN=1.95.0 cargo clippy --offline --locked \
  -p xindex-bitgo-adapter -p xindex-bitgo-client -p xindex-custody-core \
  -p xindex-custody-node -p xindex-bitgo-dev-gate \
  --all-targets --all-features -- -D warnings

RUSTUP_TOOLCHAIN=1.95.0 cargo test --offline --locked \
  -p xindex-bitgo-adapter

RUSTUP_TOOLCHAIN=1.95.0 cargo test --offline --locked \
  -p xindex-bitgo-client
```

The 12 gate, 16 adapter and 36 client/coordinator/runtime tests are deliberately
key-free. They cover the valid unsigned shape remaining blocked without live
artifacts, the unsafe memo-before-change order,
PSBT signing-stage mutation, exact P2WSH commitment and captured role-key
binding, RBF rejection, native-change build controls, rejection of a synthetic
half-signed witness, rejection of a purported final transaction without
witnesses, exact wire-field serialization, fee/change/sighash mutations,
rejection of signer-added PSBT policy metadata, transport redaction and body
bounds, exact wallet/build/sequence/approval correlation, immutable wallet
topology evidence, refusal of public in-memory stores, write-ahead idempotency,
non-release of send and pending-approval reservations, terminal rejection,
read-only approval reconciliation, rejection of an approved rebuild that
differs from the exact retained policy, refusal to accept user signing before
durable RIC one-shot authorization, expiry refusal, invalid-RIC non-transition,
canonical authorization/artifact hashing, exact Auth V2/V3 HMAC vectors,
response-HMAC rejection and capture, mainnet runtime refusal, closed runtime
capabilities, terminal send-state refusal, and
verification of static public half-signed/final examples from BitGo's manual
withdrawal guide. The tests verify existing public signatures; they never
create or use a private key.

## Disabled runtime handoff

`docs/runbooks/bitgo-custody-runtime.example.json` is deliberately invalid and
capability-empty. Copy it to an absolute owner-only directory, replace every
placeholder only after the corresponding L0-L3 authorization, and keep the
configuration, token, IntentProof, signed transaction and both SQLite files at
mode `0600` with one hard link. The containing directory must be owner-only.

The runtime subcommands are `status`, `build`, `authorize`,
`record-user-signed`, `submit`, and `manifest`. `status` performs no provider
I/O. `build` is the only command allowed to create the workflow database.
`submit` either crosses the one-shot final-sign-and-broadcast boundary or uses
read-only reconciliation after an existing reservation. Merely compiling or
invoking `--help` performs no BitGo action; do not run a provider-facing command
until its separately written authorization names the exact network, wallet,
sequence, time window, capability and maximum satoshis at risk.

## Live qualification stages

Each stage has a separate authorization boundary. Do not paste an access token,
wallet passphrase, xprv, encrypted private key, backup material, or key share
into this repository, an evidence file, terminal output captured for review, or
chat.

| Stage | Action | Authorization/status |
|---|---|---|
| L0 | Create a BitGo test account and narrowly scoped test token; read wallet and coin metadata | External account action; founder performs it |
| L1 | Generate one `tbtc4` self-custody hot 2-of-3 multisig wallet and P2WSH address | Key-generation ceremony; requires explicit authorization |
| L2 | Fund a capped P2WSH UTXO and build an unsigned PSBT with the exact controls | Testnet action; requires an approved satoshi cap, but no signing |
| L3 | User-sign, validate the half-signed artifact, then submit for BitGo cosign/broadcast | Key use plus external transaction; requires separate explicit authorization |

BitGo's documented `tx/send` route final-signs **and broadcasts** the half-signed
transaction. The offline gate can validate the user-signed artifact before that
call, but the BitGo-added signature can only be checked after the broadcasted
transaction is returned. This is acceptable for a capped Testnet4 compatibility
test; it is not sufficient by itself for production pre-broadcast policy.
BitGo also documents that a pending-approval withdrawal can be rebuilt with
current fees after approval. Such a rebuild must not be treated as the already
gated transaction: the coordinator reads the resolved approval and associated
transfer, but any final skeleton change fails the original exact-policy check.
The real provider behavior still needs live, capped production-policy
qualification.

The one-shot boundary deliberately favors safety over availability. If the
process dies after persisting `send_reserved` but before BitGo durably accepts
the request, and an exact sequence lookup finds nothing, the workflow stays
locked for operator investigation; it does not blindly POST again.

The earlier authorization boundary uses two durable stores in a deliberate
order: BitGo build state first, then custody replay consumption, then
`intent_authorized`. If the process dies after replay consumption but before
the workflow transition, retry the exact same RIC and unsigned txid; the replay
arm is idempotent for that pair and the receipt can be persisted. A different
certificate or transaction remains a one-shot conflict. Never manually insert
or release an authorization receipt.

### L0 — account only

The founder creates the test account and token directly in BitGo. Restrict the
token to the test enterprise, least permissions, and an IP allowlist where
available. Keep it outside the repository. L0 may corroborate an existing
wallet but must not create a wallet or key.

### L1 — wallet and P2WSH address

After explicit authorization, create one `tbtc4` self-custody hot multisig
wallet. Record only public wallet/key IDs, the exact compressed public keys for
the user, offline-backup and BitGo roles, and xpub fingerprints in private
evidence. Preserve the backup xprv/recovery kit offline and independently from
the user key. Request a P2WSH receive address using external chain code 20,
reconstruct the canonical 2-of-3 witness script from the captured role keys,
and corroborate that the address script is
`OP_0 <SHA256(witness_script)>`.

### L2 — unsigned compatibility proof

1. Fund only the authorized Testnet4 cap at the P2WSH address and wait for the
   approved confirmation depth.
2. Cross-check the chosen outpoint, value, script and exact 2-of-3 witness
   script on independent Testnet4/wallet evidence; do not derive the
   `expected` object solely from BitGo's build response.
3. Use a controlled Testnet4 receiver as the payout. Encode an exact valid
   <=80-byte THORChain memo in a zero-value OP_RETURN recipient.
4. Build with an explicit ordered unspent list, the `VIN0` address as
   `changeAddress`, `changeAddressType=p2wsh`, `noSplitChange=true`,
   `isReplaceableByFee=false`, `txFormat=psbt`, a fixed fee cap, and exactly the
   payout plus OP_RETURN recipients. Set a unique `sequenceId`.
5. Capture the raw request, sequence correlation, and returned unsigned PSBT.
   Do not sign yet. The later submit response must also retain its BitGo
   transfer ID and final transaction ID.
6. Fill a private copy of
   `docs/runbooks/bitgo-gate-evidence.example.json` and run the gate. The
   identity, input, layout, and fee checks must pass; signature/finalization
   checks must remain blocked.

### L3 — sign, submit, and corroborate

1. Only after the unsigned report is reviewed, sign through a locally operated
   BitGo Express or external-signer flow. Never pass the private key to the
   Xindex gate.
2. Capture the returned half-signed artifact. BitGo's documented manual BTC
   flow returns raw `txHex`, so add it as `user_signed_artifact` with
   `format="transaction"`, `encoding="hex"`, and the captured hex in `data`.
   A flow that genuinely returns BIP-174 may instead use `format="psbt"` with
   hex or base64 encoding. Run the gate again;
   `user_signature_preservation` must cryptographically verify the captured
   user role key before submission.
3. Under the separately authorized Testnet4 transaction cap, submit the
   half-signed transaction for BitGo final signing and broadcast.
4. Retrieve the transfer with raw transaction data, corroborate it on
   independent Testnet4 sources, record the final transaction hex and txid, and
   set the live capture fields only when backed by retained raw responses.
5. Run the final validator. `bitgo_cosign_preservation` must cryptographically
   verify exactly the supplied user + BitGo role signatures. The
   `live_corroboration` check must still remain blocked until an independently
   pinned provider envelope authenticates the role key and raw responses.

## Running captured evidence

Keep live evidence outside Git with owner-only permissions:

```sh
umask 077
cp docs/runbooks/bitgo-gate-evidence.example.json \
  /private/tmp/bitgo-gate-evidence.json

RUSTUP_TOOLCHAIN=1.95.0 cargo run --offline --locked \
  -p xindex-bitgo-dev-gate -- \
  --evidence /private/tmp/bitgo-gate-evidence.json \
  --output /private/tmp/bitgo-gate-report.json
```

Exit code `1` means at least one consistency check fails. Exit code `2` means
the capture is incomplete or is structurally complete but still lacks
authenticated provider provenance. Exit code `0` is intentionally unreachable
in the current schema. The example contains placeholders and is intentionally
not executable until every placeholder is replaced with a real capture.

## Qualification decision rule

BitGo remains disabled. L2 and L3 must preserve outputs, change, inputs, fee cap
and the transaction skeleton during both signing stages, but internal
consistency is not qualification. Closure additionally requires an
authenticated provider-evidence envelope, pinned reviewer identities and
manifest signatures, production custody-binary activation, policy, recovery,
operator-separation, incident, commercial, legal and independent-review gates.

The selected model deliberately accepts native Bitcoin 2-of-3 multisig instead
of MPC for BTC. The Gate-4 closure procedure is
[`gate4-bitgo-rehearsal.md`](./gate4-bitgo-rehearsal.md).
