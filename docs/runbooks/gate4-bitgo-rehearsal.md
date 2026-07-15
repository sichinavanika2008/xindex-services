# Gate 4 — BitGo BTC Testnet4 and failure rehearsal

> **Status: BLOCKED / not complete.** BitGo is the selected future BTC custody
> provider. This runbook does not authorize account or wallet creation, key
> generation, funding, signing, deployment, or network transactions.

## 1. Locked security boundary

Gate 4 keeps two independent quorums:

- observation, RIC and settlement certification remain 3-of-5 across five
  independently administered operators; and
- BTC custody is a BitGo self-custody hot wallet using native Bitcoin on-chain
  2-of-3 multisig: user key, offline backup key and BitGo key.

The normal pair is user + BitGo. User + backup is the tested recovery path.
The backup must remain independently administered and offline outside an
authorized recovery drill. This is Bitcoin multisig, not MPC. The selected BTC
address type is explicit P2WSH; BitGo's default Taproot/MuSig2 address type is
not accepted by this qualification.

BitGo is selected for BTC only. EVM, Cosmos, Solana, Tron and XRP production
custody remain disabled until separately designed and qualified. Turnkey and
Cobo are not fallback providers.

## 2. Network boundary

BitGo's test BTC asset is `tbtc4` on Bitcoin Testnet4. Public THORChain
stagenet uses real external-chain assets, so a `tbtc4` end-to-end rehearsal
must use an explicitly controlled THORChain devnet configured for Testnet4.
A BitGo-only Testnet4 transaction proves transaction shape and signing
compatibility, but does not by itself prove THORChain settlement.

The exact Gate-4 environment identifier is:

```text
sepolia+thorchain-devnet+btc-testnet4
```

## 3. Authority and secret handling

Repository checks are key-free and offline. Every action that creates a BitGo
account, enterprise, wallet or key; accesses a token; funds an address; signs;
approves; broadcasts; deploys; or changes an external network requires a new,
explicit user authorization naming that scope and the maximum funds at risk.

Never commit access tokens, wallet passphrases, encrypted private-key blobs,
mnemonics, xprvs, backup material or recovery packages. Gate evidence contains
only public identifiers, public-key fingerprints/hashes, redacted requests,
PSBT/final transaction artifacts, transaction IDs and hashes.

## 4. Mandatory preconditions

All preconditions fail closed:

1. Protocol and services commits are pinned and the locked/offline build,
   profile, lint and test gates pass.
2. The wallet lookup proves `coin=tbtc4`, `type=hot`, `multisigType=onchain`,
   self-custody and `m=2,n=3`.
3. The exact compressed user, backup and BitGo public keys match the reviewed
   canonical 2-of-3 witness script. The three custody roles have distinct
   administration and failure domains.
4. Receive and change addresses are created with the reviewed P2WSH address
   type. No implicit provider default is permitted.
5. The build request pins `txFormat=psbt`, explicit unspents in certified input
   order, the VIN0-derived `changeAddress`, `changeAddressType=p2wsh`,
   `noSplitChange=true`, `isReplaceableByFee=false`, one payout recipient and
   one zero-value `scriptPubKey:<OP_RETURN_HEX>` recipient.
6. Independent evidence supplies every input amount/script, exact witness
   script, expected payout, exact memo, VIN0 change script and a maximum fee.
   Provider responses are not the sole source of truth.
7. The shared key-free `xindex-bitgo-adapter` generates and validates the exact
   build policy. The current `xindex-bitgo-dev-gate` can validate internal
   transaction consistency, but it must return `overall: blocked` because its
   caller-supplied BitGo identities and responses have no authenticated
   provider provenance. A future qualification gate must verify an
   independently pinned provider envelope before Gate 4 can close.
8. Five observation/certification operators use distinct administrative,
   infrastructure, RPC and THORNode-source domains, with at least two THORNode
   origins per operator.
9. Alerts, pause paths, caps and an operator-independent WORM evidence sink are
   active. A written authorization artifact records networks, operations,
   operators, time window, loss cap and abort authority.

## 5. Local key-free preflight

```sh
# Solidity repository
forge test --offline --deny never --no-match-path 'test/*.fork.t.sol'
forge build --sizes --deny never

# Nested services repository
bash scripts/check-abi.sh --solidity-root ..
bash scripts/check-production-profile.sh
RUSTUP_TOOLCHAIN=1.95.0 cargo fmt --all -- --check
RUSTUP_TOOLCHAIN=1.95.0 cargo clippy --locked --offline \
  --workspace --all-targets --all-features -- -D warnings
RUSTUP_TOOLCHAIN=1.95.0 cargo test --locked --offline \
  --workspace --all-targets --all-features --no-run
RUSTUP_TOOLCHAIN=1.95.0 cargo test --locked --offline \
  -p xindex-bitgo-adapter -p xindex-bitgo-dev-gate

# Expected BLOCKED until authorized live Testnet4 artifacts replace placeholders
RUSTUP_TOOLCHAIN=1.95.0 cargo run --locked --offline \
  -p xindex-bitgo-dev-gate -- \
  --evidence /absolute/private/bitgo-gate-evidence.json \
  --output /absolute/private/bitgo-live-report.json
```

An unsigned or incomplete capture must remain `blocked`; malformed, synthetic
or cryptographically invalid signature evidence must fail. Even a structurally
complete capture remains `blocked` until provider provenance is authenticated.
None of these results is acceptable Gate-4 closure evidence.

## 6. Authorized BitGo qualification sequence

After separate authorization:

1. Create or identify the dedicated BitGo test enterprise and `tbtc4`
   self-custody hot wallet. Record only public wallet/key identifiers.
2. Verify the exact compressed user, offline-backup and BitGo public keys and
   record SHA-256 hashes of the reviewed public keyset. Reconstruct the
   canonical 2-of-3 witness script and create explicit P2WSH receive/change
   addresses using external chain code 20.
3. Fund with deliberately small Testnet4 value inside the written loss cap.
4. Independently select and certify unspents, payout, memo, VIN0 change and fee
   cap. Build an unsigned PSBT with the locked request fields.
5. Run the offline gate before any signature. Abort if any input, output,
   address type, order, memo, change or fee check fails.
6. Produce the user partial signature, rerun preservation checks, and require a
   valid `SIGHASH_ALL` signature from the captured user key before requesting
   the BitGo approval/co-sign path. Capture any rebuilt PSBT and revalidate it;
   pending approvals may be rebuilt with current fees.
7. Treat the final send operation as signing plus broadcast. Revalidate the
   final transaction skeleton, txid and exact valid user + BitGo signatures,
   then independently confirm Testnet4 inclusion.
8. Separately exercise user + backup recovery with the BitGo signer unavailable,
   then return the backup to its offline state and document the ceremony.
9. Repeat the exact transaction and settlement path against the controlled
   Testnet4-aware THORChain devnet.

## 7. Required drills

The strict bundle contains exactly these 23 drills:

| ID | Required outcome |
| --- | --- |
| `G4-MINT-HAPPY` | Capped Sepolia mint lifecycle is independently observed and finalized |
| `G4-REDEEM-HAPPY` | BitGo/Testnet4/THORChain-devnet redemption and settlement complete once |
| `G4-RECOVERY-CONTROLLED` | Reviewed protocol recovery or make-whole path stays within caps |
| `G4-ORACLE-DIVERGENCE` | Divergent reference data fails closed and alerts |
| `G4-ORACLE-STALE` | Stale, future or non-positive data fails closed |
| `G4-SEQUENCER-OUTAGE` | Outage and recovery grace block affected use |
| `G4-SIGNER-LOSS` | 3-of-5 certification tolerates two losses and rejects three |
| `G4-SIGNER-COMPROMISE` | Wrong signer/key/source cannot create accepted evidence |
| `G4-THOR-HALT` | Halt creates no custody signature or broadcast |
| `G4-VAULT-ROTATION` | Stale vault fails; freshly certified vault succeeds |
| `G4-ROUTER-ROTATION` | Wrong Router fails; reviewed rotation succeeds |
| `G4-STREAM-PARTIAL` | Partial delivery/refund settles exact values once |
| `G4-REFUND-FULL` | Full refund restores exact accounting without replay |
| `G4-DELAYED-INCLUSION` | Delay/reorg preserves reservation and retry safety |
| `G4-EMERGENCY-PAUSE` | Pause blocks new risk; reviewed unpause restores only allowed flow |
| `G4-CHALLENGE-INVALIDATION` | Invalid pending data is removed without replay regression |
| `G4-BITGO-BACKUP-RECOVERY` | User + backup recover the same wallet and broadcast a capped Testnet4 transaction |
| `G4-BITGO-APPROVAL-OUTAGE` | Approval/policy/service outage creates no second signature or broadcast |
| `G4-BITGO-TAMPER-REJECT` | Input/output/order/memo/change/fee mutations are rejected before signing |
| `G4-CTD-FORGED-DESTINATION` | Honest certificate plus attacker destination is rejected |
| `G4-REPLAY-EQUIVOCATION` | Re-drive/conflicting certificate creates no new signature |
| `G4-VOLUME-CAP` | Service and on-chain caps reject over-cap operations |
| `G4-ALERT-WORM` | Incident pages an operator and creates independent WORM evidence |

Positive custody drills require both a signature and independently verified
broadcast.
Negative custody drills require neither. Every drill records timestamps,
operators, expected and observed outcomes, response budget/actual time, at
least two owner-only artifacts, and external evidence. The current checker
validates only the declared shape and local hashes of those records; a future
closure verifier must authenticate their origins. Provider-facing BitGo drills
require a provider-request record; backup recovery instead requires a ceremony
record and Testnet4 transaction.

## 8. Bundle verification and closure

Copy `gate4-evidence.example.json` outside the repository, replace every
placeholder, and make the manifest, BitGo report, referenced raw BitGo capture
and every drill artifact owner-only regular files with mode `0600` and link
count one. The checker recomputes the capture hash and requires the BitGo report
to bind that exact value and the same wallet ID recorded in the custody
topology.

```sh
RUSTUP_TOOLCHAIN=1.95.0 cargo run --locked --offline \
  -p xindex-ops --bin xindex-gate4-check -- \
  /absolute/private/gate4/evidence.json \
  /absolute/private/gate4/bitgo-live-report.json
```

The current checker authenticates neither reviewer/provider identities nor Git
commit existence. A structurally consistent self-authored bundle therefore
prints `overall: format_valid` and exits with code `2`; it can never print
`pass`. Gate 4 remains blocked until a versioned evidence envelope pins trusted
reviewer/provider keys, verifies signatures over a canonical manifest, resolves
the recorded commits in the intended repositories, and authenticates raw
chain/provider records. Two independent reviewers must then sign the final
decision, and no mainnet readiness claim follows from this testnet gate.
