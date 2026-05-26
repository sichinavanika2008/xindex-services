# Runbook — Phase 3.2 Safe v1.4.1 per-chain key ceremony

> Scope: how the 3-of-5 EVM-family Safe is generated, deployed, and
> publicly disclosed for each Phase 3.2 destination chain
> (ETH / BSC / AVAX / BASE / POL). This runbook is the EVM-family
> counterpart to `key-ceremony.md` (which covers the UTXO-family
> P2WSH descriptor ceremony) and inherits its invariants verbatim
> where they apply (no key extraction, no threshold concentration,
> independent verification, air-gapped generation).
>
> **Mainnet funds do NOT move on any Phase 3.2 chain until this
> ceremony has completed on that chain.** DL-P3-7 + P3.2-3.

## The key set (do not conflate with Bitcoin Set A)

Phase 3.2 introduces a **third** secp256k1 key set — Set C: EVM Safe
ownership. Each Phase 3.2 chain has its OWN 3-of-5 Set C
(no cross-chain key sharing — DL-P3-7).

| Set | Curve / use | On-chain anchor | Compromise impact |
|---|---|---|---|
| A — Bitcoin custody | secp256k1, P2WSH `wsh(multi(3,…))` | The UTXO multisig address | Spends real BTC |
| B — Ethereum attestation | secp256k1, EIP-712 signer | `AttestationOracle` `_isSigner` set | Forges k-of-n attestation |
| **C — EVM Safe ownership (per chain)** | secp256k1, EOA address | `Safe.getOwners()` on chain X | Co-signs Safe `execTransaction` on chain X |

Set C is **a separate key per (signer organisation, chain)** — five
organisations × five chains = up to 25 distinct keys. A compromise of
one Set-C key on one chain does not propagate to other chains.

The 5 signer organisations match Set A + Set B (same mix of
institutional custodians + internal YubiHSM2 operators). Each
organisation generates its Set-C key for chain X in an air-gapped
ceremony on chain X's day; only the disclosed EOA address crosses
the air gap.

## Invariants the ceremony must guarantee

1. **No key extraction.** Set-C private keys generated inside the
   organisation's HSM (YubiHSM2 internal; custodian's equivalent for
   external). Non-exportable. See `yubihsm2-provisioning.md`.
2. **No threshold concentration.** No person / machine / network ever
   sees ≥ 3 Set-C private keys for one chain. Parties exchange
   **EOA addresses** (20-byte hex) only.
3. **Per-chain isolation.** Each chain's Set C is generated in a
   separate ceremony — never reuse a private key across chains.
   Defends against a single-chain compromise becoming a multi-chain
   one. Per-chain rotation policy is independent.
4. **Owner-set ordering invariant.** Safe v1.4.1 stores owners as a
   circular linked list (`SENTINEL_OWNERS → first → second → … →
   SENTINEL_OWNERS`). Internal ordering is operationally irrelevant
   to `checkSignatures` (which sorts by recovered address ascending),
   but our deployment uses the disclosed-EOAs-sorted-ascending order
   for canonical reproducibility.
5. **Independent verification.** Every party independently
   reconstructs the Safe proxy address from the disclosed owner-set
   + threshold + factory + singleton + chain — see Step 5 below — and
   matches it against the deploy script's broadcast output before any
   funds enter the Safe.
6. **Air-gapped generation.** Same shape as `key-ceremony.md` for
   Sets A/B.

## Procedure (per chain, sequential)

### Step 1 — Schedule the ceremony per chain

The five signer organisations agree on a ceremony date per chain.
**Do not parallelise across chains** — one chain per ceremony day,
so any human error stays scoped.

Suggested order (lowest stakes first to absorb procedure mistakes):
BASE → POL → AVAX → BSC → ETH. Mainnet ETH last.

### Step 2 — Air-gapped key generation (each party, in parallel within a chain)

Each of the 5 signer organisations independently:

1. Provisions a fresh HSM partition per `yubihsm2-provisioning.md`
   with `EXPORTABLE_UNDER_WRAP = false`.
2. Generates a new secp256k1 key for this chain. The key NEVER leaves
   the HSM.
3. Derives the EOA address (`keccak256(pubkey)[-20:]`) and exports
   the address (and ONLY the address — not the public key, not the
   private key) on QR / printed media.
4. Crosses the air gap.

The 5 disclosed EOA addresses are the Safe owner-set for this chain.

### Step 3 — Cross-disclosure + verification

Each party:

1. Receives the four other parties' disclosed addresses (over a
   channel that has integrity, not necessarily confidentiality — the
   addresses ARE public on-chain after deploy).
2. Independently logs the 5-address set sorted ascending.
3. Cross-checks against the other 4 parties' disclosed lists. All
   five lists MUST be byte-identical sorted output. Any disagreement
   → STOP, restart the ceremony.

### Step 4 — Safe deployment

Use the canonical Safe factory + singleton on the chain — see
`safe-global/safe-deployments` pinned to commit hash
`<TBD-at-deploy-time>`. Per-chain addresses live in the operator's
deploy notes; reference them from `chain_registry`-aligned constants
once mainnet ceremonies complete.

Deploy via `SafeProxyFactory.createProxyWithNonce(singleton, initData,
saltNonce)` where `initData` calls
`Safe.setup(owners=[...sorted addresses], threshold=3, to=address(0),
data="", fallbackHandler=address(0), paymentToken=address(0),
payment=0, paymentReceiver=address(0))`.

Critical setup args:

- `to = address(0)`: no delegatecall during setup. Refuses module /
  guard installation at setup time (P3.2-5 invariant).
- `fallbackHandler = address(0)`: no fallback handler. Reduces
  upgrade surface.
- `paymentToken / payment / paymentReceiver = 0/0/0`: no relayer
  payment.

The deploy can be performed by any party — the resulting Safe proxy
address is a pure function of `(factory, singleton, initData, salt)`.

### Step 5 — Independent address verification (each party)

Every party independently:

1. Re-derives the Safe proxy address via the same
   `create2(SafeProxyFactory, salt, keccak256(SafeProxyCreationCode ++
   abi.encode(singleton)))` formula.
2. Reads `Safe.getOwners()` from the deployed contract and asserts:
   - Returned owner-set is a permutation of the 5 disclosed addresses.
   - `Safe.getThreshold() == 3`.
   - `Safe.getModulesPaginated(SENTINEL_OWNERS, 10) == [[], SENTINEL_OWNERS]`
     (P3.2-5 — no modules enabled).
   - `Safe.nonce() == 0` (no transactions executed yet).

If ANY of these checks fail, the Safe is repudiated and the chain's
ceremony restarts from Step 2.

### Step 6 — Disclosure

The Safe proxy address + the 5 disclosed EOA addresses + the deploy
tx hash are published in a public artefact (e.g. an entry in
`deployments/<chain>/phase32.json` committed to the Xindex repo).
After this point, the Safe address is treated as a public infra
component.

### Step 7 — V10 registration on Ethereum (post-ceremony)

Once the Safe address is independently verified on chain X, the
operator runs the V10 Foundry script against Ethereum mainnet with
`SAFE_ADDRESS_<CHAIN>` env populated:

```bash
SAFE_ADDRESS_ETH=0x… \
SAFE_ADDRESS_BSC=0x… \
SAFE_ADDRESS_AVAX=0x… \
SAFE_ADDRESS_BASE=0x… \
SAFE_ADDRESS_POL=0x… \
forge script script/DeployPhase32Adapters.s.sol \
  --rpc-url $ETH_RPC_URL \
  --private-key $XINDEX_DEPLOYER_KEY \
  --broadcast
```

This deploys 5 new `ThorchainAdapter` instances on Ethereum (one per
EVM destination chain, each pointing at its Safe via
`nativeCustodyAddress`) and flips `factory.setAdapterAllowed` per
adapter.

**Do not flip `setAdapterAllowed` until every party has independently
verified the Safe addresses in `deployments/<chain>/phase32.json`.**

### Step 8 — Rehearsal on signet / testnet (mandatory)

Before mainnet funds move:

1. Repeat steps 1-7 on each chain's testnet (Sepolia / BSC testnet /
   Avalanche Fuji / BASE Sepolia / Polygon Amoy) with the same
   ceremony rigor.
2. Execute one round-trip mint + redeem leg through the testnet Safe
   end-to-end. The cycle MUST complete with funds returning to the
   user; any failure aborts the mainnet ceremony.
3. The testnet Safes can be longer-lived (for ongoing rehearsal
   coverage). Their owner-sets do NOT need to match the mainnet
   Set-C — testnet uses Anvil dev keys is acceptable.

## What this runbook deliberately does NOT cover

- **Rotation procedure.** Adding / removing a Safe owner on a live
  chain requires a `swapOwner` / `addOwnerWithThreshold` /
  `removeOwner` transaction signed by ≥ threshold current owners.
  Operationally identical to any other redeem (`xindex-redeem-evm`
  drives it). Procedure for the social-coordination side
  (who-pings-who, escrow-of-funds-during-rotation) is a separate v2
  runbook.
- **Compromised-key incident response.** If a single Set-C key is
  compromised: redeem-via-Safe of all funds on that chain to a fresh
  Safe with a fresh Set-C (same threshold, replacement owner for the
  compromised one), then update `chain_registry` Safe constants +
  redeploy V10 against the new Safe. Operational checklist tracked
  separately.
- **Module / guard installation.** Out of scope by invariant
  (P3.2-5). Future module additions would require a coordinated
  re-deploy + ceremony, intentionally high-friction.

## Cross-references

- `KNOWN_FINDINGS.md` — Phase 3.2 entries P3.2-1..15, especially
  P3.2-3 (per-chain ceremony required) and P3.2-5 (no modules / no
  guard).
- `docs/runbooks/key-ceremony.md` — Set A / Set B ceremony (this
  runbook's UTXO counterpart).
- `docs/runbooks/yubihsm2-provisioning.md` — device-side controls
  for the internal-operator HSMs.
- `Xindex/script/DeployPhase32Adapters.s.sol` — V10 deploy script.
- `~/refs/safe-global/safe-deployments` — canonical Safe singleton +
  proxy factory addresses per chain (pin commit at deploy time).
