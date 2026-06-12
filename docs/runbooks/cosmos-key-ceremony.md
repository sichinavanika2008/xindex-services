# Runbook — Phase 3.3 Cosmos `LegacyAminoPubKey` per-chain key ceremony

> Scope: how the 3-of-5 Cosmos-family multisig is generated, derived, and
> publicly disclosed for each Phase 3.3 destination chain (GAIA / ATOM
> today; other Cosmos-SDK chains later). This runbook is the Cosmos-family
> counterpart to `safe-key-ceremony.md` (EVM Safe) and `key-ceremony.md`
> (UTXO P2WSH), and inherits their invariants verbatim where they apply
> (no key extraction, no threshold concentration, independent
> verification, air-gapped generation).
>
> **Mainnet funds do NOT move on any Cosmos chain until this ceremony has
> completed AND the address has been byte-matched against `gaiad`** —
> DL-P3-7 + KNOWN_FINDINGS P3.3-3 / P3.3-17.

## The key set (do not conflate with Sets A / B / C)

Phase 3.3 introduces a **fourth** secp256k1 key set — Set D: Cosmos
multisig membership. Each Cosmos chain has its OWN 3-of-5 Set D
(no cross-chain key sharing — DL-P3-7).

| Set | Curve / use | On-chain anchor | Compromise impact |
|---|---|---|---|
| A — Bitcoin custody | secp256k1, P2WSH `wsh(multi(3,…))` | The UTXO multisig address | Spends real BTC |
| B — Ethereum attestation | secp256k1, EIP-712 signer | `AttestationOracle` `_isSigner` set | Forges k-of-n attestation |
| C — EVM Safe ownership (per chain) | secp256k1, EOA address | `Safe.getOwners()` on chain X | Co-signs Safe `execTransaction` on chain X |
| **D — Cosmos multisig membership (per chain)** | secp256k1, compressed pubkey | The `LegacyAminoPubKey` account address | Co-signs a `MsgSend` from the Cosmos multisig |

Set D is **a separate key per (signer organisation, Cosmos chain)**. A
compromise of one Set-D key on one chain does not propagate to other
chains or to Sets A/B/C.

The 5 signer organisations match Sets A/B/C (same mix of institutional
custodians + internal YubiHSM2 operators). Each organisation generates
its Set-D key for chain X in an air-gapped ceremony; only the disclosed
**compressed public key** (33 bytes) crosses the air gap — unlike the
EVM ceremony, which discloses an EOA address, the Cosmos multisig address
is a function of the member **pubkeys** (not their derived addresses), so
the full compressed pubkey must be disclosed.

## Invariants the ceremony must guarantee

1. **No key extraction.** Set-D private keys generated inside the
   organisation's HSM, non-exportable. See `yubihsm2-provisioning.md`.
   The same secp256k1 HSM key the signer-daemon uses for the EIP-712
   attestation (Set B) is NOT reused — Set D is a distinct key (DL-P3-7).
2. **No threshold concentration.** No person / machine / network ever
   sees ≥ 3 Set-D private keys for one chain. Parties exchange
   **33-byte compressed pubkeys** only.
3. **Per-chain isolation.** Each Cosmos chain's Set D is a separate
   ceremony — never reuse a private key across chains.
4. **Frozen member order.** Unlike a Safe (whose `checkSignatures` sorts
   by recovered address) and unlike a Bitcoin `sortedmulti`, a Cosmos
   `LegacyAminoPubKey` is **positional**: the account address is
   `bech32(hrp, sha256(amino(LegacyAminoPubKey{threshold, public_keys}))[:20])`
   over the members in their **given order**. A permutation yields a
   different, unrecoverable address. The ceremony MUST freeze a canonical
   member order (e.g. ascending by compressed-pubkey hex) and record it;
   `crates/cosmos-tx/src/lib.rs::CosmosMultisig` preserves it, and the
   signer-daemon's `my_member_pubkey` + the executor's `--member-pubkeys`
   list MUST use that exact order.
5. **Independent verification + gaiad byte-match.** Every party
   independently derives the multisig address from the ordered pubkey set
   + threshold AND matches it against `gaiad keys add --multisig` for the
   target SDK version (Step 5). This is the P3.3-3 byte-exactness gate —
   our hand-rolled encoding (`addr.rs`) is pinned to unit tests, not to
   gaiad ground truth, until this step is performed.
6. **Air-gapped generation.** Same shape as the other ceremonies.

## Procedure (per Cosmos chain, sequential)

### Step 1 — Schedule the ceremony per chain

The five signer organisations agree on a ceremony date per chain. Do not
parallelise across chains — one chain per ceremony day so any human error
stays scoped. GAIA is the only Phase 3.3 chain today.

### Step 2 — Air-gapped key generation (each party, in parallel within a chain)

Each of the 5 signer organisations independently:

1. Provisions a fresh HSM partition per `yubihsm2-provisioning.md` with
   `EXPORTABLE_UNDER_WRAP = false`.
2. Generates a new secp256k1 key for this chain. The key NEVER leaves the
   HSM.
3. Exports the **33-byte compressed public key** (`0x02…` / `0x03…`) — and
   ONLY the pubkey — on QR / printed media.
4. Crosses the air gap.

### Step 3 — Cross-disclosure + canonical ordering

Each party:

1. Receives the four other parties' disclosed compressed pubkeys (over a
   channel with integrity; the pubkeys are public after the first tx).
2. Sorts the 5 pubkeys into the **frozen canonical order** (ascending by
   lowercase compressed-pubkey hex) and records it. This order is the
   one passed to `CosmosMultisig::new` and to `--member-pubkeys`.
3. Cross-checks against the other 4 parties' lists. All five MUST be
   byte-identical ordered output. Any disagreement → STOP, restart.

### Step 4 — Multisig address derivation

Derive the account address from the ordered member set + threshold (3):

- Our implementation: `xindex_cosmos_tx::CosmosMultisig::new(3, members,
  "cosmos").account_address()` — equivalently the
  `xindex-redeem-cosmos --multisig-address …` self-check at startup.
- Reference: `gaiad keys add xindex-multisig --multisig
  "<p1>,<p2>,<p3>,<p4>,<p5>" --multisig-threshold 3
  --nosort-pubkeys` (older SDKs: `--pubkey-sort-mode preserve`). The
  order-preserving flag is **MANDATORY** — confirmed by the P3.3-3
  byte-match (2026-06-12): the cosmos-sdk DEFAULT sorts members, which
  yields a DIFFERENT address than our frozen order. Our address
  derivation, the `TxRaw` `public_keys`, and the `CompactBitArray` bit
  positions all use the frozen member order, so the on-chain account
  MUST preserve it.

### Step 5 — Independent address verification + gaiad byte-match (each party)

Every party independently:

1. Re-derives the bech32 address from the ordered pubkey set + threshold
   via `CosmosMultisig::account_address()`.
2. Runs `gaiad keys add … --multisig …` (pinned to the **exact Gaia SDK
   version** `cosmoshub-4` is running) and asserts the printed `cosmos1…`
   address is **byte-identical** to step 1.
3. Builds a sample `MsgSend` and asserts the full `TxRaw` and sign-bytes
   produced by `xindex-redeem-cosmos` equal `gaiad tx bank send
   --generate-only` + `gaiad tx multisign` for the same inputs
   (KNOWN_FINDINGS P3.3-3). A single divergent byte aborts the ceremony.

⚠ The order-preserving flag (Step 4) is mandatory: the cosmos-sdk
DEFAULT sort produces a different address than our frozen order
(P3.3-3, cosmjs-confirmed). Without `--nosort-pubkeys` the addresses
will NOT match — abort and re-run with the flag. Record the
frozen-order convention in the disclosure artefact.

If ANY check fails, the multisig is repudiated and the ceremony restarts
from Step 2.

### Step 6 — Disclosure

The multisig `cosmos1…` address + the 5 ordered compressed pubkeys + the
frozen ordering convention are published in a public artefact (e.g.
`deployments/gaia/phase33.json` committed to the Xindex repo). After this
point the address is treated as public infrastructure.

### Step 7 — Signer-daemon + executor configuration

Each signer-daemon is configured with its Set-D role for this chain:
`CosmosSignerConfig { chain, cosmos_chain_id, account_address,
my_signer_address, my_member_pubkey }` — `my_member_pubkey` is this
party's disclosed compressed pubkey; `account_address` is the verified
multisig address. The coordinator's `xindex-redeem-cosmos` is given the
ordered `--member-pubkeys`, `--multisig-address` (self-checked against the
derived address at startup), `--signer-daemons`, and `--signer-pubkeys`.

### Step 8 — Rehearsal on a testnet (mandatory)

Before mainnet funds move:

1. Repeat steps 1-7 on a Cosmos testnet (e.g. `theta-testnet-001`) with
   the same ceremony rigor.
2. Execute one round-trip redeem leg end-to-end through the testnet
   multisig: `xindex-redeem-cosmos --broadcast` builds + signs + broadcasts
   the `MsgSend`, the C6 cross-check attests the delivery/refund. The
   cycle MUST complete; any failure aborts the mainnet ceremony.
3. The testnet multisig may use throwaway keys (the byte-match in Step 5
   is still mandatory there — it validates the encoding, not the keys).

## What this runbook deliberately does NOT cover

- **Rotation procedure.** Changing the member set rotates the multisig
  ADDRESS (positional `LegacyAminoPubKey`) — funds must be redeemed from
  the old multisig and the new address re-derived + re-disclosed. A v2
  runbook covers the social-coordination + escrow-during-rotation side.
- **Compromised-key incident response.** Redeem all funds from the
  affected chain's multisig to a fresh Set-D multisig (replacement member
  for the compromised one), re-derive + re-verify the address, update the
  daemon/executor config. Operational checklist tracked separately.
- **Cancel-stuck escrow.** If the threshold cannot be reached (signer
  party offline / compromised), a redemption stalls — see KNOWN_FINDINGS
  P3.3-16 and the SD-B redemption-stuck runbook (formal review pending).

## Cross-references

- `KNOWN_FINDINGS.md` — Phase 3.3 entries P3.3-1..17, especially P3.3-3
  (gaiad byte-match gate) and P3.3-17 (this ceremony required).
- `docs/runbooks/safe-key-ceremony.md` — Set C ceremony (EVM Safe), the
  closest structural analogue.
- `docs/runbooks/key-ceremony.md` — Set A / Set B ceremony (UTXO + ETH
  attestation).
- `docs/runbooks/yubihsm2-provisioning.md` — device-side controls.
- `crates/cosmos-tx/` — `CosmosMultisig` (address derivation), `amino`
  (sign-bytes), `tx` (`TxRaw`) — the code the byte-match validates.
