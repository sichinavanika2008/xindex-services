# Runbook — Phase 4.4 XRP `SignerList` per-chain key ceremony

> Scope: how the 3-of-5 XRP-family multisig is generated, established
> on-chain, and publicly disclosed for each Phase 4.4 destination chain
> (XRP / XRP.XRP today). This runbook is the XRP-family counterpart to
> `cosmos-key-ceremony.md`, `safe-key-ceremony.md`, and `key-ceremony.md`,
> and inherits their invariants verbatim where they apply (no key
> extraction, no threshold concentration, independent verification,
> air-gapped generation).
>
> **Mainnet funds do NOT move on any XRP chain until this ceremony has
> completed AND the serialization has been byte-matched against `rippled`
> / `xrpl.js`** — DL-P3-7 + KNOWN_FINDINGS P4.4-1 / P4.4-3.

## The key set (do not conflate with Sets A / B / C / D)

Phase 4.4 introduces a **fifth** secp256k1 key set — Set E: XRP
`SignerList` membership. Each XRP chain has its OWN 3-of-5 Set E (no
cross-chain key sharing — DL-P3-7).

| Set | Curve / use | On-chain anchor | Compromise impact |
|---|---|---|---|
| A — Bitcoin custody | secp256k1, P2WSH `wsh(multi(3,…))` | The UTXO multisig address | Spends real BTC |
| B — Ethereum attestation | secp256k1, EIP-712 signer | `AttestationOracle` `_isSigner` set | Forges k-of-n attestation |
| C — EVM Safe ownership (per chain) | secp256k1, EOA address | `Safe.getOwners()` on chain X | Co-signs Safe `execTransaction` on chain X |
| D — Cosmos multisig membership (per chain) | secp256k1, compressed pubkey | The `LegacyAminoPubKey` account address | Co-signs a `MsgSend` from the Cosmos multisig |
| **E — XRP SignerList membership (per chain)** | secp256k1, compressed pubkey | The account's on-chain `SignerList` entry | Co-signs a `Payment` from the XRP multisig |

Set E is **a separate key per (signer organisation, XRP chain)**. A
compromise of one Set-E key does not propagate to other chains or sets.

## The XRP-specific structural difference (read this first)

Unlike the Cosmos `LegacyAminoPubKey` multisig — whose account address is
**derived from** the member pubkeys — an XRP multisig is a **separately
funded ordinary XRPL account** whose control is moved to a `SignerList`
by a one-time on-chain bootstrap:

1. **Fund the account** so it meets the base reserve plus the owner
   reserve for a `SignerList` (each `SignerEntry` adds an owner-reserve
   increment — size the funding for 5 entries).
2. **`SignerListSet`** — establish the 3-of-5 list: `SignerQuorum = 3`,
   five `SignerEntry { Account, SignerWeight: 1 }`. Submitted by the
   account's **master key** (the account still has one at this point).
   Built by `xindex_xrp_tx::tx::serialize_signer_list_set`.
3. **`AccountSet` with `SetFlag = asfDisableMaster` (4)** — disable the
   master key so the `SignerList` is the ONLY way to authorise a
   transaction. Submit this **only after** the `SignerListSet` is
   validated; rippled refuses to disable the sole signing method.

After step 3 the account is controlled solely by the 3-of-5 Set-E
members. The **account r-address is configuration** (the funded account),
NOT a function of the member set — it is supplied explicitly to the
daemon (`XrpSignerConfig.account_address`) and the executor
(`--multisig-address`).

## Invariants the ceremony must guarantee

1. **No key extraction.** Set-E private keys generated inside the
   organisation's HSM, non-exportable. See `yubihsm2-provisioning.md`.
   Set E is a distinct key from Sets B/C/D (DL-P3-7).
2. **No threshold concentration.** No person / machine / network ever
   sees ≥ 3 Set-E private keys for one chain. Parties exchange **33-byte
   compressed pubkeys** only.
3. **Per-chain isolation.** Each XRP chain's Set E is a separate
   ceremony — never reuse a private key across chains.
4. **Member set frozen; order is by AccountID.** Unlike the positional
   Cosmos `LegacyAminoPubKey`, the XRP `Signers` array and the
   `SignerEntries` list are **sorted by AccountID ascending** — handled
   in code (`xindex_xrp_tx::XrpMultisig` sorts members;
   `tx::build_signed_multisig_tx` + `serialize_signer_list_set` sort the
   arrays). The ceremony therefore freezes the member **set** (the five
   pubkeys + weight 1 each + quorum 3), not a hand-chosen order; every
   party derives the same sorted set. Each member's `AccountID` =
   `RIPEMD160(SHA256(compressed_pubkey))`.
5. **Independent verification + `rippled` byte-match.** Every party
   independently (a) derives each member `AccountID` + r-address via
   `xindex_xrp_tx::addr`, and (b) byte-matches the `SignerListSet`
   serialization and a sample multisigned `Payment` against `xrpl.js`
   `encodeForMultisigning` + `multisign` (or `rippled sign_for`) for the
   pinned amendment set (Step 5). This is the P4.4-1 / P4.4-3
   byte-exactness gate — our hand-rolled `st.rs` / `signing.rs` is pinned
   to unit tests + the sourced single-sign vector, NOT to native-multisign
   ground truth, until this step is performed.
6. **Air-gapped generation.** Same shape as the other ceremonies.

## Procedure (per XRP chain, sequential)

### Step 1 — Schedule the ceremony per chain

The five signer organisations agree on a ceremony date per chain. Do not
parallelise across chains — one chain per ceremony day. XRP is the only
Phase 4.4 chain today.

### Step 2 — Air-gapped key generation (each party, in parallel within a chain)

Each of the 5 signer organisations independently:

1. Provisions a fresh HSM partition per `yubihsm2-provisioning.md` with
   `EXPORTABLE_UNDER_WRAP = false`.
2. Generates a new secp256k1 key for this chain. The key NEVER leaves the
   HSM.
3. Exports the **33-byte compressed public key** (`0x02…` / `0x03…`) — and
   ONLY the pubkey — on QR / printed media.
4. Crosses the air gap.

### Step 3 — Cross-disclosure + descriptor assembly

Each party:

1. Receives the four other parties' disclosed compressed pubkeys.
2. Assembles the frozen member SET — the five pubkeys, each weight 1,
   quorum 3 — and constructs
   `xindex_xrp_tx::XrpMultisig::new(3, [(pk, 1); 5])`. The descriptor
   sorts members by `AccountID`; the resulting order is deterministic
   (no hand-chosen ordering to disagree about).
3. Cross-checks each member's derived `AccountID` (and r-address) against
   the other 4 parties' computations. All five MUST agree. Any
   disagreement → STOP, restart.

### Step 4 — Fund the account + establish the SignerList on-chain

A designated facilitator (holding the freshly-generated **master key** of
the multisig account — itself produced in an air-gapped ceremony and
destroyed after Step 4c):

1. **Fund** the account r-address with enough XRP for the base reserve +
   5× the owner reserve (size for the `SignerList`), plus fee headroom.
2. **`SignerListSet`** (`SignerQuorum = 3`, the five `SignerEntry`s) —
   built by `serialize_signer_list_set`, single-signed by the master key,
   submitted, and awaited until **validated**.
3. **`AccountSet` `asfDisableMaster`** — single-signed by the master key,
   submitted, awaited until validated. After this the master key is dead;
   destroy it.

### Step 5 — Independent verification + `rippled` byte-match (each party)

Every party independently:

1. Re-derives each member `AccountID` + r-address via
   `xindex_xrp_tx::addr` and confirms the on-chain `SignerList`
   (`account_objects` / `account_info` `signer_lists`) matches the frozen
   set + quorum 3 + weight 1 each.
2. **Byte-match** the `SignerListSet` serialization produced by
   `serialize_signer_list_set` against `xrpl.js` `encode` for the same
   `SignerListSet` JSON (pinned amendment set).
3. Builds a sample `Payment` and asserts the multisigned tx-blob produced
   by `build_signed_multisig_tx` (+ the per-signer
   `signing::multisign_blob`) equals `xrpl.js` `encodeForMultisigning` +
   `multisign` (or `rippled sign_for`) for the same inputs
   (KNOWN_FINDINGS P4.4-1). A single divergent byte aborts the ceremony.

If ANY check fails, the multisig is repudiated and the ceremony restarts
from Step 2 (or Step 4 if only the on-chain bootstrap diverged).

### Step 6 — Disclosure

The multisig r-address + the 5 member compressed pubkeys (+ derived
AccountIDs) + `SignerQuorum`/weights are published in a public artefact
(e.g. `deployments/xrp/phase44.json` committed to the Xindex repo). After
this point the address is treated as public infrastructure.

### Step 7 — Signer-daemon + executor configuration

Each signer-daemon is configured with its Set-E role for this chain:
`XrpSignerConfig { chain, account_address, my_signer_address,
my_member_pubkey }` — `my_member_pubkey` is this party's disclosed
compressed pubkey (the daemon derives its own `AccountID` suffix from it);
`account_address` is the verified multisig r-address. The coordinator's
`xindex-redeem-xrp` is given the `--member-pubkeys`, `--multisig-address`,
`--quorum 3`, `--signer-daemons`, and `--signer-pubkeys`.

### Step 8 — Rehearsal on a testnet (mandatory)

Before mainnet funds move:

1. Repeat steps 1-7 on the XRP **Testnet** (or Devnet) with the same
   ceremony rigor.
2. Execute one round-trip redeem leg end-to-end through the testnet
   multisig: `xindex-redeem-xrp --broadcast` builds + signs + submits the
   `Payment`, the C6 cross-check attests the delivery/refund. The cycle
   MUST complete; any failure aborts the mainnet ceremony.
3. The testnet multisig may use throwaway keys (the byte-match in Step 5
   is still mandatory there — it validates the encoding, not the keys).

## What this runbook deliberately does NOT cover

- **Rotation procedure.** Changing the member set is a new `SignerListSet`
  (the account address is stable). A v2 runbook covers the
  social-coordination + escrow-during-rotation side; note that — unlike
  Cosmos — XRP rotation does NOT move the funds (the address is unchanged),
  only the on-chain `SignerList`.
- **Compromised-key incident response.** Submit a `SignerListSet`
  replacing the compromised member (requires 3-of-5 of the CURRENT list),
  re-verify, update the daemon/executor config. Operational checklist
  tracked separately.
- **Cancel-stuck escrow.** If the quorum cannot be reached (signer party
  offline / compromised), a redemption stalls — see KNOWN_FINDINGS P4.4
  and the SD-B redemption-stuck runbook (formal review pending).

## Cross-references

- `KNOWN_FINDINGS.md` — Phase 4.4 entries, especially P4.4-1 (`rippled`
  byte-match gate) and the ceremony requirement.
- `docs/runbooks/cosmos-key-ceremony.md` — Set D ceremony, the closest
  structural analogue (but Cosmos derives the address from members; XRP
  does not).
- `docs/runbooks/yubihsm2-provisioning.md` — device-side controls.
- `crates/xrp-tx/` — `XrpMultisig` (descriptor + AccountID derivation),
  `st` / `signing` (serialization + multisign blob), `tx`
  (`build_signed_multisig_tx`, `serialize_signer_list_set`) — the code the
  byte-match validates.
