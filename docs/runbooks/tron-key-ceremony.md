# Runbook — Phase 4.6 TRON account-permission per-chain key ceremony

> Scope: how the 3-of-5 TRON-family multisig is generated, established
> on-chain, and publicly disclosed for each Phase 4.6 destination chain
> (TRON / TRON.TRX + TRC20 USDT today). This runbook is the TRON-family
> counterpart to `xrp-key-ceremony.md`, `cosmos-key-ceremony.md`,
> `safe-key-ceremony.md`, and `key-ceremony.md`, and inherits their
> invariants verbatim where they apply (no key extraction, no threshold
> concentration, independent verification, air-gapped generation).
>
> **Mainnet funds do NOT move on any TRON chain until this ceremony has
> completed AND the serialization has been byte-matched against `tronweb`
> / `java-tron`** — DL-P3-7 + KNOWN_FINDINGS P-TRON-1 / P-TRON-2.

## The key set (do not conflate with Sets A / B / C / D / E / F)

Phase 4.6 introduces a **seventh** key set — Set G: TRON account-permission
membership. It is secp256k1 (like Sets A–E; NOT ed25519 like Solana's
Set F), so it reuses the existing `HsmDigestSigner` path. Each TRON chain
has its OWN 3-of-5 Set G (no cross-chain key sharing — DL-P3-7).

| Set | Curve / use | On-chain anchor | Compromise impact |
|---|---|---|---|
| A — Bitcoin custody | secp256k1, P2WSH `wsh(multi(3,…))` | The UTXO multisig address | Spends real BTC |
| B — Ethereum attestation | secp256k1, EIP-712 signer | `AttestationOracle` `_isSigner` set | Forges k-of-n attestation |
| C — EVM Safe ownership (per chain) | secp256k1, EOA address | `Safe.getOwners()` on chain X | Co-signs Safe `execTransaction` on chain X |
| D — Cosmos multisig membership (per chain) | secp256k1, compressed pubkey | The `LegacyAminoPubKey` account address | Co-signs a `MsgSend` from the Cosmos multisig |
| E — XRP SignerList membership (per chain) | secp256k1, compressed pubkey | The account's on-chain `SignerList` entry | Co-signs a `Payment` from the XRP multisig |
| F — Solana Squads membership (per chain) | ed25519, member pubkey | The Squads `Multisig` account member set | Approves a Squads vault transaction |
| **G — TRON Permission membership (per chain)** | secp256k1, compressed pubkey | The account's `Active` `Permission` key entry | Co-signs a transfer from the TRON multisig |

Set G is **a separate key per (signer organisation, TRON chain)**. A
compromise of one Set-G key does not propagate to other chains or sets.

## The TRON-specific structural difference (read this first)

Like XRP (and unlike the Cosmos `LegacyAminoPubKey` multisig, whose
address is **derived from** the member pubkeys), a TRON multisig is a
**separately funded ordinary account** whose control is moved to a
weighted `Active` `Permission` by a one-time on-chain bootstrap:

1. **Fund the account** with enough TRX for the bootstrap (the
   `AccountPermissionUpdateContract` itself costs **100 TRX**) plus a
   working balance for bandwidth/energy on subsequent redeem txs.
2. **`AccountPermissionUpdateContract`** — establish the 3-of-5. This
   contract **OVERWRITES the owner + witness + all active permissions
   wholesale**, so you MUST first `getaccount` the funded account and
   restate everything you intend to keep. Set:
   - `owner_permission`: keep a controlled owner (the bootstrapping key,
     or its own k-of-n — see step 4).
   - `actives[0]`: `{ type: Active, id: 2, permission_name: "active",
     threshold: 3, keys: [ {address: memberᵢ, weight: 1} × 5 ],
     operations: <bitmap with bit 1 (TransferContract) + bit 31
     (TriggerSmartContract) set> }`.
   - The `operations` bitmap is 32 bytes / 256 bits, little-endian per
     byte (`operations[id/8] |= 1 << (id%8)`). The common-default
     `7fff1fc0033ec30f…` covers the transfer set; a minimal
     transfer-only vault needs only bits 1 and 31.
   Submitted by the account's **owner key** (still present at this
   point).
3. **Verify** the on-chain permission via `getaccount`: confirm
   `active_permission[0]` has `id == 2`, `threshold == 3`, exactly the 5
   member addresses each at `weight 1`, and the intended `operations`.
4. **Harden the owner permission.** Either move the owner permission to
   its own 3-of-5 (recommended — no single owner key can re-write the
   active permission) or destroy the bootstrapping owner key per the
   organisation's policy. The active permission is what the redeem path
   signs under; the owner permission governs future permission changes.

After the bootstrap, redeem txs set `Contract.Permission_id = 2` (the
active permission id). **`Permission_id` lives inside `raw_data`, so it is
hashed into the `txID`** — all members sign the identical `txID`, and a
wrong permission id changes the hash (so a mismatch fails closed). The
account **`T…` address is configuration** (the funded account), NOT a
function of the member set — supplied explicitly to the daemon
(`TronSignerConfig.owner_address`) and the executor (`--multisig-address`).

## Invariants the ceremony must guarantee

1. **No key extraction.** Set-G private keys generated inside the
   organisation's HSM, non-exportable. See `yubihsm2-provisioning.md`.
   (Set G is secp256k1, so it uses the existing HSM digest path — no
   ed25519 provisioning is required, unlike Set F.)
2. **No threshold concentration.** The 5 Set-G members are held by 5
   distinct signer organisations; no organisation holds ≥ 3.
3. **Per-chain isolation.** A fresh Set G per TRON chain; never reuse a
   Set-A…F key or another chain's Set G.
4. **Independent verification.** Each organisation independently derives
   its member `T…` address from its own pubkey
   (`base58check(0x41 ‖ keccak256(uncompressed_pubkey)[12:])`) and
   confirms it appears in the on-chain `active_permission` at `weight 1`.
5. **Byte-match gate (P-TRON-1).** Before mainnet funds, build a sample
   redeem tx (both a `TransferContract` and a `TriggerSmartContract`) and
   the `AccountPermissionUpdateContract` with `tronweb` / `java-tron` and
   confirm `raw_data_hex` + `txID` match `xindex-tron-tx`'s output
   byte-for-byte. The native-TRX `TransferContract` `txID` is already
   pinned in-repo against a sourced thornode vector
   (`trx_txid_matches_thornode_sourced_vector`), but the TRC20 path, the
   permission-update tx, and the multi-sig `signature[]` assembly are NOT.
6. **Testnet rehearsal.** Run the full ceremony + a 3-of-5 redeem on the
   Nile testnet (or Shasta) before mainnet.

## Disclosure artefact

Publish, per TRON chain: the multisig `T…` address, the 5 member `T…`
addresses + compressed pubkeys, the active `Permission_id` (2), the
`threshold` (3), and the `operations` bitmap. Anyone can `getaccount` the
address and confirm the on-chain permission matches the disclosure.

## What moves funds after the ceremony

A redeem leg (`xindex-redeem-tron`) reads the current block for the TAPOS
reference, builds the `raw_data` once, distributes the `txID`, collects 3
of 5 daemon signatures over that identical `txID`, appends them to
`Transaction.signature[]`, and broadcasts via `broadcasthex`. The TRON
node recovers each signer, sums the `Active` permission weights, and
applies the tx iff `Σ weight ≥ 3`. There is no master/owner key in the
redeem path — only the 3-of-5 active permission.
