# Runbook — Phase 4.5 Solana Squads V4 per-chain key ceremony

> Scope: how the 3-of-5 Solana-family multisig is generated, established
> on-chain (Squads V4), and publicly disclosed for the Phase 4.5
> destination chain (SOL / SOL.SOL). This runbook is the Solana-family
> counterpart to `xrp-key-ceremony.md`, `cosmos-key-ceremony.md`,
> `safe-key-ceremony.md`, and `key-ceremony.md`, and inherits their
> invariants verbatim where they apply (no key extraction, no threshold
> concentration, independent verification, air-gapped generation).
>
> **Mainnet funds do NOT move on Solana until this ceremony has completed
> AND the instruction serialization has been byte-matched against the
> `@sqds/multisig` JS SDK on devnet** — DL-P3-7 + KNOWN_FINDINGS P-SOL-1.

## The key set (do not conflate with Sets A–E)

Phase 4.5 introduces a **sixth** key set — Set F: Squads V4 membership.
**Set F is the first ed25519 key set** — every prior set is secp256k1.
Each Solana chain has its OWN 3-of-5 Set F (no cross-chain key sharing —
DL-P3-7).

| Set | Curve / use | On-chain anchor | Compromise impact |
|---|---|---|---|
| A — Bitcoin custody | secp256k1, P2WSH `wsh(multi(3,…))` | The UTXO multisig address | Spends real BTC |
| B — Ethereum attestation | secp256k1, EIP-712 signer | `AttestationOracle` `_isSigner` set | Forges k-of-n attestation |
| C — EVM Safe ownership (per chain) | secp256k1, EOA | `Safe.getOwners()` | Co-signs Safe `execTransaction` |
| D — Cosmos multisig membership (per chain) | secp256k1, compressed pubkey | The `LegacyAminoPubKey` address | Co-signs a `MsgSend` |
| E — XRP SignerList membership (per chain) | secp256k1, compressed pubkey | The account's `SignerList` entry | Co-signs a `Payment` |
| **F — Squads V4 membership (per chain)** | **ed25519**, 32-byte pubkey | The Squads `Multisig` account's `members` | Casts one approval on a Squads proposal |

Set F is **a separate ed25519 key per (signer organisation, Solana
chain)**. A compromise of one Set-F key does not propagate to other chains
or sets, and — crucially — a single Set-F key can only cast ONE approval; a
spend requires `threshold` (3) distinct approvals plus the on-chain Squads
program's enforcement.

## The Solana-specific structural difference (read this first)

Core Solana has **no account-level k-of-n for native SOL** (only the SPL
Token program has a `Multisig`, and only for tokens). FROST/TSS is
deferred. So custody of native SOL under separate-key k-of-n **requires an
on-chain program** — Squads V4 (mainnet program
`SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`). The multisig is established
by a one-time on-chain bootstrap and addressed by PDAs:

1. **`multisig_create_v2`** — creates the `Multisig` account at the PDA
   `find_pda(["multisig", "multisig", create_key], program)`, where
   `create_key` is a one-time ed25519 keypair (a nonce that fixes the
   address; it does NOT control the multisig and is destroyed after the
   ceremony). Parameters (DL-2026-05-09, locked):
   - `threshold = 3`
   - `members` = the five Set-F pubkeys, each with permission mask
     `Initiate | Vote | Execute` (`0b111`, `PERMISSION_ALL`)
   - `config_authority = None` — **controlled-by-members** (no external
     admin key; config changes require a member vote)
   - `time_lock = 0` — our off-chain k-of-n collection time IS the delay
   - `rent_collector = None`
   Built by `xindex_solana_tx::squads::MultisigCreateV2`.
2. **Vault** — funds are held at the vault PDA
   `find_pda(["multisig", multisig, "vault", [0]], program)` (`vault_index
   = 0`). This is the address THORChain delivers SOL to and that
   redemptions spend from. It is an off-curve PDA — no private key exists
   for it; only the Squads program can authorise a spend, and only after a
   `threshold`-approved `vault_transaction`.

There is **no "disable master" step** (Squads has no master key — unlike
XRP). `config_authority = None` is the equivalent hardening: the member
set is the only authority.

The **multisig PDA and vault PDA are configuration** (functions of the
one-time `create_key`), supplied explicitly to the daemon
(`SolSignerConfig.multisig_pda`) and the executor (`--multisig-address`).

## Invariants the ceremony must guarantee

1. **No key extraction.** Set-F **ed25519** private keys generated inside
   the organisation's HSM, non-exportable. **ed25519 is net-new to our
   signer stack** (every other family is secp256k1) — the HSM /
   Web3Signer front-end MUST be provisioned for ed25519 before this
   ceremony (see `yubihsm2-provisioning.md`; the ed25519 capability is the
   Set-F prerequisite). Set F is a distinct key from Sets A–E (DL-P3-7).
2. **No threshold concentration.** No person / machine / network ever sees
   ≥ 3 Set-F private keys for one chain. Parties exchange **32-byte
   ed25519 pubkeys** (base58) only.
3. **Per-chain isolation.** Each Solana chain's Set F is a separate
   ceremony — never reuse a private key across chains.
4. **Member set frozen.** Squads stores `members` sorted by key on-chain
   and identifies a member by its pubkey (not a positional index), so —
   unlike Cosmos — the ceremony freezes the member **set** (the five
   ed25519 pubkeys + threshold 3 + `PERMISSION_ALL` each); there is no
   hand-chosen order to disagree about. The multisig address is a function
   of the one-time `create_key`, NOT of the member set.
5. **Independent verification + Squads-JS byte-match.** Every party
   independently (a) re-derives the multisig PDA, vault PDA, and per-tx
   transaction/proposal PDAs via `xindex_solana_tx::squads`, and (b)
   byte-matches the `multisig_create_v2` instruction AND a sample
   `vault_transaction_create` / `proposal_create` / `proposal_approve` /
   `vault_transaction_execute` against the `@sqds/multisig` JS SDK on
   devnet. This is the **P-SOL-1** byte-exactness gate — our hand-rolled
   `squads.rs` / `message.rs` is pinned to unit tests + a hand-computed
   inner-message vector, NOT to Squads ground truth, until this step is
   performed.
6. **Air-gapped generation.** Same shape as the other ceremonies.

## Procedure (per Solana chain, sequential)

### Step 1 — Schedule the ceremony per chain

The five signer organisations agree on a ceremony date per chain. Do not
parallelise across chains. SOL is the only Phase 4.5 chain today.

### Step 2 — Air-gapped key generation (each party)

Each of the 5 signer organisations independently:

1. Provisions a fresh HSM partition with **ed25519** enabled and
   `EXPORTABLE_UNDER_WRAP = false`.
2. Generates a new ed25519 key for this chain. The key NEVER leaves the HSM.
3. Exports ONLY the **32-byte ed25519 public key** (base58) on QR /
   printed media.
4. Crosses the air gap.

### Step 3 — Cross-disclosure + descriptor assembly

Each party:

1. Receives the four other parties' disclosed ed25519 pubkeys.
2. Assembles the frozen member SET — the five pubkeys, each
   `PERMISSION_ALL`, threshold 3 — and computes the multisig PDA from the
   agreed one-time `create_key` and the vault PDA via
   `xindex_solana_tx::squads::{multisig_pda, vault_pda}`.
3. Cross-checks the derived multisig PDA + vault PDA against the other 4
   parties' computations. All five MUST agree. Any disagreement → STOP,
   restart.

### Step 4 — Establish the multisig on-chain

A designated facilitator (holding the one-time `create_key` and a funded
fee payer):

1. Reads the Squads `ProgramConfig` PDA
   (`find_pda(["multisig", "program_config"], program)`) to obtain the
   `treasury` pubkey required by `multisig_create_v2`.
2. Submits **`multisig_create_v2`** (built by
   `squads::MultisigCreateV2`, signed by `create_key` + the fee payer),
   awaiting finalization.
3. Confirms the created `Multisig` account: `threshold == 3`,
   `time_lock == 0`, `config_authority == None`, and the five members each
   carry `PERMISSION_ALL`. Then **destroy the `create_key`** (it has no
   further use; the multisig is member-controlled).

### Step 5 — Independent verification + Squads-JS byte-match (each party)

Every party independently:

1. Reads the on-chain `Multisig` account (`getAccountInfo`, base64) and
   decodes it via `xindex_chain_solana::parse_multisig_account`, confirming
   the frozen member set + threshold 3 + `time_lock 0`.
2. **Byte-matches** the `multisig_create_v2` instruction data + account
   metas produced by `squads::MultisigCreateV2` against the
   `@sqds/multisig` SDK's `instructions.multisigCreateV2` on devnet
   (P-SOL-1).
3. Builds a sample redemption and asserts the bytes of each of
   `vault_transaction_create` (incl. the inner `TransactionMessage`),
   `proposal_create`, `proposal_approve`, and `vault_transaction_execute`
   equal the `@sqds/multisig` SDK output for the same inputs. A single
   divergent byte aborts the ceremony.

If ANY check fails, the multisig is repudiated and the ceremony restarts
from Step 2 (or Step 4 if only the on-chain bootstrap diverged).

### Step 6 — Disclosure

The multisig PDA + vault PDA + the 5 member ed25519 pubkeys + `threshold`
are published in a public artefact (e.g. `deployments/solana/phase45.json`
committed to the Xindex repo). After this point the addresses are treated
as public infrastructure.

### Step 7 — Signer-daemon + executor configuration

Each signer-daemon is configured with its Set-F role for this chain:
`SolSignerConfig { chain, multisig_pda, vault_index: 0, my_member_pubkey }`
— `my_member_pubkey` is this party's disclosed ed25519 pubkey;
`multisig_pda` is the verified multisig address. The coordinator's
`xindex-redeem-solana` is given `--multisig-address`, `--member-pubkeys`,
`--threshold 3`, `--vault-index 0`, `--signer-daemons`, and
`--signer-pubkeys`.

### Step 8 — Rehearsal on devnet/testnet (mandatory)

Before mainnet funds move:

1. Repeat steps 1-7 on Solana **devnet** with the same ceremony rigor.
2. Fund the devnet vault PDA and execute one round-trip redeem leg
   end-to-end: `xindex-redeem-solana --broadcast` drives the
   propose → approve×3 → execute choreography; confirm the user address
   receives the native SOL and the inbound observer attests it. The cycle
   MUST complete; any failure aborts the mainnet ceremony.
3. The devnet multisig may use throwaway keys (the byte-match in Step 5 is
   still mandatory there — it validates the encoding, not the keys).

## What this runbook deliberately does NOT cover

- **Rotation / config change.** Changing the member set or threshold is a
  Squads config transaction (a member-voted `config_transaction`); the
  multisig + vault PDAs are stable (funds do NOT move on rotation, unlike
  Cosmos). A v2 runbook covers the social-coordination side.
- **Compromised-key incident response.** Vote in a `config_transaction`
  replacing the compromised member (requires 3-of-5 of the CURRENT set),
  re-verify, update the daemon/executor config.
- **Cancel-stuck escrow.** If the quorum cannot be reached, a redemption
  stalls — see KNOWN_FINDINGS P-SOL and the SD-B redemption-stuck runbook
  (formal review pending). Note proposer/executor are `cosigner[0]` with no
  fallback yet (P-SOL-5).

## Cross-references

- `KNOWN_FINDINGS.md` — Phase 4.5 entries, especially P-SOL-1 (Squads-JS
  byte-match gate) and the ceremony requirement (P-SOL-2).
- `docs/runbooks/xrp-key-ceremony.md` — Set E ceremony, the closest
  structural analogue (separately-anchored multisig with an on-chain
  bootstrap; XRP is secp256k1, Solana is ed25519).
- `docs/runbooks/yubihsm2-provisioning.md` — device-side controls; the
  **ed25519 capability** is the Set-F prerequisite.
- `crates/solana-tx/src/squads.rs` — PDA derivations + instruction
  encoders the byte-match validates; `crates/chain-solana` — the account
  decoders.
