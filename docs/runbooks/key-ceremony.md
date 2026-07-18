# Runbook — 3-of-5 key-generation ceremony + signer-set disclosure (M6)

> Scope: how the two independent 3-of-5 key sets are generated,
> distributed, verified, and publicly disclosed. This runbook is
> **protocol-independent** — it covers key material and the descriptor,
> not the signer-daemon wire protocol (that is the separately-locked M5
> signing-architecture design). No private key ever leaves the HSM that
> generated or imported it; no single party ever holds ≥ threshold keys.

## The two key sets (do not conflate)

Xindex has **two** distinct 3-of-5 secp256k1 key sets. They are
generated in separate ceremonies, stored on separate HSM partitions,
and disclosed separately. A single signer organisation holds **one** key
in each set, never two in the same set.

| Set | Curve / use | On-chain anchor | Compromise impact |
|---|---|---|---|
| **A — Bitcoin custody** | secp256k1, P2WSH `wsh(multi(3,…5 pubkeys))` | The multisig address holding real BTC | Spends real BTC |
| **B — Ethereum attestation** | secp256k1, EIP-712 signer | `AttestationOracle` `_isSigner` set, threshold 3 | Forges a k-of-n attestation |

Both are **3-of-5**. The 5 signer organisations are the same five
parties for both sets (a mix of institutional custodians and internal YubiHSM2 operators),
but each party generates and holds an independent key per set.

## Invariants the ceremony must guarantee

1. **No key extraction.** Each private key is generated *inside* its
   YubiHSM2 (or the custodian's equivalent HSM) and is non-exportable.
   See `yubihsm2-provisioning.md` for the device-side controls.
2. **No threshold concentration.** No person, machine, or network sees
   ≥ 3 private keys of either set, at any moment, including during
   generation. Parties generate independently and exchange **public**
   keys only.
3. **Deterministic descriptor ordering.** The Bitcoin descriptor is
   `wsh(multi(3, <pubkeys sorted lexicographically by compressed
   33-byte pubkey>))`. Sorting makes the multisig address a pure
   function of the pubkey set — every party derives the *same* address
   independently and the key-ceremony order is irrelevant (matches
   `crates/multisig` descriptor derivation).
4. **Independent verification.** Every party independently recomputes
   the Bitcoin multisig address and the Ethereum signer address list
   from the disclosed pubkeys before any funds or registration occur.
5. **Air-gapped generation.** Internal-operator key generation runs on
   an air-gapped host; the YubiHSM2 is provisioned per
   `yubihsm2-provisioning.md`; only public keys cross the air gap (on
   QR/printed media, transcribed and re-verified).

## Procedure

Roles: **ceremony coordinator** (drives, holds NO keys), **5 signer
operators** (one per party, each generates one key per set), **2
independent verifiers** (recompute and attest the public artifacts).

### Phase 1 — Per-party key generation (parallel, isolated)

Each of the 5 operators, independently and without network contact with
the others:

1. Provision the YubiHSM2 / custodian HSM per `yubihsm2-provisioning.md`
   (separate domains/partitions for Set A and Set B).
2. Generate **Set A** key: one secp256k1 keypair, non-exportable,
   inside the HSM. Record the **compressed public key** (33 bytes hex).
3. Generate **Set B** key: a second secp256k1 keypair, non-exportable,
   separate HSM object. Record the **public key** and the derived
   **Ethereum address** (keccak of the uncompressed pubkey, last 20
   bytes).
4. Produce a signed *attestation of generation*: the operator signs a
   fixed challenge string with each new key and publishes
   `(pubkey, signature)` so others can verify the operator actually
   controls the key (not a copied/placeholder pubkey).

No private key, seed, or mnemonic is transmitted, photographed, or
written down at any point. Generation that emits a mnemonic/seed is a
ceremony failure — abort and regenerate (a true HSM key has no
exportable seed).

### Phase 2 — Public-key exchange + independent derivation

1. Each operator sends the coordinator only: Set A compressed pubkey,
   Set B pubkey + ETH address, and the two generation attestations.
2. The coordinator publishes the collected set to all parties + the 2
   verifiers over an authenticated channel (each item signed by its
   originating operator).
3. **Every party and both verifiers independently**:
   - Verify each generation-attestation signature against its claimed
     pubkey (proves possession).
   - Sort the 5 Set-A compressed pubkeys lexicographically, build
     `wsh(multi(3, …))`, derive the mainnet P2WSH address, and confirm
     all 7 derivations match **byte-for-byte**.
   - Recompute the 5 Set-B Ethereum addresses and confirm the list.
4. Any mismatch ⇒ **halt**. Do not proceed to funding/registration
   until all independent derivations agree.

### Phase 3 — Signer-set disclosure (public artifact)

Publish, in the repo and the public docs, a **disclosure record** (only
public material — never a private key, seed, or HSM credential):

- The 5 Set-A compressed public keys, the sorted descriptor string, and
  the resulting P2WSH custody address.
- The 5 Set-B Ethereum signer addresses and the `AttestationOracle`
  threshold (3).
- For each of the 5 parties: legal/operational identity, the HSM class
  (YubiHSM2 / named institutional custodian), and the
  generation-attestation signature.
- The ceremony date, the coordinator + 2 verifiers, and a hash of this
  runbook version used.

This disclosure is what lets anyone independently confirm the on-chain
`AttestationOracle._isSigner` set and the BTC custody address match the
publicly committed signer set. It is a **standing public commitment**;
changing it requires the rotation procedure below + a new disclosure.

### Phase 4 — On-chain registration + funding gate

1. Register the 5 Set-B addresses in `AttestationOracle` (threshold 3).
   A third party independently reads the on-chain signer set back and
   diffs it against the disclosure record.
2. Only after Phase 3 disclosure is published **and** the on-chain
   readback matches: the BTC custody address may receive funds.
   Funding before disclosure+verification is a ceremony violation.

## Rotation / revocation (reference)

Key rotation is a re-run of Phases 1-4 for the affected set, plus:

- **Set A (Bitcoin):** a new descriptor ⇒ a new custody address. Funds
  are migrated by a 3-of-5 spend from the old multisig to the new one;
  the old descriptor is retired in the disclosure record. There is no
  in-place key swap for a P2WSH multisig — the address *is* the key set.
- **Set B (Ethereum):** `AttestationOracle` signer add/remove under its
  existing admin process (the Ownable2Step / future M-A2 timelock — out
  of scope here; this runbook only governs key material + disclosure).
- A compromised or suspected-compromised key triggers **immediate**
  rotation of that set and a new disclosure; do not wait for a
  scheduled rotation.

## Failure handling

- Any derivation mismatch, missing/invalid generation attestation, or
  evidence a key was exportable ⇒ abort, regenerate the affected key,
  restart from Phase 1 for that party. Never "patch" a partial ceremony.
- A party unable to complete generation does **not** get a placeholder
  key — the ceremony is blocked until all 5 are genuine HSM keys. A
  3-of-5 set with a weak 5th key is a 3-of-4 set in practice.
