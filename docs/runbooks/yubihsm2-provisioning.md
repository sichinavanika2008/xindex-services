# Runbook — YubiHSM2 provisioning (M6)

> Scope: device-side hardening for the internal HSM-backed signer
> operators (the non-custodian members of the 3-of-5 sets). Institutional
> custodians (Anchorage / BitGo / Coinbase Custody) follow their own
> certified provisioning; this runbook governs the YubiHSM2 units Xindex
> operates directly. Consumed by `key-ceremony.md` Phase 1. Protocol-
> independent — no signer-daemon wire-protocol assumptions.

## Goal

A YubiHSM2 that can generate and use a secp256k1 key for signing but
from which the private key is **non-exportable**, with administrative
authority split so no single operator can both use and exfiltrate a key.

## Hard requirements

1. **Non-exportable keys.** Signing keys are generated on-device with
   capabilities limited to `sign-ecdsa` (+ `sign-pkcs` only if required
   by the fronting service). The `exportable-under-wrap` capability is
   **not** granted. A key that can be wrapped/exported is a ceremony
   failure (`key-ceremony.md` invariant 1).
2. **No raw-key import path left open.** After provisioning, the
   `put-asymmetric-key` / wrap-import capabilities are removed from all
   non-admin auth keys. Keys are *generated*, not *imported*.
3. **Split administrative authority.** The factory default auth key
   (ID 1, password) is **deleted** after a new admin auth key is
   installed. Admin authority is held under an M-of-N split (e.g. a
   wrap key escrowed across separate custodians) so device re-init
   cannot be done unilaterally.
4. **Least-privilege application auth.** The auth key the fronting
   signing service uses has `sign-ecdsa` on its own domain only — not
   `delete`, not `put`, not `export`, not `reset`.
5. **Separate domains per key set.** Set A (Bitcoin custody) and Set B
   (Ethereum attestation) keys live on **distinct YubiHSM2 domains** so
   the application auth for one set cannot operate the other set's key.
6. **Physical + logical isolation.** Generation runs on an air-gapped
   host; in production the device is reachable only by the local
   fronting service over `yubihsm-connector` bound to loopback, never
   exposed on a routable interface.

## Procedure

Roles: **device operator** (one per internal unit), **admin-split
custodians** (hold shares of the admin/wrap authority), **verifier**.

### Phase 1 — Factory bring-up (air-gapped)

1. On an air-gapped host, inspect device + firmware version; record the
   serial. Reject any unit whose tamper-evident packaging is broken.
2. Perform a factory `reset` to a known clean state.
3. Create the **admin auth key**: a strong, split-knowledge credential
   (no single operator knows it whole — e.g. Shamir-split passphrase or
   a wrap key escrowed across custodians).
4. **Delete the default auth key (ID 1).** Verify it is gone by
   attempting an authenticated session with the default credential and
   confirming it fails.

### Phase 2 — Domain + application auth setup

1. Allocate two domains: `D_A` (Bitcoin/Set A), `D_B`
   (Ethereum/Set B).
2. Create one **application auth key per set**, each scoped to its
   domain with capabilities = `{sign-ecdsa}` (and `generate-asymmetric`
   only for the generation step; revoke `generate`/`put` afterward so
   the production auth can sign but not create or replace keys).
3. Confirm neither application auth key carries `export-wrapped`,
   `exportable-under-wrap`, `put-asymmetric`, `delete-asymmetric`,
   `reset-device`, or cross-domain access.

### Phase 3 — Key generation (driven by `key-ceremony.md` Phase 1)

1. Under the application auth for `D_A`, `generate-asymmetric` a
   secp256k1 key with capability `sign-ecdsa` only,
   **without** `exportable-under-wrap`. Record the compressed public
   key.
2. Repeat under `D_B` for the Set-B key; record the public key + derived
   Ethereum address.
3. Revoke the `generate-asymmetric` / `put` capabilities from the
   application auth keys (production auth = sign-only from here on).
4. Hand the **public keys** to the ceremony coordinator. Nothing private
   crosses the air gap.

### Phase 4 — Hardening + verification

1. **Verifier** independently confirms, via an audit-log read:
   - Default auth key absent; admin auth split; application auth keys
     are sign-only, single-domain, non-exporting.
   - Exactly one signing key per domain, both non-exportable.
   - No wrap/export key with authority over the signing domains.
2. Enable and export the device **audit log**; wire it to the operator's
   monitoring so every `sign` is logged off-device. Set the audit-log
   policy to *force* (signing blocked if the log is full and unread)
   so signing can never proceed silently un-audited.
3. Record the device serial, firmware, public keys, and the verifier
   attestation into the `key-ceremony.md` Phase 3 disclosure inputs.

### Phase 5 — Production placement

1. Device installed in its production host; `yubihsm-connector` bound to
   loopback only; the fronting signing service is the *only* local
   process with the application auth credential.
2. Smoke test: the fronting service signs a throwaway challenge with
   each key; the verifier confirms the signature recovers to the
   disclosed public key. No mainnet message is signed during the smoke
   test.
3. Tamper-response: any tamper indication, unexplained audit-log gap, or
   unexpected `sign` entry ⇒ treat the corresponding key as
   compromised, trigger `key-ceremony.md` rotation for that set
   immediately, do not wait for a scheduled rotation.

## Anti-patterns (automatic ceremony failure)

- Generating a key off-device and importing it.
- Granting `exportable-under-wrap` "for backup" — HSM key backup is via
  the admin-split wrap authority under custodian control, never by
  making the signing key itself exportable.
- Leaving the default auth key (ID 1) in place "temporarily".
- One application auth key with cross-domain (Set A + Set B) access.
- `yubihsm-connector` reachable off-host.
- Audit log disabled or set to non-forcing to "avoid signing stalls".
