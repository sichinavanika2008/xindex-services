# Byte-match reference encoders

Reference scripts for the per-family byte-match gates: they regenerate the
exact hex our Rust unit tests pin, so the pinned values have auditable
provenance (a named reference implementation at a pinned version, not a
hand-typed constant).

| Script | Reference | Rust test it backs | Finding |
|---|---|---|---|
| `xrp.mjs` | `ripple-binary-codec` 2.8.0 + `ripple-address-codec` 5.0.1 | `xrp-tx` `multisign_encoding_matches_xrpljs_reference` | P4.4-1 |
| `solana.mjs` | `@sqds/multisig` 2.1.4 (+ `@solana/web3.js` 1.98.4) | `solana-tx` `instruction_data_matches_squads_js` | P-SOL-1 |

The TRON gate (P-TRON-1) does not use a script here — it pins against
real TRON-node-serialized vectors vendored in THORChain bifrost
(`createtransaction.json`, `triggersmartcontract.json`), which is a
stronger reference than an SDK rebuild.

## Run

```sh
npm install --ignore-scripts   # exact pinned versions; no postinstall scripts
node xrp.mjs
node solana.mjs
```

Each prints labelled hex; if it diverges from the pinned Rust constant,
either the SDK changed (bump the version + re-pin) or our encoder
regressed (a real bug). `node_modules/` and the lockfile are gitignored —
the pinned versions in `package.json` are the contract.
