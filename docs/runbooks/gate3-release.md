# Gate-3 release preflight

Status: code/release preflight only. This is not production approval and cannot
supply operator independence, custody authorization, live topology, alert/WORM
drills, provider provenance, or chain-rehearsal evidence.

## Production-profile behavior

Run from the nested services repository:

```bash
./scripts/check-production-profile.sh
```

The command first runs `check-production-profile-behavior.sh`. That gate builds
and executes exactly eight tests named
`production_profile_behavior_rejects_unsafe_mutations`, one in each production
entry point:

- signer daemon;
- price signer and price collector;
- BTC redemption executor;
- registry signer and registry coordinator;
- finalized settlement observer; and
- settlement collector.

Each test drives the same compiled preflight function called by its binary and
mutates prohibited backends/defaults, topology thresholds, endpoints, durable
state, peer pins, metrics/listener policy, or network scope as applicable. Test
fixtures contain unreadable dummy secret paths. A mutation must return its
policy error before any secret-path inspection, client construction, listener
bind, signing operation, or custody operation. Removing or bypassing a checked
branch causes the corresponding mutation to be accepted or to reach dummy-path
I/O, failing the test. The wrapper also requires the exact 8/8 marker count so
silently deleting or renaming a test fails closed.

The remaining fixed-string checks in `check-production-profile.sh` are
supplemental call-site, provider-removal, documentation, and supervision lints.
They are not treated as behavioral proof.

## Release evidence wrapper

After the normal format, Clippy, test, ABI and supply-chain gates, a release
custodian runs:

```bash
./scripts/check-gate3-release.sh \
  /secure/release/gate3-topology.json \
  /var/lib/xindex/evidence/ROLE
```

This additionally requires `promtool`, an owner-only non-placeholder topology,
checked alert rules, and populated evidence inventories. It still does not
approve a release: the external audit, custody/key ceremonies, live alert/WORM
drills, Gate-4 chain rehearsals, and independent review remain separate gates.
