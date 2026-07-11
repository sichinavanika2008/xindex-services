# Safe v1.4.1 runtime fixtures

These are the unmodified `deployedBytecode` values from the official
`@safe-global/safe-contracts@1.4.1` npm release:

- `safe-v1.4.1-runtime.hex`: `contracts/Safe.sol/Safe.json`
- `safe-proxy-factory-v1.4.1-runtime.hex`:
  `contracts/proxies/SafeProxyFactory.sol/SafeProxyFactory.json`

The integration test checks the fixtures against the canonical Keccak hashes
published by `safe-global/safe-deployments` before staging either runtime:

- Safe: `0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4`
- SafeProxyFactory: `0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317`

Primary sources:

- https://www.npmjs.com/package/@safe-global/safe-contracts/v/1.4.1
- https://github.com/safe-global/safe-deployments/tree/main/src/assets/v1.4.1

Regenerate from the release tarball by extracting each artifact's
`deployedBytecode` field. Do not regenerate from a different compiler build:
the canonical code-hash assertions are intentional supply-chain pins.
