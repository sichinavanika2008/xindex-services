// P3.3-3 byte-match: our `xindex-cosmos-tx` amino `StdSignDoc` canonical
// sign-bytes vs @cosmjs/amino's `serializeSignDoc(makeSignDoc(...))` — the
// reference TypeScript implementation of the cosmos-sdk
// SIGN_MODE_LEGACY_AMINO_JSON canonicalization (sorted keys, no
// whitespace, numbers-as-strings). These are the bytes every multisig
// member signs; a single divergent byte = an invalid signature (stuck
// funds) or a wrong-spend. Fixture mirrors the Rust `amino::tests::sample`.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { makeSignDoc, serializeSignDoc } = require('@cosmjs/amino');

const msg = {
  type: 'cosmos-sdk/MsgSend',
  value: {
    from_address: 'cosmos1from',
    to_address: 'cosmos1to',
    amount: [{ amount: '1000000', denom: 'uatom' }],
  },
};
const fee = { amount: [{ amount: '5000', denom: 'uatom' }], gas: '200000' };
const memo = '=:ETH.USDT:0xabc:0/1/0';
const chainId = 'cosmoshub-4';
const accountNumber = '12345';
const sequence = '7';

const signDoc = makeSignDoc([msg], fee, chainId, memo, accountNumber, sequence);
const bytes = serializeSignDoc(signDoc);
console.log('cosmos_amino_signdoc=', Buffer.from(bytes).toString('utf8'));

// Multisig address: LegacyAminoPubKey(threshold=2, members=[pk1,pk2,pk3])
// where pk(n) = 0x02 ‖ 0x00*31 ‖ n (the Rust addr::tests::pk helper).
const { createMultisigThresholdPubkey, pubkeyToAddress, encodeSecp256k1Pubkey } = require('@cosmjs/amino');
const pk = (n) => {
  const b = Buffer.alloc(33);
  b[0] = 0x02;
  b[32] = n;
  return encodeSecp256k1Pubkey(new Uint8Array(b));
};
const ms = createMultisigThresholdPubkey([pk(1), pk(2), pk(3)], 2);
console.log('cosmos_multisig_addr=', pubkeyToAddress(ms, 'cosmos'));
