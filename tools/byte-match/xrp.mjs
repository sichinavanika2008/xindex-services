// P4.4-1 byte-match: our `xindex-xrp-tx` encoders vs xrpl.js's
// ripple-binary-codec (the reference implementation rippled validators
// accept from). Fixtures mirror crates/xrp-tx/src/tx.rs tests exactly.
//
// Run: node xrp.mjs
// Output: three labelled reference hexes. The Rust test
// `multisign_encoding_matches_xrpljs_reference` pins our encoder
// outputs to these values (provenance: this script + the pinned
// package versions in package.json).
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { encode, encodeForMultisigning } = require('ripple-binary-codec');
const { encodeAccountID } = require('ripple-address-codec');

const hex = (s) => Buffer.from(s, 'hex');
const addr = (byte) => encodeAccountID(hex(byte.repeat(20)));

// ── Fixture A: the multisign body (tx.rs `multisign_body_…` test) ──
// account 0x11*20, dest 0x22*20, 1_000_000 drops, fee 30, seq 5,
// LastLedgerSequence 9_000_005, memo "=:ETH.USDT:0xabc:0".
const memoA = Buffer.from('=:ETH.USDT:0xabc:0', 'utf8').toString('hex').toUpperCase();
const txA = {
  TransactionType: 'Payment',
  Account: addr('11'),
  Destination: addr('22'),
  Amount: '1000000',
  Fee: '30',
  Sequence: 5,
  LastLedgerSequence: 9000005,
  SigningPubKey: '',
  Memos: [{ Memo: { MemoData: memoA } }],
};
console.log('A_multisign_body=', encode(txA).toLowerCase());

// ── Fixture B: per-signer blob for signer account 0x01*20 ──
// Our signing_blob = "SMT\0" ‖ body ‖ signer_account_id.
console.log(
  'B_signing_blob_signer01=',
  encodeForMultisigning(txA, addr('01')).toLowerCase(),
);

// ── Fixture C: assembled tx (tx.rs `assembled_tx_inserts_signers_…`) ──
// fee 60, NO LastLedgerSequence, memo "m"; two well-formed fake
// signers sorted ascending by account id (what our builder emits).
const txC = {
  TransactionType: 'Payment',
  Account: addr('11'),
  Destination: addr('22'),
  Amount: '1000000',
  Fee: '60',
  Sequence: 5,
  SigningPubKey: '',
  Signers: [
    {
      Signer: {
        Account: addr('01'),
        SigningPubKey: '02' + '02'.repeat(32),
        TxnSignature: '3006020101020101',
      },
    },
    {
      Signer: {
        Account: addr('09'),
        SigningPubKey: '03' + '02'.repeat(32),
        TxnSignature: '3006020101020101',
      },
    },
  ],
  Memos: [{ Memo: { MemoData: '6D' } }],
};
console.log('C_assembled_tx=', encode(txC).toLowerCase());
