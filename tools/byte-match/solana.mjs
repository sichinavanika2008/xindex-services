// P-SOL-1 byte-match: our `xindex-solana-tx` Squads V4 instruction-data
// encodings vs @sqds/multisig 2.1.4 (the reference SDK). We compare the
// full `data` field (8-byte discriminator + Borsh args). Account-meta
// ORDER is checked separately by the Rust account-layout tests; here we
// pin the on-the-wire instruction data.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const sqds = require('@sqds/multisig');
const { PublicKey } = require('@solana/web3.js');
const g = sqds.generated;

const hex = (u8) => Buffer.from(u8).toString('hex');
// Deterministic throwaway pubkeys (values don't matter — only data bytes).
const PK = (b) => new PublicKey(Buffer.alloc(32, b));

// ── proposal_approve, memo = "ok" ──
// Rust: discriminator ‖ Option<String> memo.
{
  const ix = g.createProposalApproveInstruction(
    { multisig: PK(1), member: PK(2), proposal: PK(3) },
    { args: { memo: 'ok' } },
  );
  console.log('proposal_approve_memo_ok=', hex(ix.data));
}

// ── proposal_create, transaction_index = 7, draft = false ──
// Rust: discriminator ‖ u64 LE index ‖ u8 draft.
{
  const ix = g.createProposalCreateInstruction(
    {
      multisig: PK(1),
      proposal: PK(2),
      creator: PK(3),
      rentPayer: PK(4),
      systemProgram: PK(0),
    },
    { args: { transactionIndex: 7n, draft: false } },
  );
  console.log('proposal_create_idx7_draftfalse=', hex(ix.data));
}

// ── vault_transaction_create, vault_index=0, ephemeral=0,
//    transactionMessage = bytes [0xaa,0xbb,0xcc], memo = "m" ──
// Rust: discriminator ‖ u8 vault_index ‖ u8 ephemeral ‖
//       anchor-bytes(vec<u8> = 4-byte LE len ‖ bytes) ‖ Option<String> memo.
{
  const ix = g.createVaultTransactionCreateInstruction(
    {
      multisig: PK(1),
      transaction: PK(2),
      creator: PK(3),
      rentPayer: PK(4),
      systemProgram: PK(0),
    },
    {
      args: {
        vaultIndex: 0,
        ephemeralSigners: 0,
        transactionMessage: Buffer.from([0xaa, 0xbb, 0xcc]),
        memo: 'm',
      },
    },
  );
  console.log('vault_tx_create=', hex(ix.data));
}
