//! Legacy Solana transaction message: compilation, serialization, and
//! transaction wrapping.
//!
//! ## Account compilation
//!
//! Mirrors `@solana/web3.js` `Transaction.compileMessage` so the bytes
//! byte-match the Squads JS SDK (the S3 gate):
//!
//! 1. Collect every instruction account meta (first-appearance order),
//!    merging duplicates by OR-ing `is_signer` / `is_writable`.
//! 2. Append each program id as a readonly non-signer.
//! 3. Stable-sort by `(is_signer desc, is_writable desc)` — signers before
//!    non-signers, writable before readonly, first-appearance within a class.
//! 4. Force the fee payer to index 0 as a writable signer.
//!
//! The header counts (`num_required_signatures`, `num_readonly_signed`,
//! `num_readonly_unsigned`) fall out of the partitioned key list.
//!
//! ## Wire layout
//!
//! `message := header(3) ‖ shortvec(account_keys) ‖ blockhash(32) ‖
//! shortvec(instructions)`; each instruction is `program_id_index(1) ‖
//! shortvec(account_indices) ‖ shortvec(data)`. A transaction is
//! `shortvec(signatures) ‖ 64·sig ‖ message`.

use crate::shortvec;
use crate::{Pubkey, SolanaTxError};

/// One account reference within an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    /// The account address.
    pub pubkey: Pubkey,
    /// Whether the account must sign the transaction.
    pub is_signer: bool,
    /// Whether the instruction may mutate the account.
    pub is_writable: bool,
}

impl AccountMeta {
    /// A writable signer account.
    #[must_use]
    pub const fn writable_signer(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: true,
            is_writable: true,
        }
    }

    /// A readonly signer account.
    #[must_use]
    pub const fn readonly_signer(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: true,
            is_writable: false,
        }
    }

    /// A writable non-signer account.
    #[must_use]
    pub const fn writable(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: true,
        }
    }

    /// A readonly non-signer account.
    #[must_use]
    pub const fn readonly(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: false,
        }
    }
}

/// A program instruction: target program, account references, opaque data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// The program to invoke.
    pub program_id: Pubkey,
    /// Accounts the program reads / writes / requires as signers.
    pub accounts: Vec<AccountMeta>,
    /// Opaque instruction data (the program's own encoding).
    pub data: Vec<u8>,
}

/// One instruction with its accounts compiled to message-key indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstruction {
    /// Index of the program id in the message account-keys list.
    pub program_id_index: u8,
    /// Indices of this instruction's accounts in the account-keys list.
    pub account_indices: Vec<u8>,
    /// Opaque instruction data.
    pub data: Vec<u8>,
}

/// A compiled legacy message, ready to serialize + sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Number of leading account keys that must sign.
    pub num_required_signatures: u8,
    /// Of the signers, how many are readonly.
    pub num_readonly_signed: u8,
    /// Of the non-signers, how many are readonly.
    pub num_readonly_unsigned: u8,
    /// The ordered account keys (writable-signers, readonly-signers,
    /// writable-non-signers, readonly-non-signers).
    pub account_keys: Vec<Pubkey>,
    /// A recent blockhash (32 bytes), bounding the transaction's lifetime.
    pub recent_blockhash: [u8; 32],
    /// The compiled instructions.
    pub instructions: Vec<CompiledInstruction>,
}

/// Merge an account meta into `keys` by OR-ing the flags of an existing
/// entry with the same pubkey, or appending a new entry.
fn merge(keys: &mut Vec<AccountMeta>, meta: AccountMeta) {
    if let Some(existing) = keys.iter_mut().find(|k| k.pubkey == meta.pubkey) {
        existing.is_signer = existing.is_signer || meta.is_signer;
        existing.is_writable = existing.is_writable || meta.is_writable;
    } else {
        keys.push(meta);
    }
}

impl Message {
    /// Compile `instructions` into a legacy message paid by `fee_payer`.
    ///
    /// # Errors
    /// Returns [`SolanaTxError::TooManyAccounts`] if the message references
    /// more than 255 distinct accounts (an index must fit a `u8`), or
    /// [`SolanaTxError::MissingAccount`] if an instruction references an
    /// account that was not compiled (a programming error).
    pub fn new_legacy(
        fee_payer: &Pubkey,
        recent_blockhash: [u8; 32],
        instructions: &[Instruction],
    ) -> Result<Self, SolanaTxError> {
        let mut keys: Vec<AccountMeta> = Vec::new();
        // Fee payer first so it leads the writable-signer class.
        merge(&mut keys, AccountMeta::writable_signer(*fee_payer));
        for ix in instructions {
            for meta in &ix.accounts {
                merge(&mut keys, meta.clone());
            }
        }
        for ix in instructions {
            merge(&mut keys, AccountMeta::readonly(ix.program_id));
        }

        // Stable sort: signers first, writable first, first-appearance
        // preserved within a class.
        keys.sort_by(|a, b| {
            b.is_signer
                .cmp(&a.is_signer)
                .then(b.is_writable.cmp(&a.is_writable))
        });

        // Defensive: force the fee payer to index 0.
        if let Some(pos) = keys.iter().position(|k| k.pubkey == *fee_payer) {
            let fp = keys.remove(pos);
            keys.insert(0, fp);
        }

        if keys.len() > usize::from(u8::MAX) {
            return Err(SolanaTxError::TooManyAccounts(keys.len()));
        }

        let num_required_signatures = count_u8(keys.iter().filter(|k| k.is_signer).count());
        let num_readonly_signed = count_u8(
            keys.iter()
                .filter(|k| k.is_signer && !k.is_writable)
                .count(),
        );
        let num_readonly_unsigned = count_u8(
            keys.iter()
                .filter(|k| !k.is_signer && !k.is_writable)
                .count(),
        );

        let account_keys: Vec<Pubkey> = keys.iter().map(|k| k.pubkey).collect();
        let index_of = |pk: &Pubkey| -> Result<u8, SolanaTxError> {
            let pos = account_keys
                .iter()
                .position(|k| k == pk)
                .ok_or_else(|| SolanaTxError::MissingAccount(pk.to_base58()))?;
            Ok(count_u8(pos))
        };

        let mut compiled = Vec::with_capacity(instructions.len());
        for ix in instructions {
            let program_id_index = index_of(&ix.program_id)?;
            let mut account_indices = Vec::with_capacity(ix.accounts.len());
            for meta in &ix.accounts {
                account_indices.push(index_of(&meta.pubkey)?);
            }
            compiled.push(CompiledInstruction {
                program_id_index,
                account_indices,
                data: ix.data.clone(),
            });
        }

        Ok(Self {
            num_required_signatures,
            num_readonly_signed,
            num_readonly_unsigned,
            account_keys,
            recent_blockhash,
            instructions: compiled,
        })
    }

    /// Serialize to the canonical legacy-message wire bytes (the bytes that
    /// each required signer signs).
    ///
    /// # Errors
    /// Returns [`SolanaTxError::ShortVecOverflow`] if any array exceeds the
    /// compact-u16 maximum.
    pub fn serialize(&self) -> Result<Vec<u8>, SolanaTxError> {
        let mut out = Vec::new();
        out.push(self.num_required_signatures);
        out.push(self.num_readonly_signed);
        out.push(self.num_readonly_unsigned);
        shortvec::encode_len(self.account_keys.len(), &mut out)?;
        for key in &self.account_keys {
            out.extend_from_slice(key.as_bytes());
        }
        out.extend_from_slice(&self.recent_blockhash);
        shortvec::encode_len(self.instructions.len(), &mut out)?;
        for ix in &self.instructions {
            out.push(ix.program_id_index);
            shortvec::encode_len(ix.account_indices.len(), &mut out)?;
            out.extend_from_slice(&ix.account_indices);
            shortvec::encode_len(ix.data.len(), &mut out)?;
            out.extend_from_slice(&ix.data);
        }
        Ok(out)
    }
}

/// Narrow a `usize` account count/index to `u8`. Callers guarantee the
/// value is `< 256` (the message is rejected above 255 accounts before any
/// index is taken), so the saturating fallback is never reached.
fn count_u8(v: usize) -> u8 {
    u8::try_from(v).unwrap_or(u8::MAX)
}

/// Serialize a signed transaction: `shortvec(sig_count) ‖ 64·sig ‖
/// message_bytes`. `signatures[i]` must correspond to the message's
/// `account_keys[i]` for `i < num_required_signatures`.
///
/// # Errors
/// Returns [`SolanaTxError::ShortVecOverflow`] if the signature count
/// exceeds the compact-u16 maximum.
pub fn serialize_transaction(
    message_bytes: &[u8],
    signatures: &[[u8; 64]],
) -> Result<Vec<u8>, SolanaTxError> {
    let mut out = Vec::new();
    shortvec::encode_len(signatures.len(), &mut out)?;
    for sig in signatures {
        out.extend_from_slice(sig);
    }
    out.extend_from_slice(message_bytes);
    Ok(out)
}

/// System Program `transfer` (instruction index 2): move `lamports` from
/// `from` (writable signer) to `to` (writable). Used both directly and as
/// the inner instruction of a Squads `vault_transaction`.
#[must_use]
pub fn system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: Pubkey::system_program(),
        accounts: vec![
            AccountMeta::writable_signer(from),
            AccountMeta::writable(to),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new([byte; 32])
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn system_transfer_message_byte_exact() {
        // from is the fee payer (writable signer); to is writable;
        // System Program is readonly non-signer.
        let from = pk(0xAA);
        let to = pk(0xBB);
        let blockhash = [0xCC; 32];
        let ix = system_transfer(from, to, 5_000_000_000);
        let msg = Message::new_legacy(&from, blockhash, &[ix]).expect("compile");

        // Header: 1 required sig, 0 readonly signed, 1 readonly unsigned.
        assert_eq!(msg.num_required_signatures, 1);
        assert_eq!(msg.num_readonly_signed, 0);
        assert_eq!(msg.num_readonly_unsigned, 1);
        // Account order: [from, to, system].
        assert_eq!(msg.account_keys, vec![from, to, Pubkey::system_program()]);
        // Instruction: program index 2, accounts [0, 1].
        assert_eq!(msg.instructions.len(), 1);
        assert_eq!(msg.instructions[0].program_id_index, 2);
        assert_eq!(msg.instructions[0].account_indices, vec![0, 1]);

        // Hand-computed wire bytes.
        let mut expected = Vec::new();
        expected.extend_from_slice(&[1, 0, 1]); // header
        expected.push(3); // shortvec: 3 account keys
        expected.extend_from_slice(&[0xAA; 32]);
        expected.extend_from_slice(&[0xBB; 32]);
        expected.extend_from_slice(&[0x00; 32]);
        expected.extend_from_slice(&[0xCC; 32]); // blockhash
        expected.push(1); // shortvec: 1 instruction
        expected.push(2); // program_id_index
        expected.push(2); // shortvec: 2 account indices
        expected.extend_from_slice(&[0, 1]);
        expected.push(12); // shortvec: 12 data bytes
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&5_000_000_000u64.to_le_bytes());

        assert_eq!(msg.serialize().expect("serialize"), expected);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn transaction_wrapping_prepends_sig_count_and_sigs() {
        let from = pk(1);
        let to = pk(2);
        let msg =
            Message::new_legacy(&from, [3; 32], &[system_transfer(from, to, 1)]).expect("compile");
        let bytes = msg.serialize().expect("serialize");
        let sig = [0x11u8; 64];
        let tx = serialize_transaction(&bytes, &[sig]).expect("wrap");
        assert_eq!(tx[0], 1); // shortvec: 1 signature
        assert_eq!(&tx[1..65], &sig);
        assert_eq!(&tx[65..], &bytes[..]);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn duplicate_account_across_instructions_merges_writable() {
        // Same account readonly in one ix, writable in another → merged
        // to writable, appears once.
        let payer = pk(1);
        let shared = pk(2);
        let prog = pk(9);
        let ix_ro = Instruction {
            program_id: prog,
            accounts: vec![AccountMeta::readonly(shared)],
            data: vec![],
        };
        let ix_w = Instruction {
            program_id: prog,
            accounts: vec![AccountMeta::writable(shared)],
            data: vec![],
        };
        let msg = Message::new_legacy(&payer, [0; 32], &[ix_ro, ix_w]).expect("compile");
        // payer(ws), shared(w), prog(ro) — shared appears once, writable.
        assert_eq!(msg.account_keys, vec![payer, shared, prog]);
        assert_eq!(msg.num_required_signatures, 1);
        assert_eq!(msg.num_readonly_unsigned, 1); // only the program
    }
}
