//! Squads V4 multisig instruction + PDA encoders (Phase 4.5 S3).
//!
//! Byte-exact hand-rolled encoders for the redemption hot path, plus the
//! one-time `multisig_create_v2` bootstrap. The account orderings and
//! argument layouts are pinned from the Squads V4 program IDL + source
//! (`programs/squads_multisig_program`, program id
//! `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`):
//!
//! - **Discriminator** = `sha256("global:<instruction_name>")[..8]`
//!   (Anchor's global-namespace scheme).
//! - **Args** = Anchor/Borsh: `u8`/`u16`/`u32`/`u64` little-endian; `Vec`
//!   and `String` prefixed by a 4-byte LE length; `Option` by a 1-byte tag.
//! - **Inner `transaction_message`** = the Squads compact `TransactionMessage`
//!   with `SmallVec<u8>` length prefixes (account keys, instructions,
//!   lookups, per-ix account indexes) and a `SmallVec<u16>` (LE) prefix on
//!   per-ix data — NOT Anchor's 4-byte Vec prefix.
//!
//! ## Mainnet gate (P-SOL-1)
//!
//! These layouts are reconstructed, not taken from a thornode reference
//! (`THORChain`'s Solana client is single-sign / TSS). Before any SOL
//! mainnet funds, a full byte-match of each instruction against the
//! `@sqds/multisig` JS SDK on devnet is required (the Solana analogue of
//! the gaiad / rippled byte-match gates).

use sha2::{Digest, Sha256};

use crate::message::{AccountMeta, Instruction, Message};
use crate::pda::find_program_address;
use crate::{Pubkey, SolanaTxError};

/// Squads V4 program id (`SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`).
pub const SQUADS_PROGRAM_ID: Pubkey = Pubkey::new([
    6, 129, 196, 206, 71, 226, 35, 104, 184, 177, 85, 94, 200, 135, 175, 9, 46, 252, 126, 251, 182,
    108, 163, 245, 47, 191, 104, 212, 172, 156, 183, 168,
]);

/// SPL Memo program v2 id (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`).
pub const MEMO_PROGRAM_ID: Pubkey = Pubkey::new([
    5, 74, 83, 90, 153, 41, 33, 6, 77, 36, 232, 113, 96, 218, 56, 124, 124, 53, 181, 221, 188, 146,
    187, 129, 228, 31, 168, 64, 65, 5, 68, 141,
]);

// Squads PDA seed constants.
const SEED_PREFIX: &[u8] = b"multisig";
const SEED_MULTISIG: &[u8] = b"multisig";
const SEED_VAULT: &[u8] = b"vault";
const SEED_TRANSACTION: &[u8] = b"transaction";
const SEED_PROPOSAL: &[u8] = b"proposal";
const SEED_PROGRAM_CONFIG: &[u8] = b"program_config";

/// The full member permission mask: `Initiate | Vote | Execute` (0b111).
pub const PERMISSION_ALL: u8 = 0b0000_0111;

// ─── PDA derivations ─────────────────────────────────────────────────────

/// Multisig account PDA from its `create_key`.
///
/// # Errors
/// [`SolanaTxError::PdaNotFound`] if no bump yields an off-curve address.
pub fn multisig_pda(create_key: &Pubkey) -> Result<(Pubkey, u8), SolanaTxError> {
    find_program_address(
        &[SEED_PREFIX, SEED_MULTISIG, create_key.as_bytes()],
        &SQUADS_PROGRAM_ID,
    )
}

/// Vault PDA for `(multisig, vault_index)`. Xindex always uses index 0.
///
/// # Errors
/// [`SolanaTxError::PdaNotFound`] if no bump yields an off-curve address.
pub fn vault_pda(multisig: &Pubkey, vault_index: u8) -> Result<(Pubkey, u8), SolanaTxError> {
    find_program_address(
        &[SEED_PREFIX, multisig.as_bytes(), SEED_VAULT, &[vault_index]],
        &SQUADS_PROGRAM_ID,
    )
}

/// `VaultTransaction` PDA for `(multisig, transaction_index)`.
///
/// # Errors
/// [`SolanaTxError::PdaNotFound`] if no bump yields an off-curve address.
pub fn transaction_pda(
    multisig: &Pubkey,
    transaction_index: u64,
) -> Result<(Pubkey, u8), SolanaTxError> {
    find_program_address(
        &[
            SEED_PREFIX,
            multisig.as_bytes(),
            SEED_TRANSACTION,
            &transaction_index.to_le_bytes(),
        ],
        &SQUADS_PROGRAM_ID,
    )
}

/// `Proposal` PDA for `(multisig, transaction_index)`.
///
/// # Errors
/// [`SolanaTxError::PdaNotFound`] if no bump yields an off-curve address.
pub fn proposal_pda(
    multisig: &Pubkey,
    transaction_index: u64,
) -> Result<(Pubkey, u8), SolanaTxError> {
    find_program_address(
        &[
            SEED_PREFIX,
            multisig.as_bytes(),
            SEED_TRANSACTION,
            &transaction_index.to_le_bytes(),
            SEED_PROPOSAL,
        ],
        &SQUADS_PROGRAM_ID,
    )
}

/// Program-config PDA (holds the treasury for `multisig_create_v2`).
///
/// # Errors
/// [`SolanaTxError::PdaNotFound`] if no bump yields an off-curve address.
pub fn program_config_pda() -> Result<(Pubkey, u8), SolanaTxError> {
    find_program_address(&[SEED_PREFIX, SEED_PROGRAM_CONFIG], &SQUADS_PROGRAM_ID)
}

// ─── Anchor / Borsh primitives ───────────────────────────────────────────

/// Anchor global-namespace instruction discriminator.
#[must_use]
pub fn discriminator(instruction_name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{instruction_name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

/// Append an Anchor `Option<String>`: 1-byte tag, then 4-byte LE length +
/// UTF-8 bytes when `Some`.
fn put_option_string(memo: Option<&str>, out: &mut Vec<u8>) {
    match memo {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
    }
}

/// Append an Anchor `Option<Pubkey>`: 1-byte tag, then 32 bytes when `Some`.
fn put_option_pubkey(key: Option<&Pubkey>, out: &mut Vec<u8>) {
    match key {
        None => out.push(0),
        Some(k) => {
            out.push(1);
            out.extend_from_slice(k.as_bytes());
        }
    }
}

/// Append an Anchor `bytes` / `Vec<u8>`: 4-byte LE length + bytes.
fn put_anchor_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

// ─── Inner Squads `TransactionMessage` (SmallVec compact form) ────────────

/// The compiled inner message: its `SmallVec` `TransactionMessage` bytes
/// (the `transaction_message` arg of `vault_transaction_create`) plus the
/// account metas to pass as `vault_transaction_execute` remaining accounts
/// (in `account_keys` order, all non-signers — the program signs for the
/// vault via `invoke_signed`).
#[derive(Debug, Clone)]
pub struct InnerMessage {
    /// The `SmallVec` `TransactionMessage` bytes.
    pub bytes: Vec<u8>,
    /// Remaining accounts for the execute instruction (account-keys order).
    pub remaining_accounts: Vec<AccountMeta>,
}

/// Compile the inner redemption message: a single native-SOL System
/// transfer `vault → destination` of `lamports`, plus an optional SPL-Memo
/// instruction. The vault PDA is the (only) inner signer.
///
/// # Errors
/// Propagates [`Message::new_legacy`] compilation errors.
pub fn compile_redemption_inner_message(
    vault: &Pubkey,
    destination: &Pubkey,
    lamports: u64,
    memo: Option<&str>,
) -> Result<InnerMessage, SolanaTxError> {
    let mut instructions = vec![crate::message::system_transfer(
        *vault,
        *destination,
        lamports,
    )];
    if let Some(m) = memo {
        instructions.push(Instruction {
            program_id: MEMO_PROGRAM_ID,
            accounts: vec![],
            data: m.as_bytes().to_vec(),
        });
    }
    // The vault is the fee payer / sole signer of the inner message.
    let msg = Message::new_legacy(vault, [0u8; 32], &instructions)?;
    let bytes = encode_transaction_message(&msg)?;

    let total = msg.account_keys.len();
    let num_signers = usize::from(msg.num_required_signatures);
    let num_writable_signers = num_signers - usize::from(msg.num_readonly_signed);
    let num_writable_non_signers = (total - num_signers) - usize::from(msg.num_readonly_unsigned);
    let remaining_accounts = msg
        .account_keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let writable = i < num_writable_signers
                || (i >= num_signers && i < num_signers + num_writable_non_signers);
            AccountMeta {
                pubkey: *key,
                is_signer: false,
                is_writable: writable,
            }
        })
        .collect();

    Ok(InnerMessage {
        bytes,
        remaining_accounts,
    })
}

/// Append a `SmallVec<u8, _>` length (1 byte).
fn put_smallvec_u8_len(len: usize, out: &mut Vec<u8>) -> Result<(), SolanaTxError> {
    let len = u8::try_from(len).map_err(|_| SolanaTxError::ShortVecOverflow(len))?;
    out.push(len);
    Ok(())
}

/// Append a `SmallVec<u16, _>` length (2 bytes LE).
fn put_smallvec_u16_len(len: usize, out: &mut Vec<u8>) -> Result<(), SolanaTxError> {
    let len = u16::try_from(len).map_err(|_| SolanaTxError::ShortVecOverflow(len))?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

/// Encode a compiled [`Message`] as the Squads `TransactionMessage` wire
/// form (header + `SmallVec` account keys / instructions, empty address
/// table lookups). The blockhash is intentionally dropped — the inner
/// message carries no lifetime of its own.
fn encode_transaction_message(msg: &Message) -> Result<Vec<u8>, SolanaTxError> {
    let total = msg.account_keys.len();
    let num_signers = msg.num_required_signatures;
    let num_writable_signers = num_signers - msg.num_readonly_signed;
    let num_writable_non_signers = u8::try_from(total)
        .map_err(|_| SolanaTxError::TooManyAccounts(total))?
        - num_signers
        - msg.num_readonly_unsigned;

    let mut out = Vec::new();
    out.push(num_signers);
    out.push(num_writable_signers);
    out.push(num_writable_non_signers);

    put_smallvec_u8_len(msg.account_keys.len(), &mut out)?;
    for key in &msg.account_keys {
        out.extend_from_slice(key.as_bytes());
    }

    put_smallvec_u8_len(msg.instructions.len(), &mut out)?;
    for ix in &msg.instructions {
        out.push(ix.program_id_index);
        put_smallvec_u8_len(ix.account_indices.len(), &mut out)?;
        out.extend_from_slice(&ix.account_indices);
        put_smallvec_u16_len(ix.data.len(), &mut out)?;
        out.extend_from_slice(&ix.data);
    }

    // address_table_lookups: SmallVec<u8> — always empty (no ALTs).
    out.push(0);
    Ok(out)
}

// ─── Instruction builders ────────────────────────────────────────────────

/// `system_program` id (32 zero bytes) — the readonly account every Squads
/// create/propose instruction appends.
fn system_program() -> Pubkey {
    Pubkey::system_program()
}

/// `vault_transaction_create` parameters (8 inputs — bundled to stay within
/// the positional-argument limit).
#[derive(Debug, Clone)]
pub struct VaultTransactionCreate<'a> {
    /// The multisig account (writable — its `transaction_index` increments).
    pub multisig: Pubkey,
    /// The `VaultTransaction` PDA being created (writable).
    pub transaction: Pubkey,
    /// The proposing member (readonly signer).
    pub creator: Pubkey,
    /// The rent payer / fee payer (writable signer).
    pub rent_payer: Pubkey,
    /// Vault index (always 0 for Xindex).
    pub vault_index: u8,
    /// Ephemeral signer count (always 0 for Xindex).
    pub ephemeral_signers: u8,
    /// The inner `TransactionMessage` bytes (from
    /// [`compile_redemption_inner_message`]).
    pub transaction_message: &'a [u8],
    /// Optional on-chain memo.
    pub memo: Option<&'a str>,
}

impl VaultTransactionCreate<'_> {
    /// Build the instruction.
    #[must_use]
    pub fn instruction(&self) -> Instruction {
        let mut data = discriminator("vault_transaction_create").to_vec();
        data.push(self.vault_index);
        data.push(self.ephemeral_signers);
        put_anchor_bytes(self.transaction_message, &mut data);
        put_option_string(self.memo, &mut data);
        Instruction {
            program_id: SQUADS_PROGRAM_ID,
            accounts: vec![
                AccountMeta::writable(self.multisig),
                AccountMeta::writable(self.transaction),
                AccountMeta::readonly_signer(self.creator),
                AccountMeta::writable_signer(self.rent_payer),
                AccountMeta::readonly(system_program()),
            ],
            data,
        }
    }
}

/// `proposal_create` parameters.
#[derive(Debug, Clone)]
pub struct ProposalCreate {
    /// The multisig account (readonly).
    pub multisig: Pubkey,
    /// The `Proposal` PDA being created (writable).
    pub proposal: Pubkey,
    /// The proposing member (readonly signer).
    pub creator: Pubkey,
    /// The rent payer / fee payer (writable signer).
    pub rent_payer: Pubkey,
    /// The transaction index this proposal is bound to.
    pub transaction_index: u64,
    /// Whether to create the proposal in the `Draft` state (false = `Active`).
    pub draft: bool,
}

impl ProposalCreate {
    /// Build the instruction.
    #[must_use]
    pub fn instruction(&self) -> Instruction {
        let mut data = discriminator("proposal_create").to_vec();
        data.extend_from_slice(&self.transaction_index.to_le_bytes());
        data.push(u8::from(self.draft));
        Instruction {
            program_id: SQUADS_PROGRAM_ID,
            accounts: vec![
                AccountMeta::readonly(self.multisig),
                AccountMeta::writable(self.proposal),
                AccountMeta::readonly_signer(self.creator),
                AccountMeta::writable_signer(self.rent_payer),
                AccountMeta::readonly(system_program()),
            ],
            data,
        }
    }
}

/// `proposal_approve`: `member` casts an approval on `proposal`.
#[must_use]
pub fn proposal_approve_ix(
    multisig: Pubkey,
    member: Pubkey,
    proposal: Pubkey,
    memo: Option<&str>,
) -> Instruction {
    let mut data = discriminator("proposal_approve").to_vec();
    put_option_string(memo, &mut data);
    Instruction {
        program_id: SQUADS_PROGRAM_ID,
        accounts: vec![
            AccountMeta::readonly(multisig),
            AccountMeta::writable_signer(member),
            AccountMeta::writable(proposal),
        ],
        data,
    }
}

/// `vault_transaction_execute`: `member` executes the approved proposal.
/// `remaining` is the inner message's account metas (from
/// [`InnerMessage::remaining_accounts`]).
#[must_use]
pub fn vault_transaction_execute_ix(
    multisig: Pubkey,
    proposal: Pubkey,
    transaction: Pubkey,
    member: Pubkey,
    remaining: &[AccountMeta],
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::readonly(multisig),
        AccountMeta::writable(proposal),
        AccountMeta::readonly(transaction),
        AccountMeta::readonly_signer(member),
    ];
    accounts.extend_from_slice(remaining);
    Instruction {
        program_id: SQUADS_PROGRAM_ID,
        accounts,
        data: discriminator("vault_transaction_execute").to_vec(),
    }
}

/// One member of a multisig being created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// The member's ed25519 public key.
    pub key: Pubkey,
    /// The permission mask ([`PERMISSION_ALL`] for Xindex).
    pub permissions: u8,
}

/// `multisig_create_v2` parameters (one-time bootstrap, run at the key
/// ceremony — see `docs/runbooks/solana-key-ceremony.md`).
#[derive(Debug, Clone)]
pub struct MultisigCreateV2<'a> {
    /// Program-config PDA (readonly).
    pub program_config: Pubkey,
    /// Treasury (writable) — read from the program-config account.
    pub treasury: Pubkey,
    /// The multisig PDA being created (writable).
    pub multisig: Pubkey,
    /// The one-time `create_key` (readonly signer).
    pub create_key: Pubkey,
    /// The creator / fee payer (writable signer).
    pub creator: Pubkey,
    /// Optional config authority (`None` = controlled-by-members).
    pub config_authority: Option<Pubkey>,
    /// Approval threshold.
    pub threshold: u16,
    /// The frozen member set.
    pub members: &'a [Member],
    /// Time lock (always 0 for Xindex).
    pub time_lock: u32,
    /// Optional rent collector.
    pub rent_collector: Option<Pubkey>,
    /// Optional memo.
    pub memo: Option<&'a str>,
}

impl MultisigCreateV2<'_> {
    /// Build the instruction.
    #[must_use]
    pub fn instruction(&self) -> Instruction {
        let mut data = discriminator("multisig_create_v2").to_vec();
        put_option_pubkey(self.config_authority.as_ref(), &mut data);
        data.extend_from_slice(&self.threshold.to_le_bytes());
        let members_len = u32::try_from(self.members.len()).unwrap_or(u32::MAX);
        data.extend_from_slice(&members_len.to_le_bytes());
        for m in self.members {
            data.extend_from_slice(m.key.as_bytes());
            data.push(m.permissions);
        }
        data.extend_from_slice(&self.time_lock.to_le_bytes());
        put_option_pubkey(self.rent_collector.as_ref(), &mut data);
        put_option_string(self.memo, &mut data);
        Instruction {
            program_id: SQUADS_PROGRAM_ID,
            accounts: vec![
                AccountMeta::readonly(self.program_config),
                AccountMeta::writable(self.treasury),
                AccountMeta::writable(self.multisig),
                AccountMeta::readonly_signer(self.create_key),
                AccountMeta::writable_signer(self.creator),
                AccountMeta::readonly(system_program()),
            ],
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new([byte; 32])
    }

    #[test]
    fn discriminators_match_anchor_global_scheme() {
        // sha256("global:<name>")[..8] — independent vectors.
        assert_eq!(
            discriminator("vault_transaction_create"),
            [48, 250, 78, 168, 208, 226, 218, 211]
        );
        assert_eq!(
            discriminator("proposal_create"),
            [220, 60, 73, 224, 30, 108, 79, 159]
        );
        assert_eq!(
            discriminator("proposal_approve"),
            [144, 37, 164, 136, 188, 216, 42, 248]
        );
        assert_eq!(
            discriminator("vault_transaction_execute"),
            [194, 8, 161, 87, 153, 164, 25, 171]
        );
        assert_eq!(
            discriminator("multisig_create_v2"),
            [50, 221, 199, 93, 40, 245, 139, 233]
        );
    }

    #[test]
    fn program_ids_decode_to_expected_base58() {
        assert_eq!(
            SQUADS_PROGRAM_ID.to_base58(),
            "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
        );
        assert_eq!(
            MEMO_PROGRAM_ID.to_base58(),
            "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn pdas_are_off_curve() {
        let ms = pk(0x42);
        assert!(multisig_pda(&pk(0x01)).is_ok());
        assert!(vault_pda(&ms, 0).is_ok());
        assert!(transaction_pda(&ms, 1).is_ok());
        assert!(proposal_pda(&ms, 1).is_ok());
        // Distinct derivations give distinct addresses.
        let (vault, _) = vault_pda(&ms, 0).expect("vault");
        let (txp, _) = transaction_pda(&ms, 1).expect("tx");
        let (prop, _) = proposal_pda(&ms, 1).expect("proposal");
        assert_ne!(vault, txp);
        assert_ne!(txp, prop);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn inner_redemption_message_byte_exact() {
        let vault = pk(0x11);
        let dest = pk(0x22);
        let inner = compile_redemption_inner_message(&vault, &dest, 1000, Some("hi"))
            .expect("compile inner");

        // Header: num_signers=1, num_writable_signers=1, num_writable_non_signers=1.
        // account_keys = [vault, dest, system, memo]; system at idx 2, memo at idx 3.
        let mut exp = vec![1u8, 1, 1, 4];
        exp.extend_from_slice(&[0x11; 32]);
        exp.extend_from_slice(&[0x22; 32]);
        exp.extend_from_slice(&[0x00; 32]);
        exp.extend_from_slice(MEMO_PROGRAM_ID.as_bytes());
        exp.push(2); // SmallVec<u8>: 2 instructions
                     // transfer: program idx 2; accounts [0,1]; data = [2,0,0,0] + 1000_le8.
        exp.push(2);
        exp.extend_from_slice(&[2, 0, 1]); // SmallVec<u8> account indexes
        exp.extend_from_slice(&[12, 0]); // SmallVec<u16> data len
        exp.extend_from_slice(&2u32.to_le_bytes());
        exp.extend_from_slice(&1000u64.to_le_bytes());
        // memo: program idx 3; no accounts; data = "hi".
        exp.push(3);
        exp.push(0);
        exp.extend_from_slice(&[2, 0]); // SmallVec<u16> data len
        exp.extend_from_slice(b"hi");
        exp.push(0); // address_table_lookups: empty

        assert_eq!(inner.bytes, exp);

        // Remaining accounts: [vault(w), dest(w), system(ro), memo(ro)], all
        // non-signers.
        assert_eq!(inner.remaining_accounts.len(), 4);
        assert_eq!(inner.remaining_accounts[0], AccountMeta::writable(vault));
        assert_eq!(inner.remaining_accounts[1], AccountMeta::writable(dest));
        assert_eq!(
            inner.remaining_accounts[2],
            AccountMeta::readonly(Pubkey::system_program())
        );
        assert_eq!(
            inner.remaining_accounts[3],
            AccountMeta::readonly(MEMO_PROGRAM_ID)
        );
    }

    #[test]
    fn vault_transaction_create_accounts_and_disc() {
        let ix = VaultTransactionCreate {
            multisig: pk(1),
            transaction: pk(2),
            creator: pk(3),
            rent_payer: pk(4),
            vault_index: 0,
            ephemeral_signers: 0,
            transaction_message: &[0xAB, 0xCD],
            memo: None,
        }
        .instruction();
        assert_eq!(ix.program_id, SQUADS_PROGRAM_ID);
        assert_eq!(&ix.data[..8], &discriminator("vault_transaction_create"));
        // vault_index, ephemeral_signers, then 4-byte len + the 2 bytes, then memo None.
        assert_eq!(&ix.data[8..10], &[0, 0]);
        assert_eq!(&ix.data[10..14], &2u32.to_le_bytes());
        assert_eq!(&ix.data[14..16], &[0xAB, 0xCD]);
        assert_eq!(ix.data[16], 0); // memo None tag
                                    // Accounts: multisig(w), transaction(w), creator(ro,signer),
                                    // rent_payer(w,signer), system(ro).
        assert_eq!(ix.accounts[0], AccountMeta::writable(pk(1)));
        assert_eq!(ix.accounts[1], AccountMeta::writable(pk(2)));
        assert_eq!(ix.accounts[2], AccountMeta::readonly_signer(pk(3)));
        assert_eq!(ix.accounts[3], AccountMeta::writable_signer(pk(4)));
        assert_eq!(
            ix.accounts[4],
            AccountMeta::readonly(Pubkey::system_program())
        );
    }

    #[test]
    fn proposal_create_accounts_and_args() {
        let ix = ProposalCreate {
            multisig: pk(1),
            proposal: pk(2),
            creator: pk(3),
            rent_payer: pk(4),
            transaction_index: 7,
            draft: false,
        }
        .instruction();
        assert_eq!(&ix.data[..8], &discriminator("proposal_create"));
        assert_eq!(&ix.data[8..16], &7u64.to_le_bytes());
        assert_eq!(ix.data[16], 0); // draft = false
        assert_eq!(ix.accounts[0], AccountMeta::readonly(pk(1)));
        assert_eq!(ix.accounts[1], AccountMeta::writable(pk(2)));
        assert_eq!(ix.accounts[2], AccountMeta::readonly_signer(pk(3)));
        assert_eq!(ix.accounts[3], AccountMeta::writable_signer(pk(4)));
    }

    #[test]
    fn proposal_approve_accounts() {
        let ix = proposal_approve_ix(pk(1), pk(5), pk(2), None);
        assert_eq!(&ix.data[..8], &discriminator("proposal_approve"));
        assert_eq!(ix.data[8], 0); // memo None
                                   // multisig(ro), member(w,signer), proposal(w).
        assert_eq!(ix.accounts[0], AccountMeta::readonly(pk(1)));
        assert_eq!(ix.accounts[1], AccountMeta::writable_signer(pk(5)));
        assert_eq!(ix.accounts[2], AccountMeta::writable(pk(2)));
    }

    #[test]
    fn vault_transaction_execute_accounts_and_remaining() {
        let remaining = vec![
            AccountMeta::writable(pk(0x11)),
            AccountMeta::readonly(Pubkey::system_program()),
        ];
        let ix = vault_transaction_execute_ix(pk(1), pk(2), pk(3), pk(5), &remaining);
        assert_eq!(ix.data, discriminator("vault_transaction_execute").to_vec());
        // multisig(ro), proposal(w), transaction(ro), member(ro,signer), then remaining.
        assert_eq!(ix.accounts[0], AccountMeta::readonly(pk(1)));
        assert_eq!(ix.accounts[1], AccountMeta::writable(pk(2)));
        assert_eq!(ix.accounts[2], AccountMeta::readonly(pk(3)));
        assert_eq!(ix.accounts[3], AccountMeta::readonly_signer(pk(5)));
        assert_eq!(ix.accounts[4], AccountMeta::writable(pk(0x11)));
        assert_eq!(
            ix.accounts[5],
            AccountMeta::readonly(Pubkey::system_program())
        );
    }

    #[test]
    fn multisig_create_v2_member_layout() {
        let members = [
            Member {
                key: pk(0xA1),
                permissions: PERMISSION_ALL,
            },
            Member {
                key: pk(0xA2),
                permissions: PERMISSION_ALL,
            },
        ];
        let ix = MultisigCreateV2 {
            program_config: pk(1),
            treasury: pk(2),
            multisig: pk(3),
            create_key: pk(4),
            creator: pk(5),
            config_authority: None,
            threshold: 3,
            members: &members,
            time_lock: 0,
            rent_collector: None,
            memo: None,
        }
        .instruction();
        assert_eq!(&ix.data[..8], &discriminator("multisig_create_v2"));
        // config_authority None (1 byte), threshold u16 (2), members len u32 (4).
        assert_eq!(ix.data[8], 0);
        assert_eq!(&ix.data[9..11], &3u16.to_le_bytes());
        assert_eq!(&ix.data[11..15], &2u32.to_le_bytes());
        // member 0: key(32) + permission(1).
        assert_eq!(&ix.data[15..47], &[0xA1; 32]);
        assert_eq!(ix.data[47], PERMISSION_ALL);
        // Accounts: program_config(ro), treasury(w), multisig(w),
        // create_key(ro,signer), creator(w,signer), system(ro).
        assert_eq!(ix.accounts[3], AccountMeta::readonly_signer(pk(4)));
        assert_eq!(ix.accounts[4], AccountMeta::writable_signer(pk(5)));
    }
}
