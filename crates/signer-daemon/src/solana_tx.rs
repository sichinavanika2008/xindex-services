//! S6 — `POST /api/v1/sign/solana-tx` handler (Phase 4.5).
//!
//! The Solana custody-family signing endpoint — the first **ed25519**
//! family (every other family is secp256k1 via the HSM digest signer).
//!
//! ## Never blind-sign (the security core)
//!
//! The daemon does NOT sign `message_hex` blindly. It re-derives the Squads
//! PDAs from its configured multisig + the request's `transaction_index`,
//! and **rebuilds the exact Solana message** from the request's semantic
//! fields — crucially building the inner System transfer from its OWN
//! re-derived **vault PDA**. It byte-matches the rebuilt message against
//! `message_hex` and only then ed25519-signs the bytes IT rebuilt.
//! Therefore:
//!
//! - The transfer **source is always our vault** — a compromised
//!   coordinator cannot obtain a signature over a spend from any other
//!   account (the rebuilt message would diverge → `solana_tx_mismatch`).
//! - Only the Squads / System / SPL-Memo programs ever appear (the daemon
//!   only ever builds those); a foreign instruction cannot match.
//! - The fee payer / sole signer is THIS member (the daemon builds the
//!   message with `member` as the payer).
//! - A destination that is the vault / multisig / a member / a program is
//!   rejected (`solana_dest_not_permitted`).
//!
//! The deeper binding "destination == the burn event's user address" is the
//! cross-check / attestation layer's job (the same posture as the XRP /
//! Cosmos daemons, which also trust the coordinator's destination) —
//! tracked as a cross-repo follow-on (`KNOWN_FINDINGS` P-SOL-7). Replay-DB
//! keying on `(chain, multisig, transaction_index, kind, member)` is
//! P-SOL-6; the on-chain Squads program already rejects duplicate
//! create/approve/execute.
//!
//! ## HSM note (P-SOL-4)
//!
//! ed25519 is net-new to the signer stack. Until the HSM front-end supports
//! ed25519, the member key is a software seed held in [`SolSignerConfig`] —
//! the same HSM-deferred posture all families carry, made explicit here
//! because the key material is local.

use alloy_primitives::hex;
use axum::{extract::State, http::StatusCode, response::Json};
use xindex_shared::chain_registry::{ChainId, CustodyFamily};
use xindex_shared::signer_wire::{
    error_codes, ErrorBody, SolanaSignResponse, SolanaTxKind, SolanaTxSignRequest,
};
use xindex_solana_tx::message::Message;
use xindex_solana_tx::{base58, sigs, squads, Pubkey};

use crate::replay::ReplayStore;
use crate::server::DaemonState;
use crate::web3signer::HsmDigestSigner;

/// Per-chain Solana signing role. One entry per Solana chain this daemon is
/// a Squads member of (no cross-chain key sharing — DL-P3-7).
#[derive(Clone)]
pub struct SolSignerConfig {
    /// Which Solana chain this config serves.
    pub chain: ChainId,
    /// The Squads multisig PDA this daemon signs for.
    pub multisig_pda: Pubkey,
    /// The vault index (always 0 for Xindex).
    pub vault_index: u8,
    /// The full member set (to reject a transfer to any member).
    pub members: Vec<Pubkey>,
    /// This daemon's ed25519 member pubkey (returned to the coordinator).
    pub member_pubkey: Pubkey,
    /// 32-byte ed25519 secret seed (software key; HSM-deferred, P-SOL-4).
    pub member_seed: [u8; 32],
}

impl std::fmt::Debug for SolSignerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret seed.
        f.debug_struct("SolSignerConfig")
            .field("chain", &self.chain)
            .field("multisig_pda", &self.multisig_pda)
            .field("vault_index", &self.vault_index)
            .field("member_pubkey", &self.member_pubkey)
            .finish_non_exhaustive()
    }
}

type DaemonErr = (StatusCode, Json<ErrorBody>);

fn err(code: &str, status: StatusCode, message: impl Into<String>) -> DaemonErr {
    (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message: message.into(),
        }),
    )
}

fn bad(field: &str, e: impl std::fmt::Display) -> DaemonErr {
    err(
        error_codes::BAD_REQUEST,
        StatusCode::BAD_REQUEST,
        format!("{field}: {e}"),
    )
}

/// Parse the inner destination + lamports a Create / Execute request must
/// carry.
fn inner_transfer(req: &SolanaTxSignRequest) -> Result<(Pubkey, u64, Option<String>), DaemonErr> {
    let dest_s = req
        .inner_destination
        .as_deref()
        .ok_or_else(|| bad("inner_destination", "required for create/execute"))?;
    let dest = Pubkey::from_base58(dest_s).map_err(|e| bad("inner_destination", e))?;
    let lamports = req
        .inner_amount_lamports
        .as_deref()
        .ok_or_else(|| bad("inner_amount_lamports", "required for create/execute"))?
        .parse::<u64>()
        .map_err(|e| bad("inner_amount_lamports", e))?;
    let memo = req.memo.clone().filter(|m| !m.is_empty());
    Ok((dest, lamports, memo))
}

/// Re-derive the vault PDA and rebuild the exact message for the request's
/// kind. Returns the serialized bytes, the vault PDA, and the inner
/// destination (Create / Execute only).
fn rebuild_message(
    req: &SolanaTxSignRequest,
    config: &SolSignerConfig,
) -> Result<(Vec<u8>, Pubkey, Option<Pubkey>), DaemonErr> {
    let transaction_index = req
        .transaction_index
        .parse::<u64>()
        .map_err(|e| bad("transaction_index", e))?;
    let blockhash =
        base58::decode_32(&req.recent_blockhash).map_err(|e| bad("recent_blockhash", e))?;
    let member = config.member_pubkey;
    let (vault, _) = squads::vault_pda(&config.multisig_pda, config.vault_index)
        .map_err(|e| bad("vault_pda", e))?;
    let (transaction, _) = squads::transaction_pda(&config.multisig_pda, transaction_index)
        .map_err(|e| bad("transaction_pda", e))?;
    let (proposal, _) = squads::proposal_pda(&config.multisig_pda, transaction_index)
        .map_err(|e| bad("proposal_pda", e))?;

    let (bytes, dest) = match req.tx_kind {
        SolanaTxKind::Create => {
            let (dest, lamports, memo) = inner_transfer(req)?;
            if req.vault_index != Some(config.vault_index) {
                return Err(err(
                    error_codes::SOLANA_NOT_OUR_VAULT,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "vault_index does not match the configured vault",
                ));
            }
            let inner =
                squads::compile_redemption_inner_message(&vault, &dest, lamports, memo.as_deref())
                    .map_err(|e| bad("inner_message", e))?;
            let create_ix = squads::VaultTransactionCreate {
                multisig: config.multisig_pda,
                transaction,
                creator: member,
                rent_payer: member,
                vault_index: config.vault_index,
                ephemeral_signers: 0,
                transaction_message: &inner.bytes,
                memo: memo.as_deref(),
            }
            .instruction();
            let propose_ix = squads::ProposalCreate {
                multisig: config.multisig_pda,
                proposal,
                creator: member,
                rent_payer: member,
                transaction_index,
                draft: false,
            }
            .instruction();
            let msg = Message::new_legacy(&member, blockhash, &[create_ix, propose_ix])
                .map_err(|e| bad("message", e))?;
            (
                msg.serialize().map_err(|e| bad("serialize", e))?,
                Some(dest),
            )
        }
        SolanaTxKind::Approve => {
            let ix = squads::proposal_approve_ix(config.multisig_pda, member, proposal, None);
            let msg =
                Message::new_legacy(&member, blockhash, &[ix]).map_err(|e| bad("message", e))?;
            (msg.serialize().map_err(|e| bad("serialize", e))?, None)
        }
        SolanaTxKind::Execute => {
            let (dest, lamports, memo) = inner_transfer(req)?;
            let inner =
                squads::compile_redemption_inner_message(&vault, &dest, lamports, memo.as_deref())
                    .map_err(|e| bad("inner_message", e))?;
            let ix = squads::vault_transaction_execute_ix(
                config.multisig_pda,
                proposal,
                transaction,
                member,
                &inner.remaining_accounts,
            );
            let msg =
                Message::new_legacy(&member, blockhash, &[ix]).map_err(|e| bad("message", e))?;
            (
                msg.serialize().map_err(|e| bad("serialize", e))?,
                Some(dest),
            )
        }
    };
    Ok((bytes, vault, dest))
}

/// Validate the request against the daemon's config and ed25519-sign the
/// rebuilt message. Pure (no IO) — the security core.
///
/// # Errors
/// A `(StatusCode, ErrorBody)` with one of the `solana_*` error codes.
pub fn validate_and_sign(
    req: &SolanaTxSignRequest,
    config: &SolSignerConfig,
) -> Result<SolanaSignResponse, DaemonErr> {
    if req.chain_id.custody_family() != CustodyFamily::Solana || req.chain_id != config.chain {
        return Err(err(
            error_codes::NON_SOLANA_CHAIN,
            StatusCode::UNPROCESSABLE_ENTITY,
            "chain is not this daemon's Solana chain",
        ));
    }
    if req.multisig_pda != config.multisig_pda.to_base58() {
        return Err(err(
            error_codes::WRONG_SOLANA_MULTISIG,
            StatusCode::UNPROCESSABLE_ENTITY,
            "multisig_pda does not match the configured multisig",
        ));
    }
    if req.member_pubkey != config.member_pubkey.to_base58() {
        return Err(err(
            error_codes::WRONG_SOLANA_MEMBER,
            StatusCode::UNPROCESSABLE_ENTITY,
            "member_pubkey is not this daemon's member key",
        ));
    }

    let (rebuilt, vault, inner_dest) = rebuild_message(req, config)?;

    let claimed_hex = req
        .message_hex
        .strip_prefix("0x")
        .unwrap_or(&req.message_hex);
    let claimed = hex::decode(claimed_hex).map_err(|e| bad("message_hex", e))?;
    if rebuilt != claimed {
        return Err(err(
            error_codes::SOLANA_TX_MISMATCH,
            StatusCode::UNPROCESSABLE_ENTITY,
            "rebuilt message does not byte-match message_hex",
        ));
    }

    // Destination sanity (Create / Execute): never the vault, the multisig,
    // a member, or a program.
    if let Some(dest) = inner_dest {
        let forbidden = dest == vault
            || dest == config.multisig_pda
            || dest == Pubkey::system_program()
            || dest == squads::SQUADS_PROGRAM_ID
            || dest == squads::MEMO_PROGRAM_ID
            || config.members.contains(&dest);
        if forbidden {
            return Err(err(
                error_codes::SOLANA_DEST_NOT_PERMITTED,
                StatusCode::UNPROCESSABLE_ENTITY,
                "destination is the vault / multisig / a member / a program",
            ));
        }
    }

    let signature = sigs::sign(&config.member_seed, &rebuilt);
    // Defence: the seed must produce the configured pubkey (catches a
    // config seed/pubkey mismatch before returning a useless signature).
    sigs::verify(&config.member_pubkey, &rebuilt, &signature).map_err(|e| {
        err(
            error_codes::WRONG_SOLANA_MEMBER,
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("configured seed does not match member pubkey: {e}"),
        )
    })?;

    Ok(SolanaSignResponse {
        pubkey: config.member_pubkey.to_base58(),
        signature: format!("0x{}", hex::encode(signature)),
    })
}

/// `POST /api/v1/sign/solana-tx`.
///
/// # Errors
/// A `(StatusCode, ErrorBody)`: `404 endpoint_disabled` if no Solana key is
/// configured for the request's chain, else a `solana_*` validation error
/// from [`validate_and_sign`].
pub async fn handle_solana_tx<S, H>(
    State(state): State<DaemonState<S, H>>,
    Json(req): Json<SolanaTxSignRequest>,
) -> Result<Json<SolanaSignResponse>, DaemonErr>
where
    S: ReplayStore + 'static,
    H: HsmDigestSigner + 'static,
{
    let config = state.sol.get(&req.chain_id).ok_or_else(|| {
        err(
            error_codes::ENDPOINT_DISABLED,
            StatusCode::NOT_FOUND,
            "no Solana signing key configured for this chain",
        )
    })?;
    Ok(Json(validate_and_sign(&req, config)?))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, clippy::unwrap_used, reason = "test code")]
    use super::*;

    fn cfg(member_seed: [u8; 32]) -> SolSignerConfig {
        let member_pubkey = sigs::pubkey_from_seed(&member_seed);
        let members = vec![
            member_pubkey,
            sigs::pubkey_from_seed(&[20; 32]),
            sigs::pubkey_from_seed(&[21; 32]),
        ];
        SolSignerConfig {
            chain: ChainId::Sol,
            multisig_pda: Pubkey::new([0x42; 32]),
            vault_index: 0,
            members,
            member_pubkey,
            member_seed,
        }
    }

    /// Build a faithful request for `kind` (mirrors the executor) so
    /// `validate_and_sign` rebuilds an identical message.
    fn request(config: &SolSignerConfig, kind: SolanaTxKind, dest: Pubkey) -> SolanaTxSignRequest {
        let transaction_index = 11u64;
        let blockhash = [7u8; 32];
        let member = config.member_pubkey;
        let (vault, _) =
            squads::vault_pda(&config.multisig_pda, config.vault_index).expect("vault");
        let (transaction, _) =
            squads::transaction_pda(&config.multisig_pda, transaction_index).expect("tx");
        let (proposal, _) =
            squads::proposal_pda(&config.multisig_pda, transaction_index).expect("prop");
        let lamports = 2_000_000_000u64;
        let memo = Some("=:ETH.USDT:0xabc:1".to_string());
        let inner =
            squads::compile_redemption_inner_message(&vault, &dest, lamports, memo.as_deref())
                .expect("inner");
        let msg = match kind {
            SolanaTxKind::Create => {
                let create_ix = squads::VaultTransactionCreate {
                    multisig: config.multisig_pda,
                    transaction,
                    creator: member,
                    rent_payer: member,
                    vault_index: config.vault_index,
                    ephemeral_signers: 0,
                    transaction_message: &inner.bytes,
                    memo: memo.as_deref(),
                }
                .instruction();
                let propose_ix = squads::ProposalCreate {
                    multisig: config.multisig_pda,
                    proposal,
                    creator: member,
                    rent_payer: member,
                    transaction_index,
                    draft: false,
                }
                .instruction();
                Message::new_legacy(&member, blockhash, &[create_ix, propose_ix]).expect("msg")
            }
            SolanaTxKind::Approve => {
                let ix = squads::proposal_approve_ix(config.multisig_pda, member, proposal, None);
                Message::new_legacy(&member, blockhash, &[ix]).expect("msg")
            }
            SolanaTxKind::Execute => {
                let ix = squads::vault_transaction_execute_ix(
                    config.multisig_pda,
                    proposal,
                    transaction,
                    member,
                    &inner.remaining_accounts,
                );
                Message::new_legacy(&member, blockhash, &[ix]).expect("msg")
            }
        };
        let include_inner = matches!(kind, SolanaTxKind::Create | SolanaTxKind::Execute);
        SolanaTxSignRequest {
            chain_id: ChainId::Sol,
            tx_kind: kind,
            multisig_pda: config.multisig_pda.to_base58(),
            member_pubkey: member.to_base58(),
            transaction_index: transaction_index.to_string(),
            recent_blockhash: base58::encode(&blockhash),
            vault_index: include_inner.then_some(config.vault_index),
            inner_destination: include_inner.then(|| dest.to_base58()),
            inner_amount_lamports: include_inner.then(|| lamports.to_string()),
            memo: if include_inner { memo } else { None },
            message_hex: format!("0x{}", hex::encode(msg.serialize().expect("ser"))),
        }
    }

    #[test]
    fn signs_valid_create_approve_execute() {
        let config = cfg([5; 32]);
        let dest = Pubkey::new([0x99; 32]);
        for kind in [
            SolanaTxKind::Create,
            SolanaTxKind::Approve,
            SolanaTxKind::Execute,
        ] {
            let req = request(&config, kind, dest);
            let resp = validate_and_sign(&req, &config).expect("sign");
            assert_eq!(resp.pubkey, config.member_pubkey.to_base58());
            // The returned signature verifies under the member pubkey.
            let sig_hex = resp.signature.strip_prefix("0x").expect("0x");
            let sig: [u8; 64] = hex::decode(sig_hex).expect("hex").try_into().expect("64");
            let bytes = hex::decode(req.message_hex.strip_prefix("0x").expect("0x")).expect("hex");
            sigs::verify(&config.member_pubkey, &bytes, &sig).expect("verifies");
        }
    }

    #[test]
    fn rejects_wrong_multisig() {
        let config = cfg([5; 32]);
        let mut req = request(&config, SolanaTxKind::Approve, Pubkey::new([0x99; 32]));
        req.multisig_pda = Pubkey::new([0x43; 32]).to_base58();
        let (status, body) = validate_and_sign(&req, &config).expect_err("reject");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.0.code, error_codes::WRONG_SOLANA_MULTISIG);
    }

    #[test]
    fn rejects_wrong_member() {
        let config = cfg([5; 32]);
        let mut req = request(&config, SolanaTxKind::Approve, Pubkey::new([0x99; 32]));
        req.member_pubkey = sigs::pubkey_from_seed(&[99; 32]).to_base58();
        let (_status, body) = validate_and_sign(&req, &config).expect_err("reject");
        assert_eq!(body.0.code, error_codes::WRONG_SOLANA_MEMBER);
    }

    #[test]
    fn rejects_tampered_message_hex() {
        let config = cfg([5; 32]);
        let mut req = request(&config, SolanaTxKind::Create, Pubkey::new([0x99; 32]));
        // Flip a byte in the claimed message — rebuild won't match.
        let mut bytes = hex::decode(req.message_hex.strip_prefix("0x").unwrap()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        req.message_hex = format!("0x{}", hex::encode(&bytes));
        let (_status, body) = validate_and_sign(&req, &config).expect_err("reject");
        assert_eq!(body.0.code, error_codes::SOLANA_TX_MISMATCH);
    }

    #[test]
    fn rejects_inner_destination_diverging_from_message() {
        // Claim a different inner_destination than the one baked into
        // message_hex → the daemon rebuilds to the claimed dest, which no
        // longer matches message_hex.
        let config = cfg([5; 32]);
        let mut req = request(&config, SolanaTxKind::Create, Pubkey::new([0x99; 32]));
        req.inner_destination = Some(Pubkey::new([0x77; 32]).to_base58());
        let (_status, body) = validate_and_sign(&req, &config).expect_err("reject");
        assert_eq!(body.0.code, error_codes::SOLANA_TX_MISMATCH);
    }

    #[test]
    fn rejects_destination_equal_to_a_member() {
        // A request whose message_hex genuinely pays a MEMBER is refused by
        // the destination sanity guard.
        let config = cfg([5; 32]);
        let member_dest = config.members[1];
        let req = request(&config, SolanaTxKind::Create, member_dest);
        let (_status, body) = validate_and_sign(&req, &config).expect_err("reject");
        assert_eq!(body.0.code, error_codes::SOLANA_DEST_NOT_PERMITTED);
    }

    #[test]
    fn rejects_destination_equal_to_vault() {
        let config = cfg([5; 32]);
        let (vault, _) = squads::vault_pda(&config.multisig_pda, 0).unwrap();
        let req = request(&config, SolanaTxKind::Execute, vault);
        let (_status, body) = validate_and_sign(&req, &config).expect_err("reject");
        assert_eq!(body.0.code, error_codes::SOLANA_DEST_NOT_PERMITTED);
    }
}
