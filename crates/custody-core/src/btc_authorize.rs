//! Shared BTC/UTXO certificate authorization with a durable-consumption receipt.
//!
//! Both provider callbacks and direct custody coordinators use this exact
//! `validate -> bind -> consume` implementation. Keeping it in custody-core
//! prevents a BTC-only provider client from depending on every family adapter
//! in `xindex-custody-node`.

use alloy_primitives::{Address, B256};
use bitcoin::hashes::Hash as _;

use xindex_shared::chain_registry::ChainId;

use crate::btc_bind::bind_outputs_to_cert;
use crate::gates::{
    consume_spend_certificate, validate_spend_certificate, ConsumeKey, CustodyConfig, GateRejection,
};
use crate::prepare::BindContext;
use crate::replay::ReplayStore;

/// The independently verified certificate identity bound to one authorized
/// UTXO transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtcCertificateSubject {
    /// A redemption-intent certificate keyed by redemption and leg.
    Redemption {
        /// Certified redemption identifier.
        redemption_id: B256,
        /// Certified basket leg index.
        leg_index: u32,
    },
    /// An acquire-cancel certificate keyed by cancellation.
    AcquireCancel {
        /// Certified cancellation identifier.
        cancel_id: B256,
        /// Certified acquisition intent identifier.
        intent_id: B256,
        /// Certified async slot index.
        slot_index: u32,
    },
}

/// Receipt returned only after the exact PSBT passes certificate verification,
/// output binding, and durable one-shot consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcSpendAuthorization {
    chain: ChainId,
    subject: BtcCertificateSubject,
    certificate_digest: B256,
    spend_txid: [u8; 32],
    valid_until_unix: u64,
    verified_signers: Vec<Address>,
}

impl BtcSpendAuthorization {
    /// Native chain whose replay namespace was consumed.
    #[must_use]
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Verified certificate identity.
    #[must_use]
    pub const fn subject(&self) -> &BtcCertificateSubject {
        &self.subject
    }

    /// Recomputed EIP-712 certificate digest.
    #[must_use]
    pub const fn certificate_digest(&self) -> B256 {
        self.certificate_digest
    }

    /// Unsigned transaction ID stored by the one-shot replay arm.
    #[must_use]
    pub const fn spend_txid(&self) -> [u8; 32] {
        self.spend_txid
    }

    /// Last Unix second at which the verified certificate remains fresh.
    #[must_use]
    pub const fn valid_until_unix(&self) -> u64 {
        self.valid_until_unix
    }

    /// Sorted distinct Set-B signers recovered during certificate validation.
    #[must_use]
    pub fn verified_signers(&self) -> &[Address] {
        &self.verified_signers
    }
}

/// Authorize one UTXO spend and return an immutable receipt after the replay
/// one-shot has been consumed.
///
/// The ordering is deliberately `validate -> bind -> consume -> receipt`: a
/// caller cannot persist an authorization receipt for an unconsumed or
/// differently bound transaction. Identical retries remain safe because the
/// replay store accepts only the same certificate digest and unsigned txid.
///
/// # Errors
/// A fail-closed gate rejection for an invalid/stale certificate, output
/// mismatch, replay conflict, or replay-store failure.
pub async fn authorize_btc_spend<S: ReplayStore>(
    ctx: &BindContext,
    replay: &S,
    config: CustodyConfig<'_>,
    custody_spk: &bitcoin::ScriptBuf,
    now_unix: i64,
) -> Result<BtcSpendAuthorization, GateRejection> {
    let spend_txid = ctx.psbt.unsigned_tx.compute_txid().to_byte_array();
    let (certified_spend, consume_key) = validate_spend_certificate(
        config,
        ctx.chain,
        ctx.ric.as_ref(),
        ctx.acc.as_ref(),
        now_unix,
    )?;
    bind_outputs_to_cert(&ctx.psbt, custody_spk, &certified_spend)?;

    let valid_for = config.intent_policy.ric_max_age_secs;
    let (subject, certificate_digest, valid_until_unix, verified_signers) = match &consume_key {
        ConsumeKey::Ric { cert, digest } => (
            BtcCertificateSubject::Redemption {
                redemption_id: cert.redemption_id,
                leg_index: cert.leg_index,
            },
            *digest,
            cert.vault_resolved_at.saturating_add(valid_for),
            cert.signers.clone(),
        ),
        ConsumeKey::Ac { cert, digest } => (
            BtcCertificateSubject::AcquireCancel {
                cancel_id: cert.cancel_id,
                intent_id: cert.intent_id,
                slot_index: cert.slot_index,
            },
            *digest,
            cert.vault_resolved_at.saturating_add(valid_for),
            cert.signers.clone(),
        ),
    };
    consume_spend_certificate(replay, ctx.chain, &consume_key, &spend_txid, now_unix).await?;

    Ok(BtcSpendAuthorization {
        chain: ctx.chain,
        subject,
        certificate_digest,
        spend_txid,
        valid_until_unix,
        verified_signers,
    })
}
