//! CTD-1 (`DL-CTD-2`) shared fixtures for the integration tests: a
//! deterministic Set-B trio whose addresses form the spawned daemons'
//! `intent_policy` whitelist, plus a quorum-signed
//! `RedemptionIntentCertificate` proof builder mirroring what the
//! per-operator observers produce (Slice B).
//!
//! Lives in a directory module (NOT `tests/ric_common.rs`) so cargo
//! does not treat it as a test target of its own.

use alloy_primitives::{keccak256, Address, B256, U256};
use k256::ecdsa::SigningKey;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::eip712::{
    attestation_oracle_domain, redemption_intent_certificate, ric_signing_hash,
};
use xindex_shared::signer_wire::IntentProof;
use xindex_signer_daemon::intent::IntentPolicy;

/// Deterministic Set-B test keys (seeds 41/42/43) → (key, EOA).
fn set_b_keys() -> Vec<(SigningKey, Address)> {
    [41u8, 42, 43]
        .iter()
        .map(|seed| {
            #[expect(clippy::expect_used, reason = "test code")]
            let sk = SigningKey::from_slice(&[*seed; 32]).expect("key");
            let vk = sk.verifying_key();
            let uncompressed = vk.to_encoded_point(false);
            let hash = keccak256(&uncompressed.as_bytes()[1..]);
            let addr = Address::from_slice(&hash[12..]);
            (sk, addr)
        })
        .collect()
}

/// 2-of-3 policy over the deterministic Set-B trio — give this to every
/// spawned daemon's `DaemonConfig.intent_policy`.
#[must_use]
pub fn policy() -> IntentPolicy {
    IntentPolicy {
        signer_whitelist: set_b_keys().into_iter().map(|(_, a)| a).collect(),
        intent_quorum: 2,
        ric_max_age_secs: 3_600,
    }
}

/// Build + quorum-sign an [`IntentProof`] certifying one leg.
///
/// `immediate_target` / `memo` are the RAW bytes the family hashes
/// (BTC: the payout `scriptPubKey` bytes / memo bytes; account
/// families: the canonical address / memo strings as UTF-8; EVM: the
/// 20-byte Asgard vault address).
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "test fixture mirrors the 8 certified inputs"
)]
pub fn proof(
    eth_chain_id: u64,
    verifying_contract: Address,
    chain: ChainId,
    rid: u8,
    leg_index: u32,
    amount: u128,
    immediate_target: &[u8],
    memo: &[u8],
) -> IntentProof {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let redemption_id = B256::repeat_byte(rid);
    let amount = U256::from(amount);
    let immediate_target_hash = keccak256(immediate_target);
    let memo_hash = keccak256(memo);
    let final_destination_hash = B256::repeat_byte(0x12);
    let ric = redemption_intent_certificate(
        redemption_id,
        U256::from(leg_index),
        chain.asset_id_hash(),
        amount,
        chain.decimals(),
        immediate_target_hash,
        memo_hash,
        final_destination_hash,
        now,
    );
    let digest = ric_signing_hash(
        &ric,
        &attestation_oracle_domain(eth_chain_id, verifying_contract),
    );
    let signatures = set_b_keys()
        .iter()
        .take(2)
        .map(|(sk, _)| {
            #[expect(clippy::expect_used, reason = "test code")]
            let (sig, recid) = sk
                .sign_prehash_recoverable(digest.as_slice())
                .expect("sign");
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(sig.to_bytes().as_ref());
            out[64] = 27 + recid.to_byte();
            format!("0x{}", alloy_primitives::hex::encode(out))
        })
        .collect();
    IntentProof {
        redemption_id: format!("{redemption_id:#x}"),
        leg_index: leg_index.to_string(),
        asset_id: format!("{:#x}", chain.asset_id_hash()),
        amount: amount.to_string(),
        amount_decimals: chain.decimals(),
        immediate_target_hash: format!("{immediate_target_hash:#x}"),
        memo_hash: format!("{memo_hash:#x}"),
        final_destination_hash: format!("{final_destination_hash:#x}"),
        vault_resolved_at: now,
        signatures,
    }
}
