//! Shared `#[cfg(test)]` helpers for the per-family decision cores.
//!
//! The EVM ([`crate::evm`]) and account ([`crate::account`]) cores build their
//! k-of-n RICs here so the secp256k1 signing + Set-B policy setup live in one
//! place. (BTC's tests in [`crate::btc`] predate this module and keep their own
//! copies of the BTC-specific PSBT builders.)

use alloy_primitives::{keccak256, Address, B256, U256};
use k256::ecdsa::SigningKey;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::eip712::{
    attestation_oracle_domain, redemption_intent_certificate, ric_signing_hash,
};
use xindex_shared::intent::IntentPolicy;
use xindex_shared::signer_wire::IntentProof;

/// Fixed "now" the recency window is centred on.
pub const NOW: i64 = 1_750_000_000;
/// Ethereum chain id pinning the RIC EIP-712 domain.
pub const CHAIN_ID: u64 = 1;

/// The `AttestationOracle` address pinning the EIP-712 domain.
pub fn oracle() -> Address {
    Address::repeat_byte(0x42)
}

/// A deterministic (`SigningKey`, EOA) pair from a single-byte seed.
#[expect(clippy::expect_used, reason = "test code")]
fn key_identity(seed: u8) -> (SigningKey, Address) {
    let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
    let vk = sk.verifying_key();
    let uncompressed = vk.to_encoded_point(false);
    let hash = keccak256(&uncompressed.as_bytes()[1..]);
    (sk, Address::from_slice(&hash[12..]))
}

/// Recoverable secp256k1 signature over `digest`, hex-encoded `0x…65 bytes`.
#[expect(clippy::expect_used, reason = "test code")]
fn sign_digest(sk: &SigningKey, digest: B256) -> String {
    let (sig, recid) = sk
        .sign_prehash_recoverable(digest.as_slice())
        .expect("sign");
    let mut o = [0u8; 65];
    o[..64].copy_from_slice(sig.to_bytes().as_ref());
    o[64] = 27 + recid.to_byte();
    format!("0x{}", alloy_primitives::hex::encode(o))
}

/// The standard 3-of-5 Set-B policy: seeds 1..=5 whitelisted, quorum 3.
pub fn policy() -> IntentPolicy {
    IntentPolicy {
        signer_whitelist: (1..=5).map(|s| key_identity(s).1).collect(),
        intent_quorum: 3,
        ric_max_age_secs: 3_600,
    }
}

fn hex32(b: B256) -> String {
    format!("0x{}", alloy_primitives::hex::encode(b.as_slice()))
}

/// A k-of-n RIC for `chain` over (`immediate_target_hash`, `memo`, `amount`),
/// signed by the whitelist members identified by `seeds` (seed ∉ 1..=5 ⇒ a
/// non-whitelisted signer, which makes the whole proof reject).
#[expect(clippy::expect_used, reason = "test code")]
pub fn signed_ric(
    chain: ChainId,
    immediate_target_hash: B256,
    memo: &str,
    amount: U256,
    seeds: &[u8],
) -> IntentProof {
    let redemption_id = B256::repeat_byte(0xab);
    let asset_id = chain.asset_id_hash();
    let decimals = chain.decimals();
    let memo_hash = keccak256(memo.as_bytes());
    let final_dest = B256::repeat_byte(0x12);
    let vra: u64 = u64::try_from(NOW - 100).expect("positive");
    let ric = redemption_intent_certificate(
        redemption_id,
        U256::ZERO,
        asset_id,
        amount,
        decimals,
        immediate_target_hash,
        memo_hash,
        final_dest,
        vra,
    );
    let digest = ric_signing_hash(&ric, &attestation_oracle_domain(CHAIN_ID, oracle()));
    let signatures = seeds
        .iter()
        .map(|s| sign_digest(&key_identity(*s).0, digest))
        .collect();
    IntentProof {
        redemption_id: hex32(redemption_id),
        leg_index: "0".to_string(),
        asset_id: hex32(asset_id),
        amount: amount.to_string(),
        amount_decimals: decimals,
        immediate_target_hash: hex32(immediate_target_hash),
        memo_hash: hex32(memo_hash),
        final_destination_hash: hex32(final_dest),
        vault_resolved_at: vra,
        signatures,
    }
}
