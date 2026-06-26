//! CTD-1 redeem-spend decision — the wire-independent core of the BTC callback.
//!
//! Given a prepared [`BindContext`] (the unsigned PSBT + its k-of-n
//! certificate), verify the certificate and bind the PSBT's output set to it;
//! APPROVE only if both pass, else a fail-closed [`Decision::Reject`]. The
//! input-sighash ↔ Fireblocks `rawMessage` tie-in and the wire adapter land at
//! Slice 0; this function is address-type-independent (it inspects outputs +
//! the certificate, the security anchor — the RIC is k-of-n signed
//! independently of the coordinator that supplied the PSBT).

use bitcoin::hashes::Hash;

use xindex_custody_core::btc_bind::bind_outputs_to_cert;
use xindex_custody_core::gates::{gate_spend_certificate, CustodyConfig};
use xindex_custody_core::replay::ReplayStore;

use crate::prepare::BindContext;
use crate::Decision;

/// Decide a BTC redeem (or mint-cancel swap-back) spend: k-of-n RIC/ACC
/// verification + one-shot consume ([`gate_spend_certificate`]) then the
/// exact-set output bind ([`bind_outputs_to_cert`]) against our own custody
/// `scriptPubKey`. APPROVE iff both pass; otherwise a fail-closed REJECT.
///
/// `spend_identity` = the unsigned tx txid, so a single certificate cannot be
/// re-driven into a second, different transaction (RA-1 / RUST-003).
pub async fn decide_redeem_spend<S: ReplayStore>(
    ctx: &BindContext,
    replay: &S,
    config: CustodyConfig<'_>,
    custody_spk: &bitcoin::ScriptBuf,
    now_unix: i64,
) -> Decision {
    let txid = ctx.psbt.unsigned_tx.compute_txid().to_byte_array();
    let cert = match gate_spend_certificate(
        config,
        replay,
        ctx.chain,
        ctx.ric.as_ref(),
        ctx.acc.as_ref(),
        &txid,
        now_unix,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return Decision::Reject { code: r.code, message: r.message },
    };
    if let Err(r) = bind_outputs_to_cert(&ctx.psbt, custody_spk, &cert) {
        return Decision::Reject { code: r.code, message: r.message };
    }
    Decision::Approve
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, Address, B256, U256};
    use bitcoin::psbt::Psbt;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid, Witness,
    };
    use k256::ecdsa::SigningKey;
    use xindex_custody_core::replay::InMemoryReplayStore;
    use xindex_shared::chain_registry::ChainId;
    use xindex_shared::eip712::{
        attestation_oracle_domain, redemption_intent_certificate, ric_signing_hash,
    };
    use xindex_shared::intent::IntentPolicy;
    use xindex_shared::signer_wire::IntentProof;

    const NOW: i64 = 1_750_000_000;
    const CHAIN_ID: u64 = 1;
    const AMOUNT_SATS: u64 = 100_000_000;
    const CHANGE_SATS: u64 = 50_000;
    const MEMO: &[u8] = b"=:ETH.USDT:0xrecipient:990000";

    fn oracle() -> Address {
        Address::repeat_byte(0x42)
    }

    /// A `scriptPubKey` (P2WPKH shape: `OP_0 PUSH20 <tag*20>`), distinct per
    /// `tag`, never `OP_RETURN`.
    fn spk(tag: u8) -> ScriptBuf {
        let mut v = vec![0x00u8, 0x14];
        v.extend_from_slice(&[tag; 20]);
        ScriptBuf::from_bytes(v)
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn op_return(data: &[u8]) -> ScriptBuf {
        let pb = PushBytesBuf::try_from(data.to_vec()).expect("push bytes");
        ScriptBuf::new_op_return(&pb)
    }

    fn out(value: u64, script_pubkey: ScriptBuf) -> TxOut {
        TxOut { value: Amount::from_sat(value), script_pubkey }
    }

    fn dummy_input() -> TxIn {
        TxIn {
            previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn psbt_with(outputs: Vec<TxOut>) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![dummy_input()],
            output: outputs,
        };
        Psbt::from_unsigned_tx(tx).expect("unsigned psbt")
    }

    /// The honest 3-output redeem PSBT: certified payout, memo `OP_RETURN`,
    /// change-to-custody. `change` perturbs the txid for the re-drive test.
    fn honest_psbt(payout: &ScriptBuf, custody: &ScriptBuf, change: u64) -> Psbt {
        psbt_with(vec![
            out(AMOUNT_SATS, payout.clone()),
            out(0, op_return(MEMO)),
            out(change, custody.clone()),
        ])
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn key_identity(seed: u8) -> (SigningKey, Address) {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let vk = sk.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        (sk, Address::from_slice(&hash[12..]))
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn sign_digest(sk: &SigningKey, digest: B256) -> String {
        let (sig, recid) = sk.sign_prehash_recoverable(digest.as_slice()).expect("sign");
        let mut o = [0u8; 65];
        o[..64].copy_from_slice(sig.to_bytes().as_ref());
        o[64] = 27 + recid.to_byte();
        format!("0x{}", alloy_primitives::hex::encode(o))
    }

    fn policy() -> IntentPolicy {
        IntentPolicy {
            signer_whitelist: (1..=5).map(|s| key_identity(s).1).collect(),
            intent_quorum: 3,
            ric_max_age_secs: 3_600,
        }
    }

    fn hex32(b: B256) -> String {
        format!("0x{}", alloy_primitives::hex::encode(b.as_slice()))
    }

    /// A k-of-n RIC over (`payout`, [`MEMO`], `amount`), signed by `seeds`.
    fn signed_ric(payout: &ScriptBuf, amount: u64, seeds: &[u8]) -> IntentProof {
        let redemption_id = B256::repeat_byte(0xab);
        let asset_id = ChainId::Btc.asset_id_hash();
        let decimals = ChainId::Btc.decimals();
        let target_hash = keccak256(payout.as_bytes());
        let memo_hash = keccak256(MEMO);
        let final_dest = B256::repeat_byte(0x12);
        let vra: u64 = u64::try_from(NOW - 100).unwrap_or(0);
        let ric = redemption_intent_certificate(
            redemption_id,
            U256::ZERO,
            asset_id,
            U256::from(amount),
            decimals,
            target_hash,
            memo_hash,
            final_dest,
            vra,
        );
        let digest = ric_signing_hash(&ric, &attestation_oracle_domain(CHAIN_ID, oracle()));
        let signatures = seeds.iter().map(|s| sign_digest(&key_identity(*s).0, digest)).collect();
        IntentProof {
            redemption_id: hex32(redemption_id),
            leg_index: "0".to_string(),
            asset_id: hex32(asset_id),
            amount: amount.to_string(),
            amount_decimals: decimals,
            immediate_target_hash: hex32(target_hash),
            memo_hash: hex32(memo_hash),
            final_destination_hash: hex32(final_dest),
            vault_resolved_at: vra,
            signatures,
        }
    }

    fn ctx(psbt: Psbt, ric: IntentProof) -> BindContext {
        BindContext { chain: ChainId::Btc, psbt, ric: Some(ric), acc: None }
    }

    fn is_reject(d: &Decision) -> bool {
        matches!(d, Decision::Reject { .. })
    }

    #[tokio::test]
    async fn honest_redeem_approves() {
        let (payout, custody) = (spk(0xaa), spk(0xcc));
        let policy = policy();
        let config = CustodyConfig {
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: &policy,
        };
        let c = ctx(honest_psbt(&payout, &custody, CHANGE_SATS), signed_ric(&payout, AMOUNT_SATS, &[1, 2, 3]));
        let replay = InMemoryReplayStore::new();
        let d = decide_redeem_spend(&c, &replay, config, &custody, NOW).await;
        assert_eq!(d, Decision::Approve);
    }

    #[tokio::test]
    async fn tampered_payout_amount_rejects() {
        // PSBT pays AMOUNT_SATS+7 but the RIC certifies AMOUNT_SATS.
        let (payout, custody) = (spk(0xaa), spk(0xcc));
        let policy = policy();
        let config = CustodyConfig {
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: &policy,
        };
        let psbt = psbt_with(vec![
            out(AMOUNT_SATS + 7, payout.clone()),
            out(0, op_return(MEMO)),
            out(CHANGE_SATS, custody.clone()),
        ]);
        let c = ctx(psbt, signed_ric(&payout, AMOUNT_SATS, &[1, 2, 3]));
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(&decide_redeem_spend(&c, &replay, config, &custody, NOW).await));
    }

    #[tokio::test]
    async fn non_whitelisted_signer_rejects() {
        let (payout, custody) = (spk(0xaa), spk(0xcc));
        let policy = policy();
        let config = CustodyConfig {
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: &policy,
        };
        // Seed 9 is not in the 1..=5 whitelist → the whole proof rejects.
        let c = ctx(honest_psbt(&payout, &custody, CHANGE_SATS), signed_ric(&payout, AMOUNT_SATS, &[1, 2, 9]));
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(&decide_redeem_spend(&c, &replay, config, &custody, NOW).await));
    }

    #[tokio::test]
    async fn second_op_return_rejects() {
        // THORChain concatenates all OP_RETURNs → a second one is injection (RA-3).
        let (payout, custody) = (spk(0xaa), spk(0xcc));
        let policy = policy();
        let config = CustodyConfig {
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: &policy,
        };
        let psbt = psbt_with(vec![
            out(AMOUNT_SATS, payout.clone()),
            out(0, op_return(MEMO)),
            out(0, op_return(b"injected")),
            out(CHANGE_SATS, custody.clone()),
        ]);
        let c = ctx(psbt, signed_ric(&payout, AMOUNT_SATS, &[1, 2, 3]));
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(&decide_redeem_spend(&c, &replay, config, &custody, NOW).await));
    }

    #[tokio::test]
    async fn unexpected_output_rejects() {
        // An output that is neither payout, memo, nor change-to-custody.
        let (payout, custody) = (spk(0xaa), spk(0xcc));
        let policy = policy();
        let config = CustodyConfig {
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: &policy,
        };
        let psbt = psbt_with(vec![
            out(AMOUNT_SATS, payout.clone()),
            out(0, op_return(MEMO)),
            out(CHANGE_SATS, spk(0xee)), // attacker address, not custody
        ]);
        let c = ctx(psbt, signed_ric(&payout, AMOUNT_SATS, &[1, 2, 3]));
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(&decide_redeem_spend(&c, &replay, config, &custody, NOW).await));
    }

    #[tokio::test]
    async fn redrive_same_ric_different_tx_rejects() {
        // One valid RIC, two distinct txs (different change → different txid):
        // the first APPROVEs, the re-drive is a one-shot conflict (RA-1).
        let (payout, custody) = (spk(0xaa), spk(0xcc));
        let policy = policy();
        let config = CustodyConfig {
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: &policy,
        };
        let replay = InMemoryReplayStore::new();
        let ric = signed_ric(&payout, AMOUNT_SATS, &[1, 2, 3]);

        let first = ctx(honest_psbt(&payout, &custody, CHANGE_SATS), ric.clone());
        assert_eq!(decide_redeem_spend(&first, &replay, config, &custody, NOW).await, Decision::Approve);

        let second = ctx(honest_psbt(&payout, &custody, CHANGE_SATS + 1), ric);
        assert!(is_reject(&decide_redeem_spend(&second, &replay, config, &custody, NOW).await));
    }
}
