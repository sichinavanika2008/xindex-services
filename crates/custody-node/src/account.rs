//! CTD-1 account-send decision (Cosmos / XRP / TRON) — the wire-independent
//! core of the account-family callback.
//!
//! Given the parsed native send (destination + decimal amount + memo) and its
//! authorizing k-of-n RIC, verify the certificate (one-shot consume) and bind
//! the send to it; APPROVE only if both pass, else a fail-closed
//! [`Decision::Reject`]. Mirrors [`crate::btc::decide_redeem_spend`] for the
//! account-model families, whose `THORChain` memo is a transaction field (not
//! an `OP_RETURN` output), so no PSBT / output-set binding is involved.

use xindex_custody_core::gates::{
    bind_account_send_to_cert, consume_ric_one_shot, validate_ric_intent, CustodyConfig,
};
use xindex_custody_core::replay::ReplayStore;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::IntentProof;

use crate::Decision;

/// A parsed account-model send awaiting a decision. Grouped into a struct so
/// the decision fn stays under the positional-argument limit.
#[derive(Debug, Clone)]
pub struct AccountSend<'a> {
    /// Which account-model chain this send settles on (pins the domain).
    pub chain: ChainId,
    /// The destination address as the family serializes it into the signed
    /// transaction (`keccak256(to_address)` must equal the certified target).
    pub to_address: &'a str,
    /// The decimal send amount in the chain's native smallest units.
    pub amount_dec: &'a str,
    /// The exact `THORChain` memo carried as a transaction field.
    pub memo: &'a str,
    /// The k-of-n RIC authorizing the redeem leg.
    pub ric: Option<&'a IntentProof>,
    /// The one-shot spend identity bound into the signed tx (the account
    /// `sequence` for Cosmos / XRP, the `txid` for TRON) — a re-drive must
    /// advance it → a one-shot conflict.
    pub spend_identity: &'a [u8],
}

/// Decide an account-model redeem send: k-of-n RIC verification + one-shot
/// consume ([`gate_ric_intent`]) then the destination/amount/memo bind
/// ([`bind_account_send_to_cert`]). APPROVE iff both pass; otherwise a
/// fail-closed REJECT.
pub async fn decide_account_send<S: ReplayStore>(
    send: &AccountSend<'_>,
    replay: &S,
    config: CustodyConfig<'_>,
    now_unix: i64,
) -> Decision {
    // TK-04: validate → bind → consume. The one-shot is recorded only after the
    // destination/amount/memo bind passes, so a bind-failing request never pins
    // the (chain, redemptionId, legIndex) slot.
    let (cert, digest) = match validate_ric_intent(config, send.chain, send.ric, now_unix) {
        Ok(c) => c,
        Err(r) => {
            return Decision::Reject {
                code: r.code,
                message: r.message,
            }
        }
    };
    if let Err(r) = bind_account_send_to_cert(send.to_address, send.amount_dec, send.memo, &cert) {
        return Decision::Reject {
            code: r.code,
            message: r.message,
        };
    }
    if let Err(r) = consume_ric_one_shot(
        replay,
        send.chain,
        &cert,
        digest,
        send.spend_identity,
        now_unix,
    )
    .await
    {
        return Decision::Reject {
            code: r.code,
            message: r.message,
        };
    }
    Decision::Approve
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, U256};
    use xindex_custody_core::replay::InMemoryReplayStore;

    use crate::test_support::{oracle, policy, signed_ric, CHAIN_ID, NOW};

    const CHAIN: ChainId = ChainId::Gaia;
    const TO: &str = "cosmos1exampledestinationaddressxxxxxxxxxxxxxxxx";
    const AMOUNT: u128 = 1_000_000;
    const MEMO: &str = "=:ETH.USDT:0xrecipient:990000";

    fn target() -> alloy_primitives::B256 {
        keccak256(TO.as_bytes())
    }

    fn config(policy: &xindex_shared::intent::IntentPolicy) -> CustodyConfig<'_> {
        CustodyConfig {
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: policy,
        }
    }

    fn send<'a>(
        amount_dec: &'a str,
        memo: &'a str,
        ric: &'a IntentProof,
        seq: &'a [u8],
    ) -> AccountSend<'a> {
        AccountSend {
            chain: CHAIN,
            to_address: TO,
            amount_dec,
            memo,
            ric: Some(ric),
            spend_identity: seq,
        }
    }

    fn is_reject(d: &Decision) -> bool {
        matches!(d, Decision::Reject { .. })
    }

    #[tokio::test]
    async fn honest_account_send_approves() {
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 3]);
        let s = send("1000000", MEMO, &ric, b"7");
        let replay = InMemoryReplayStore::new();
        assert_eq!(
            decide_account_send(&s, &replay, config(&policy), NOW).await,
            Decision::Approve
        );
    }

    #[tokio::test]
    async fn tampered_amount_rejects() {
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 3]);
        let s = send("1000001", MEMO, &ric, b"7");
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(
            &decide_account_send(&s, &replay, config(&policy), NOW).await
        ));
    }

    #[tokio::test]
    async fn wrong_destination_rejects() {
        // The RIC certifies TO; the send pays a different address.
        let policy = policy();
        let other = keccak256(b"cosmos1attackerxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".as_slice());
        let ric = signed_ric(CHAIN, other, MEMO, U256::from(AMOUNT), &[1, 2, 3]);
        let s = send("1000000", MEMO, &ric, b"7");
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(
            &decide_account_send(&s, &replay, config(&policy), NOW).await
        ));
    }

    #[tokio::test]
    async fn tampered_memo_rejects() {
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 3]);
        let s = send("1000000", "=:ETH.USDT:0xattacker:1", &ric, b"7");
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(
            &decide_account_send(&s, &replay, config(&policy), NOW).await
        ));
    }

    #[tokio::test]
    async fn non_whitelisted_signer_rejects() {
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 9]);
        let s = send("1000000", MEMO, &ric, b"7");
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(
            &decide_account_send(&s, &replay, config(&policy), NOW).await
        ));
    }

    #[tokio::test]
    async fn bind_failure_does_not_pin_the_leg() {
        // TK-04: a valid-RIC but bind-failing request (wrong memo) with a bogus
        // identity must NOT consume the one-shot; a later honest request under
        // the same RIC (different identity) still APPROVES. Pre-fix (consume
        // before bind) the bogus identity pinned the slot → the honest request
        // hit a one-shot conflict and the leg was unspendable.
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 3]);
        let replay = InMemoryReplayStore::new();

        let bad = send("1000000", "=:ETH.USDT:0xattacker:1", &ric, b"bogus");
        assert!(is_reject(
            &decide_account_send(&bad, &replay, config(&policy), NOW).await
        ));

        let good = send("1000000", MEMO, &ric, b"honest");
        assert_eq!(
            decide_account_send(&good, &replay, config(&policy), NOW).await,
            Decision::Approve
        );
    }

    #[tokio::test]
    async fn redrive_same_ric_advanced_sequence_rejects() {
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 3]);
        let replay = InMemoryReplayStore::new();

        let first = send("1000000", MEMO, &ric, b"7");
        assert_eq!(
            decide_account_send(&first, &replay, config(&policy), NOW).await,
            Decision::Approve
        );

        let second = send("1000000", MEMO, &ric, b"8");
        assert!(is_reject(
            &decide_account_send(&second, &replay, config(&policy), NOW).await
        ));
    }
}
