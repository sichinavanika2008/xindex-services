//! CTD-1 EVM redeem-deposit decision — the wire-independent core of the EVM
//! callback.
//!
//! Given the parsed EVM custody transaction (a `Router.depositWithExpiry`
//! call) and its authorizing k-of-n RIC, verify the certificate (one-shot
//! consume) and bind the tx to it; APPROVE only if both pass, else a
//! fail-closed [`Decision::Reject`]. Mirrors [`crate::btc::decide_redeem_spend`]
//! for a possible plain single-signature EVM custody key. No EVM custody
//! provider is currently selected or production-wired.

use alloy_primitives::{Address, U256};

use xindex_custody_core::evm_bind::bind_evm_deposit_to_cert;
use xindex_custody_core::gates::{consume_ric_one_shot, validate_ric_intent, CustodyConfig};
use xindex_custody_core::replay::ReplayStore;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::IntentProof;

use crate::Decision;

/// A parsed EVM custody spend awaiting a decision: the redeem-leg
/// `Router.depositWithExpiry` transaction fields, its authorizing RIC, and the
/// per-spend one-shot identity. Grouped into a struct so the decision fn stays
/// under the positional-argument limit.
#[derive(Debug, Clone)]
pub struct EvmDeposit<'a> {
    /// Which EVM chain this spend settles on (pins the Router + domain).
    pub chain: ChainId,
    /// The transaction recipient (must be the registry-pinned Router).
    pub to: Address,
    /// The transaction `value` (a native deposit carries `msg.value`).
    pub value: U256,
    /// The ABI-encoded `depositWithExpiry` calldata.
    pub data: &'a [u8],
    /// The k-of-n RIC authorizing the redeem leg.
    pub ric: Option<&'a IntentProof>,
    /// The one-shot spend identity bound into the signed tx (the EVM account
    /// nonce) — a re-drive must advance the nonce → a one-shot conflict.
    pub spend_identity: &'a [u8],
}

/// Decide an EVM redeem deposit: k-of-n RIC verification + one-shot consume
/// ([`gate_ric_intent`]) then the calldata/value bind
/// ([`bind_evm_deposit_to_cert`]). APPROVE iff both pass; otherwise a
/// fail-closed REJECT.
pub async fn decide_evm_deposit<S: ReplayStore>(
    deposit: &EvmDeposit<'_>,
    replay: &S,
    config: CustodyConfig<'_>,
    now_unix: i64,
) -> Decision {
    // TK-04: validate → bind → consume (see [`crate::account`]).
    let (cert, digest) = match validate_ric_intent(config, deposit.chain, deposit.ric, now_unix) {
        Ok(c) => c,
        Err(r) => {
            return Decision::Reject {
                code: r.code,
                message: r.message,
            }
        }
    };
    if let Err(r) = bind_evm_deposit_to_cert(
        deposit.chain,
        deposit.to,
        deposit.value,
        deposit.data,
        &cert,
    ) {
        return Decision::Reject {
            code: r.code,
            message: r.message,
        };
    }
    if let Err(r) = consume_ric_one_shot(
        replay,
        deposit.chain,
        &cert,
        digest,
        deposit.spend_identity,
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
    use alloy_primitives::keccak256;
    use alloy_sol_types::SolCall;
    use xindex_custody_core::replay::InMemoryReplayStore;
    use xindex_shared::thorchain_router::depositWithExpiryCall;

    use crate::test_support::{oracle, policy, signed_ric, CHAIN_ID, NOW};

    const CHAIN: ChainId = ChainId::Eth;
    const AMOUNT: u128 = 1_000_000_000_000_000_000;
    const MEMO: &str = "=:ETH.USDT:0xrecipient:990000";

    fn vault() -> Address {
        Address::repeat_byte(0x11)
    }

    fn router() -> Address {
        #[expect(clippy::expect_used, reason = "test code")]
        CHAIN
            .thorchain_router_address()
            .expect("EVM chain has a router")
    }

    fn calldata(amount: U256, memo: &str) -> Vec<u8> {
        depositWithExpiryCall {
            vault: vault(),
            asset: Address::ZERO,
            amount,
            memo: memo.to_string(),
            expiry: U256::from(1_750_007_200u64),
        }
        .abi_encode()
    }

    fn config(policy: &xindex_shared::intent::IntentPolicy) -> CustodyConfig<'_> {
        CustodyConfig {
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: policy,
        }
    }

    fn deposit<'a>(
        data: &'a [u8],
        value: U256,
        ric: &'a IntentProof,
        nonce: &'a [u8],
    ) -> EvmDeposit<'a> {
        EvmDeposit {
            chain: CHAIN,
            to: router(),
            value,
            data,
            ric: Some(ric),
            spend_identity: nonce,
        }
    }

    fn target() -> alloy_primitives::B256 {
        keccak256(vault().as_slice())
    }

    fn is_reject(d: &Decision) -> bool {
        matches!(d, Decision::Reject { .. })
    }

    #[tokio::test]
    async fn honest_evm_deposit_approves() {
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 3]);
        let data = calldata(U256::from(AMOUNT), MEMO);
        let d = deposit(&data, U256::from(AMOUNT), &ric, b"0");
        let replay = InMemoryReplayStore::new();
        assert_eq!(
            decide_evm_deposit(&d, &replay, config(&policy), NOW).await,
            Decision::Approve
        );
    }

    #[tokio::test]
    async fn tampered_amount_rejects() {
        // RIC certifies AMOUNT; the tx deposits AMOUNT+1 (calldata + value).
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 3]);
        let data = calldata(U256::from(AMOUNT + 1), MEMO);
        let d = deposit(&data, U256::from(AMOUNT + 1), &ric, b"0");
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(
            &decide_evm_deposit(&d, &replay, config(&policy), NOW).await
        ));
    }

    #[tokio::test]
    async fn non_whitelisted_signer_rejects() {
        // Seed 9 is not in the 1..=5 whitelist → the proof fails the gate.
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 9]);
        let data = calldata(U256::from(AMOUNT), MEMO);
        let d = deposit(&data, U256::from(AMOUNT), &ric, b"0");
        let replay = InMemoryReplayStore::new();
        assert!(is_reject(
            &decide_evm_deposit(&d, &replay, config(&policy), NOW).await
        ));
    }

    #[tokio::test]
    async fn redrive_same_ric_advanced_nonce_rejects() {
        // One valid RIC, two distinct nonces: the first APPROVEs, the re-drive
        // under an advanced nonce is a one-shot conflict.
        let policy = policy();
        let ric = signed_ric(CHAIN, target(), MEMO, U256::from(AMOUNT), &[1, 2, 3]);
        let data = calldata(U256::from(AMOUNT), MEMO);
        let replay = InMemoryReplayStore::new();

        let first = deposit(&data, U256::from(AMOUNT), &ric, b"0");
        assert_eq!(
            decide_evm_deposit(&first, &replay, config(&policy), NOW).await,
            Decision::Approve
        );

        let second = deposit(&data, U256::from(AMOUNT), &ric, b"1");
        assert!(is_reject(
            &decide_evm_deposit(&second, &replay, config(&policy), NOW).await
        ));
    }
}
