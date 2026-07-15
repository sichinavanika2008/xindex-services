//! CTD-1 (`DL-CTD-2`): EVM redeem-deposit binding, transport-agnostic.
//!
//! For a future plain single-signature EVM custody adapter, the honest
//! redemption leg is a direct
//! `Router.depositWithExpiry(vault, address(0), amount, memo, expiry)` call
//! with `value == amount`. This is the de-Safed sibling of the (transitional)
//! signer-daemon's `bind_safe_tx_to_cert`: the same router / asset / vault /
//! amount / memo binds, with no Safe-tx wrapper. No EVM custody provider is
//! selected or production-wired by this provider-neutral decision core.

use alloy_primitives::{keccak256, Address, U256};
use alloy_sol_types::SolCall;

use xindex_shared::chain_registry::ChainId;
use xindex_shared::intent::VerifiedIntent;
use xindex_shared::signer_wire::error_codes;
use xindex_shared::thorchain_router::depositWithExpiryCall;

use crate::gates::GateRejection;

/// Bind a plain EVM redeem transaction to the certified intent. The honest
/// leg is exactly `Router.depositWithExpiry(vault, address(0), amount, memo,
/// expiry)` with `value == amount` (the executor builds nothing else), so this
/// refuses anything that is not byte-decodable as that call with:
///
/// - `to` == the registry-pinned `THORChain` Router for `chain` (our OWN pin,
///   not a certified field — a fake router IS the drain);
/// - `asset` == `address(0)` (native-asset leg, matching the gate's
///   `asset_id_hash` bind);
/// - `keccak256(vault)` == the certified Asgard target;
/// - calldata `amount` == tx `value` == the certified amount;
/// - `keccak256(memo)` == the certified memo hash.
///
/// `expiry` is execution-local (executor-chosen) and deliberately NOT
/// certified.
///
/// # Errors
/// [`GateRejection`] (`intent_mismatch`) on a wrong router, a non-native
/// asset, a vault/amount/value/memo mismatch, or undecodable calldata.
pub fn bind_evm_deposit_to_cert(
    chain: ChainId,
    to: Address,
    value: U256,
    data: &[u8],
    cert: &VerifiedIntent,
) -> Result<(), GateRejection> {
    let mismatch = |what: String| GateRejection::unprocessable(error_codes::INTENT_MISMATCH, what);
    let router = chain.thorchain_router_address().ok_or_else(|| {
        mismatch(format!(
            "chain {chain:?} has no registry-pinned THORChain Router"
        ))
    })?;
    if to != router {
        return Err(mismatch(format!(
            "EVM tx `to` {to:#x} is not the registry-pinned THORChain Router {router:#x}"
        )));
    }
    let call = depositWithExpiryCall::abi_decode(data, true)
        .map_err(|e| mismatch(format!("calldata is not depositWithExpiry: {e}")))?;
    if call.asset != Address::ZERO {
        return Err(mismatch(format!(
            "deposit asset {:#x} != address(0) — RIC v1 certifies native-asset legs only",
            call.asset
        )));
    }
    if keccak256(call.vault.as_slice()) != cert.immediate_target_hash {
        return Err(mismatch(format!(
            "deposit vault {:#x} does not hash to the certified Asgard target",
            call.vault
        )));
    }
    if call.amount != cert.amount {
        return Err(mismatch(format!(
            "deposit amount {} != certified amount {}",
            call.amount, cert.amount
        )));
    }
    if value != cert.amount {
        return Err(mismatch(format!(
            "tx value {value} != certified amount {} (native deposit carries msg.value)",
            cert.amount
        )));
    }
    if keccak256(call.memo.as_bytes()) != cert.memo_hash {
        return Err(mismatch(
            "deposit memo does not hash to the certified memo".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};

    const CHAIN: ChainId = ChainId::Eth;
    const AMOUNT: u128 = 1_000_000_000_000_000_000;
    const MEMO: &str = "=:ETH.USDT:0xrecipient:990000";

    fn vault() -> Address {
        Address::repeat_byte(0x11)
    }

    /// A `VerifiedIntent` whose certified fields match the honest call below.
    fn cert() -> VerifiedIntent {
        VerifiedIntent {
            redemption_id: B256::repeat_byte(0xab),
            leg_index: 0,
            asset_id: CHAIN.asset_id_hash(),
            amount: U256::from(AMOUNT),
            amount_decimals: CHAIN.decimals(),
            immediate_target_hash: keccak256(vault().as_slice()),
            memo_hash: keccak256(MEMO.as_bytes()),
            final_destination_hash: B256::repeat_byte(0x12),
            vault_resolved_at: 1_750_000_000,
            signers: vec![],
        }
    }

    fn encode(vault: Address, asset: Address, amount: U256, memo: &str) -> Vec<u8> {
        depositWithExpiryCall {
            vault,
            asset,
            amount,
            memo: memo.to_string(),
            expiry: U256::from(1_750_007_200u64),
        }
        .abi_encode()
    }

    fn router() -> Address {
        #[expect(clippy::expect_used, reason = "test code")]
        CHAIN
            .thorchain_router_address()
            .expect("EVM chain has a router")
    }

    #[test]
    fn honest_deposit_binds() {
        let data = encode(vault(), Address::ZERO, U256::from(AMOUNT), MEMO);
        assert!(
            bind_evm_deposit_to_cert(CHAIN, router(), U256::from(AMOUNT), &data, &cert()).is_ok()
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn wrong_router_rejects() {
        let data = encode(vault(), Address::ZERO, U256::from(AMOUNT), MEMO);
        let bad_to = Address::repeat_byte(0xee);
        let e = bind_evm_deposit_to_cert(CHAIN, bad_to, U256::from(AMOUNT), &data, &cert())
            .expect_err("a `to` that is not the pinned router must reject");
        assert_eq!(e.code, error_codes::INTENT_MISMATCH);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn non_native_asset_rejects() {
        let erc20 = Address::repeat_byte(0x99);
        let data = encode(vault(), erc20, U256::from(AMOUNT), MEMO);
        bind_evm_deposit_to_cert(CHAIN, router(), U256::from(AMOUNT), &data, &cert())
            .expect_err("a non-zero deposit asset must reject (native-asset legs only)");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn wrong_vault_rejects() {
        let other_vault = Address::repeat_byte(0x22);
        let data = encode(other_vault, Address::ZERO, U256::from(AMOUNT), MEMO);
        bind_evm_deposit_to_cert(CHAIN, router(), U256::from(AMOUNT), &data, &cert())
            .expect_err("a vault that does not hash to the certified target must reject");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn calldata_amount_mismatch_rejects() {
        let data = encode(vault(), Address::ZERO, U256::from(AMOUNT + 1), MEMO);
        bind_evm_deposit_to_cert(CHAIN, router(), U256::from(AMOUNT + 1), &data, &cert())
            .expect_err("calldata amount != certified amount must reject");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn value_not_matching_amount_rejects() {
        // Calldata amount is correct, but msg.value underfunds the deposit —
        // THORChain credits `msg.value`, so this would short the swap.
        let data = encode(vault(), Address::ZERO, U256::from(AMOUNT), MEMO);
        bind_evm_deposit_to_cert(CHAIN, router(), U256::from(AMOUNT - 1), &data, &cert())
            .expect_err("tx value != certified amount must reject");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn tampered_memo_rejects() {
        let data = encode(
            vault(),
            Address::ZERO,
            U256::from(AMOUNT),
            "=:ETH.USDT:0xattacker:1",
        );
        bind_evm_deposit_to_cert(CHAIN, router(), U256::from(AMOUNT), &data, &cert())
            .expect_err("a memo that does not hash to the certified memo must reject");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn undecodable_calldata_rejects() {
        bind_evm_deposit_to_cert(
            CHAIN,
            router(),
            U256::from(AMOUNT),
            &[0x01, 0x02, 0x03],
            &cert(),
        )
        .expect_err("calldata that is not depositWithExpiry must reject");
    }
}
