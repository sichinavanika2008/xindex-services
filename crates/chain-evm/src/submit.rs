//! Per-chain transaction-request builder for Safe `execTransaction`.
//!
//! Selects EIP-1559 vs legacy tx-type from
//! [`xindex_shared::chain_registry::ChainId::tx_type`] (V1) and packs
//! the Safe `execTransaction` calldata (built by [`xindex_safe_evm`]'s
//! `exec::build_exec_transaction_calldata`) into the chain's expected
//! envelope shape.
//!
//! Returns an `alloy::rpc::types::TransactionRequest` the caller signs
//! (via its own EOA / HSM-fronted submitter key) and submits via
//! [`crate::EvmChainClient::submit_raw`].
//!
//! ## Why caller-supplied fee
//!
//! DL-P3.2-7 locks gas-price out-of-scope for v1. Caller passes
//! [`EvmTxFee`] explicit values; chain-evm does NOT consult an oracle,
//! does NOT estimate from base-fee, does NOT fetch from any HTTP fee
//! API. Operators / V7 supply via env / CLI.

use alloy::network::TransactionBuilder;
use alloy::rpc::types::TransactionRequest;
use alloy_primitives::{Address, Bytes, U256};
use xindex_shared::chain_registry::{ChainId, EvmTxType};

/// Caller-supplied per-tx fee parameters. The shape varies per
/// `EvmTxType`:
///
/// - [`EvmTxType::Eip1559`]: uses `max_fee_per_gas` +
///   `max_priority_fee_per_gas`. `gas_price` is ignored.
/// - [`EvmTxType::Legacy`]: uses `gas_price`. Other fields ignored.
///
/// All values are wei-per-gas. Callers convert from gwei at the CLI /
/// env boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmTxFee {
    /// Gas units the caller is willing to pay for. Pre-estimated /
    /// hard-coded by the operator — chain-evm doesn't run
    /// `eth_estimateGas`.
    pub gas_limit: u64,
    /// EIP-1559 max-fee-per-gas (wei).
    pub max_fee_per_gas: u128,
    /// EIP-1559 priority fee (wei).
    pub max_priority_fee_per_gas: u128,
    /// Legacy gas price (wei).
    pub gas_price: u128,
}

/// Build a `TransactionRequest` for `Safe.execTransaction(...)` on
/// `chain`, with the chain's expected tx-type envelope.
///
/// Inputs:
/// - `chain`: the Phase 3.2 destination chain.
/// - `from`: the EOA submitter address (also used to look up nonce
///   externally — caller fills `from` so alloy's fillers can attach
///   the submitter nonce). For unit tests, this is the Anvil dev
///   account; for prod it's the HSM-fronted relayer key.
/// - `safe_address`: the Safe contract address — the `to` of the
///   submitted tx.
/// - `exec_transaction_calldata`: bytes produced by
///   `xindex_safe_evm::exec::build_exec_transaction_calldata`.
/// - `fee`: caller-supplied gas / fee parameters.
///
/// # Errors
/// Returns `None` if `chain` is not in the EVM custody family (no
/// `tx_type`).
#[must_use]
pub fn build_safe_exec_tx_request(
    chain: ChainId,
    from: Address,
    safe_address: Address,
    exec_transaction_calldata: Bytes,
    fee: EvmTxFee,
) -> Option<TransactionRequest> {
    let tx_type = chain.tx_type()?;
    let evm_chain_id = chain.evm_chain_id()?;
    let mut req = TransactionRequest::default()
        .from(from)
        .to(safe_address)
        .input(exec_transaction_calldata.into())
        .value(U256::ZERO)
        .gas_limit(fee.gas_limit)
        .with_chain_id(evm_chain_id);
    match tx_type {
        EvmTxType::Eip1559 => {
            req = req
                .max_fee_per_gas(fee.max_fee_per_gas)
                .max_priority_fee_per_gas(fee.max_priority_fee_per_gas);
        }
        EvmTxType::Legacy => {
            req = req.with_gas_price(fee.gas_price);
        }
    }
    Some(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn dummy_fee() -> EvmTxFee {
        EvmTxFee {
            gas_limit: 300_000,
            max_fee_per_gas: 50_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
            gas_price: 5_000_000_000,
        }
    }

    /// EIP-1559 chains (ETH/AVAX/BASE/POL) produce a request with both
    /// `max_fee_per_gas` and `max_priority_fee_per_gas` set.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn eip1559_chain_sets_max_fee_fields() {
        for chain in [ChainId::Eth, ChainId::Avax, ChainId::Base, ChainId::Pol] {
            let req = build_safe_exec_tx_request(
                chain,
                address!("1111111111111111111111111111111111111111"),
                address!("2222222222222222222222222222222222222222"),
                Bytes::from(vec![0xaa, 0xbb, 0xcc]),
                dummy_fee(),
            )
            .expect("eip1559 chain");
            assert_eq!(
                req.max_fee_per_gas,
                Some(50_000_000_000),
                "{chain:?} should set max_fee_per_gas"
            );
            assert_eq!(
                req.max_priority_fee_per_gas,
                Some(1_500_000_000),
                "{chain:?} should set max_priority_fee_per_gas"
            );
            assert_eq!(req.gas_price, None, "{chain:?} should NOT set gas_price");
        }
    }

    /// BSC stays on type-0 legacy — populates `gas_price`, leaves
    /// max-fee fields empty (DL-P3.2-4).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn bsc_sets_legacy_gas_price() {
        let req = build_safe_exec_tx_request(
            ChainId::Bsc,
            address!("1111111111111111111111111111111111111111"),
            address!("2222222222222222222222222222222222222222"),
            Bytes::from(vec![0xaa, 0xbb, 0xcc]),
            dummy_fee(),
        )
        .expect("legacy chain");
        assert_eq!(req.gas_price, Some(5_000_000_000));
        assert_eq!(req.max_fee_per_gas, None);
        assert_eq!(req.max_priority_fee_per_gas, None);
    }

    /// Every EVM chain stamps the matching `chain_id` on the request so
    /// the EIP-155 / EIP-1559 signed envelope binds to the right chain.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn chain_id_is_stamped_per_chain() {
        for (chain, expected) in [
            (ChainId::Eth, 1u64),
            (ChainId::Bsc, 56),
            (ChainId::Avax, 43_114),
            (ChainId::Base, 8_453),
            (ChainId::Pol, 137),
        ] {
            let req = build_safe_exec_tx_request(
                chain,
                address!("1111111111111111111111111111111111111111"),
                address!("2222222222222222222222222222222222222222"),
                Bytes::new(),
                dummy_fee(),
            )
            .expect("evm chain");
            assert_eq!(req.chain_id, Some(expected), "{chain:?}");
        }
    }

    /// UTXO chains have no EVM tx-type — returns `None`.
    #[test]
    fn utxo_chains_return_none() {
        for chain in [
            ChainId::Btc,
            ChainId::Ltc,
            ChainId::Bch,
            ChainId::Doge,
            ChainId::Zec,
        ] {
            let req = build_safe_exec_tx_request(
                chain,
                address!("1111111111111111111111111111111111111111"),
                address!("2222222222222222222222222222222222222222"),
                Bytes::new(),
                dummy_fee(),
            );
            assert!(req.is_none(), "{chain:?} should not produce a tx request");
        }
    }

    /// Calldata, `to`, and `value` are passed through verbatim. The
    /// caller's safe-evm `execTransaction` bytes land in `input`.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn calldata_passes_through_to_input_field() {
        let safe = address!("1234567890123456789012345678901234567890");
        let calldata = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        let req = build_safe_exec_tx_request(
            ChainId::Eth,
            address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            safe,
            calldata.clone(),
            dummy_fee(),
        )
        .expect("eth");
        assert_eq!(req.to, Some(safe.into()));
        assert_eq!(req.value, Some(U256::ZERO));
        // `input.input` is the canonical field on `TransactionInput`.
        assert_eq!(req.input.input.as_ref(), Some(&calldata));
    }
}
