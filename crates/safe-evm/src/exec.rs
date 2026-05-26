//! Safe v1.4.1 `execTransaction` ABI calldata builder.
//!
//! Produces the bytes the executor (V7) passes as `data` when sending a
//! tx to the Safe proxy address. The Safe internally recomputes the
//! `safeTxHash`, calls `checkSignatures` with the aggregated blob
//! (see [`crate::sigs::aggregate_signatures`]), and forwards the
//! Safe-internal call to `to` with `value` / `data` / `operation`.

use alloy_primitives::Bytes;
use alloy_sol_types::{sol, SolCall};

use crate::digest::SafeTransaction;

sol! {
    /// Safe v1.4.1 `execTransaction` ABI. The `signatures` field is the
    /// concatenation of 65-byte ECDSA sigs sorted ascending by signer
    /// (see [`crate::sigs::aggregate_signatures`]).
    function execTransaction(
        address to,
        uint256 value,
        bytes data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes signatures
    ) external payable returns (bool success);
}

/// Build the `execTransaction(...)` ABI calldata. The `tx` is the same
/// `SafeTransaction` value that was hashed by
/// [`crate::digest::safe_tx_hash`] — every field MUST match the hashed
/// inputs verbatim, otherwise the Safe's on-chain recomputation will
/// produce a different digest and `checkSignatures` will reject.
#[must_use]
pub fn build_exec_transaction_calldata(tx: &SafeTransaction, signatures: Vec<u8>) -> Bytes {
    let call = execTransactionCall {
        to: tx.to,
        value: tx.value,
        data: tx.data.clone(),
        operation: tx.operation as u8,
        safeTxGas: tx.safe_tx_gas,
        baseGas: tx.base_gas,
        gasPrice: tx.gas_price,
        gasToken: tx.gas_token,
        refundReceiver: tx.refund_receiver,
        signatures: signatures.into(),
    };
    Bytes::from(call.abi_encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SafeOperation;
    use alloy_primitives::{address, hex, Address, U256};

    /// `execTransaction` selector is `0x6a761202`. Verifies the
    /// alloy-sol-encoded calldata starts with the expected 4 bytes.
    #[test]
    fn exec_transaction_selector_pinned() {
        let tx = SafeTransaction {
            to: Address::ZERO,
            value: U256::ZERO,
            data: Bytes::new(),
            operation: SafeOperation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::ZERO,
        };
        let cd = build_exec_transaction_calldata(&tx, vec![0u8; 65]);
        // Safe `execTransaction` selector.
        let expected_selector = hex!("6a761202");
        assert_eq!(&cd[..4], &expected_selector);
    }

    /// Calldata length grows in 32-byte chunks for the static fields +
    /// 2 × 32 bytes for dynamic-offset words for `data` and
    /// `signatures` + padded payloads.
    #[test]
    fn exec_transaction_calldata_grows_with_signatures_payload() {
        let tx = SafeTransaction {
            to: address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            value: U256::ZERO,
            data: Bytes::new(),
            operation: SafeOperation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::ZERO,
        };
        let one_sig = build_exec_transaction_calldata(&tx, vec![0u8; 65]);
        let two_sigs = build_exec_transaction_calldata(&tx, vec![0u8; 130]);
        // Two sigs is +1 × 32-byte word of padded payload (65+65=130
        // pads to 4 × 32 = 128; 65 pads to 3 × 32 = 96).
        assert!(two_sigs.len() > one_sig.len());
        // Selector unchanged.
        assert_eq!(&one_sig[..4], &two_sigs[..4]);
    }

    /// Round-trip a calldata blob through alloy's decoder — defends
    /// against a refactor that scrambles field order.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn exec_transaction_calldata_round_trips_via_alloy_decode() {
        let tx = SafeTransaction {
            to: address!("000000000000000000000000000000000000beef"),
            value: U256::from(1_234_567u64),
            data: Bytes::from_static(b"hello-safe"),
            operation: SafeOperation::Call,
            safe_tx_gas: U256::from(100_000u64),
            base_gas: U256::from(21_000u64),
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::from(7u64),
        };
        let sigs = vec![0xabu8; 65];
        let cd = build_exec_transaction_calldata(&tx, sigs.clone());
        let decoded = execTransactionCall::abi_decode(&cd, true).expect("decode");
        assert_eq!(decoded.to, tx.to);
        assert_eq!(decoded.value, tx.value);
        assert_eq!(decoded.data, tx.data);
        assert_eq!(decoded.operation, tx.operation as u8);
        assert_eq!(decoded.safeTxGas, tx.safe_tx_gas);
        assert_eq!(decoded.baseGas, tx.base_gas);
        assert_eq!(decoded.gasPrice, tx.gas_price);
        assert_eq!(decoded.gasToken, tx.gas_token);
        assert_eq!(decoded.refundReceiver, tx.refund_receiver);
        assert_eq!(decoded.signatures.to_vec(), sigs);
    }
}
