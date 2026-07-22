#![expect(
    clippy::expect_used,
    reason = "fixed EVM fixtures should fail loudly in tests"
)]

use alloy_primitives::{keccak256, Address, U256};
use xindex_custody_core::evm_tx::{build_unsigned, EvmUnsignedParams};
use xindex_shared::chain_registry::ChainId;

fn params(chain: ChainId) -> EvmUnsignedParams<'static> {
    EvmUnsignedParams {
        chain,
        nonce: 1,
        gas_limit: 3,
        max_fee_per_gas: 5,
        max_priority_fee_per_gas: 2,
        gas_price: 2,
        to: Address::repeat_byte(0x11),
        value: U256::from(4),
        data: &[0xaa],
    }
}

#[test]
fn eip1559_vultisig_payload_is_the_typed_signing_encoding() {
    let unsigned = build_unsigned(&params(ChainId::Eth)).expect("EVM chain");
    let payload = unsigned.encoded_for_vultisig();

    assert_eq!(payload[0], 2);
    assert_eq!(keccak256(&payload), unsigned.signature_hash());
}

#[test]
fn legacy_vultisig_payload_is_type_zero_plus_six_unsigned_fields() {
    let unsigned = build_unsigned(&params(ChainId::Bsc)).expect("EVM chain");
    let payload = unsigned.encoded_for_vultisig();

    let mut expected = vec![0x00, 0xdb, 0x01, 0x02, 0x03, 0x94];
    expected.extend_from_slice(&[0x11; 20]);
    expected.extend_from_slice(&[0x04, 0x81, 0xaa]);
    assert_eq!(payload, expected);

    // The EIP-155 chain id is deliberately absent from the transport payload;
    // the pinned verifier's chain-specific signer adds it when deriving the
    // exact hash that Xindex independently computed.
    assert!(!payload.contains(&56));
}
