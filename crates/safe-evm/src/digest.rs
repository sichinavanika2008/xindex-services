//! Safe v1.4.1 EIP-712 `safeTxHash` builder.
//!
//! Mirrors `Safe.sol`'s `encodeTransactionData` + `getTransactionHash`
//! semantics verbatim. Hand-rolled to avoid any "EIP-712 helper" that
//! defaults to the full `name+version+chainId+verifyingContract` domain
//! (Safe uses ONLY `chainId+verifyingContract` — see crate-level docs).
//!
//! Reference: <https://github.com/safe-global/safe-smart-account>
//! `contracts/Safe.sol@v1.4.1`. Key constants:
//!
//! ```text
//! DOMAIN_SEPARATOR_TYPEHASH = keccak256(
//!     "EIP712Domain(uint256 chainId,address verifyingContract)"
//! )
//! SAFE_TX_TYPEHASH = keccak256(
//!     "SafeTx(address to,uint256 value,bytes data,uint8 operation,"
//!     "uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,"
//!     "address gasToken,address refundReceiver,uint256 nonce)"
//! )
//! ```

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};

use crate::SafeOperation;

/// Type string of Safe's EIP-712 domain. Frozen across Safe v1.3 / 1.4 /
/// 1.5 (DL-P3.2-3 — version pin is digest-stable).
pub const SAFE_DOMAIN_TYPE_STRING: &[u8] =
    b"EIP712Domain(uint256 chainId,address verifyingContract)";

/// Type string of the `SafeTx` struct.
pub const SAFE_TX_TYPE_STRING: &[u8] = b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";

/// All Safe-transaction inputs, in the EXACT order the Safe contract
/// encodes them. The crate enforces ordering via the struct field
/// layout — there is no `set_field(name, value)` API the caller could
/// misuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeTransaction {
    /// `to`: recipient of the Safe-side call.
    pub to: Address,
    /// `value`: native-asset wei sent with the call.
    pub value: U256,
    /// `data`: ABI-encoded calldata. For an ERC20 transfer this is the
    /// `transfer(address,uint256)` calldata; for the Phase 3.2
    /// `THORChain` `depositWithExpiry(...)` redeem path, the
    /// `Router.depositWithExpiry` calldata.
    pub data: Bytes,
    /// `operation`: `Call` (default) or `DelegateCall` (Phase 3.2
    /// custody never delegatecalls).
    pub operation: SafeOperation,
    /// `safeTxGas`: gas budget for the Safe-side call. Pass 0 to use
    /// the full available gas at execution time (v1.3+ behaviour).
    pub safe_tx_gas: U256,
    /// `baseGas`: gas charged for the Safe overhead (signature
    /// verification, refund). Pass 0 when `gasPrice == 0`.
    pub base_gas: U256,
    /// `gasPrice`: per-gas refund price the executor pays. **Always 0
    /// in Phase 3.2** (DL-P3.2-7: gas-price is caller-supplied at the
    /// tx-broadcast layer, not at Safe's refund machinery).
    pub gas_price: U256,
    /// `gasToken`: token used for the gas refund. `address(0)` =
    /// native asset. **Always `address(0)` in Phase 3.2** (no Safe-
    /// side refund).
    pub gas_token: Address,
    /// `refundReceiver`: recipient of the gas refund. **Always
    /// `address(0)` in Phase 3.2** (no refund).
    pub refund_receiver: Address,
    /// `nonce`: Safe's monotonic nonce. Read from the chain via
    /// `Safe.nonce()` immediately before constructing this tx.
    pub nonce: U256,
}

/// Compute Safe's domain separator for a `(chain_id, safe_address)`
/// pair. Returns a 32-byte digest matching
/// `keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, safe))`.
#[must_use]
pub fn safe_domain_separator(chain_id: u64, safe: Address) -> B256 {
    let typehash = keccak256(SAFE_DOMAIN_TYPE_STRING);
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(typehash.as_slice());
    // chain_id: uint256 big-endian
    buf.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    // safe: address left-padded to 32 bytes
    buf.extend_from_slice(&padded_address(safe));
    keccak256(&buf)
}

/// Compute the `SafeTx` struct hash. Returns
/// `keccak256(abi.encode(SAFE_TX_TYPEHASH, ...10 fields...))`.
#[must_use]
pub fn safe_struct_hash(tx: &SafeTransaction) -> B256 {
    let typehash = keccak256(SAFE_TX_TYPE_STRING);
    // 11 × 32 bytes = 352-byte preimage (typehash + 10 fields).
    let mut buf = Vec::with_capacity(11 * 32);
    buf.extend_from_slice(typehash.as_slice());
    buf.extend_from_slice(&padded_address(tx.to));
    buf.extend_from_slice(&tx.value.to_be_bytes::<32>());
    // `bytes data` is dynamic → encoded as `keccak256(data)`.
    buf.extend_from_slice(keccak256(&tx.data).as_slice());
    // `uint8 operation` left-padded to 32 bytes.
    let mut op_padded = [0u8; 32];
    op_padded[31] = tx.operation as u8;
    buf.extend_from_slice(&op_padded);
    buf.extend_from_slice(&tx.safe_tx_gas.to_be_bytes::<32>());
    buf.extend_from_slice(&tx.base_gas.to_be_bytes::<32>());
    buf.extend_from_slice(&tx.gas_price.to_be_bytes::<32>());
    buf.extend_from_slice(&padded_address(tx.gas_token));
    buf.extend_from_slice(&padded_address(tx.refund_receiver));
    buf.extend_from_slice(&tx.nonce.to_be_bytes::<32>());
    keccak256(&buf)
}

/// Compute the final `safeTxHash` —
/// `keccak256(0x1901 || domainSeparator || structHash)`.
/// This is the 32-byte digest the HSM-backed signer signs.
#[must_use]
pub fn safe_tx_hash(chain_id: u64, safe: Address, tx: &SafeTransaction) -> B256 {
    let ds = safe_domain_separator(chain_id, safe);
    let sh = safe_struct_hash(tx);
    let mut buf = Vec::with_capacity(66);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(ds.as_slice());
    buf.extend_from_slice(sh.as_slice());
    keccak256(&buf)
}

/// 20-byte address left-padded to 32 bytes (the ABI encoding of
/// `address`).
fn padded_address(a: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(a.as_slice());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, hex};

    /// Pinned typehash bytes — changing any character in the
    /// `SAFE_DOMAIN_TYPE_STRING` or `SAFE_TX_TYPE_STRING` produces a
    /// different keccak256 and the Safe's on-chain `checkSignatures`
    /// would reject every signature.
    #[test]
    fn safe_domain_typehash_bytes_pinned() {
        let expected = hex!("47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218");
        assert_eq!(keccak256(SAFE_DOMAIN_TYPE_STRING).as_slice(), &expected);
    }

    /// Pinned `SafeTx` typehash bytes. Reference: Safe v1.3+ source.
    #[test]
    fn safe_tx_typehash_bytes_pinned() {
        let expected = hex!("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8");
        assert_eq!(keccak256(SAFE_TX_TYPE_STRING).as_slice(), &expected);
    }

    /// `padded_address` left-pads the 20-byte address with 12 zero
    /// bytes. This is the ABI encoding rule for `address`.
    #[test]
    fn padded_address_left_pads_twelve_zeros() {
        let a = address!("1111111111111111111111111111111111111111");
        let padded = padded_address(a);
        // First 12 bytes are zero; last 20 are the address.
        assert_eq!(&padded[..12], &[0u8; 12]);
        assert_eq!(&padded[12..], a.as_slice());
    }

    /// Domain separator is sensitive to `chain_id` — every chain has a
    /// distinct domain even with the same Safe address. Defends against
    /// cross-chain signature replay.
    #[test]
    fn domain_separator_changes_with_chain_id() {
        let safe = address!("dead000000000000000000000000000000000001");
        let ds_eth = safe_domain_separator(1, safe);
        let ds_bsc = safe_domain_separator(56, safe);
        let ds_pol = safe_domain_separator(137, safe);
        assert_ne!(ds_eth, ds_bsc);
        assert_ne!(ds_eth, ds_pol);
        assert_ne!(ds_bsc, ds_pol);
    }

    /// Domain separator is sensitive to `safe_address` — two Safes on
    /// the same chain have distinct domains. Defends against same-
    /// chain cross-Safe replay.
    #[test]
    fn domain_separator_changes_with_safe_address() {
        let s1 = address!("0000000000000000000000000000000000000001");
        let s2 = address!("0000000000000000000000000000000000000002");
        assert_ne!(safe_domain_separator(1, s1), safe_domain_separator(1, s2));
    }

    /// Struct hash is sensitive to every field — a flip of even one
    /// byte produces a different digest. Sweeps every field with a
    /// representative perturbation.
    #[test]
    fn struct_hash_changes_with_every_field() {
        let base = SafeTransaction {
            to: address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            value: U256::from(1u64),
            data: Bytes::from_static(&[0x42]),
            operation: SafeOperation::Call,
            safe_tx_gas: U256::from(100_000u64),
            base_gas: U256::from(21_000u64),
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::from(7u64),
        };
        let h0 = safe_struct_hash(&base);

        let perturbations = [
            SafeTransaction {
                to: address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ..base.clone()
            },
            SafeTransaction {
                value: U256::from(2u64),
                ..base.clone()
            },
            SafeTransaction {
                data: Bytes::from_static(&[0x43]),
                ..base.clone()
            },
            SafeTransaction {
                operation: SafeOperation::DelegateCall,
                ..base.clone()
            },
            SafeTransaction {
                safe_tx_gas: U256::from(100_001u64),
                ..base.clone()
            },
            SafeTransaction {
                base_gas: U256::from(21_001u64),
                ..base.clone()
            },
            SafeTransaction {
                gas_price: U256::from(1u64),
                ..base.clone()
            },
            SafeTransaction {
                gas_token: address!("0000000000000000000000000000000000000001"),
                ..base.clone()
            },
            SafeTransaction {
                refund_receiver: address!("0000000000000000000000000000000000000001"),
                ..base.clone()
            },
            SafeTransaction {
                nonce: U256::from(8u64),
                ..base.clone()
            },
        ];

        for (i, p) in perturbations.iter().enumerate() {
            assert_ne!(safe_struct_hash(p), h0, "field {i} perturbation");
        }
    }

    /// `safe_tx_hash` is the 0x1901-prefixed combiner — different
    /// chain/safe/tx triples produce different digests. Sanity: tx hash
    /// changes when the `chain_id` changes (cross-chain replay defence).
    #[test]
    fn safe_tx_hash_changes_with_chain_id_and_nonce() {
        let safe = address!("0123456789abcdef0123456789abcdef01234567");
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
            nonce: U256::from(1u64),
        };
        let h_eth = safe_tx_hash(1, safe, &tx);
        let h_bsc = safe_tx_hash(56, safe, &tx);
        assert_ne!(h_eth, h_bsc);

        // Different nonce → different digest.
        let tx2 = SafeTransaction {
            nonce: U256::from(2u64),
            ..tx
        };
        let h_eth_n2 = safe_tx_hash(1, safe, &tx2);
        assert_ne!(h_eth, h_eth_n2);
    }

    /// `safe_tx_hash` matches the manual construction
    /// `keccak256(0x19 || 0x01 || domainSeparator || structHash)`. A
    /// regression test that pins the combiner — defends against an
    /// accidental refactor that drops the 0x1901 prefix or swaps the
    /// argument order.
    #[test]
    fn safe_tx_hash_manual_combiner_matches() {
        let safe = address!("a000000000000000000000000000000000000001");
        let tx = SafeTransaction {
            to: address!("b000000000000000000000000000000000000002"),
            value: U256::from(42u64),
            data: Bytes::from_static(b"hello"),
            operation: SafeOperation::Call,
            safe_tx_gas: U256::from(1u64),
            base_gas: U256::from(2u64),
            gas_price: U256::from(3u64),
            gas_token: address!("c000000000000000000000000000000000000003"),
            refund_receiver: address!("d000000000000000000000000000000000000004"),
            nonce: U256::from(99u64),
        };
        let ds = safe_domain_separator(1, safe);
        let sh = safe_struct_hash(&tx);
        let mut manual = Vec::with_capacity(66);
        manual.push(0x19);
        manual.push(0x01);
        manual.extend_from_slice(ds.as_slice());
        manual.extend_from_slice(sh.as_slice());
        let manual_hash = keccak256(&manual);
        assert_eq!(safe_tx_hash(1, safe, &tx), manual_hash);
    }
}
