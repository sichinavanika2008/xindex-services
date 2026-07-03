//! Shared EVM unsigned-tx construction + signing hash.
//!
//! The single builder used by BOTH the Turnkey EVM executor (to compute the
//! payload it asks the enclave to sign) and the approver (to independently
//! recompute that payload from the RIC-bound prepared fields and assert it
//! equals the signing request — TK-01). Keeping one builder guarantees the two
//! sides cannot silently diverge and false-reject an honest spend.
//!
//! `chain` pins the envelope type + EIP-155 chain id (derived here, never
//! trusted from the caller); the remaining fields are the operational tx
//! parameters that the approver additionally range-checks (the fee cap, TK-02).

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, PrimitiveSignature, TxKind, B256, U256};

use xindex_shared::chain_registry::{ChainId, EvmTxType};

/// The signing-hash inputs for an EVM `depositWithExpiry` redeem tx.
#[derive(Debug, Clone)]
pub struct EvmUnsignedParams<'a> {
    /// EVM custody chain — pins the envelope type + EIP-155 chain id.
    pub chain: ChainId,
    /// Account nonce.
    pub nonce: u64,
    /// Gas units the tx may consume.
    pub gas_limit: u64,
    /// EIP-1559 max-fee-per-gas (wei); unused for a legacy chain.
    pub max_fee_per_gas: u128,
    /// EIP-1559 priority fee (wei); unused for a legacy chain.
    pub max_priority_fee_per_gas: u128,
    /// Legacy gas price (wei); unused for an EIP-1559 chain.
    pub gas_price: u128,
    /// Recipient (the `THORChain` Router).
    pub to: Address,
    /// Native `value` (the deposit amount).
    pub value: U256,
    /// ABI-encoded `depositWithExpiry` calldata.
    pub data: &'a [u8],
}

/// An unsigned EVM tx, per envelope type.
#[derive(Debug)]
pub enum Unsigned {
    /// EIP-1559 dynamic-fee tx.
    Eip1559(Box<TxEip1559>),
    /// Legacy (EIP-155) tx.
    Legacy(Box<TxLegacy>),
}

impl Unsigned {
    /// The signing hash the custody key signs.
    #[must_use]
    pub fn signature_hash(&self) -> B256 {
        match self {
            Self::Eip1559(t) => t.signature_hash(),
            Self::Legacy(t) => t.signature_hash(),
        }
    }

    /// Attach the signature and 2718-encode to broadcastable bytes.
    #[must_use]
    pub fn into_raw(self, sig: PrimitiveSignature) -> Bytes {
        let envelope = match self {
            Self::Eip1559(t) => TxEnvelope::from(t.into_signed(sig)),
            Self::Legacy(t) => TxEnvelope::from(t.into_signed(sig)),
        };
        envelope.encoded_2718().into()
    }
}

/// Build the unsigned tx for `params.chain`'s envelope type. Returns `None` if
/// the chain is not an EVM custody chain (no `tx_type` / `evm_chain_id`).
#[must_use]
pub fn build_unsigned(params: &EvmUnsignedParams) -> Option<Unsigned> {
    let tx_type = params.chain.tx_type()?;
    let evm_chain_id = params.chain.evm_chain_id()?;
    let to = TxKind::Call(params.to);
    let input = Bytes::from(params.data.to_vec());
    Some(match tx_type {
        EvmTxType::Eip1559 => Unsigned::Eip1559(Box::new(TxEip1559 {
            chain_id: evm_chain_id,
            nonce: params.nonce,
            gas_limit: params.gas_limit,
            max_fee_per_gas: params.max_fee_per_gas,
            max_priority_fee_per_gas: params.max_priority_fee_per_gas,
            to,
            value: params.value,
            access_list: AccessList::default(),
            input,
        })),
        EvmTxType::Legacy => Unsigned::Legacy(Box::new(TxLegacy {
            chain_id: Some(evm_chain_id),
            nonce: params.nonce,
            gas_price: params.gas_price,
            gas_limit: params.gas_limit,
            to,
            value: params.value,
            input,
        })),
    })
}

/// The signing hash for `params`, or `None` for a non-EVM chain.
#[must_use]
pub fn evm_signing_hash(params: &EvmUnsignedParams) -> Option<B256> {
    Some(build_unsigned(params)?.signature_hash())
}
