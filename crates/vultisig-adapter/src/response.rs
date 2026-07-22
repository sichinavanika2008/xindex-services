//! Strict local verification of Vultisig keysign responses and canonical
//! family transaction assembly.

use std::error::Error;
use std::fmt;

use alloy_primitives::{hex, PrimitiveSignature, B256};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use bitcoin::consensus::serialize;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::Witness;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
use k256::ecdsa::{
    RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey,
};
use serde::{Deserialize, Serialize};
use xindex_cosmos_tx::tx::{build_direct_signing_package, CosmosTxParams};
use xindex_custody_core::evm_tx::{build_unsigned, EvmUnsignedParams};
use xindex_custody_core::prepare::{AccountSigning, PreparedSpend};
use xindex_shared::chain_registry::ChainId;
use xindex_solana_tx::message::serialize_transaction;
use xindex_tron_tx::tx::build_signed_transaction as build_signed_tron_transaction;
use xindex_xrp_tx::addr::decode_classic_address;
use xindex_xrp_tx::tx::{build_signed_single_sig_tx, PaymentBody};

use crate::request::{AuthorizedVultisigKeysign, VultisigPublicKey, VultisigSigningPayload};

/// Exact `mobile-tss-lib` keysign response JSON returned through the reviewed
/// Vultisig relay.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VultisigKeysignResponse {
    msg: String,
    r: String,
    s: String,
    der_signature: String,
    recovery_id: String,
}

/// Non-cloneable, broadcast-ready bytes produced only after every response
/// verifies locally against the sealed request.
#[derive(Debug)]
pub struct VerifiedVultisigTransaction {
    chain: ChainId,
    bytes: Box<[u8]>,
}

impl VerifiedVultisigTransaction {
    /// Native chain of the signed transaction.
    #[must_use]
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Exact canonical broadcast bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the capability into its exact broadcast bytes.
    #[must_use]
    pub fn into_bytes(self) -> Box<[u8]> {
        self.bytes
    }
}

/// Strict response verification or final transaction assembly failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VultisigResponseError {
    /// One response is required for every independently reconstructed payload.
    #[error("Vultisig response count is {actual}, expected {expected}")]
    ResponseCount {
        /// Required count.
        expected: usize,
        /// Supplied count.
        actual: usize,
    },
    /// The relay response does not name the exact requested message.
    #[error("Vultisig response {index} message differs from the sealed request")]
    MessageMismatch {
        /// Response index.
        index: usize,
    },
    /// A response field is not canonical lowercase hex of the exact length.
    #[error("Vultisig response {index} has invalid {field}")]
    InvalidHex {
        /// Response index.
        index: usize,
        /// Invalid field name.
        field: &'static str,
    },
    /// The secp256k1 signature is not strict DER or disagrees with `r || s`.
    #[error("Vultisig response {index} DER signature differs from r/s")]
    DerMismatch {
        /// Response index.
        index: usize,
    },
    /// High-S ECDSA signatures are non-canonical and rejected.
    #[error("Vultisig response {index} contains a high-S ECDSA signature")]
    HighS {
        /// Response index.
        index: usize,
    },
    /// Signature verification against the exact expected key/message failed.
    #[error("Vultisig response {index} signature verification failed")]
    SignatureInvalid {
        /// Response index.
        index: usize,
    },
    /// Recovery id is absent, out of range, or recovers a different key.
    #[error("Vultisig response {index} recovery id is invalid")]
    RecoveryInvalid {
        /// Response index.
        index: usize,
    },
    /// A response signature family differs from the prepared chain family.
    #[error("Vultisig response signature family differs from {0:?}")]
    SignatureFamily(ChainId),
    /// The legacy prepared profile is intentionally not a direct Vultisig
    /// transaction profile.
    #[error("prepared spend profile is not supported for direct Vultisig finalization on {0:?}")]
    Unsupported(ChainId),
    /// Canonical family assembly failed.
    #[error("Vultisig signed transaction assembly failed: {0}")]
    Assembly(String),
}

/// A local finalization failure that retains the original sealed request.
///
/// Remote signing may already have completed when response retrieval or local
/// verification fails. Returning the request prevents an ordinary error from
/// destroying the only non-cloneable capability for that exact operation.
pub struct VultisigFinalizationFailure {
    request: Box<AuthorizedVultisigKeysign>,
    error: VultisigResponseError,
}

impl fmt::Debug for VultisigFinalizationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VultisigFinalizationFailure")
            .field("request", &"<redacted>")
            .field("error", &self.error)
            .finish()
    }
}

impl VultisigFinalizationFailure {
    /// Borrow the retained sealed request.
    #[must_use]
    pub fn request(&self) -> &AuthorizedVultisigKeysign {
        &self.request
    }

    /// Inspect the strict local failure reason.
    #[must_use]
    pub const fn error(&self) -> &VultisigResponseError {
        &self.error
    }

    /// Recover the sealed request for same-session reconciliation.
    #[must_use]
    pub fn into_request(self) -> AuthorizedVultisigKeysign {
        *self.request
    }

    /// Recover the sealed request and failure reason together.
    #[must_use]
    pub fn into_parts(self) -> (AuthorizedVultisigKeysign, VultisigResponseError) {
        (*self.request, self.error)
    }
}

impl fmt::Display for VultisigFinalizationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl Error for VultisigFinalizationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum VerifiedSignature {
    Secp256k1 {
        compact: [u8; 64],
        der: Vec<u8>,
        recovery_id: u8,
    },
    Ed25519([u8; 64]),
}

/// Consume one sealed request and its complete ordered relay responses,
/// verify every signature locally, and return exact broadcast bytes.
///
/// # Errors
/// Missing/extra/malformed responses, message/key/signature/recovery mismatch,
/// high-S ECDSA, or family assembly disagreement fails closed.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the exact response set is consumed with the non-cloneable request"
)]
pub fn finalize_vultisig_keysign(
    request: AuthorizedVultisigKeysign,
    responses: Vec<VultisigKeysignResponse>,
) -> Result<VerifiedVultisigTransaction, VultisigFinalizationFailure> {
    match try_finalize_vultisig_keysign(&request, &responses) {
        Ok(transaction) => Ok(transaction),
        Err(error) => Err(VultisigFinalizationFailure {
            request: Box::new(request),
            error,
        }),
    }
}

fn try_finalize_vultisig_keysign(
    request: &AuthorizedVultisigKeysign,
    responses: &[VultisigKeysignResponse],
) -> Result<VerifiedVultisigTransaction, VultisigResponseError> {
    if responses.len() != request.payloads.len() {
        return Err(VultisigResponseError::ResponseCount {
            expected: request.payloads.len(),
            actual: responses.len(),
        });
    }
    let signatures = request
        .payloads
        .iter()
        .zip(responses)
        .enumerate()
        .map(|(index, (payload, response))| {
            verify_response(
                index,
                payload,
                response,
                request.config.signing_public_key(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    if !request.payloads.iter().any(|payload| {
        request
            .prepare_key
            .strip_prefix("0x")
            .unwrap_or(&request.prepare_key)
            .eq_ignore_ascii_case(&hex::encode(payload.message()))
    }) {
        return Err(VultisigResponseError::Assembly(
            "sealed authorization key no longer matches its payload set".to_string(),
        ));
    }
    let chain = request.config.chain();
    let bytes = assemble_transaction(
        request.spend.clone(),
        &request.transaction_bytes,
        &request.payloads,
        &signatures,
        request.config.signing_public_key(),
    )?;
    Ok(VerifiedVultisigTransaction {
        chain,
        bytes: bytes.into_boxed_slice(),
    })
}

fn verify_response(
    index: usize,
    payload: &VultisigSigningPayload,
    response: &VultisigKeysignResponse,
    public_key: VultisigPublicKey,
) -> Result<VerifiedSignature, VultisigResponseError> {
    if response.msg != BASE64.encode(payload.message()) {
        return Err(VultisigResponseError::MessageMismatch { index });
    }
    match public_key {
        VultisigPublicKey::Secp256k1(public_key) => {
            verify_secp256k1_response(index, payload.message(), response, &public_key)
        }
        VultisigPublicKey::Ed25519(public_key) => {
            verify_ed25519_response(index, payload.message(), response, &public_key)
        }
    }
}

fn verify_secp256k1_response(
    index: usize,
    message: &[u8],
    response: &VultisigKeysignResponse,
    public_key: &[u8; 33],
) -> Result<VerifiedSignature, VultisigResponseError> {
    if message.len() != 32 {
        return Err(VultisigResponseError::SignatureInvalid { index });
    }
    let r = decode_fixed_hex::<32>(&response.r, index, "r")?;
    let s = decode_fixed_hex::<32>(&response.s, index, "s")?;
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&r);
    compact[32..].copy_from_slice(&s);
    let signature = Secp256k1Signature::from_slice(&compact)
        .map_err(|_| VultisigResponseError::SignatureInvalid { index })?;
    if signature.normalize_s().is_some() {
        return Err(VultisigResponseError::HighS { index });
    }

    let der = decode_canonical_hex(&response.der_signature, index, "der_signature")?;
    let parsed_der = Secp256k1Signature::from_der(&der)
        .map_err(|_| VultisigResponseError::DerMismatch { index })?;
    if parsed_der != signature || parsed_der.to_der().as_bytes() != der.as_slice() {
        return Err(VultisigResponseError::DerMismatch { index });
    }

    let recovery_id = match response.recovery_id.as_str() {
        "00" => 0,
        "01" => 1,
        _ => return Err(VultisigResponseError::RecoveryInvalid { index }),
    };
    let verifying_key = Secp256k1VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| VultisigResponseError::SignatureInvalid { index })?;
    verifying_key
        .verify_prehash(message, &signature)
        .map_err(|_| VultisigResponseError::SignatureInvalid { index })?;
    let recovered = Secp256k1VerifyingKey::recover_from_prehash(
        message,
        &signature,
        RecoveryId::from_byte(recovery_id)
            .ok_or(VultisigResponseError::RecoveryInvalid { index })?,
    )
    .map_err(|_| VultisigResponseError::RecoveryInvalid { index })?;
    if recovered.to_encoded_point(true).as_bytes() != public_key {
        return Err(VultisigResponseError::RecoveryInvalid { index });
    }

    Ok(VerifiedSignature::Secp256k1 {
        compact,
        der,
        recovery_id,
    })
}

fn verify_ed25519_response(
    index: usize,
    message: &[u8],
    response: &VultisigKeysignResponse,
    public_key: &[u8; 32],
) -> Result<VerifiedSignature, VultisigResponseError> {
    let r = decode_fixed_hex::<32>(&response.r, index, "r")?;
    let s = decode_fixed_hex::<32>(&response.s, index, "s")?;
    if !response.recovery_id.is_empty() {
        return Err(VultisigResponseError::RecoveryInvalid { index });
    }
    if !response.der_signature.is_empty() {
        let _ = decode_canonical_hex(&response.der_signature, index, "der_signature")?;
    }
    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(&r);
    signature_bytes[32..].copy_from_slice(&s);
    let public_key = Ed25519VerifyingKey::from_bytes(public_key)
        .map_err(|_| VultisigResponseError::SignatureInvalid { index })?;
    public_key
        .verify_strict(message, &Ed25519Signature::from_bytes(&signature_bytes))
        .map_err(|_| VultisigResponseError::SignatureInvalid { index })?;
    Ok(VerifiedSignature::Ed25519(signature_bytes))
}

#[expect(
    clippy::too_many_lines,
    reason = "one exhaustive family match keeps signature assembly behavior explicit"
)]
fn assemble_transaction(
    spend: PreparedSpend,
    transaction_bytes: &[u8],
    payloads: &[VultisigSigningPayload],
    signatures: &[VerifiedSignature],
    public_key: VultisigPublicKey,
) -> Result<Vec<u8>, VultisigResponseError> {
    match spend {
        PreparedSpend::Btc(context) => Err(VultisigResponseError::Unsupported(context.chain)),
        PreparedSpend::DirectUtxo(context) => {
            assemble_direct_utxo(*context, signatures, public_key)
        }
        PreparedSpend::Zcash(context) => {
            let der = signatures
                .iter()
                .map(|signature| match signature {
                    VerifiedSignature::Secp256k1 { der, .. } => Ok(der.clone()),
                    VerifiedSignature::Ed25519(_) => {
                        Err(VultisigResponseError::SignatureFamily(ChainId::Zec))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            context
                .transaction
                .signed_bytes(&der)
                .map_err(|error| VultisigResponseError::Assembly(error.to_string()))
        }
        PreparedSpend::Evm(prepared) => {
            let (compact, recovery_id) = one_secp_signature(signatures, prepared.chain)?;
            let unsigned = build_unsigned(&EvmUnsignedParams {
                chain: prepared.chain,
                nonce: prepared.signing.nonce,
                gas_limit: prepared.signing.gas_limit,
                max_fee_per_gas: prepared.signing.max_fee_per_gas,
                max_priority_fee_per_gas: prepared.signing.max_priority_fee_per_gas,
                gas_price: prepared.signing.gas_price,
                to: prepared.to,
                value: prepared.value,
                data: &prepared.data,
            })
            .ok_or(VultisigResponseError::Unsupported(prepared.chain))?;
            let r = B256::from_slice(&compact[..32]);
            let s = B256::from_slice(&compact[32..]);
            let signature = PrimitiveSignature::from_scalars_and_parity(r, s, recovery_id == 1);
            Ok(unsigned.into_raw(signature).to_vec())
        }
        PreparedSpend::Account(prepared) => match prepared.signing {
            AccountSigning::CosmosDirect {
                from_address,
                cosmos_chain_id,
                account_number,
                sequence,
                denom,
                fee_amount,
                gas_limit,
                signing_pub_key,
            } => {
                let (compact, _) = one_secp_signature(signatures, prepared.chain)?;
                let signing_pub_key: [u8; 33] = signing_pub_key.try_into().map_err(|_| {
                    VultisigResponseError::Assembly(
                        "Cosmos direct public key is not 33 bytes".to_string(),
                    )
                })?;
                let fee_amount = fee_amount.to_string();
                let package = build_direct_signing_package(
                    &signing_pub_key,
                    &CosmosTxParams {
                        from_address: &from_address,
                        to_address: &prepared.to_address,
                        denom: &denom,
                        send_amount: &prepared.amount_dec,
                        fee_amount: &fee_amount,
                        gas_limit,
                        memo: &prepared.memo,
                        sequence,
                    },
                    &cosmos_chain_id,
                    account_number,
                );
                Ok(package.signed_tx_raw(compact))
            }
            AccountSigning::Xrp {
                account_address,
                signing_pub_key,
                sequence,
                last_ledger_sequence,
                fee_drops,
            } => {
                let (_, der, _) = one_secp_signature_with_der(signatures, prepared.chain)?;
                let signing_pub_key: [u8; 33] = signing_pub_key.try_into().map_err(|_| {
                    VultisigResponseError::Assembly("XRP public key is not 33 bytes".to_string())
                })?;
                let account = decode_classic_address(&account_address).map_err(|error| {
                    VultisigResponseError::Assembly(format!("XRP account: {error}"))
                })?;
                let destination =
                    decode_classic_address(&prepared.to_address).map_err(|error| {
                        VultisigResponseError::Assembly(format!("XRP destination: {error}"))
                    })?;
                let amount_drops = prepared.amount_dec.parse::<u64>().map_err(|error| {
                    VultisigResponseError::Assembly(format!("XRP amount: {error}"))
                })?;
                let fee_drops = u64::try_from(fee_drops).map_err(|_| {
                    VultisigResponseError::Assembly("XRP fee exceeds u64".to_string())
                })?;
                build_signed_single_sig_tx(
                    &PaymentBody {
                        account,
                        destination,
                        amount_drops,
                        fee_drops,
                        sequence,
                        last_ledger_sequence: Some(last_ledger_sequence),
                        network_id: None,
                        memo: prepared.memo.into_bytes(),
                    },
                    &signing_pub_key,
                    der,
                )
                .map_err(|error| VultisigResponseError::Assembly(error.to_string()))
            }
            AccountSigning::Solana { .. } => {
                let signature = one_ed25519_signature(signatures, prepared.chain)?;
                let message = payloads
                    .first()
                    .ok_or(VultisigResponseError::ResponseCount {
                        expected: 1,
                        actual: 0,
                    })?;
                serialize_transaction(message.message(), &[*signature])
                    .map_err(|error| VultisigResponseError::Assembly(error.to_string()))
            }
            AccountSigning::Tron { .. } => {
                let (compact, recovery_id) = one_secp_signature(signatures, prepared.chain)?;
                let mut signature = [0u8; 65];
                signature[..64].copy_from_slice(compact);
                signature[64] = recovery_id;
                Ok(build_signed_tron_transaction(
                    transaction_bytes,
                    &[signature],
                ))
            }
            AccountSigning::Cosmos { .. } => {
                Err(VultisigResponseError::Unsupported(prepared.chain))
            }
        },
    }
}

fn assemble_direct_utxo(
    context: xindex_custody_core::prepare::BindContext,
    signatures: &[VerifiedSignature],
    public_key: VultisigPublicKey,
) -> Result<Vec<u8>, VultisigResponseError> {
    if signatures.len() != context.psbt.unsigned_tx.input.len() {
        return Err(VultisigResponseError::ResponseCount {
            expected: context.psbt.unsigned_tx.input.len(),
            actual: signatures.len(),
        });
    }
    let public_key = match public_key {
        VultisigPublicKey::Secp256k1(key) => key,
        VultisigPublicKey::Ed25519(_) => {
            return Err(VultisigResponseError::SignatureFamily(context.chain))
        }
    };
    let mut transaction = context.psbt.unsigned_tx;
    for (input, signature) in transaction.input.iter_mut().zip(signatures) {
        let der = match signature {
            VerifiedSignature::Secp256k1 { der, .. } => der,
            VerifiedSignature::Ed25519(_) => {
                return Err(VultisigResponseError::SignatureFamily(context.chain))
            }
        };
        let sighash_byte = match context.chain {
            ChainId::Btc | ChainId::Ltc | ChainId::Doge => 0x01,
            ChainId::Bch => 0x41,
            _ => return Err(VultisigResponseError::Unsupported(context.chain)),
        };
        let mut signature_with_sighash = der.clone();
        signature_with_sighash.push(sighash_byte);
        match context.chain {
            ChainId::Btc | ChainId::Ltc => {
                input.witness = Witness::from_slice(&[
                    signature_with_sighash.as_slice(),
                    public_key.as_slice(),
                ]);
            }
            ChainId::Bch | ChainId::Doge => {
                let signature_push = PushBytesBuf::try_from(signature_with_sighash)
                    .map_err(|error| VultisigResponseError::Assembly(error.to_string()))?;
                let public_key_push = PushBytesBuf::try_from(public_key.to_vec())
                    .map_err(|error| VultisigResponseError::Assembly(error.to_string()))?;
                input.script_sig = Builder::new()
                    .push_slice(signature_push)
                    .push_slice(public_key_push)
                    .into_script();
            }
            _ => return Err(VultisigResponseError::Unsupported(context.chain)),
        }
    }
    Ok(serialize(&transaction))
}

fn one_secp_signature(
    signatures: &[VerifiedSignature],
    chain: ChainId,
) -> Result<(&[u8; 64], u8), VultisigResponseError> {
    let (compact, _, recovery_id) = one_secp_signature_with_der(signatures, chain)?;
    Ok((compact, recovery_id))
}

fn one_secp_signature_with_der(
    signatures: &[VerifiedSignature],
    chain: ChainId,
) -> Result<(&[u8; 64], &[u8], u8), VultisigResponseError> {
    match signatures {
        [VerifiedSignature::Secp256k1 {
            compact,
            der,
            recovery_id,
        }] => Ok((compact, der, *recovery_id)),
        _ => Err(VultisigResponseError::SignatureFamily(chain)),
    }
}

fn one_ed25519_signature(
    signatures: &[VerifiedSignature],
    chain: ChainId,
) -> Result<&[u8; 64], VultisigResponseError> {
    match signatures {
        [VerifiedSignature::Ed25519(signature)] => Ok(signature),
        _ => Err(VultisigResponseError::SignatureFamily(chain)),
    }
}

fn decode_fixed_hex<const N: usize>(
    value: &str,
    index: usize,
    field: &'static str,
) -> Result<[u8; N], VultisigResponseError> {
    let bytes = decode_canonical_hex(value, index, field)?;
    bytes
        .try_into()
        .map_err(|_| VultisigResponseError::InvalidHex { index, field })
}

fn decode_canonical_hex(
    value: &str,
    index: usize,
    field: &'static str,
) -> Result<Vec<u8>, VultisigResponseError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VultisigResponseError::InvalidHex { index, field });
    }
    hex::decode(value).map_err(|_| VultisigResponseError::InvalidHex { index, field })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test vectors")]

    use alloy_primitives::{Address, U256};
    use xindex_custody_core::prepare::{EvmPrepared, EvmSigning};

    use super::*;
    use crate::chain::vultisig_chain_profile;
    use crate::request::VultisigVaultConfig;

    const GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn fixed_secp_response() -> (VultisigSigningPayload, VultisigKeysignResponse) {
        let mut message = [0u8; 32];
        message[31] = 1;
        let compact = hex::decode(
            "6673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e88984c1a971652e0ada880120ef8025e709fff2080c4a39aae068d12eed009b68c89",
        )
        .expect("fixed compact signature");
        let signature = Secp256k1Signature::from_slice(&compact).expect("fixed signature");
        let expected = Secp256k1VerifyingKey::from_sec1_bytes(&GENERATOR).expect("generator");
        let recovery_id = [0u8, 1]
            .into_iter()
            .find(|candidate| {
                let Some(recovery_id) = RecoveryId::from_byte(*candidate) else {
                    return false;
                };
                Secp256k1VerifyingKey::recover_from_prehash(&message, &signature, recovery_id)
                    .is_ok_and(|recovered| recovered == expected)
            })
            .expect("fixed tuple recovery id");
        (
            VultisigSigningPayload {
                message: message.to_vec(),
                lookup_hash: [0; 32],
            },
            VultisigKeysignResponse {
                msg: BASE64.encode(message),
                r: hex::encode(&compact[..32]),
                s: hex::encode(&compact[32..]),
                der_signature: hex::encode(signature.to_der().as_bytes()),
                recovery_id: format!("{recovery_id:02x}"),
            },
        )
    }

    #[test]
    fn fixed_key_free_secp_tuple_verifies_with_recovery_and_der_binding() {
        let (payload, response) = fixed_secp_response();
        assert!(matches!(
            verify_response(
                0,
                &payload,
                &response,
                VultisigPublicKey::Secp256k1(GENERATOR),
            ),
            Ok(VerifiedSignature::Secp256k1 { .. })
        ));
    }

    #[test]
    fn secp_response_rejects_message_der_and_high_s_mutations() {
        let (payload, mut response) = fixed_secp_response();
        response.msg = BASE64.encode([2u8; 32]);
        assert_eq!(
            verify_response(
                0,
                &payload,
                &response,
                VultisigPublicKey::Secp256k1(GENERATOR),
            ),
            Err(VultisigResponseError::MessageMismatch { index: 0 })
        );

        let (_, mut response) = fixed_secp_response();
        response.der_signature.push_str("00");
        assert_eq!(
            verify_response(
                0,
                &payload,
                &response,
                VultisigPublicKey::Secp256k1(GENERATOR),
            ),
            Err(VultisigResponseError::DerMismatch { index: 0 })
        );

        let (_, mut response) = fixed_secp_response();
        response.s = "b3e568e9ad1f52577fedf107fda18f5ebb8e5c220badf23532bf6fbcc67fb4b8".to_string();
        assert_eq!(
            verify_response(
                0,
                &payload,
                &response,
                VultisigPublicKey::Secp256k1(GENERATOR),
            ),
            Err(VultisigResponseError::HighS { index: 0 })
        );
    }

    #[test]
    fn fixed_rfc8032_ed25519_tuple_verifies_without_a_recovery_id() {
        let public_key =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .expect("RFC public key")
                .try_into()
                .expect("32-byte public key");
        let signature = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .expect("RFC signature");
        let payload = VultisigSigningPayload {
            message: Vec::new(),
            lookup_hash: [0; 32],
        };
        let response = VultisigKeysignResponse {
            msg: String::new(),
            r: hex::encode(&signature[..32]),
            s: hex::encode(&signature[32..]),
            der_signature: String::new(),
            recovery_id: String::new(),
        };

        assert!(matches!(
            verify_response(
                0,
                &payload,
                &response,
                VultisigPublicKey::Ed25519(public_key),
            ),
            Ok(VerifiedSignature::Ed25519(_))
        ));
    }

    #[test]
    fn response_json_rejects_unknown_fields() {
        let json = r#"{
            "msg":"", "r":"00", "s":"00", "der_signature":"",
            "recovery_id":"", "unexpected":true
        }"#;
        assert!(serde_json::from_str::<VultisigKeysignResponse>(json).is_err());
    }

    #[test]
    fn finalization_failure_retains_the_non_cloneable_request() {
        let mut message = [0u8; 32];
        message[31] = 1;
        let config = VultisigVaultConfig::new(
            ChainId::Eth,
            GENERATOR,
            VultisigPublicKey::Secp256k1(GENERATOR),
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        )
        .expect("fixed vault configuration");
        let request = AuthorizedVultisigKeysign {
            prepare_key: hex::encode(message),
            spend: PreparedSpend::Evm(EvmPrepared {
                chain: ChainId::Eth,
                to: Address::repeat_byte(0x11),
                value: U256::ZERO,
                data: Vec::new(),
                signing: EvmSigning {
                    nonce: 0,
                    gas_limit: 21_000,
                    max_fee_per_gas: 1,
                    max_priority_fee_per_gas: 1,
                    gas_price: 0,
                },
                ric: None,
                spend_identity: vec![0],
            }),
            config,
            profile: vultisig_chain_profile(ChainId::Eth),
            transaction_bytes: Vec::new(),
            sign_bytes: None,
            payloads: vec![VultisigSigningPayload {
                message: message.to_vec(),
                lookup_hash: [0; 32],
            }],
            bitcoin_authorization: None,
        };

        let failure = finalize_vultisig_keysign(request, Vec::new())
            .expect_err("missing response must fail locally");
        assert_eq!(
            failure.error(),
            &VultisigResponseError::ResponseCount {
                expected: 1,
                actual: 0,
            }
        );
        assert_eq!(failure.request().payloads().len(), 1);
        assert_eq!(failure.into_request().payloads().len(), 1);
    }
}
