//! Sealed, policy-authorized Vultisig plugin keysign requests.
//!
//! Callers cannot construct [`AuthorizedVultisigKeysign`] directly. The only
//! public entry consumes custody-node's non-cloneable authorization after the
//! complete Xindex RIC/ACC, fee, payload and one-shot checks pass, then
//! independently reconstructs the exact transaction and signing bytes again.

use alloy_primitives::hex;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use bitcoin::secp256k1::PublicKey as Secp256k1PublicKey;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use xindex_chain_utxo::single_key::derive_single_key_psbt_sighashes;
use xindex_cosmos_tx::tx::{build_direct_signing_package, CosmosTxParams};
use xindex_custody_core::evm_tx::{build_unsigned, EvmUnsignedParams};
use xindex_custody_core::prepare::{AccountSigning, BindContext, PreparedSpend};
use xindex_custody_node::dispatch::AuthorizedPreparedSpend;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::TronAssetKind;
use xindex_solana_tx::message::{build_transfer_message, serialize_transaction};
use xindex_solana_tx::Pubkey;
use xindex_tron_tx::addr::{
    decode_base58check as decode_tron_address, decode_to_evm20, pubkey_to_address,
};
use xindex_tron_tx::tx::{
    build_trx_raw_data, build_usdt_raw_data, txid as tron_txid, Tapos, TrxTransfer, UsdtTransfer,
};
use xindex_xrp_tx::addr::{
    account_id as xrp_account_id, decode_classic_address, encode_classic_address,
};
use xindex_xrp_tx::signing::single_sign_digest;
use xindex_xrp_tx::tx::{serialize_single_sign, PaymentBody};

use crate::chain::{vultisig_chain_profile, VultisigChainProfile, VultisigSignatureScheme};

const TRANSACTION_TYPE: &str = "xindex_custody_spend";
const BITCOIN_OPERATION_ID_DOMAIN: &[u8] = b"XINDEX/VULTISIG/BTC-KEYSIGN-OPERATION/V1";
const MAX_EVIDENCE_IDENTITY_BYTES: usize = 256;

/// Reviewed release and vault topology bound to one Bitcoin keysign request.
///
/// This configuration is attached only after the strict finalized-inventory
/// policy and custody one-shot have both passed. Participant identities are
/// supplied by the exact connector verifier topology after the relay reports
/// the actual session parties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VultisigBitcoinEvidenceConfig {
    upstream_release_manifest_sha256: [u8; 32],
    vault_id: String,
    threshold: u16,
    reshare_epoch: u64,
}

impl VultisigBitcoinEvidenceConfig {
    /// Construct one reviewed Bitcoin evidence topology.
    ///
    /// # Errors
    /// Placeholder release identities, non-canonical vault IDs, and a zero
    /// threshold fail closed.
    pub fn new(
        upstream_release_manifest_sha256: [u8; 32],
        vault_id: impl Into<String>,
        threshold: u16,
        reshare_epoch: u64,
    ) -> Result<Self, VultisigRequestError> {
        if upstream_release_manifest_sha256 == [0; 32] {
            return Err(VultisigRequestError::Config(
                "Bitcoin evidence release-manifest identity must be non-zero".to_string(),
            ));
        }
        let vault_id = vault_id.into();
        if vault_id.is_empty()
            || vault_id.len() > MAX_EVIDENCE_IDENTITY_BYTES
            || vault_id.trim() != vault_id
            || !vault_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(VultisigRequestError::Config(
                "Bitcoin evidence vault ID must be canonical printable ASCII".to_string(),
            ));
        }
        if threshold == 0 {
            return Err(VultisigRequestError::Config(
                "Bitcoin evidence threshold must be non-zero".to_string(),
            ));
        }
        Ok(Self {
            upstream_release_manifest_sha256,
            vault_id,
            threshold,
            reshare_epoch,
        })
    }

    /// SHA-256 of the reviewed aggregate upstream release manifest.
    #[must_use]
    pub const fn upstream_release_manifest_sha256(&self) -> [u8; 32] {
        self.upstream_release_manifest_sha256
    }

    /// Exact reviewed Vultisig vault identity.
    #[must_use]
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// Required DKLS threshold for the configured participant set.
    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Reviewed reshare generation for the configured vault.
    #[must_use]
    pub const fn reshare_epoch(&self) -> u64 {
        self.reshare_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BitcoinAuthorizationBinding {
    pub(crate) max_fee_sats: u64,
    pub(crate) initial_policy_id: [u8; 32],
    pub(crate) initial_provenance_id: [u8; 32],
    pub(crate) evidence: VultisigBitcoinEvidenceConfig,
    pub(crate) operation_id: [u8; 32],
}

/// Non-authorizing data needed to re-cross the strict Bitcoin policy after a
/// process restart.
///
/// The connector journal stores the same sealed PSBT and RIC/ACC material that
/// was authorized before signing. Recovery reissues current finalized inputs
/// and consumes the same one-shot idempotently; this value alone cannot sign or
/// broadcast anything.
#[derive(Debug, Clone)]
pub struct VultisigBitcoinRecoveryMaterial {
    context: BindContext,
    max_fee_sats: u64,
    expected_signing_hashes: Vec<[u8; 32]>,
    operation_id: [u8; 32],
}

impl VultisigBitcoinRecoveryMaterial {
    /// Exact PSBT and RIC/ACC data retained by the sealed request.
    #[must_use]
    pub const fn context(&self) -> &BindContext {
        &self.context
    }

    /// Original absolute fee ceiling used before signing.
    #[must_use]
    pub const fn max_fee_sats(&self) -> u64 {
        self.max_fee_sats
    }

    /// Complete ordered signing hashes retained by the sealed request.
    #[must_use]
    pub fn expected_signing_hashes(&self) -> &[[u8; 32]] {
        &self.expected_signing_hashes
    }

    /// Content identity joining the strict policy, sealed request, and
    /// evidence topology.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 32] {
        self.operation_id
    }
}

/// Exact derived public key expected to verify a Vultisig signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VultisigPublicKey {
    /// Compressed secp256k1 child public key for the chain derivation path.
    Secp256k1([u8; 33]),
    /// Ed25519 vault public key. Solana has no BIP-32 derivation path in the
    /// reviewed verifier.
    Ed25519([u8; 32]),
}

impl VultisigPublicKey {
    fn scheme(self) -> VultisigSignatureScheme {
        match self {
            Self::Secp256k1(_) => VultisigSignatureScheme::Secp256k1,
            Self::Ed25519(_) => VultisigSignatureScheme::Ed25519,
        }
    }
}

/// Reviewed vault and plugin identities for one exact Xindex chain profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VultisigVaultConfig {
    pub(crate) chain: ChainId,
    pub(crate) vault_ecdsa_public_key: [u8; 33],
    pub(crate) signing_public_key: VultisigPublicKey,
    pub(crate) plugin_id: String,
    pub(crate) policy_id: String,
}

impl VultisigVaultConfig {
    /// Construct a chain-pinned vault configuration.
    ///
    /// # Errors
    /// Invalid curve points, a zero Ed25519 key, non-canonical UUIDs, or a key
    /// family that differs from the chain profile fail closed.
    pub fn new(
        chain: ChainId,
        vault_ecdsa_public_key: [u8; 33],
        signing_public_key: VultisigPublicKey,
        plugin_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Result<Self, VultisigRequestError> {
        Secp256k1PublicKey::from_slice(&vault_ecdsa_public_key).map_err(|_| {
            VultisigRequestError::Config(
                "vault ECDSA public key is not a compressed secp256k1 point".to_string(),
            )
        })?;
        match signing_public_key {
            VultisigPublicKey::Secp256k1(bytes) => {
                Secp256k1PublicKey::from_slice(&bytes).map_err(|_| {
                    VultisigRequestError::Config(
                        "derived signing public key is not a compressed secp256k1 point"
                            .to_string(),
                    )
                })?;
            }
            VultisigPublicKey::Ed25519(bytes) => {
                let verifying_key = Ed25519VerifyingKey::from_bytes(&bytes).map_err(|_| {
                    VultisigRequestError::Config(
                        "Ed25519 signing public key is not a valid point".to_string(),
                    )
                })?;
                if bytes == [0; 32] || verifying_key.is_weak() {
                    return Err(VultisigRequestError::Config(
                        "Ed25519 signing public key must not be zero or small-order".to_string(),
                    ));
                }
            }
        }

        let profile = vultisig_chain_profile(chain);
        if signing_public_key.scheme() != profile.signature_scheme() {
            return Err(VultisigRequestError::KeySchemeMismatch {
                chain,
                expected: profile.signature_scheme(),
                supplied: signing_public_key.scheme(),
            });
        }

        let plugin_id = plugin_id.into();
        let policy_id = policy_id.into();
        if !is_canonical_uuid(&plugin_id) {
            return Err(VultisigRequestError::Config(
                "plugin ID is not a canonical UUID".to_string(),
            ));
        }
        if !is_canonical_uuid(&policy_id) {
            return Err(VultisigRequestError::Config(
                "policy ID is not a canonical UUID".to_string(),
            ));
        }

        Ok(Self {
            chain,
            vault_ecdsa_public_key,
            signing_public_key,
            plugin_id,
            policy_id,
        })
    }

    /// Chain identity this vault profile may sign for.
    #[must_use]
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Exact chain-derived public key used for local signature verification.
    #[must_use]
    pub const fn signing_public_key(&self) -> VultisigPublicKey {
        self.signing_public_key
    }
}

/// One exact message independently reconstructed from the authorized spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VultisigSigningPayload {
    pub(crate) message: Vec<u8>,
    pub(crate) lookup_hash: [u8; 32],
}

impl VultisigSigningPayload {
    /// Exact bytes supplied to DKLS/EdDSA signing.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Exact Vultisig result-map lookup key.
    #[must_use]
    pub const fn lookup_hash(&self) -> [u8; 32] {
        self.lookup_hash
    }
}

/// Opaque, non-cloneable capability for one authorized Vultisig signing
/// operation.
#[derive(Debug)]
pub struct AuthorizedVultisigKeysign {
    pub(crate) prepare_key: String,
    pub(crate) spend: PreparedSpend,
    pub(crate) config: VultisigVaultConfig,
    pub(crate) profile: VultisigChainProfile,
    pub(crate) transaction_bytes: Vec<u8>,
    pub(crate) sign_bytes: Option<Vec<u8>>,
    pub(crate) payloads: Vec<VultisigSigningPayload>,
    pub(crate) bitcoin_authorization: Option<BitcoinAuthorizationBinding>,
}

impl AuthorizedVultisigKeysign {
    /// Exact Xindex chain/Vultisig wire profile.
    #[must_use]
    pub const fn profile(&self) -> VultisigChainProfile {
        self.profile
    }

    /// Exact transaction bytes independently reconstructed from the approved
    /// prepared spend.
    #[must_use]
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }

    /// Cosmos protobuf `SignDoc` bytes; absent on every non-Cosmos family.
    #[must_use]
    pub fn sign_bytes(&self) -> Option<&[u8]> {
        self.sign_bytes.as_deref()
    }

    /// Complete ordered signing payload set (one per UTXO input, otherwise
    /// one).
    #[must_use]
    pub fn payloads(&self) -> &[VultisigSigningPayload] {
        &self.payloads
    }

    /// Strict Bitcoin evidence topology attached before remote signing.
    #[must_use]
    pub fn bitcoin_evidence_config(&self) -> Option<&VultisigBitcoinEvidenceConfig> {
        self.bitcoin_authorization
            .as_ref()
            .map(|binding| &binding.evidence)
    }

    /// Stable identity of a strict Bitcoin keysign operation.
    #[must_use]
    pub fn bitcoin_operation_id(&self) -> Option<[u8; 32]> {
        self.bitcoin_authorization
            .as_ref()
            .map(|binding| binding.operation_id)
    }

    /// Reconstruct non-authorizing material for a current-policy restart
    /// check. Generic or non-Bitcoin requests return `Ok(None)`.
    ///
    /// # Errors
    /// A corrupted strict marker, spend family, or payload width fails closed.
    pub fn bitcoin_recovery_material(
        &self,
    ) -> Result<Option<VultisigBitcoinRecoveryMaterial>, VultisigRequestError> {
        let Some(binding) = &self.bitcoin_authorization else {
            return Ok(None);
        };
        let PreparedSpend::DirectUtxo(context) = &self.spend else {
            return Err(VultisigRequestError::Reconstruction(
                "strict Bitcoin authorization is attached to another spend family".to_string(),
            ));
        };
        if context.chain != ChainId::Btc {
            return Err(VultisigRequestError::Reconstruction(
                "strict Bitcoin authorization is attached to a non-BTC chain".to_string(),
            ));
        }
        let expected_signing_hashes = self
            .payloads
            .iter()
            .map(|payload| {
                payload.message.as_slice().try_into().map_err(|_| {
                    VultisigRequestError::Reconstruction(
                        "strict Bitcoin signing payload is not 32 bytes".to_string(),
                    )
                })
            })
            .collect::<Result<Vec<[u8; 32]>, _>>()?;
        validate_bitcoin_binding(self, binding)?;
        Ok(Some(VultisigBitcoinRecoveryMaterial {
            context: (**context).clone(),
            max_fee_sats: binding.max_fee_sats,
            expected_signing_hashes,
            operation_id: binding.operation_id,
        }))
    }

    /// Materialize the reviewed verifier JSON schema with fresh coordinator
    /// session material. The sealed capability itself remains consumed only by
    /// final signature verification.
    ///
    /// # Errors
    /// A non-canonical or non-v4 session UUID fails closed.
    pub fn wire_request(
        &self,
        session_id: &str,
        encryption_key: [u8; 16],
    ) -> Result<VultisigPluginKeysignRequest, VultisigRequestError> {
        if !is_uuid_v4(session_id) {
            return Err(VultisigRequestError::Wire(
                "session ID must be a canonical UUIDv4".to_string(),
            ));
        }
        let messages = self
            .payloads
            .iter()
            .map(|payload| VultisigKeysignMessage {
                tx_indexer_id: String::new(),
                raw_message: String::new(),
                message: BASE64.encode(&payload.message),
                hash: BASE64.encode(payload.lookup_hash),
                hash_function: "SHA256",
                chain: self.profile.upstream_name().to_string(),
            })
            .collect();
        Ok(VultisigPluginKeysignRequest {
            public_key: hex::encode(self.config.vault_ecdsa_public_key),
            messages,
            session: session_id.to_string(),
            hex_encryption_key: hex::encode(encryption_key),
            parties: Vec::new(),
            plugin_id: self.config.plugin_id.clone(),
            policy_id: self.config.policy_id.clone(),
            transactions: BASE64.encode(&self.transaction_bytes),
            transaction_type: TRANSACTION_TYPE,
            sign_bytes: self.sign_bytes.as_ref().map(|bytes| BASE64.encode(bytes)),
        })
    }
}

/// Exact upstream `KeysignMessage` JSON shape.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct VultisigKeysignMessage {
    tx_indexer_id: String,
    raw_message: String,
    message: String,
    hash: String,
    hash_function: &'static str,
    chain: String,
}

/// Exact upstream `PluginKeysignRequest` JSON shape.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct VultisigPluginKeysignRequest {
    public_key: String,
    messages: Vec<VultisigKeysignMessage>,
    session: String,
    hex_encryption_key: String,
    parties: Vec<String>,
    plugin_id: String,
    policy_id: String,
    transactions: String,
    transaction_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sign_bytes: Option<String>,
}

/// Failure to reconstruct or bind a sealed Vultisig signing request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VultisigRequestError {
    /// Static vault/plugin configuration is invalid.
    #[error("invalid Vultisig configuration: {0}")]
    Config(String),
    /// The authorized prepared spend belongs to a different chain profile.
    #[error("authorized spend chain {spend:?} differs from configured chain {configured:?}")]
    ChainMismatch {
        /// Chain carried by the prepared spend.
        spend: ChainId,
        /// Chain pinned by the vault configuration.
        configured: ChainId,
    },
    /// The configured derived key family does not match the chain.
    #[error(
        "Vultisig key scheme mismatch for {chain:?}: expected {expected:?}, supplied {supplied:?}"
    )]
    KeySchemeMismatch {
        /// Chain being configured.
        chain: ChainId,
        /// Scheme selected by its reviewed Vultisig profile.
        expected: VultisigSignatureScheme,
        /// Scheme supplied by configuration.
        supplied: VultisigSignatureScheme,
    },
    /// A signing key embedded in the authorized transaction differs from the
    /// configured derived key.
    #[error("authorized transaction signing public key differs from the configured Vultisig key")]
    SigningKeyMismatch,
    /// The family has not yet reached the sealed request boundary.
    #[error("Vultisig request reconstruction is not implemented for {0:?}")]
    Unsupported(ChainId),
    /// Canonical transaction reconstruction failed.
    #[error("Vultisig transaction reconstruction failed: {0}")]
    Reconstruction(String),
    /// The reconstructed message differs from the message authorized by
    /// custody-node.
    #[error("reconstructed Vultisig message does not equal the authorized prepare key")]
    AuthorizationMismatch,
    /// Fresh wire/session material is invalid.
    #[error("invalid Vultisig wire request: {0}")]
    Wire(String),
}

/// Consume the complete custody authorization and produce an opaque Vultisig
/// signing capability for the same exact bytes.
///
/// # Errors
/// Chain/key mismatch, unsupported transaction profile, reconstruction error,
/// or disagreement with the custody-authorized signing payload fails closed.
pub fn prepare_vultisig_keysign(
    authorization: AuthorizedPreparedSpend,
    config: VultisigVaultConfig,
) -> Result<AuthorizedVultisigKeysign, VultisigRequestError> {
    let (prepare_key, spend) = authorization.into_parts();
    build_from_parts(prepare_key, spend, config)
}

#[expect(
    clippy::too_many_lines,
    reason = "one exhaustive family match keeps transaction reconstruction and payload binding local"
)]
pub(crate) fn build_from_parts(
    prepare_key: String,
    spend: PreparedSpend,
    config: VultisigVaultConfig,
) -> Result<AuthorizedVultisigKeysign, VultisigRequestError> {
    let spend_chain = match &spend {
        PreparedSpend::Btc(context) | PreparedSpend::DirectUtxo(context) => context.chain,
        PreparedSpend::Zcash(_) => ChainId::Zec,
        PreparedSpend::Evm(prepared) => prepared.chain,
        PreparedSpend::Account(prepared) => prepared.chain,
    };
    if spend_chain != config.chain {
        return Err(VultisigRequestError::ChainMismatch {
            spend: spend_chain,
            configured: config.chain,
        });
    }
    let profile = vultisig_chain_profile(spend_chain);
    if profile.signature_scheme() != config.signing_public_key.scheme() {
        return Err(VultisigRequestError::KeySchemeMismatch {
            chain: spend_chain,
            expected: profile.signature_scheme(),
            supplied: config.signing_public_key.scheme(),
        });
    }

    let (transaction_bytes, sign_bytes, messages, lookup_is_message) = match &spend {
        PreparedSpend::DirectUtxo(context) => {
            let expected_key = match config.signing_public_key {
                VultisigPublicKey::Secp256k1(key) => key,
                VultisigPublicKey::Ed25519(_) => {
                    return Err(VultisigRequestError::SigningKeyMismatch)
                }
            };
            let messages =
                derive_single_key_psbt_sighashes(context.chain, &context.psbt, &expected_key)
                    .map_err(|error| VultisigRequestError::Reconstruction(error.to_string()))?
                    .into_iter()
                    .map(|message| message.to_vec())
                    .collect();
            (context.psbt.serialize(), None, messages, false)
        }
        PreparedSpend::Zcash(context) => {
            let expected_key = match config.signing_public_key {
                VultisigPublicKey::Secp256k1(key) => key,
                VultisigPublicKey::Ed25519(_) => {
                    return Err(VultisigRequestError::SigningKeyMismatch)
                }
            };
            if context.transaction.aggregate_public_key() != expected_key {
                return Err(VultisigRequestError::SigningKeyMismatch);
            }
            let messages = context
                .transaction
                .signing_hashes()
                .map_err(|error| VultisigRequestError::Reconstruction(error.to_string()))?
                .into_iter()
                .map(|message| message.to_vec())
                .collect();
            let transaction_bytes = context
                .transaction
                .serialize_with_metadata()
                .map_err(|error| VultisigRequestError::Reconstruction(error.to_string()))?;
            (transaction_bytes, None, messages, false)
        }
        PreparedSpend::Evm(prepared) => {
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
            .ok_or_else(|| VultisigRequestError::Reconstruction("not an EVM chain".to_string()))?;
            (
                unsigned.encoded_for_vultisig(),
                None,
                vec![unsigned.signature_hash().as_slice().to_vec()],
                false,
            )
        }
        PreparedSpend::Account(prepared) => match &prepared.signing {
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
                let expected_key = match config.signing_public_key {
                    VultisigPublicKey::Secp256k1(key) => key,
                    VultisigPublicKey::Ed25519(_) => {
                        return Err(VultisigRequestError::SigningKeyMismatch)
                    }
                };
                if signing_pub_key.as_slice() != expected_key {
                    return Err(VultisigRequestError::SigningKeyMismatch);
                }
                let fee_amount = fee_amount.to_string();
                let params = CosmosTxParams {
                    from_address,
                    to_address: &prepared.to_address,
                    denom,
                    send_amount: &prepared.amount_dec,
                    fee_amount: &fee_amount,
                    gas_limit: *gas_limit,
                    memo: &prepared.memo,
                    sequence: *sequence,
                };
                let package = build_direct_signing_package(
                    &expected_key,
                    &params,
                    cosmos_chain_id,
                    *account_number,
                );
                (
                    package.unsigned_tx_bytes().to_vec(),
                    Some(package.sign_doc_bytes().to_vec()),
                    vec![package.signing_hash().to_vec()],
                    true,
                )
            }
            AccountSigning::Xrp {
                account_address,
                signing_pub_key,
                sequence,
                last_ledger_sequence,
                fee_drops,
            } => {
                let expected_key = match config.signing_public_key {
                    VultisigPublicKey::Secp256k1(key) => key,
                    VultisigPublicKey::Ed25519(_) => {
                        return Err(VultisigRequestError::SigningKeyMismatch)
                    }
                };
                if signing_pub_key.as_slice() != expected_key
                    || encode_classic_address(&xrp_account_id(&expected_key)) != *account_address
                {
                    return Err(VultisigRequestError::SigningKeyMismatch);
                }
                let amount_drops = prepared.amount_dec.parse::<u64>().map_err(|error| {
                    VultisigRequestError::Reconstruction(format!("XRP amount: {error}"))
                })?;
                let fee_drops = u64::try_from(*fee_drops).map_err(|_| {
                    VultisigRequestError::Reconstruction(
                        "XRP fee exceeds the u64 drops range".to_string(),
                    )
                })?;
                let account = decode_classic_address(account_address).map_err(|error| {
                    VultisigRequestError::Reconstruction(format!("XRP account: {error}"))
                })?;
                let destination =
                    decode_classic_address(&prepared.to_address).map_err(|error| {
                        VultisigRequestError::Reconstruction(format!("XRP destination: {error}"))
                    })?;
                let body = PaymentBody {
                    account,
                    destination,
                    amount_drops,
                    fee_drops,
                    sequence: *sequence,
                    last_ledger_sequence: Some(*last_ledger_sequence),
                    network_id: None,
                    memo: prepared.memo.clone().into_bytes(),
                };
                let unsigned = serialize_single_sign(&body, &expected_key).map_err(|error| {
                    VultisigRequestError::Reconstruction(format!("XRP serialize: {error}"))
                })?;
                let digest = single_sign_digest(&unsigned);
                (unsigned, None, vec![digest.to_vec()], true)
            }
            AccountSigning::Solana {
                from_pubkey,
                recent_blockhash,
            } => {
                let expected_key = match config.signing_public_key {
                    VultisigPublicKey::Ed25519(key) => key,
                    VultisigPublicKey::Secp256k1(_) => {
                        return Err(VultisigRequestError::SigningKeyMismatch)
                    }
                };
                if *from_pubkey != expected_key {
                    return Err(VultisigRequestError::SigningKeyMismatch);
                }
                let lamports = prepared.amount_dec.parse::<u64>().map_err(|error| {
                    VultisigRequestError::Reconstruction(format!("Solana amount: {error}"))
                })?;
                let destination = Pubkey::from_base58(&prepared.to_address).map_err(|error| {
                    VultisigRequestError::Reconstruction(format!("Solana destination: {error}"))
                })?;
                let (_, message) = build_transfer_message(
                    Pubkey::new(expected_key),
                    destination,
                    lamports,
                    &prepared.memo,
                    *recent_blockhash,
                )
                .map_err(|error| {
                    VultisigRequestError::Reconstruction(format!("Solana message: {error}"))
                })?;
                let unsigned = serialize_transaction(&message, &[[0; 64]]).map_err(|error| {
                    VultisigRequestError::Reconstruction(format!(
                        "Solana unsigned transaction: {error}"
                    ))
                })?;
                (unsigned, None, vec![message], false)
            }
            AccountSigning::Tron {
                owner_address,
                asset,
                contract_address,
                ref_block_bytes,
                ref_block_hash,
                expiration,
                timestamp,
                fee_limit,
                permission_id,
            } => {
                let expected_key = match config.signing_public_key {
                    VultisigPublicKey::Secp256k1(key) => key,
                    VultisigPublicKey::Ed25519(_) => {
                        return Err(VultisigRequestError::SigningKeyMismatch)
                    }
                };
                let expected_address = pubkey_to_address(&expected_key).map_err(|error| {
                    VultisigRequestError::Reconstruction(format!("TRON public key: {error}"))
                })?;
                if expected_address != *owner_address {
                    return Err(VultisigRequestError::SigningKeyMismatch);
                }
                let amount = prepared.amount_dec.parse::<u64>().map_err(|error| {
                    VultisigRequestError::Reconstruction(format!("TRON amount: {error}"))
                })?;
                let owner = decode_tron_address(owner_address).map_err(|error| {
                    VultisigRequestError::Reconstruction(format!("TRON owner: {error}"))
                })?;
                let tapos = Tapos {
                    ref_block_bytes: *ref_block_bytes,
                    ref_block_hash: *ref_block_hash,
                    expiration: *expiration,
                    timestamp: *timestamp,
                    fee_limit: *fee_limit,
                    memo: prepared.memo.as_bytes().to_vec(),
                    permission_id: *permission_id,
                };
                let raw_data = match asset {
                    TronAssetKind::Trx => {
                        let to = decode_tron_address(&prepared.to_address).map_err(|error| {
                            VultisigRequestError::Reconstruction(format!(
                                "TRON destination: {error}"
                            ))
                        })?;
                        build_trx_raw_data(&TrxTransfer { owner, to, amount }, &tapos)
                    }
                    TronAssetKind::Usdt => {
                        let contract_address = contract_address.as_deref().ok_or_else(|| {
                            VultisigRequestError::Reconstruction(
                                "TRON USDT contract address is missing".to_string(),
                            )
                        })?;
                        let contract = decode_tron_address(contract_address).map_err(|error| {
                            VultisigRequestError::Reconstruction(format!(
                                "TRON USDT contract: {error}"
                            ))
                        })?;
                        let to_evm20 = decode_to_evm20(&prepared.to_address).map_err(|error| {
                            VultisigRequestError::Reconstruction(format!(
                                "TRON destination: {error}"
                            ))
                        })?;
                        build_usdt_raw_data(
                            &UsdtTransfer {
                                owner,
                                contract,
                                to_evm20,
                                amount,
                            },
                            &tapos,
                        )
                    }
                };
                let digest = tron_txid(&raw_data);
                (raw_data, None, vec![digest.to_vec()], true)
            }
            AccountSigning::Cosmos { .. } => {
                return Err(VultisigRequestError::Unsupported(prepared.chain));
            }
        },
        PreparedSpend::Btc(_) => return Err(VultisigRequestError::Unsupported(spend_chain)),
    };

    if !messages
        .iter()
        .any(|message| payloads_equal(&prepare_key, message))
    {
        return Err(VultisigRequestError::AuthorizationMismatch);
    }
    let payloads = messages
        .into_iter()
        .map(|message| {
            let lookup_hash = if lookup_is_message {
                message.as_slice().try_into().map_err(|_| {
                    VultisigRequestError::Reconstruction(
                        "direct lookup message is not 32 bytes".to_string(),
                    )
                })?
            } else {
                Sha256::digest(&message).into()
            };
            Ok(VultisigSigningPayload {
                message,
                lookup_hash,
            })
        })
        .collect::<Result<Vec<_>, VultisigRequestError>>()?;

    Ok(AuthorizedVultisigKeysign {
        prepare_key,
        spend,
        config,
        profile,
        transaction_bytes,
        sign_bytes,
        payloads,
        bitcoin_authorization: None,
    })
}

pub(crate) fn attach_bitcoin_authorization(
    request: &mut AuthorizedVultisigKeysign,
    max_fee_sats: u64,
    initial_policy_id: [u8; 32],
    initial_provenance_id: [u8; 32],
    evidence: VultisigBitcoinEvidenceConfig,
) -> Result<(), VultisigRequestError> {
    if request.bitcoin_authorization.is_some()
        || request.profile.chain() != ChainId::Btc
        || !matches!(request.spend, PreparedSpend::DirectUtxo(_))
        || max_fee_sats == 0
        || initial_policy_id == [0; 32]
        || initial_provenance_id == [0; 32]
    {
        return Err(VultisigRequestError::Config(
            "strict Bitcoin authorization metadata is invalid".to_string(),
        ));
    }
    let mut binding = BitcoinAuthorizationBinding {
        max_fee_sats,
        initial_policy_id,
        initial_provenance_id,
        evidence,
        operation_id: [0; 32],
    };
    binding.operation_id = compute_bitcoin_operation_id(request, &binding)?;
    request.bitcoin_authorization = Some(binding);
    Ok(())
}

pub(crate) fn restore_bitcoin_authorization(
    request: &mut AuthorizedVultisigKeysign,
    binding: BitcoinAuthorizationBinding,
) -> Result<(), VultisigRequestError> {
    if request.bitcoin_authorization.is_some() {
        return Err(VultisigRequestError::Config(
            "strict Bitcoin authorization metadata is duplicated".to_string(),
        ));
    }
    validate_bitcoin_binding(request, &binding)?;
    request.bitcoin_authorization = Some(binding);
    Ok(())
}

fn validate_bitcoin_binding(
    request: &AuthorizedVultisigKeysign,
    binding: &BitcoinAuthorizationBinding,
) -> Result<(), VultisigRequestError> {
    if request.profile.chain() != ChainId::Btc
        || !matches!(request.spend, PreparedSpend::DirectUtxo(_))
        || binding.max_fee_sats == 0
        || binding.initial_policy_id == [0; 32]
        || binding.initial_provenance_id == [0; 32]
        || binding.operation_id == [0; 32]
        || compute_bitcoin_operation_id(request, binding)? != binding.operation_id
    {
        return Err(VultisigRequestError::Config(
            "strict Bitcoin authorization commitment is invalid".to_string(),
        ));
    }
    Ok(())
}

fn compute_bitcoin_operation_id(
    request: &AuthorizedVultisigKeysign,
    binding: &BitcoinAuthorizationBinding,
) -> Result<[u8; 32], VultisigRequestError> {
    let spend = request
        .spend
        .encode_durable()
        .map_err(|error| VultisigRequestError::Reconstruction(error.to_string()))?;
    let mut hasher = Sha256::new();
    hash_operation_field(&mut hasher, BITCOIN_OPERATION_ID_DOMAIN);
    hash_operation_field(&mut hasher, request.prepare_key.as_bytes());
    hash_operation_field(&mut hasher, &spend);
    hash_operation_field(&mut hasher, &request.transaction_bytes);
    hash_operation_field(&mut hasher, &binding.max_fee_sats.to_be_bytes());
    hash_operation_field(&mut hasher, &binding.initial_policy_id);
    hash_operation_field(&mut hasher, &binding.initial_provenance_id);
    hash_operation_field(
        &mut hasher,
        &binding.evidence.upstream_release_manifest_sha256,
    );
    hash_operation_field(&mut hasher, binding.evidence.vault_id.as_bytes());
    hash_operation_field(&mut hasher, &binding.evidence.threshold.to_be_bytes());
    hash_operation_field(&mut hasher, &binding.evidence.reshare_epoch.to_be_bytes());
    Ok(hasher.finalize().into())
}

fn hash_operation_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn payloads_equal(prepare_key: &str, message: &[u8]) -> bool {
    prepare_key
        .strip_prefix("0x")
        .unwrap_or(prepare_key)
        .eq_ignore_ascii_case(&hex::encode(message))
}

fn is_canonical_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
    })
}

fn is_uuid_v4(value: &str) -> bool {
    is_canonical_uuid(value)
        && value.as_bytes()[14] == b'4'
        && matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "deterministic request fixtures")]

    use alloy_primitives::{Address, U256};
    use base64::Engine as _;
    use sha2::Digest as _;
    use xindex_custody_core::evm_tx::{build_unsigned, EvmUnsignedParams};
    use xindex_custody_core::prepare::{
        AccountPrepared, AccountSigning, BindContext, EvmPrepared, EvmSigning, PreparedSpend,
        ZcashBindContext,
    };
    use xindex_shared::chain_registry::ChainId;
    use xindex_zcash_tx::{SaplingV4Transaction, TransparentInput, TransparentOutput};

    use super::{
        attach_bitcoin_authorization, build_from_parts, restore_bitcoin_authorization,
        VultisigBitcoinEvidenceConfig, VultisigPublicKey, VultisigVaultConfig,
    };
    use crate::VultisigSignatureScheme;

    const GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    const ED25519_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    fn config(chain: ChainId, signing_key: VultisigPublicKey) -> VultisigVaultConfig {
        VultisigVaultConfig::new(
            chain,
            GENERATOR,
            signing_key,
            "123e4567-e89b-12d3-a456-426614174000",
            "123e4567-e89b-12d3-a456-426614174001",
        )
        .expect("valid key-free fixture config")
    }

    fn evm_spend(chain: ChainId) -> (PreparedSpend, String) {
        let signing = EvmSigning {
            nonce: 7,
            gas_limit: 120_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 2_000_000_000,
            gas_price: 5_000_000_000,
        };
        let prepared = EvmPrepared {
            chain,
            to: Address::repeat_byte(0x22),
            value: U256::from(9),
            data: vec![0xde, 0xad, 0xbe, 0xef],
            signing: signing.clone(),
            ric: None,
            spend_identity: 7u64.to_be_bytes().to_vec(),
        };
        let unsigned = build_unsigned(&EvmUnsignedParams {
            chain,
            nonce: signing.nonce,
            gas_limit: signing.gas_limit,
            max_fee_per_gas: signing.max_fee_per_gas,
            max_priority_fee_per_gas: signing.max_priority_fee_per_gas,
            gas_price: signing.gas_price,
            to: prepared.to,
            value: prepared.value,
            data: &prepared.data,
        })
        .expect("EVM chain");
        (
            PreparedSpend::Evm(prepared),
            format!(
                "0x{}",
                alloy_primitives::hex::encode(unsigned.signature_hash())
            ),
        )
    }

    fn utxo_spend(chain: ChainId) -> (PreparedSpend, String) {
        use bitcoin::absolute::LockTime;
        use bitcoin::bip32::{DerivationPath, Fingerprint};
        use bitcoin::psbt::{Psbt, PsbtSighashType};
        use bitcoin::sighash::EcdsaSighashType;
        use bitcoin::transaction::Version;
        use bitcoin::{
            Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        };

        let public_key = PublicKey::from_slice(&GENERATOR).expect("fixed public key");
        let previous_script = match chain {
            ChainId::Btc | ChainId::Ltc => {
                ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().expect("compressed public key"))
            }
            ChainId::Bch | ChainId::Doge => ScriptBuf::new_p2pkh(&public_key.pubkey_hash()),
            _ => unreachable!("direct PSBT fixture chain"),
        };
        let previous = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(200_000),
                script_pubkey: previous_script,
            }],
        };
        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: previous.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(199_000),
                script_pubkey: ScriptBuf::new_p2pkh(&public_key.pubkey_hash()),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("PSBT");
        psbt.inputs[0].bip32_derivation.insert(
            public_key.inner,
            (Fingerprint::default(), DerivationPath::default()),
        );
        match chain {
            ChainId::Btc | ChainId::Ltc => {
                psbt.inputs[0].witness_utxo = Some(previous.output[0].clone());
                psbt.inputs[0].sighash_type = Some(EcdsaSighashType::All.into());
            }
            ChainId::Bch => {
                psbt.inputs[0].non_witness_utxo = Some(previous);
                psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0x41));
            }
            ChainId::Doge => {
                psbt.inputs[0].non_witness_utxo = Some(previous);
                psbt.inputs[0].sighash_type = Some(EcdsaSighashType::All.into());
            }
            _ => unreachable!("direct PSBT fixture chain"),
        }
        let sighashes = xindex_chain_utxo::single_key::derive_single_key_psbt_sighashes(
            chain, &psbt, &GENERATOR,
        )
        .expect("direct sighash");
        (
            PreparedSpend::DirectUtxo(Box::new(BindContext {
                chain,
                psbt,
                ric: None,
                acc: None,
            })),
            format!("0x{}", alloy_primitives::hex::encode(sighashes[0])),
        )
    }

    fn zcash_spend() -> (PreparedSpend, String, Vec<u8>) {
        let transaction = SaplingV4Transaction::new(
            GENERATOR,
            vec![TransparentInput::new([0x44; 32], 1, 200_000)],
            vec![TransparentOutput::new(199_000, vec![0x51])],
        )
        .expect("valid Zcash transaction");
        let signing_hash = transaction.signing_hashes().expect("ZIP-243 hash")[0];
        let metadata = transaction
            .serialize_with_metadata()
            .expect("Zcash verifier metadata");
        (
            PreparedSpend::Zcash(Box::new(ZcashBindContext {
                transaction,
                ric: None,
                acc: None,
            })),
            format!("0x{}", alloy_primitives::hex::encode(signing_hash)),
            metadata,
        )
    }

    #[test]
    fn strict_bitcoin_binding_survives_reconstruction_and_rejects_mutation() {
        let (spend, prepare_key) = utxo_spend(ChainId::Btc);
        let mut request = build_from_parts(
            prepare_key.clone(),
            spend,
            config(ChainId::Btc, VultisigPublicKey::Secp256k1(GENERATOR)),
        )
        .expect("direct Bitcoin request");
        let evidence =
            VultisigBitcoinEvidenceConfig::new([0x31; 32], "vault-testnet4-runtime", 2, 7)
                .expect("evidence config");
        attach_bitcoin_authorization(&mut request, 10_000, [0x41; 32], [0x42; 32], evidence)
            .expect("strict binding");
        let operation_id = request.bitcoin_operation_id().expect("strict operation ID");
        let recovery = request
            .bitcoin_recovery_material()
            .expect("recovery material")
            .expect("Bitcoin recovery marker");
        assert_eq!(recovery.max_fee_sats(), 10_000);
        assert_eq!(recovery.operation_id(), operation_id);
        assert_eq!(recovery.expected_signing_hashes().len(), 1);

        let binding = request
            .bitcoin_authorization
            .clone()
            .expect("durable binding");
        let (reconstructed_spend, reconstructed_key) = utxo_spend(ChainId::Btc);
        let mut reconstructed = build_from_parts(
            reconstructed_key,
            reconstructed_spend,
            config(ChainId::Btc, VultisigPublicKey::Secp256k1(GENERATOR)),
        )
        .expect("reconstructed request");
        restore_bitcoin_authorization(&mut reconstructed, binding.clone())
            .expect("exact durable reconstruction");
        assert_eq!(reconstructed.bitcoin_operation_id(), Some(operation_id));

        let (mutated_spend, mutated_key) = utxo_spend(ChainId::Btc);
        let mut mutated = build_from_parts(
            mutated_key,
            mutated_spend,
            config(ChainId::Btc, VultisigPublicKey::Secp256k1(GENERATOR)),
        )
        .expect("mutated request base");
        let mut mutated_binding = binding;
        mutated_binding.max_fee_sats += 1;
        assert!(restore_bitcoin_authorization(&mut mutated, mutated_binding).is_err());
    }

    #[test]
    fn every_evm_chain_builds_the_exact_verifier_request() {
        for chain in [
            ChainId::Eth,
            ChainId::Bsc,
            ChainId::Avax,
            ChainId::Base,
            ChainId::Pol,
        ] {
            let (spend, prepare_key) = evm_spend(chain);
            let request = build_from_parts(
                prepare_key,
                spend,
                config(chain, VultisigPublicKey::Secp256k1(GENERATOR)),
            )
            .expect("authorized EVM request");
            let wire = request
                .wire_request("123e4567-e89b-42d3-a456-426614174002", [0x11; 16])
                .expect("wire request");

            assert_eq!(wire.messages.len(), 1, "{chain:?}");
            assert_eq!(wire.messages[0].chain, request.profile().upstream_name());
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(&wire.transactions)
                    .expect("base64 transaction"),
                request.transaction_bytes(),
                "{chain:?}"
            );
            assert_eq!(
                request.profile().signature_scheme(),
                VultisigSignatureScheme::Secp256k1
            );
        }
    }

    #[test]
    fn vault_config_rejects_malformed_ed25519_points() {
        let mut small_order_identity = [0u8; 32];
        small_order_identity[0] = 1;
        assert!(VultisigVaultConfig::new(
            ChainId::Sol,
            GENERATOR,
            VultisigPublicKey::Ed25519(small_order_identity),
            "123e4567-e89b-12d3-a456-426614174000",
            "123e4567-e89b-12d3-a456-426614174001",
        )
        .is_err());
    }

    #[test]
    fn four_psbt_utxo_chains_build_complete_per_input_requests() {
        for chain in [ChainId::Btc, ChainId::Ltc, ChainId::Bch, ChainId::Doge] {
            let (spend, prepare_key) = utxo_spend(chain);
            let expected_transaction = match &spend {
                PreparedSpend::DirectUtxo(context) => context.psbt.serialize(),
                _ => unreachable!("UTXO fixture variant"),
            };
            let request = build_from_parts(
                prepare_key,
                spend,
                config(chain, VultisigPublicKey::Secp256k1(GENERATOR)),
            )
            .expect("direct UTXO request");

            assert_eq!(request.transaction_bytes(), expected_transaction);
            assert_eq!(request.payloads().len(), 1);
            assert_eq!(
                request.payloads()[0].lookup_hash(),
                <[u8; 32]>::from(sha2::Sha256::digest(request.payloads()[0].message())),
                "{chain:?}"
            );
        }
    }

    #[test]
    fn zcash_builds_the_exact_sapling_metadata_request() {
        let (spend, prepare_key, expected_metadata) = zcash_spend();
        let request = build_from_parts(
            prepare_key,
            spend,
            config(ChainId::Zec, VultisigPublicKey::Secp256k1(GENERATOR)),
        )
        .expect("authorized Zcash request");

        assert_eq!(request.transaction_bytes(), expected_metadata);
        assert_eq!(request.payloads().len(), 1);
        assert_eq!(
            request.payloads()[0].lookup_hash(),
            <[u8; 32]>::from(sha2::Sha256::digest(request.payloads()[0].message()))
        );
        assert_eq!(request.profile().upstream_name(), "Zcash");
    }

    #[test]
    fn gaia_and_noble_use_direct_sign_doc_bytes() {
        for chain in [ChainId::Gaia, ChainId::Noble] {
            let (from, to, chain_id, denom) = match chain {
                ChainId::Gaia => (
                    "cosmos1custody",
                    "cosmos1asgardvault",
                    "cosmoshub-4",
                    "uatom",
                ),
                ChainId::Noble => ("noble1custody", "noble1asgardvault", "noble-1", "uusdc"),
                _ => unreachable!("fixture chain"),
            };
            let prepared = AccountPrepared {
                chain,
                to_address: to.to_string(),
                amount_dec: "5000000".to_string(),
                memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
                signing: AccountSigning::CosmosDirect {
                    from_address: from.to_string(),
                    cosmos_chain_id: chain_id.to_string(),
                    account_number: 42,
                    sequence: 7,
                    denom: denom.to_string(),
                    fee_amount: 5_000,
                    gas_limit: 200_000,
                    signing_pub_key: GENERATOR.to_vec(),
                },
                ric: None,
                spend_identity: 7u64.to_be_bytes().to_vec(),
            };
            let params = xindex_cosmos_tx::tx::CosmosTxParams {
                from_address: from,
                to_address: to,
                denom,
                send_amount: "5000000",
                fee_amount: "5000",
                gas_limit: 200_000,
                memo: "=:ETH.USDT:0xrecipient:990000",
                sequence: 7,
            };
            let expected = xindex_cosmos_tx::tx::build_direct_signing_package(
                &GENERATOR, &params, chain_id, 42,
            );
            let request = build_from_parts(
                format!(
                    "0x{}",
                    alloy_primitives::hex::encode(expected.signing_hash())
                ),
                PreparedSpend::Account(prepared),
                config(chain, VultisigPublicKey::Secp256k1(GENERATOR)),
            )
            .expect("authorized Cosmos request");

            assert_eq!(request.transaction_bytes(), expected.unsigned_tx_bytes());
            assert_eq!(request.sign_bytes(), Some(expected.sign_doc_bytes()));
            assert_eq!(request.payloads()[0].message(), expected.signing_hash());
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "three native-family binding fixtures"
    )]
    fn xrp_solana_and_tron_bind_their_native_signing_messages() {
        let account_id = xindex_xrp_tx::addr::account_id(&GENERATOR);
        let xrp_address = xindex_xrp_tx::addr::encode_classic_address(&account_id);
        let xrp = AccountPrepared {
            chain: ChainId::Xrp,
            to_address: xrp_address.clone(),
            amount_dec: "1000000".to_string(),
            memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
            signing: AccountSigning::Xrp {
                account_address: xrp_address,
                signing_pub_key: GENERATOR.to_vec(),
                sequence: 9,
                last_ledger_sequence: 1_000,
                fee_drops: 12,
            },
            ric: None,
            spend_identity: 9u32.to_be_bytes().to_vec(),
        };
        let xrp_body = xindex_xrp_tx::tx::PaymentBody {
            account: account_id,
            destination: account_id,
            amount_drops: 1_000_000,
            fee_drops: 12,
            sequence: 9,
            last_ledger_sequence: Some(1_000),
            network_id: None,
            memo: b"=:ETH.USDT:0xrecipient:990000".to_vec(),
        };
        let xrp_unsigned =
            xindex_xrp_tx::tx::serialize_single_sign(&xrp_body, &GENERATOR).expect("XRP tx");
        let xrp_key = format!(
            "0x{}",
            alloy_primitives::hex::encode(xindex_xrp_tx::signing::single_sign_digest(
                &xrp_unsigned
            ))
        );
        let xrp_request = build_from_parts(
            xrp_key,
            PreparedSpend::Account(xrp),
            config(ChainId::Xrp, VultisigPublicKey::Secp256k1(GENERATOR)),
        )
        .expect("XRP request");
        assert_eq!(
            xrp_request.payloads()[0].lookup_hash(),
            xrp_request.payloads()[0].message()
        );

        let sol_destination = xindex_solana_tx::Pubkey::new([0x44; 32]).to_base58();
        let sol = AccountPrepared {
            chain: ChainId::Sol,
            to_address: sol_destination,
            amount_dec: "5000000".to_string(),
            memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
            signing: AccountSigning::Solana {
                from_pubkey: ED25519_PUBLIC_KEY,
                recent_blockhash: [0x55; 32],
            },
            ric: None,
            spend_identity: [0x55; 32].to_vec(),
        };
        let (_, sol_message) = xindex_solana_tx::message::build_transfer_message(
            xindex_solana_tx::Pubkey::new(ED25519_PUBLIC_KEY),
            xindex_solana_tx::Pubkey::new([0x44; 32]),
            5_000_000,
            "=:ETH.USDT:0xrecipient:990000",
            [0x55; 32],
        )
        .expect("Solana message");
        let sol_key = format!("0x{}", alloy_primitives::hex::encode(sol_message));
        let sol_request = build_from_parts(
            sol_key,
            PreparedSpend::Account(sol),
            config(ChainId::Sol, VultisigPublicKey::Ed25519(ED25519_PUBLIC_KEY)),
        )
        .expect("Solana request");
        assert_eq!(
            sol_request.payloads()[0].lookup_hash(),
            <[u8; 32]>::from(sha2::Sha256::digest(sol_request.payloads()[0].message()))
        );

        let tron_address =
            xindex_tron_tx::addr::pubkey_to_address(&GENERATOR).expect("TRON address");
        let tron = AccountPrepared {
            chain: ChainId::Tron,
            to_address: tron_address.clone(),
            amount_dec: "2500000".to_string(),
            memo: "=:ETH.USDT:0xrecipient:990000".to_string(),
            signing: AccountSigning::Tron {
                owner_address: tron_address,
                asset: xindex_shared::signer_wire::TronAssetKind::Trx,
                contract_address: None,
                ref_block_bytes: [0x01, 0x02],
                ref_block_hash: [0x03; 8],
                expiration: 1_800_000_000_000,
                timestamp: 1_799_999_940_000,
                fee_limit: 0,
                permission_id: 0,
            },
            ric: None,
            spend_identity: vec![0x77; 32],
        };
        let tron_raw = xindex_tron_tx::addr::decode_base58check(match &tron.signing {
            AccountSigning::Tron { owner_address, .. } => owner_address,
            _ => unreachable!("TRON fixture"),
        })
        .expect("TRON owner");
        let tron_raw_data = xindex_tron_tx::tx::build_trx_raw_data(
            &xindex_tron_tx::tx::TrxTransfer {
                owner: tron_raw,
                to: tron_raw,
                amount: 2_500_000,
            },
            &xindex_tron_tx::tx::Tapos {
                ref_block_bytes: [0x01, 0x02],
                ref_block_hash: [0x03; 8],
                expiration: 1_800_000_000_000,
                timestamp: 1_799_999_940_000,
                fee_limit: 0,
                memo: b"=:ETH.USDT:0xrecipient:990000".to_vec(),
                permission_id: 0,
            },
        );
        let tron_key = format!(
            "0x{}",
            alloy_primitives::hex::encode(xindex_tron_tx::tx::txid(&tron_raw_data))
        );
        let tron_request = build_from_parts(
            tron_key,
            PreparedSpend::Account(tron),
            config(ChainId::Tron, VultisigPublicKey::Secp256k1(GENERATOR)),
        )
        .expect("TRON request");
        assert_eq!(
            tron_request.payloads()[0].lookup_hash(),
            tron_request.payloads()[0].message()
        );
    }
}
