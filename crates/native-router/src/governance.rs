use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{sol, SolCall, SolValue};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use xindex_ops::network::HttpClientPolicy;

use crate::catalog::Provider;
use crate::http::{BoundedJsonClient, JsonEvidence};
use crate::selection::GovernanceBinding;
use crate::NativeRouterError;

sol! {
    struct ProviderConfigHashInput {
        uint256 chainId;
        address registry;
        bytes32 providerId;
        address endpoint;
        bytes32 endpointCodehash;
        uint8 dispatchMode;
        uint16 maxTotalCostBps;
        uint16 maxChunks;
        uint32 maxStreamDuration;
        uint16 streamBlockSeconds;
        uint64 version;
        bool enabled;
    }

    struct ProviderAssetConfigHashInput {
        uint256 chainId;
        address registry;
        bytes32 providerId;
        bytes32 assetId;
        bytes32 providerAssetId;
        bytes32 executionAssetId;
        uint32 destinationChain;
        uint32 destinationToken;
        uint8 providerDecimals;
        uint8 nativeDecimals;
        uint64 version;
        bool enabled;
    }

    struct RpcProviderConfig {
        address endpoint;
        bytes32 endpointCodehash;
        uint8 mode;
        uint16 maxTotalCostBps;
        uint16 maxChunks;
        uint32 maxStreamDuration;
        uint16 streamBlockSeconds;
        uint64 version;
        bool enabled;
    }

    struct RpcProviderAssetConfig {
        bytes32 providerAssetId;
        bytes32 executionAssetId;
        uint32 destinationChain;
        uint32 destinationToken;
        uint8 providerDecimals;
        uint8 nativeDecimals;
        uint64 version;
        bool enabled;
    }

    interface INativeRouteRegistryRpc {
        function providerConfig(bytes32 providerId) external view returns (RpcProviderConfig memory config);
        function providerConfigHash(bytes32 providerId) external view returns (bytes32 configHash);
        function providerAssetConfig(bytes32 providerId, bytes32 assetId)
            external
            view
            returns (RpcProviderAssetConfig memory config);
        function providerAssetConfigHash(bytes32 providerId, bytes32 assetId)
            external
            view
            returns (bytes32 configHash);
    }
}

/// Exact decoded value returned by `NativeRouteRegistry.providerConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfigSnapshot {
    pub endpoint: Address,
    pub endpoint_codehash: B256,
    pub dispatch_mode: u8,
    pub max_total_cost_bps: u16,
    pub max_chunks: u16,
    pub max_stream_duration_seconds: u32,
    pub stream_block_seconds: u16,
    pub version: u64,
    pub enabled: bool,
}

/// Exact decoded value returned by `NativeRouteRegistry.providerAssetConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAssetConfigSnapshot {
    pub provider_asset_id: B256,
    pub execution_asset_id: B256,
    pub destination_chain: u32,
    pub destination_token: u32,
    pub provider_decimals: u8,
    pub native_decimals: u8,
    pub version: u64,
    pub enabled: bool,
}

/// One finalized, internally consistent registry read. The reported hashes
/// come from the two on-chain hash getters. `observed_endpoint_codehash` comes
/// from the endpoint runtime at the same finalized block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceSnapshot {
    pub chain_id: u64,
    pub registry: Address,
    pub provider_id: B256,
    pub asset_id: B256,
    pub provider: ProviderConfigSnapshot,
    pub asset: ProviderAssetConfigSnapshot,
    pub reported_provider_config_hash: B256,
    pub reported_asset_config_hash: B256,
    pub observed_endpoint_codehash: B256,
}

/// One bounded finalized RPC capture. The raw JSON bodies are returned so the
/// caller can persist them before using `evidence_hash` in an authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedGovernanceRead {
    pub snapshot: GovernanceSnapshot,
    pub binding: GovernanceBinding,
    pub finalized_block_number: u64,
    pub finalized_block_hash: B256,
    pub raw_responses: Vec<Vec<u8>>,
    pub evidence_hash: B256,
}

/// Exact agreement result across at least two independently configured RPCs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusGovernanceRead {
    pub binding: GovernanceBinding,
    pub finalized_block_number: u64,
    pub finalized_block_hash: B256,
    pub source_evidence_hashes: Vec<B256>,
    pub evidence_hash: B256,
}

/// Bounded HTTPS-only reader for the exact finalized registry state used by a
/// route signer. Production callers construct one client per independent RPC.
#[derive(Clone)]
pub struct RegistryRpcClient {
    http: BoundedJsonClient,
    registry: Address,
}

impl std::fmt::Debug for RegistryRpcClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryRpcClient")
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RpcBlock {
    number: String,
    hash: String,
}

#[derive(Debug, Default)]
struct RpcEvidence {
    raw_responses: Vec<Vec<u8>>,
    response_hashes: Vec<B256>,
}

/// Reproduce `NativeRouteRegistry.providerConfigHash` byte-for-byte.
#[must_use]
pub fn provider_config_hash(
    chain_id: u64,
    registry: Address,
    provider_id: B256,
    config: &ProviderConfigSnapshot,
) -> B256 {
    keccak256(
        ProviderConfigHashInput {
            chainId: U256::from(chain_id),
            registry,
            providerId: provider_id,
            endpoint: config.endpoint,
            endpointCodehash: config.endpoint_codehash,
            dispatchMode: config.dispatch_mode,
            maxTotalCostBps: config.max_total_cost_bps,
            maxChunks: config.max_chunks,
            maxStreamDuration: config.max_stream_duration_seconds,
            streamBlockSeconds: config.stream_block_seconds,
            version: config.version,
            enabled: config.enabled,
        }
        .abi_encode(),
    )
}

/// Reproduce `NativeRouteRegistry.providerAssetConfigHash` byte-for-byte.
#[must_use]
pub fn provider_asset_config_hash(
    chain_id: u64,
    registry: Address,
    provider_id: B256,
    asset_id: B256,
    config: &ProviderAssetConfigSnapshot,
) -> B256 {
    keccak256(
        ProviderAssetConfigHashInput {
            chainId: U256::from(chain_id),
            registry,
            providerId: provider_id,
            assetId: asset_id,
            providerAssetId: config.provider_asset_id,
            executionAssetId: config.execution_asset_id,
            destinationChain: config.destination_chain,
            destinationToken: config.destination_token,
            providerDecimals: config.provider_decimals,
            nativeDecimals: config.native_decimals,
            version: config.version,
            enabled: config.enabled,
        }
        .abi_encode(),
    )
}

impl RegistryRpcClient {
    /// Build a production reader. Plain HTTP is rejected.
    ///
    /// # Errors
    /// Invalid registry, URL, network policy or client construction.
    pub fn new(
        endpoint: &str,
        registry: Address,
        policy: HttpClientPolicy,
    ) -> Result<Self, NativeRouterError> {
        if registry == Address::ZERO {
            return Err(NativeRouterError::Policy(
                "native-route registry address is zero",
            ));
        }
        Ok(Self {
            http: BoundedJsonClient::new(endpoint, policy)?,
            registry,
        })
    }

    #[cfg(test)]
    fn loopback(
        endpoint: &str,
        registry: Address,
        policy: HttpClientPolicy,
    ) -> Result<Self, NativeRouterError> {
        if registry == Address::ZERO {
            return Err(NativeRouterError::Policy(
                "native-route registry address is zero",
            ));
        }
        Ok(Self {
            http: BoundedJsonClient::new_loopback(endpoint, policy)?,
            registry,
        })
    }

    /// Read registry code, both configurations and both reported hashes at one
    /// EIP-1898 canonical finalized block, then re-read the configured endpoint
    /// runtime at that same block.
    ///
    /// # Errors
    /// Any transport/schema/ABI/hash/runtime/configuration disagreement.
    #[expect(
        clippy::too_many_lines,
        reason = "one linear finalized read keeps the exact RPC evidence order auditable"
    )]
    pub async fn finalized_governance(
        &self,
        provider_id: B256,
        asset_id: B256,
    ) -> Result<FinalizedGovernanceRead, NativeRouterError> {
        if provider_id == B256::ZERO || asset_id == B256::ZERO {
            return Err(NativeRouterError::Policy(
                "native-route provider or asset id is zero",
            ));
        }
        let mut evidence = RpcEvidence::default();
        let chain_id_raw: String = self
            .rpc("eth_chainId", serde_json::json!([]), &mut evidence)
            .await?;
        let chain_id = parse_quantity(&chain_id_raw, "rpc.chainId")?;
        let finalized: Option<RpcBlock> = self
            .rpc(
                "eth_getBlockByNumber",
                serde_json::json!(["finalized", false]),
                &mut evidence,
            )
            .await?;
        let finalized = finalized.ok_or(NativeRouterError::InvalidProviderData(
            "RPC has no finalized block",
        ))?;
        let finalized_block_number = parse_quantity(&finalized.number, "rpc.finalized.number")?;
        let finalized_block_hash = parse_b256(&finalized.hash, "rpc.finalized.hash")?;
        if finalized_block_hash == B256::ZERO {
            return Err(NativeRouterError::InvalidProviderData(
                "RPC finalized hash is zero",
            ));
        }
        let block = serde_json::json!({
            "blockHash": format!("{finalized_block_hash:#x}"),
            "requireCanonical": true
        });

        self.require_contract_code(self.registry, &block, &mut evidence)
            .await?;
        let provider_raw = self
            .eth_call(
                INativeRouteRegistryRpc::providerConfigCall {
                    providerId: provider_id,
                }
                .abi_encode(),
                &block,
                &mut evidence,
            )
            .await?;
        let provider = RpcProviderConfig::abi_decode(&provider_raw, true)
            .map_err(|_| NativeRouterError::InvalidCalldata)?;
        let provider_hash_raw = self
            .eth_call(
                INativeRouteRegistryRpc::providerConfigHashCall {
                    providerId: provider_id,
                }
                .abi_encode(),
                &block,
                &mut evidence,
            )
            .await?;
        let reported_provider_config_hash = B256::abi_decode(&provider_hash_raw, true)
            .map_err(|_| NativeRouterError::InvalidCalldata)?;

        let asset_raw = self
            .eth_call(
                INativeRouteRegistryRpc::providerAssetConfigCall {
                    providerId: provider_id,
                    assetId: asset_id,
                }
                .abi_encode(),
                &block,
                &mut evidence,
            )
            .await?;
        let asset = RpcProviderAssetConfig::abi_decode(&asset_raw, true)
            .map_err(|_| NativeRouterError::InvalidCalldata)?;
        let asset_hash_raw = self
            .eth_call(
                INativeRouteRegistryRpc::providerAssetConfigHashCall {
                    providerId: provider_id,
                    assetId: asset_id,
                }
                .abi_encode(),
                &block,
                &mut evidence,
            )
            .await?;
        let reported_asset_config_hash = B256::abi_decode(&asset_hash_raw, true)
            .map_err(|_| NativeRouterError::InvalidCalldata)?;
        let endpoint_code = self
            .contract_code(provider.endpoint, &block, &mut evidence)
            .await?;
        if endpoint_code.is_empty() {
            return Err(NativeRouterError::InvalidProviderData(
                "configured provider endpoint has no code",
            ));
        }

        let snapshot = GovernanceSnapshot {
            chain_id,
            registry: self.registry,
            provider_id,
            asset_id,
            provider: ProviderConfigSnapshot {
                endpoint: provider.endpoint,
                endpoint_codehash: provider.endpointCodehash,
                dispatch_mode: provider.mode,
                max_total_cost_bps: provider.maxTotalCostBps,
                max_chunks: provider.maxChunks,
                max_stream_duration_seconds: provider.maxStreamDuration,
                stream_block_seconds: provider.streamBlockSeconds,
                version: provider.version,
                enabled: provider.enabled,
            },
            asset: ProviderAssetConfigSnapshot {
                provider_asset_id: asset.providerAssetId,
                execution_asset_id: asset.executionAssetId,
                destination_chain: asset.destinationChain,
                destination_token: asset.destinationToken,
                provider_decimals: asset.providerDecimals,
                native_decimals: asset.nativeDecimals,
                version: asset.version,
                enabled: asset.enabled,
            },
            reported_provider_config_hash,
            reported_asset_config_hash,
            observed_endpoint_codehash: keccak256(&endpoint_code),
        };
        let binding = snapshot.validate()?;
        let evidence_hash =
            governance_evidence_hash(finalized_block_hash, &evidence.response_hashes);
        Ok(FinalizedGovernanceRead {
            snapshot,
            binding,
            finalized_block_number,
            finalized_block_hash,
            raw_responses: evidence.raw_responses,
            evidence_hash,
        })
    }

    async fn rpc<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
        evidence: &mut RpcEvidence,
    ) -> Result<T, NativeRouterError> {
        let response: JsonEvidence<RpcResponse<T>> = self
            .http
            .post_with_evidence(
                "",
                &RpcRequest {
                    jsonrpc: "2.0",
                    id: 1,
                    method,
                    params,
                },
            )
            .await?;
        if response.value.jsonrpc != "2.0"
            || response.value.id != 1
            || response.value.error.is_some()
        {
            return Err(NativeRouterError::InvalidProviderData(
                "malformed or failed Ethereum JSON-RPC response",
            ));
        }
        let value = response
            .value
            .result
            .ok_or(NativeRouterError::InvalidProviderData(
                "Ethereum JSON-RPC response lacks result",
            ))?;
        evidence.raw_responses.push(response.raw_body);
        evidence.response_hashes.push(response.response_hash);
        Ok(value)
    }

    async fn eth_call(
        &self,
        calldata: Vec<u8>,
        block: &serde_json::Value,
        evidence: &mut RpcEvidence,
    ) -> Result<Vec<u8>, NativeRouterError> {
        let result: String = self
            .rpc(
                "eth_call",
                serde_json::json!([{
                    "to": format!("{:#x}", self.registry),
                    "data": format!("0x{}", alloy_primitives::hex::encode(calldata))
                }, block]),
                evidence,
            )
            .await?;
        decode_hex(&result, "rpc.eth_call")
    }

    async fn contract_code(
        &self,
        address: Address,
        block: &serde_json::Value,
        evidence: &mut RpcEvidence,
    ) -> Result<Vec<u8>, NativeRouterError> {
        let result: String = self
            .rpc(
                "eth_getCode",
                serde_json::json!([format!("{address:#x}"), block]),
                evidence,
            )
            .await?;
        decode_hex(&result, "rpc.eth_getCode")
    }

    async fn require_contract_code(
        &self,
        address: Address,
        block: &serde_json::Value,
        evidence: &mut RpcEvidence,
    ) -> Result<(), NativeRouterError> {
        if self
            .contract_code(address, block, evidence)
            .await?
            .is_empty()
        {
            return Err(NativeRouterError::InvalidProviderData(
                "native-route registry has no code",
            ));
        }
        Ok(())
    }
}

/// Require finalized state agreement across at least two independently
/// configured RPC sources. Source evidence hashes are sorted before deriving
/// the combined hash so operators agree independently of source ordering.
///
/// # Errors
/// Too few sources or any block/state/binding disagreement.
pub fn consensus_governance_reads(
    reads: &[FinalizedGovernanceRead],
    minimum_sources: usize,
) -> Result<ConsensusGovernanceRead, NativeRouterError> {
    let required = minimum_sources.max(2);
    if reads.len() < required {
        return Err(NativeRouterError::InsufficientSources {
            supplied: reads.len(),
            required,
        });
    }
    let first = reads
        .first()
        .ok_or(NativeRouterError::InsufficientSources {
            supplied: 0,
            required,
        })?;
    if reads.iter().any(|read| {
        read.finalized_block_number != first.finalized_block_number
            || read.finalized_block_hash != first.finalized_block_hash
            || read.snapshot != first.snapshot
            || read.binding != first.binding
    }) {
        return Err(NativeRouterError::SourceDisagreement(
            "finalized NativeRouteRegistry state",
        ));
    }
    let mut source_evidence_hashes = reads
        .iter()
        .map(|read| read.evidence_hash)
        .collect::<Vec<_>>();
    source_evidence_hashes.sort_unstable();
    let evidence_hash =
        governance_evidence_hash(first.finalized_block_hash, &source_evidence_hashes);
    Ok(ConsensusGovernanceRead {
        binding: first.binding.clone(),
        finalized_block_number: first.finalized_block_number,
        finalized_block_hash: first.finalized_block_hash,
        source_evidence_hashes,
        evidence_hash,
    })
}

fn governance_evidence_hash(block_hash: B256, response_hashes: &[B256]) -> B256 {
    keccak256(
        (
            keccak256("XINDEX_NATIVE_ROUTE_GOVERNANCE_EVIDENCE_V1"),
            block_hash,
            response_hashes.to_vec(),
        )
            .abi_encode(),
    )
}

fn parse_quantity(raw: &str, field: &'static str) -> Result<u64, NativeRouterError> {
    let value = raw
        .strip_prefix("0x")
        .ok_or(NativeRouterError::InvalidField {
            field,
            reason: "missing 0x prefix".to_string(),
        })?;
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(NativeRouterError::InvalidField {
            field,
            reason: "not a canonical hex quantity".to_string(),
        });
    }
    u64::from_str_radix(value, 16).map_err(|_| NativeRouterError::InvalidField {
        field,
        reason: "quantity exceeds uint64 or is malformed".to_string(),
    })
}

fn parse_b256(raw: &str, field: &'static str) -> Result<B256, NativeRouterError> {
    raw.parse::<B256>()
        .map_err(|_| NativeRouterError::InvalidField {
            field,
            reason: "not an exact bytes32 hex value".to_string(),
        })
}

fn decode_hex(raw: &str, field: &'static str) -> Result<Vec<u8>, NativeRouterError> {
    let value = raw
        .strip_prefix("0x")
        .ok_or(NativeRouterError::InvalidField {
            field,
            reason: "missing 0x prefix".to_string(),
        })?;
    if value.len() % 2 != 0 {
        return Err(NativeRouterError::InvalidField {
            field,
            reason: "hex value has odd length".to_string(),
        });
    }
    alloy_primitives::hex::decode(value).map_err(|_| NativeRouterError::InvalidField {
        field,
        reason: "invalid hex".to_string(),
    })
}

impl GovernanceSnapshot {
    /// Validate both reported hashes, the endpoint runtime and every registry
    /// bound before making the snapshot eligible for quote planning.
    ///
    /// # Errors
    /// Zero/stale identities, unsupported provider, malformed configuration,
    /// hash disagreement or endpoint runtime drift.
    pub fn validate(&self) -> Result<GovernanceBinding, NativeRouterError> {
        let provider = if self.provider_id == Provider::Chainflip.id() {
            Provider::Chainflip
        } else if self.provider_id == Provider::Maya.id() {
            Provider::Maya
        } else {
            return Err(NativeRouterError::UnsupportedAsset(
                "unsupported native-route provider".to_string(),
            ));
        };
        if self.chain_id == 0
            || self.registry == Address::ZERO
            || self.asset_id == B256::ZERO
            || self.provider.version == 0
            || self.asset.version == 0
            || self.provider.endpoint == Address::ZERO
            || self.provider.endpoint_codehash == B256::ZERO
            || self.provider.dispatch_mode != 0
            || self.provider.max_total_cost_bps > 100
            || self.provider.max_chunks == 0
            || self.provider.max_chunks > 256
            || self.provider.max_stream_duration_seconds > 24 * 60 * 60
            || (self.provider.max_chunks == 1 && self.provider.max_stream_duration_seconds != 0)
            || (self.provider.max_chunks > 1 && self.provider.max_stream_duration_seconds == 0)
            || self.provider.stream_block_seconds > 60 * 60
            || self.asset.provider_asset_id == B256::ZERO
            || self.asset.execution_asset_id == B256::ZERO
            || self.asset.provider_decimals > 18
            || self.asset.native_decimals > 18
            || ((self.asset.destination_chain == 0) != (self.asset.destination_token == 0))
        {
            return Err(NativeRouterError::Policy(
                "invalid finalized native-route governance snapshot",
            ));
        }
        if self.reported_provider_config_hash
            != provider_config_hash(
                self.chain_id,
                self.registry,
                self.provider_id,
                &self.provider,
            )
            || self.reported_asset_config_hash
                != provider_asset_config_hash(
                    self.chain_id,
                    self.registry,
                    self.provider_id,
                    self.asset_id,
                    &self.asset,
                )
        {
            return Err(NativeRouterError::SourceDisagreement(
                "NativeRouteRegistry config hash",
            ));
        }
        if self.observed_endpoint_codehash != self.provider.endpoint_codehash {
            return Err(NativeRouterError::SourceDisagreement(
                "native-route endpoint runtime codehash",
            ));
        }
        if (provider == Provider::Chainflip
            && (self.asset.destination_chain == 0 || self.provider.stream_block_seconds != 0))
            || (provider == Provider::Maya
                && (self.asset.destination_chain != 0 || self.provider.stream_block_seconds != 6))
        {
            return Err(NativeRouterError::Policy(
                "provider-specific governance configuration mismatch",
            ));
        }
        Ok(GovernanceBinding {
            provider_id: self.provider_id,
            provider_config_hash: self.reported_provider_config_hash,
            asset_id: self.asset_id,
            provider_asset_config_hash: self.reported_asset_config_hash,
            provider_asset_id: self.asset.provider_asset_id,
            execution_asset_id: self.asset.execution_asset_id,
            destination_chain: self.asset.destination_chain,
            destination_token: self.asset.destination_token,
            provider_decimals: self.asset.provider_decimals,
            native_decimals: self.asset.native_decimals,
            endpoint: self.provider.endpoint,
            dispatch_mode: self.provider.dispatch_mode,
            max_total_cost_bps: self.provider.max_total_cost_bps,
            max_chunks: self.provider.max_chunks,
            max_stream_duration_seconds: self.provider.max_stream_duration_seconds,
            stream_block_seconds: self.provider.stream_block_seconds,
            enabled: self.provider.enabled,
            asset_enabled: self.asset.enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures must fail loudly")]
    #![expect(
        clippy::too_many_lines,
        reason = "the RPC fixture explicitly binds every finalized call and response"
    )]

    use std::time::Duration;

    use alloy_primitives::b256;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn chainflip_snapshot() -> GovernanceSnapshot {
        let provider = ProviderConfigSnapshot {
            endpoint: Address::repeat_byte(0xbb),
            endpoint_codehash: B256::repeat_byte(0x33),
            dispatch_mode: 0,
            max_total_cost_bps: 75,
            max_chunks: 256,
            max_stream_duration_seconds: 24 * 60 * 60,
            stream_block_seconds: 0,
            version: 9,
            enabled: true,
        };
        let asset = ProviderAssetConfigSnapshot {
            provider_asset_id: B256::repeat_byte(0x55),
            execution_asset_id: B256::repeat_byte(0x66),
            destination_chain: 3,
            destination_token: 5,
            provider_decimals: 8,
            native_decimals: 8,
            version: 7,
            enabled: true,
        };
        let chain_id = 1;
        let registry = Address::repeat_byte(0xaa);
        let provider_id = B256::repeat_byte(0x22);
        let asset_id = B256::repeat_byte(0x44);
        GovernanceSnapshot {
            chain_id,
            registry,
            provider_id,
            asset_id,
            reported_provider_config_hash: provider_config_hash(
                chain_id,
                registry,
                provider_id,
                &provider,
            ),
            reported_asset_config_hash: provider_asset_config_hash(
                chain_id,
                registry,
                provider_id,
                asset_id,
                &asset,
            ),
            observed_endpoint_codehash: provider.endpoint_codehash,
            provider,
            asset,
        }
    }

    #[test]
    fn config_hashes_match_solidity_abi_encode_goldens() {
        let snapshot = chainflip_snapshot();
        assert_eq!(
            snapshot.reported_provider_config_hash,
            b256!("0x0914b5fbe817ab11c3348919c73bff785931ecf6f54a81333277949bcfe2a870")
        );
        assert_eq!(
            snapshot.reported_asset_config_hash,
            b256!("0x97ba83e1df580560e4864412b961ef6c7e81afba64cd6158d218341ff6b51ec0")
        );
    }

    #[test]
    fn snapshot_rejects_provider_identity_and_runtime_drift() {
        let mut snapshot = chainflip_snapshot();
        snapshot.provider_id = Provider::Chainflip.id();
        snapshot.reported_provider_config_hash = provider_config_hash(
            snapshot.chain_id,
            snapshot.registry,
            snapshot.provider_id,
            &snapshot.provider,
        );
        snapshot.reported_asset_config_hash = provider_asset_config_hash(
            snapshot.chain_id,
            snapshot.registry,
            snapshot.provider_id,
            snapshot.asset_id,
            &snapshot.asset,
        );
        assert!(snapshot.validate().is_ok());

        snapshot.observed_endpoint_codehash = B256::repeat_byte(0xff);
        assert!(snapshot.validate().is_err());
    }

    #[tokio::test]
    async fn finalized_rpc_reader_pins_one_block_and_retains_every_response() {
        let server = MockServer::start().await;
        let registry = Address::repeat_byte(0xaa);
        let endpoint = Address::repeat_byte(0xbb);
        let provider_id = Provider::Chainflip.id();
        let asset_id = keccak256("BTC.BTC");
        let block_hash = B256::repeat_byte(0x77);
        let registry_code = vec![0x60, 0x00];
        let endpoint_code = vec![0x60, 0x01];
        let endpoint_codehash = keccak256(&endpoint_code);
        let provider = ProviderConfigSnapshot {
            endpoint,
            endpoint_codehash,
            dispatch_mode: 0,
            max_total_cost_bps: 75,
            max_chunks: 256,
            max_stream_duration_seconds: 24 * 60 * 60,
            stream_block_seconds: 0,
            version: 9,
            enabled: true,
        };
        let asset = ProviderAssetConfigSnapshot {
            provider_asset_id: keccak256("Bitcoin:BTC"),
            execution_asset_id: keccak256("Bitcoin:BTC"),
            destination_chain: 3,
            destination_token: 5,
            provider_decimals: 8,
            native_decimals: 8,
            version: 7,
            enabled: true,
        };
        let provider_hash = provider_config_hash(1, registry, provider_id, &provider);
        let asset_hash = provider_asset_config_hash(1, registry, provider_id, asset_id, &asset);
        let block = json!({
            "blockHash": format!("{block_hash:#x}"),
            "requireCanonical": true
        });

        mount_rpc(&server, "eth_chainId", json!([]), json!("0x1")).await;
        mount_rpc(
            &server,
            "eth_getBlockByNumber",
            json!(["finalized", false]),
            json!({"number": "0x64", "hash": format!("{block_hash:#x}")}),
        )
        .await;
        mount_rpc(
            &server,
            "eth_getCode",
            json!([format!("{registry:#x}"), block.clone()]),
            json!(hex(&registry_code)),
        )
        .await;
        mount_eth_call(
            &server,
            registry,
            &block,
            INativeRouteRegistryRpc::providerConfigCall {
                providerId: provider_id,
            }
            .abi_encode(),
            RpcProviderConfig {
                endpoint,
                endpointCodehash: endpoint_codehash,
                mode: 0,
                maxTotalCostBps: 75,
                maxChunks: 256,
                maxStreamDuration: 24 * 60 * 60,
                streamBlockSeconds: 0,
                version: 9,
                enabled: true,
            }
            .abi_encode(),
        )
        .await;
        mount_eth_call(
            &server,
            registry,
            &block,
            INativeRouteRegistryRpc::providerConfigHashCall {
                providerId: provider_id,
            }
            .abi_encode(),
            provider_hash.abi_encode(),
        )
        .await;
        mount_eth_call(
            &server,
            registry,
            &block,
            INativeRouteRegistryRpc::providerAssetConfigCall {
                providerId: provider_id,
                assetId: asset_id,
            }
            .abi_encode(),
            RpcProviderAssetConfig {
                providerAssetId: asset.provider_asset_id,
                executionAssetId: asset.execution_asset_id,
                destinationChain: 3,
                destinationToken: 5,
                providerDecimals: 8,
                nativeDecimals: 8,
                version: 7,
                enabled: true,
            }
            .abi_encode(),
        )
        .await;
        mount_eth_call(
            &server,
            registry,
            &block,
            INativeRouteRegistryRpc::providerAssetConfigHashCall {
                providerId: provider_id,
                assetId: asset_id,
            }
            .abi_encode(),
            asset_hash.abi_encode(),
        )
        .await;
        mount_rpc(
            &server,
            "eth_getCode",
            json!([format!("{endpoint:#x}"), block]),
            json!(hex(&endpoint_code)),
        )
        .await;

        let policy = HttpClientPolicy {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 64 * 1024,
        };
        let client = RegistryRpcClient::loopback(&server.uri(), registry, policy).expect("client");
        let read = client
            .finalized_governance(provider_id, asset_id)
            .await
            .expect("finalized read");
        assert_eq!(read.finalized_block_number, 100);
        assert_eq!(read.raw_responses.len(), 8);
        assert_eq!(read.binding.provider_config_hash, provider_hash);
        assert_ne!(read.evidence_hash, B256::ZERO);

        let consensus = consensus_governance_reads(&[read.clone(), read], 2).expect("consensus");
        assert_eq!(consensus.finalized_block_hash, block_hash);
        assert_ne!(consensus.evidence_hash, B256::ZERO);
    }

    async fn mount_rpc(
        server: &MockServer,
        rpc_method: &'static str,
        params: serde_json::Value,
        result: serde_json::Value,
    ) {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": rpc_method,
                "params": params
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": result
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn mount_eth_call(
        server: &MockServer,
        registry: Address,
        block: &serde_json::Value,
        calldata: Vec<u8>,
        result: Vec<u8>,
    ) {
        mount_rpc(
            server,
            "eth_call",
            json!([{
                "to": format!("{registry:#x}"),
                "data": hex(&calldata)
            }, block]),
            json!(hex(&result)),
        )
        .await;
    }

    fn hex(value: &[u8]) -> String {
        format!("0x{}", alloy_primitives::hex::encode(value))
    }
}
