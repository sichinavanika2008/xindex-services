//! CTD-1 (`DL-CTD-2` Slice B): the per-operator REDEMPTION OBSERVER.
//!
//! Each of the 5 operators runs its OWN observer. Before its Set-B HSM
//! certifies a custody spend, the observer independently:
//!   1. reads the `RedeemDispatched` leg facts (amount / memo / final
//!      destination) from its OWN Ethereum RPC ([`RedeemLegSource`]);
//!   2. resolves the Asgard inbound from its OWN diverse `THORChain`
//!      sources, cross-confirmed across ≥2 ([`AsgardAgreement`],
//!      refinement 1) — a single poisoned endpoint cannot drive a sign;
//!   3. builds the canonical [`RedemptionIntentCertificate`] and asks
//!      its OWN Set-B daemon to sign it ([`RicSigner`]).
//!
//! A compromised coordinator/relay can fan a certify request out to the
//! observers but cannot forge what an honest observer resolves: the
//! certified `immediate_target_hash` is the observer's own Asgard
//! resolution, not the coordinator's word. The relay then collects
//! k-of-n identical certificates ([`xindex_shared::ric_relay`]) and the
//! RPC-free custody daemon re-verifies them statelessly. This is the
//! "teeth" Slice A's mechanism was waiting for.
//!
//! Honest ceiling (L5): k-of-n operator honesty with diverse sources —
//! there is no `THORChain` light-client vault proof. See the plan.

use alloy_primitives::{keccak256, Address, B256, U256};
use bitcoin::Network;
use xindex_shared::chain_registry::{ChainId, CustodyFamily};
use xindex_shared::eip712::{attestation_oracle_domain, redemption_intent_certificate};
use xindex_shared::signer_wire::{error_codes, ObserverCertifyRequest, ObserverCertifyResponse};
use xindex_signer::{RicSigner, SignerError};

/// The on-chain facts of one redemption leg, read from the observer's
/// OWN Ethereum RPC via the `RedeemDispatched` event. These are the
/// amount / memo / final-destination the certificate binds; the Asgard
/// inbound is resolved separately (diverse sources).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegFacts {
    /// Native smallest units to spend (sats for BTC) — the on-chain
    /// `RedeemDispatched.amount`.
    pub amount: U256,
    /// The contract-built `THORChain` swap memo bytes (trusted from the
    /// event; the daemon binds the `OP_RETURN` to its keccak).
    pub memo: Vec<u8>,
    /// The user's final payout destination on-chain (the
    /// `RedeemDispatched.destination`, i.e. the `IndexToken` in the
    /// consolidated-USDT model). Hashed into the certificate so every
    /// observer commits to the same downstream target.
    pub final_destination: Address,
}

/// One observed leg: the facts plus when THIS observer first saw the
/// `RedeemDispatched` (its own clock). The E2 fraud-window delay
/// (`DL-CTD-E`) is measured from `observed_at`; first-write-wins in the
/// leg map means a reorg-replayed event can never reset the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedLeg {
    /// The leg facts as first observed.
    pub facts: LegFacts,
    /// Unix seconds (this observer's clock) of the FIRST observation.
    pub observed_at: u64,
}

/// Source of [`LegFacts`] for a `(redemption_id, leg_index)`. The live
/// impl scans `RedeemDispatched` logs on the operator's own RPC; tests
/// inject a fake. AFIT (no `async-trait`) — the observer is generic, so
/// dispatch is static.
pub trait RedeemLegSource {
    /// Return the leg's facts + first-observation stamp, or `None` if no
    /// `RedeemDispatched` for `(redemption_id, leg_index)` is visible on
    /// this observer's RPC.
    ///
    /// # Errors
    /// Implementation-defined transport / decode failure.
    fn leg_facts(
        &self,
        redemption_id: B256,
        leg_index: u32,
    ) -> impl std::future::Future<Output = Result<Option<ObservedLeg>, String>> + Send;
}

/// In-memory [`RedeemLegSource`] backed by a shared map the observer's
/// event loop populates as it sees `RedeemDispatched` on its OWN RPC.
/// Lookups are non-blocking; a certify request for a leg the observer
/// has not yet seen returns `None` (→ `OBSERVER_EVENT_NOT_FOUND`, the
/// relay re-polls). This keeps the live alloy provider entirely inside
/// the event loop — the leg source itself is trivially testable.
#[derive(Debug, Clone, Default)]
pub struct InMemoryLegSource {
    facts: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<(B256, u32), ObservedLeg>>>,
}

impl InMemoryLegSource {
    /// Empty source — the event loop fills it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a leg's facts (called by the event loop on each
    /// `RedeemDispatched`) stamped with the observer's own clock. First
    /// write wins per `(redemption_id, leg_index)`; a re-observation of
    /// the same leg is ignored, so a reorg-replayed event can neither
    /// mutate already-certified facts nor reset the E2 fraud-window
    /// clock.
    pub fn insert(&self, redemption_id: B256, leg_index: u32, facts: LegFacts, observed_at: u64) {
        if let Ok(mut map) = self.facts.write() {
            map.entry((redemption_id, leg_index))
                .or_insert(ObservedLeg { facts, observed_at });
        }
    }
}

impl RedeemLegSource for InMemoryLegSource {
    async fn leg_facts(
        &self,
        redemption_id: B256,
        leg_index: u32,
    ) -> Result<Option<ObservedLeg>, String> {
        let map = self
            .facts
            .read()
            .map_err(|e| format!("leg map poisoned: {e}"))?;
        Ok(map.get(&(redemption_id, leg_index)).cloned())
    }
}

/// Source of the on-chain `CustodyGuard.isHalted()` flag (`DL-CTD-E`),
/// read via the operator's OWN Ethereum RPC. AFIT, static dispatch —
/// same shape as [`RedeemLegSource`].
pub trait HaltSource {
    /// `Ok(true)` while a halt is active. Errors fail CLOSED at the
    /// caller — certification is refused rather than skipping the
    /// halt check.
    fn is_halted(&self) -> impl std::future::Future<Output = Result<bool, String>> + Send;
}

/// No halt gate (DEV ONLY — production wires [`HttpHaltSource`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverHalted;

impl HaltSource for NeverHalted {
    async fn is_halted(&self) -> Result<bool, String> {
        Ok(false)
    }
}

/// Live halt source: a plain JSON-RPC `eth_call` of `isHalted()` on the
/// deployed `CustodyGuard`, via the operator's own HTTP endpoint.
/// Deliberately raw JSON-RPC (not an alloy provider) so it stays
/// generic-free and wiremock-testable.
#[derive(Debug, Clone)]
pub struct HttpHaltSource {
    url: String,
    guard: Address,
    client: reqwest::Client,
}

impl HttpHaltSource {
    /// Halt source over `url` (HTTP JSON-RPC) for the guard contract.
    #[must_use]
    pub fn new(url: String, guard: Address) -> Self {
        Self {
            url,
            guard,
            client: reqwest::Client::new(),
        }
    }
}

impl HaltSource for HttpHaltSource {
    async fn is_halted(&self) -> Result<bool, String> {
        let selector = &keccak256(b"isHalted()")[..4];
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [
                {
                    "to": format!("{:#x}", self.guard),
                    "data": format!("0x{}", alloy_primitives::hex::encode(selector)),
                },
                "latest"
            ]
        });
        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("halt eth_call: {e}"))?;
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("halt eth_call body: {e}"))?;
        let result = v
            .get("result")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("halt eth_call: no result ({v})"))?;
        let raw = alloy_primitives::hex::decode(result.trim_start_matches("0x"))
            .map_err(|e| format!("halt eth_call hex: {e}"))?;
        // A mis-addressed guard returns `0x` — fail CLOSED, never read
        // an empty result as "not halted".
        if raw.len() != 32 {
            return Err(format!(
                "halt eth_call: result length {} != 32 (guard mis-addressed?)",
                raw.len()
            ));
        }
        Ok(raw[31] == 1)
    }
}

/// Either-or halt source for binary wiring (mirrors `AnyHsmBackend`).
#[derive(Debug, Clone)]
pub enum AnyHaltSource {
    /// DEV ONLY — no halt gate.
    Never(NeverHalted),
    /// Production: the deployed on-chain `CustodyGuard`.
    Http(HttpHaltSource),
}

impl HaltSource for AnyHaltSource {
    async fn is_halted(&self) -> Result<bool, String> {
        match self {
            Self::Never(n) => n.is_halted().await,
            Self::Http(h) => h.is_halted().await,
        }
    }
}

/// Static configuration of one observer: which custody chain it serves,
/// the attestation-oracle EIP-712 domain it certifies under, the BTC
/// network (for UTXO scriptPubKey derivation), and how far a proposed
/// issuance stamp may sit from local time.
#[derive(Debug, Clone)]
pub struct ObserverConfig {
    /// The custody chain this observer certifies (e.g. `Btc`). Requests
    /// for any other chain are refused (`OBSERVER_CHAIN_UNSUPPORTED`).
    pub chain: ChainId,
    /// Ethereum chain id of the RIC EIP-712 domain — MUST match the
    /// custody daemon's pinned `chain_id`.
    pub eth_chain_id: u64,
    /// `AttestationOracle` address — the domain verifying contract.
    pub oracle: Address,
    /// BTC network for parsing the Asgard address into a scriptPubKey
    /// (UTXO families only).
    pub btc_network: Network,
    /// Max absolute skew (seconds) between `now` and a proposed
    /// `vault_resolved_at` the observer will accept.
    pub stamp_window_secs: u64,
    /// E2 fraud window (`DL-CTD-E`): legs with `amount` STRICTLY ABOVE
    /// this (native smallest units) wait `large_spend_delay_secs` from
    /// first observation before this observer certifies. `None`
    /// disables — DEV ONLY; production sets ≈2% of per-chain custody,
    /// re-tuned operationally.
    pub large_spend_threshold: Option<U256>,
    /// E2 fraud-window delay in seconds (production: 1800 = 30 min).
    pub large_spend_delay_secs: u64,
}

/// Why an observer refused to certify. Each maps to a wire error code so
/// the relay can branch.
#[derive(Debug, thiserror::Error)]
pub enum ObserverError {
    /// Request chain ≠ this observer's served chain (or `sol`, RA-2).
    #[error("observer does not serve chain: {0}")]
    ChainUnsupported(String),
    /// Malformed request field.
    #[error("invalid request: {0}")]
    BadRequest(String),
    /// No `RedeemDispatched` visible on this observer's own RPC.
    #[error("no RedeemDispatched for ({redemption_id:#x}, {leg_index})")]
    EventNotFound { redemption_id: B256, leg_index: u32 },
    /// On-chain leg facts failed validation (amount / memo).
    #[error("event invalid: {0}")]
    EventInvalid(String),
    /// Proposed issuance stamp outside the local clock window.
    #[error("stamp out of window: {0}")]
    StampOutOfWindow(String),
    /// Diverse-source Asgard agreement gate refused.
    #[error("asgard agreement: {0}")]
    AsgardUnavailable(String),
    /// The observer's own Set-B daemon refused or was unreachable.
    #[error("signer unavailable: {0}")]
    SignerUnavailable(#[from] SignerError),
    /// Leg-source RPC failure.
    #[error("leg source: {0}")]
    LegSource(String),
    /// `DL-CTD-E`: the on-chain `CustodyGuard` halt is active — every
    /// certification is refused until it expires or a quorum un-halts.
    #[error("custody halt active")]
    Halted,
    /// `DL-CTD-E` E2: the leg exceeds the large-spend threshold and its
    /// fraud window has not elapsed; retry once `until` passes (the
    /// halt is re-checked on every attempt).
    #[error("fraud window active until {until}")]
    FraudWindowActive {
        /// Unix seconds when the window opens.
        until: u64,
    },
    /// The halt source (the observer's own Ethereum RPC) failed — the
    /// observer fails CLOSED rather than certifying with the halt flag
    /// unknown.
    #[error("halt source: {0}")]
    HaltUnavailable(String),
}

impl ObserverError {
    /// Stable wire error-code string for this rejection.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ChainUnsupported(_) => error_codes::OBSERVER_CHAIN_UNSUPPORTED,
            Self::BadRequest(_) => error_codes::INTENT_PROOF_INVALID,
            Self::EventNotFound { .. } => error_codes::OBSERVER_EVENT_NOT_FOUND,
            Self::EventInvalid(_) => error_codes::OBSERVER_EVENT_INVALID,
            Self::StampOutOfWindow(_) => error_codes::OBSERVER_STAMP_OUT_OF_WINDOW,
            Self::AsgardUnavailable(_) | Self::LegSource(_) => {
                error_codes::OBSERVER_ASGARD_UNAVAILABLE
            }
            Self::SignerUnavailable(_) => error_codes::OBSERVER_SIGNER_UNAVAILABLE,
            Self::Halted => error_codes::OBSERVER_HALTED,
            Self::FraudWindowActive { .. } => error_codes::OBSERVER_FRAUD_WINDOW,
            Self::HaltUnavailable(_) => error_codes::OBSERVER_HALT_UNAVAILABLE,
        }
    }
}

/// `MAX_OP_RETURN_BYTES`-equivalent bound applied to the memo at the
/// observer (the multisig crate enforces the same on the spend side;
/// duplicated here so a bad event is refused before it ever reaches a
/// PSBT). `THORChain`'s 80-byte `OP_RETURN` relay limit.
const MAX_MEMO_BYTES: usize = 80;

/// One operator's redemption observer.
#[derive(Debug)]
pub struct Observer<L, S, G> {
    config: ObserverConfig,
    asgard: xindex_chain_thor::AsgardAgreement,
    legs: L,
    signer: S,
    halt: G,
}

impl<L, S, G> Observer<L, S, G>
where
    L: RedeemLegSource,
    S: RicSigner,
    G: HaltSource,
{
    /// Build an observer over its leg source, diverse-source Asgard
    /// gate, its own Set-B signer, and the on-chain halt source
    /// (`DL-CTD-E`).
    #[must_use]
    pub fn new(
        config: ObserverConfig,
        asgard: xindex_chain_thor::AsgardAgreement,
        legs: L,
        signer: S,
        halt: G,
    ) -> Self {
        Self {
            config,
            asgard,
            legs,
            signer,
            halt,
        }
    }

    /// Independently resolve + certify one redemption leg's custody
    /// spend. Returns the full certified plaintext + this observer's
    /// Set-B signature; the relay aggregates k-of-n.
    ///
    /// # Errors
    /// [`ObserverError`] — see each variant. The observer fails closed
    /// on any divergence between its own view and the request.
    pub async fn certify_ric(
        &self,
        req: &ObserverCertifyRequest,
        now_unix: u64,
    ) -> Result<ObserverCertifyResponse, ObserverError> {
        if req.chain_id != self.config.chain || req.chain_id == ChainId::Sol {
            return Err(ObserverError::ChainUnsupported(format!(
                "{:?}",
                req.chain_id
            )));
        }
        // DL-CTD-E: the on-chain operator halt vetoes ALL certifications.
        // Fail closed — a halt-source failure also refuses.
        if self
            .halt
            .is_halted()
            .await
            .map_err(ObserverError::HaltUnavailable)?
        {
            return Err(ObserverError::Halted);
        }
        let redemption_id = parse_b256(&req.redemption_id, "redemption_id")?;
        let leg_index = req
            .leg_index
            .parse::<u32>()
            .map_err(|e| ObserverError::BadRequest(format!("leg_index: {e}")))?;
        self.check_stamp(req.vault_resolved_at, now_unix)?;

        let observed = self
            .legs
            .leg_facts(redemption_id, leg_index)
            .await
            .map_err(ObserverError::LegSource)?
            .ok_or(ObserverError::EventNotFound {
                redemption_id,
                leg_index,
            })?;
        let facts = observed.facts;
        validate_facts(&facts)?;

        // DL-CTD-E E2: large spends wait out the fraud window, measured
        // from FIRST observation on this observer's own clock. A refusal
        // forces a fresh certify call, so the halt above is re-checked
        // on every attempt during (and after) the window.
        if let Some(threshold) = self.config.large_spend_threshold {
            if facts.amount > threshold {
                let until = observed
                    .observed_at
                    .saturating_add(self.config.large_spend_delay_secs);
                if now_unix < until {
                    return Err(ObserverError::FraudWindowActive { until });
                }
            }
        }

        let asgard_address = self
            .asgard
            .resolve_agreed(thor_chain_name(self.config.chain))
            .await
            .map_err(|e| ObserverError::AsgardUnavailable(e.to_string()))?
            .address;
        let immediate_target_hash = self.immediate_target_hash(&asgard_address)?;

        let memo_hash = keccak256(&facts.memo);
        let final_destination_hash = keccak256(facts.final_destination.as_slice());
        let ric = redemption_intent_certificate(
            redemption_id,
            U256::from(leg_index),
            self.config.chain.asset_id_hash(),
            facts.amount,
            self.config.chain.decimals(),
            immediate_target_hash,
            memo_hash,
            final_destination_hash,
            req.vault_resolved_at,
        );
        let domain = attestation_oracle_domain(self.config.eth_chain_id, self.config.oracle);
        let sig = self.signer.sign_ric(self.config.chain, &ric, &domain)?;

        Ok(ObserverCertifyResponse {
            chain_id: self.config.chain,
            redemption_id: format!("{redemption_id:#x}"),
            leg_index: leg_index.to_string(),
            asset_id: format!("{:#x}", self.config.chain.asset_id_hash()),
            amount: facts.amount.to_string(),
            amount_decimals: self.config.chain.decimals(),
            immediate_target_hash: format!("{immediate_target_hash:#x}"),
            memo_hash: format!("{memo_hash:#x}"),
            final_destination_hash: format!("{final_destination_hash:#x}"),
            vault_resolved_at: req.vault_resolved_at,
            asgard_address,
            signature: format!("0x{}", alloy_primitives::hex::encode(sig)),
            signer_address: format!("{:#x}", self.signer.ric_signer_address()),
        })
    }

    fn check_stamp(&self, stamp: u64, now: u64) -> Result<(), ObserverError> {
        let skew = stamp.abs_diff(now);
        if skew > self.config.stamp_window_secs {
            return Err(ObserverError::StampOutOfWindow(format!(
                "|{stamp} - {now}| = {skew}s > window {}s",
                self.config.stamp_window_secs
            )));
        }
        Ok(())
    }

    /// Derive the certified immediate-target hash for the resolved
    /// Asgard inbound, matching the custody daemon's family-specific
    /// bind byte-for-byte:
    /// - UTXO: `keccak256(scriptPubKey)` (psbt.rs `bind_outputs_to_cert`).
    /// - EVM: `keccak256(20-byte router/vault address)` (`evm_safe.rs`).
    /// - account string (Cosmos / XRP / TRON):
    ///   `keccak256(address_utf8)` (server.rs `bind_account_send_to_cert`).
    fn immediate_target_hash(&self, asgard_address: &str) -> Result<B256, ObserverError> {
        match self.config.chain.custody_family() {
            CustodyFamily::Utxo => {
                let addr = bitcoin::Address::from_str(asgard_address)
                    .map_err(|e| {
                        ObserverError::AsgardUnavailable(format!("asgard addr parse: {e}"))
                    })?
                    .require_network(self.config.btc_network)
                    .map_err(|e| {
                        ObserverError::AsgardUnavailable(format!("asgard network: {e}"))
                    })?;
                Ok(keccak256(addr.script_pubkey().as_bytes()))
            }
            CustodyFamily::Evm => {
                let addr = Address::from_str(asgard_address).map_err(|e| {
                    ObserverError::AsgardUnavailable(format!("asgard evm addr: {e}"))
                })?;
                Ok(keccak256(addr.as_slice()))
            }
            CustodyFamily::Cosmos | CustodyFamily::Xrp | CustodyFamily::Tron => {
                Ok(keccak256(asgard_address.as_bytes()))
            }
            CustodyFamily::Solana => Err(ObserverError::ChainUnsupported("sol".to_string())),
        }
    }
}

use std::str::FromStr;

/// The `THORChain` inbound-chain identifier for a [`ChainId`] — the
/// prefix of `thor_asset()` before the dot (`BTC.BTC` → `BTC`,
/// `GAIA.ATOM` → `GAIA`). This is the string keying
/// `/thorchain/inbound_addresses`.
fn thor_chain_name(chain: ChainId) -> &'static str {
    let asset = chain.thor_asset();
    match asset.split_once('.') {
        Some((prefix, _)) => prefix,
        None => asset,
    }
}

fn validate_facts(facts: &LegFacts) -> Result<(), ObserverError> {
    if facts.amount == U256::ZERO {
        return Err(ObserverError::EventInvalid("zero amount".to_string()));
    }
    if facts.memo.is_empty() {
        return Err(ObserverError::EventInvalid("empty memo".to_string()));
    }
    if facts.memo.len() > MAX_MEMO_BYTES {
        return Err(ObserverError::EventInvalid(format!(
            "memo {} bytes > {MAX_MEMO_BYTES}",
            facts.memo.len()
        )));
    }
    Ok(())
}

fn parse_b256(hex_str: &str, field: &str) -> Result<B256, ObserverError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = alloy_primitives::hex::decode(stripped)
        .map_err(|e| ObserverError::BadRequest(format!("{field}: bad hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ObserverError::BadRequest(format!("{field}: not 32 bytes")))?;
    Ok(B256::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use xindex_chain_thor::{AsgardAgreement, ThorClient};
    use xindex_shared::eip712::{ric_signing_hash, RedemptionIntentCertificate};
    use xindex_signer::{HsmBackend, SoftwareSigner};

    const NOW: u64 = 1_750_000_000;
    // A real signet/mainnet-form P2WPKH bech32 the bitcoin crate parses.
    const ASGARD_BTC: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";

    struct FakeLegs {
        facts: Option<LegFacts>,
        observed_at: u64,
    }

    impl RedeemLegSource for FakeLegs {
        async fn leg_facts(
            &self,
            _redemption_id: B256,
            _leg_index: u32,
        ) -> Result<Option<ObservedLeg>, String> {
            Ok(self.facts.clone().map(|facts| ObservedLeg {
                facts,
                observed_at: self.observed_at,
            }))
        }
    }

    fn oracle() -> Address {
        Address::repeat_byte(0x42)
    }

    /// Anvil account #0 key — deterministic Set-B test signer.
    fn signer() -> SoftwareSigner {
        #[expect(clippy::expect_used, reason = "test code")]
        SoftwareSigner::from_hex(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .expect("key")
    }

    async fn btc_source(address: &str, halted: bool) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/thorchain/inbound_addresses"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "chain": "BTC",
                    "pub_key": "thorpub1example",
                    "address": address,
                    "halted": halted,
                    "global_trading_paused": false,
                    "chain_trading_paused": false,
                    "chain_lp_actions_paused": false
                }])),
            )
            .mount(&server)
            .await;
        server
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn agreement(servers: &[&MockServer]) -> AsgardAgreement {
        let clients = servers
            .iter()
            .map(|s| ThorClient::with_base_url(s.uri()).expect("client"))
            .collect();
        AsgardAgreement::new(clients).expect("two sources")
    }

    fn config() -> ObserverConfig {
        ObserverConfig {
            chain: ChainId::Btc,
            eth_chain_id: 1,
            oracle: oracle(),
            btc_network: Network::Bitcoin,
            stamp_window_secs: 600,
            large_spend_threshold: None,
            large_spend_delay_secs: 1_800,
        }
    }

    /// DL-CTD-E halt fake: `Some(flag)` answers, `None` errors (RPC
    /// down) — exercising the fail-closed path.
    struct FakeHalt {
        halted: Option<bool>,
    }

    impl HaltSource for FakeHalt {
        async fn is_halted(&self) -> Result<bool, String> {
            self.halted.ok_or_else(|| "halt rpc down".to_string())
        }
    }

    fn facts() -> LegFacts {
        LegFacts {
            amount: U256::from(50_000_000u64),
            memo: b"=:ETH.USDT:0x000000000000000000000000000000000000dEaD:1".to_vec(),
            final_destination: Address::repeat_byte(0xde),
        }
    }

    fn certify_req() -> ObserverCertifyRequest {
        ObserverCertifyRequest {
            chain_id: ChainId::Btc,
            redemption_id: format!("0x{}", "ab".repeat(32)),
            leg_index: "0".to_string(),
            vault_resolved_at: NOW,
        }
    }

    /// Happy path: two agreeing sources, valid leg facts → a certificate
    /// whose signature recovers to the observer's Set-B address over the
    /// independently-rebuilt RIC digest. This is the end-to-end teeth.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn certifies_with_two_agreeing_sources() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let observer = Observer::new(
            config(),
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        let resp = observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect("must certify");

        assert_eq!(resp.asgard_address, ASGARD_BTC);
        assert_eq!(resp.amount, "50000000");
        assert_eq!(resp.amount_decimals, 8);

        // Rebuild the digest the daemon would and confirm the signature
        // recovers to the observer's Set-B signer.
        let btc_addr = bitcoin::Address::from_str(ASGARD_BTC)
            .expect("addr")
            .require_network(Network::Bitcoin)
            .expect("net");
        let expect_target = keccak256(btc_addr.script_pubkey().as_bytes());
        assert_eq!(resp.immediate_target_hash, format!("{expect_target:#x}"));

        let ric = RedemptionIntentCertificate {
            redemptionId: B256::repeat_byte(0xab),
            legIndex: U256::ZERO,
            assetId: ChainId::Btc.asset_id_hash(),
            amount: U256::from(50_000_000u64),
            amountDecimals: 8,
            immediateTargetHash: expect_target,
            memoHash: keccak256(&facts().memo),
            finalDestinationHash: keccak256(facts().final_destination.as_slice()),
            vaultResolvedAt: NOW,
        };
        let digest = ric_signing_hash(&ric, &attestation_oracle_domain(1, oracle()));
        let sig_bytes =
            alloy_primitives::hex::decode(resp.signature.trim_start_matches("0x")).expect("hex");
        let sig =
            alloy_primitives::PrimitiveSignature::try_from(sig_bytes.as_slice()).expect("sig");
        let recovered = sig.recover_address_from_prehash(&digest).expect("recover");
        assert_eq!(format!("{recovered:#x}"), resp.signer_address);
        assert_eq!(recovered, signer().signer_address());
    }

    /// Refinement 1: a disagreement between the operator's two sources
    /// is a hard refusal — the observer never certifies on a split.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn source_disagreement_refuses_to_certify() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", false).await;
        let observer = Observer::new(
            config(),
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        let err = observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect_err("must refuse");
        assert_eq!(err.error_code(), error_codes::OBSERVER_ASGARD_UNAVAILABLE);
    }

    /// A halt flag on any agreeing source refuses certification.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn halted_source_refuses_to_certify() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, true).await;
        let observer = Observer::new(
            config(),
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        let err = observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect_err("must refuse");
        assert_eq!(err.error_code(), error_codes::OBSERVER_ASGARD_UNAVAILABLE);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn missing_event_is_not_found() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let observer = Observer::new(
            config(),
            agreement(&[&a, &b]),
            FakeLegs {
                facts: None,
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        let err = observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect_err("must 404");
        assert_eq!(err.error_code(), error_codes::OBSERVER_EVENT_NOT_FOUND);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn wrong_chain_refused() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let observer = Observer::new(
            config(),
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        let mut req = certify_req();
        req.chain_id = ChainId::Ltc;
        let err = observer
            .certify_ric(&req, NOW)
            .await
            .expect_err("served chain is BTC");
        assert_eq!(err.error_code(), error_codes::OBSERVER_CHAIN_UNSUPPORTED);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn solana_always_refused() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let mut cfg = config();
        cfg.chain = ChainId::Sol;
        let observer = Observer::new(
            cfg,
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        let mut req = certify_req();
        req.chain_id = ChainId::Sol;
        let err = observer
            .certify_ric(&req, NOW)
            .await
            .expect_err("RA-2: never certify Solana");
        assert_eq!(err.error_code(), error_codes::OBSERVER_CHAIN_UNSUPPORTED);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn stale_stamp_refused() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let observer = Observer::new(
            config(),
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        let mut req = certify_req();
        req.vault_resolved_at = NOW - 601;
        let err = observer
            .certify_ric(&req, NOW)
            .await
            .expect_err("stamp out of window");
        assert_eq!(err.error_code(), error_codes::OBSERVER_STAMP_OUT_OF_WINDOW);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn zero_amount_event_invalid() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let mut f = facts();
        f.amount = U256::ZERO;
        let observer = Observer::new(
            config(),
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(f),
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        let err = observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect_err("zero amount invalid");
        assert_eq!(err.error_code(), error_codes::OBSERVER_EVENT_INVALID);
    }

    /// DL-CTD-E: an active on-chain halt vetoes every certification.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn halted_guard_refuses_certification() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let observer = Observer::new(
            config(),
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW,
            },
            signer(),
            FakeHalt { halted: Some(true) },
        );
        let err = observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect_err("halt vetoes");
        assert_eq!(err.error_code(), error_codes::OBSERVER_HALTED);
    }

    /// DL-CTD-E: a halt-source failure fails CLOSED — the observer
    /// refuses rather than certifying with the halt flag unknown.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn halt_source_failure_fails_closed() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let observer = Observer::new(
            config(),
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW,
            },
            signer(),
            FakeHalt { halted: None },
        );
        let err = observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect_err("fail closed");
        assert_eq!(err.error_code(), error_codes::OBSERVER_HALT_UNAVAILABLE);
    }

    /// DL-CTD-E E2: a leg above the large-spend threshold is refused
    /// while its fraud window (measured from FIRST observation) is
    /// open, with the retry timestamp surfaced.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn large_leg_waits_out_fraud_window() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let mut cfg = config();
        cfg.large_spend_threshold = Some(U256::from(10_000_000u64));
        let observed_at = NOW - 100;
        let observer = Observer::new(
            cfg,
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at,
            },
            signer(),
            FakeHalt {
                halted: Some(false),
            },
        );
        let err = observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect_err("window open");
        assert_eq!(err.error_code(), error_codes::OBSERVER_FRAUD_WINDOW);
        // The error-code assertion above admits only this variant.
        let ObserverError::FraudWindowActive { until } = err else {
            unreachable!()
        };
        assert_eq!(until, observed_at + 1_800);
    }

    /// DL-CTD-E E2: the same large leg certifies once the window has
    /// elapsed.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn large_leg_certifies_after_fraud_window() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let mut cfg = config();
        cfg.large_spend_threshold = Some(U256::from(10_000_000u64));
        let observer = Observer::new(
            cfg,
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW - 1_801,
            },
            signer(),
            FakeHalt {
                halted: Some(false),
            },
        );
        let resp = observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect("window elapsed");
        assert_eq!(resp.amount, "50000000");
    }

    /// DL-CTD-E E2: legs AT or below the threshold (strict >) skip the
    /// fraud window entirely.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn small_leg_skips_fraud_window() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let mut cfg = config();
        cfg.large_spend_threshold = Some(U256::from(50_000_000u64));
        let observer = Observer::new(
            cfg,
            agreement(&[&a, &b]),
            FakeLegs {
                facts: Some(facts()),
                observed_at: NOW,
            },
            signer(),
            FakeHalt {
                halted: Some(false),
            },
        );
        observer
            .certify_ric(&certify_req(), NOW)
            .await
            .expect("at-threshold leg flows instantly");
    }

    #[test]
    fn thor_chain_name_strips_asset_suffix() {
        assert_eq!(thor_chain_name(ChainId::Btc), "BTC");
        assert_eq!(thor_chain_name(ChainId::Gaia), "GAIA");
        assert_eq!(thor_chain_name(ChainId::Eth), "ETH");
        assert_eq!(thor_chain_name(ChainId::Bsc), "BSC");
    }
}
