//! CTD-1 (`DL-CTD-2` Slice B): the per-operator REDEMPTION OBSERVER.
//!
//! Each of the 5 operators runs its OWN observer. Before its Set-B HSM
//! certifies a custody spend, the observer independently:
//!   1. reads the `RedeemDispatched` leg facts (amount / memo / final
//!      destination) from its OWN Ethereum RPC ([`RedeemLegSource`]);
//!   2. resolves the Asgard inbound from its OWN diverse `THORChain`
//!      sources, cross-confirmed across a fullnode plus two providers
//!      ([`AsgardAgreement`],
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
use xindex_shared::eip712::{
    acquire_cancel_certificate, attestation_oracle_domain, redemption_intent_certificate,
};
use xindex_shared::signer_wire::{
    error_codes, ObserverCertifyAccRequest, ObserverCertifyAccResponse, ObserverCertifyRequest,
    ObserverCertifyResponse,
};
use xindex_signer::{RicSigner, SignerError};

const MAX_HALT_BODY: usize = 64 * 1024;

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

/// Independent source of a fresh, fail-closed Asgard inbound. Production
/// implementations may apply complete Mimir/pool/consensus policy and durable
/// advancing-tip checks; the legacy [`xindex_chain_thor::AsgardAgreement`]
/// adapter remains available for development tests.
pub trait AsgardSource {
    /// Resolve one chain's current inbound address at `now_unix`.
    ///
    /// # Errors
    /// Incomplete/stale/disagreeing source evidence or a halted route.
    fn resolve_asgard(
        &self,
        chain: &str,
        now_unix: u64,
    ) -> impl std::future::Future<Output = Result<xindex_chain_thor::InboundAddress, String>> + Send;
}

impl AsgardSource for xindex_chain_thor::AsgardAgreement {
    async fn resolve_asgard(
        &self,
        chain: &str,
        _now_unix: u64,
    ) -> Result<xindex_chain_thor::InboundAddress, String> {
        self.resolve_agreed(chain)
            .await
            .map_err(|error| error.to_string())
    }
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

/// The on-chain facts of one mint cancellation (CTD-1 Slice C tail),
/// read from the observer's OWN Ethereum RPC via the `AcquireCancelled`
/// event. Deliberately EXCLUDES the event's `amount`: it is the
/// NON-authoritative USDT allocation recomputed at cancel time (Xindex
/// A1/A5) and must never size a native swap-back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelFacts {
    /// Intent id of the cancelled mint (`AcquireCancelled.intentId`).
    pub intent_id: B256,
    /// Async slot index (`AcquireCancelled.slotIndex`, clamped to `u32`
    /// at record time — the ACC wire constrains it the same way).
    pub slot_index: u32,
}

/// One observed cancellation: the facts plus when THIS observer first
/// saw the `AcquireCancelled`. The E2 fraud-window delay on the
/// swap-back is measured from `observed_at`; first-write-wins means a
/// reorg-replayed event can never reset the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedCancel {
    /// The cancel facts as first observed.
    pub facts: CancelFacts,
    /// Unix seconds (this observer's clock) of the FIRST observation.
    pub observed_at: u64,
}

/// In-memory `AcquireCancelled` record keyed by `cancel_id`, populated
/// by the binary's event loop on the operator's OWN RPC — the cancel
/// sibling of [`InMemoryLegSource`]. Concrete (no trait): the live impl
/// IS the in-memory map, and tests insert into it directly.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCancelSource {
    facts: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<B256, ObservedCancel>>>,
}

impl InMemoryCancelSource {
    /// Empty source — the event loop fills it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cancellation's facts (called by the event loop on each
    /// `AcquireCancelled`) stamped with the observer's own clock. First
    /// write wins per `cancel_id`.
    pub fn insert(&self, cancel_id: B256, facts: CancelFacts, observed_at: u64) {
        if let Ok(mut map) = self.facts.write() {
            map.entry(cancel_id)
                .or_insert(ObservedCancel { facts, observed_at });
        }
    }

    /// Atomically replace the compatibility view from the durable canonical
    /// store after restart or reorg rollback.
    ///
    /// # Errors
    /// Poisoned lock or duplicate cancellation identity in the supplied rows.
    pub fn replace_all(&self, rows: Vec<(B256, ObservedCancel)>) -> Result<(), String> {
        let mut replacement = std::collections::HashMap::with_capacity(rows.len());
        for (cancel_id, observed) in rows {
            if replacement.insert(cancel_id, observed).is_some() {
                return Err(format!("duplicate canonical cancel {cancel_id:#x}"));
            }
        }
        let mut map = self
            .facts
            .write()
            .map_err(|error| format!("cancel map poisoned: {error}"))?;
        *map = replacement;
        Ok(())
    }

    fn get(&self, cancel_id: B256) -> Result<Option<ObservedCancel>, String> {
        let map = self
            .facts
            .read()
            .map_err(|e| format!("cancel map poisoned: {e}"))?;
        Ok(map.get(&cancel_id).copied())
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
#[derive(Clone)]
pub struct HttpHaltSource {
    url: String,
    guard: Address,
    block_tag: &'static str,
    client: reqwest::Client,
}

impl std::fmt::Debug for HttpHaltSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpHaltSource")
            .field("url", &"<redacted>")
            .field("guard", &self.guard)
            .finish_non_exhaustive()
    }
}

impl HttpHaltSource {
    /// Halt source over `url` (HTTP JSON-RPC) for the guard contract.
    #[must_use]
    pub fn new(url: String, guard: Address) -> Self {
        Self {
            url,
            guard,
            block_tag: "latest",
            client: reqwest::Client::new(),
        }
    }

    /// Production form: evaluate the guard at the execution client's
    /// consensus-finalized tag, matching finalized event ingestion.
    #[must_use]
    pub fn finalized(url: String, guard: Address) -> Self {
        Self {
            url,
            guard,
            block_tag: "finalized",
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
                self.block_tag
            ]
        });
        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("halt eth_call transport: {}", transport_class(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("halt eth_call http {}", status.as_u16()));
        }
        if resp
            .content_length()
            .is_some_and(|length| length > MAX_HALT_BODY as u64)
        {
            return Err("halt eth_call response exceeds 64 KiB".to_string());
        }
        let mut bytes = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = futures_util::StreamExt::next(&mut stream).await {
            let chunk =
                chunk.map_err(|e| format!("halt eth_call body: {}", transport_class(&e)))?;
            if bytes.len().saturating_add(chunk.len()) > MAX_HALT_BODY {
                return Err("halt eth_call response exceeds 64 KiB".to_string());
            }
            bytes.extend_from_slice(&chunk);
        }
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| "halt eth_call body is malformed json".to_string())?;
        let result = v
            .get("result")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "halt eth_call: no result".to_string())?;
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
        if raw[..31].iter().any(|byte| *byte != 0) || !matches!(raw[31], 0 | 1) {
            return Err("halt eth_call returned a non-canonical bool".to_string());
        }
        Ok(raw[31] == 1)
    }
}

fn transport_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_request() {
        "request"
    } else {
        "unknown"
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
    /// CTD-1 Slice C tail: the Ethereum address this operator pins as
    /// the ONLY destination a mint-cancel swap-back memo may pay (the
    /// protocol's documented recovery sink — ceremony/runbook material,
    /// like the volume caps). `None` disables `certify_acc` entirely —
    /// there is no safe default destination.
    pub cancel_recovery_dest: Option<Address>,
    /// CTD-1 Slice C tail: the `THORChain` asset string a swap-back
    /// memo must target (`ETH.USDT` on mainnet; stagenet differs).
    pub swap_back_asset: String,
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
    /// No `AcquireCancelled` visible on this observer's own RPC.
    #[error("no AcquireCancelled for {cancel_id:#x}")]
    CancelNotFound {
        /// The requested cancel id.
        cancel_id: B256,
    },
    /// This observer has no mint-cancel recovery destination configured
    /// — the `certify_acc` path is disabled (operator configuration).
    #[error("mint-cancel certification disabled: no recovery destination configured")]
    CancelDisabled,
    /// The proposed swap-back memo failed the grammar/destination pin —
    /// the coordinator-steered-destination refusal.
    #[error("swap-back memo rejected: {0}")]
    MemoRejected(String),
}

impl ObserverError {
    /// Stable wire error-code string for this rejection.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ChainUnsupported(_) => error_codes::OBSERVER_CHAIN_UNSUPPORTED,
            Self::BadRequest(_) => error_codes::INTENT_PROOF_INVALID,
            Self::EventNotFound { .. } | Self::CancelNotFound { .. } => {
                error_codes::OBSERVER_EVENT_NOT_FOUND
            }
            Self::EventInvalid(_) => error_codes::OBSERVER_EVENT_INVALID,
            Self::StampOutOfWindow(_) => error_codes::OBSERVER_STAMP_OUT_OF_WINDOW,
            Self::AsgardUnavailable(_) | Self::LegSource(_) => {
                error_codes::OBSERVER_ASGARD_UNAVAILABLE
            }
            Self::SignerUnavailable(_) => error_codes::OBSERVER_SIGNER_UNAVAILABLE,
            Self::Halted => error_codes::OBSERVER_HALTED,
            Self::FraudWindowActive { .. } => error_codes::OBSERVER_FRAUD_WINDOW,
            Self::HaltUnavailable(_) => error_codes::OBSERVER_HALT_UNAVAILABLE,
            Self::CancelDisabled => error_codes::OBSERVER_CANCEL_DISABLED,
            Self::MemoRejected(_) => error_codes::OBSERVER_MEMO_REJECTED,
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
pub struct Observer<L, S, G, A = xindex_chain_thor::AsgardAgreement> {
    config: ObserverConfig,
    asgard: A,
    legs: L,
    cancels: InMemoryCancelSource,
    signer: std::sync::Arc<S>,
    halt: G,
}

impl<L, S, G, A> Observer<L, S, G, A>
where
    L: RedeemLegSource,
    S: RicSigner,
    G: HaltSource,
    A: AsgardSource,
{
    /// Build an observer over its leg source, diverse-source Asgard
    /// gate, its own Set-B signer, and the on-chain halt source
    /// (`DL-CTD-E`). The mint-cancel record starts empty — the event
    /// loop writes into the handle [`Observer::cancel_source`] returns.
    #[must_use]
    pub fn new(config: ObserverConfig, asgard: A, legs: L, signer: S, halt: G) -> Self {
        Self {
            config,
            asgard,
            legs,
            cancels: InMemoryCancelSource::new(),
            signer: std::sync::Arc::new(signer),
            halt,
        }
    }

    /// Shared handle to this observer's `AcquireCancelled` record (the
    /// maps are `Arc`-backed; the event loop and tests write through
    /// this clone).
    #[must_use]
    pub fn cancel_source(&self) -> InMemoryCancelSource {
        self.cancels.clone()
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
    ) -> Result<ObserverCertifyResponse, ObserverError>
    where
        S: Send + Sync + 'static,
    {
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
            .resolve_asgard(thor_chain_name(self.config.chain), now_unix)
            .await
            .map_err(ObserverError::AsgardUnavailable)?
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
        // The Set-B signer is a reqwest::blocking client — run its call on a
        // blocking thread, not this async worker (a blocking reqwest call on a
        // runtime worker panics dropping reqwest's temp runtime). spawn_blocking
        // works on both multi-thread and current-thread (test) runtimes.
        let chain = self.config.chain;
        let signer = std::sync::Arc::clone(&self.signer);
        let sig = tokio::task::spawn_blocking(move || signer.sign_ric(chain, &ric, &domain))
            .await
            .map_err(|e| SignerError::Backend(format!("sign_ric task: {e}")))??;

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

    /// Independently resolve + certify one mint-cancel swap-back (CTD-1
    /// Slice C tail) — the [`Observer::certify_ric`] sibling rooted on
    /// the `AcquireCancelled` event.
    ///
    /// Trust split (see [`ObserverCertifyAccRequest`]): `intent_id` /
    /// `slot_index` come from this observer's OWN event record, the
    /// Asgard inbound from its OWN agreement gate, and the memo's
    /// destination is pinned to its OWN configured recovery address.
    /// The `amount` is proposer-supplied (the authoritative figure is a
    /// native-chain fact) and is BOUNDED instead: the E2 fraud window
    /// delays large values from first cancel observation, and the Set-B
    /// daemon's per-chain volume window meters the total.
    ///
    /// # Errors
    /// [`ObserverError`] — fails closed on any divergence between this
    /// observer's view and the request.
    pub async fn certify_acc(
        &self,
        req: &ObserverCertifyAccRequest,
        now_unix: u64,
    ) -> Result<ObserverCertifyAccResponse, ObserverError>
    where
        S: Send + Sync + 'static,
    {
        if req.chain_id != self.config.chain || req.chain_id == ChainId::Sol {
            return Err(ObserverError::ChainUnsupported(format!(
                "{:?}",
                req.chain_id
            )));
        }
        if self
            .halt
            .is_halted()
            .await
            .map_err(ObserverError::HaltUnavailable)?
        {
            return Err(ObserverError::Halted);
        }
        let recovery = self
            .config
            .cancel_recovery_dest
            .ok_or(ObserverError::CancelDisabled)?;
        let cancel_id = parse_b256(&req.cancel_id, "cancel_id")?;
        self.check_stamp(req.vault_resolved_at, now_unix)?;
        let amount = U256::from_str_radix(&req.amount, 10)
            .map_err(|e| ObserverError::BadRequest(format!("amount: {e}")))?;
        if amount == U256::ZERO {
            return Err(ObserverError::BadRequest("zero amount".to_string()));
        }
        validate_swap_back_memo(&req.memo, &self.config.swap_back_asset, recovery)?;

        let observed = self
            .cancels
            .get(cancel_id)
            .map_err(ObserverError::LegSource)?
            .ok_or(ObserverError::CancelNotFound { cancel_id })?;

        // DL-CTD-E E2: a large swap-back waits out the fraud window,
        // measured from the FIRST observation of the cancel event.
        if let Some(threshold) = self.config.large_spend_threshold {
            if amount > threshold {
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
            .resolve_asgard(thor_chain_name(self.config.chain), now_unix)
            .await
            .map_err(ObserverError::AsgardUnavailable)?
            .address;
        let immediate_target_hash = self.immediate_target_hash(&asgard_address)?;

        let memo_hash = keccak256(req.memo.as_bytes());
        let final_destination_hash = keccak256(recovery.as_slice());
        let acc = acquire_cancel_certificate(
            cancel_id,
            observed.facts.intent_id,
            U256::from(observed.facts.slot_index),
            self.config.chain.asset_id_hash(),
            amount,
            self.config.chain.decimals(),
            immediate_target_hash,
            memo_hash,
            final_destination_hash,
            req.vault_resolved_at,
        );
        let domain = attestation_oracle_domain(self.config.eth_chain_id, self.config.oracle);
        // See certify_ric: run the reqwest::blocking signer off the async worker.
        let chain = self.config.chain;
        let signer = std::sync::Arc::clone(&self.signer);
        let sig = tokio::task::spawn_blocking(move || signer.sign_acc(chain, &acc, &domain))
            .await
            .map_err(|e| SignerError::Backend(format!("sign_acc task: {e}")))??;

        Ok(ObserverCertifyAccResponse {
            chain_id: self.config.chain,
            cancel_id: format!("{cancel_id:#x}"),
            intent_id: format!("{:#x}", observed.facts.intent_id),
            slot_index: observed.facts.slot_index.to_string(),
            asset_id: format!("{:#x}", self.config.chain.asset_id_hash()),
            amount: amount.to_string(),
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

/// CTD-1 Slice C tail: enforce the swap-back memo grammar and pin its
/// destination to THIS operator's configured recovery address. The memo
/// is proposer-built (the executor needs control of the limit field),
/// but a memo that pays anywhere except the pinned recovery sink is
/// refused — the coordinator cannot steer the swapped-back USDT. Strict
/// AND total (RUST-001): `=:<asset>:<recovery>[:<lim>]` ONLY — at most 4
/// colon-fields, so no `THORChain` affiliate (field 4 = `THORName`, field 5 =
/// fee bps) or dex-aggregator (fields 6-8) field can ride along. ≤ 80 bytes.
fn validate_swap_back_memo(
    memo: &str,
    swap_back_asset: &str,
    recovery: Address,
) -> Result<(), ObserverError> {
    if memo.is_empty() {
        return Err(ObserverError::MemoRejected("empty memo".to_string()));
    }
    if memo.len() > MAX_MEMO_BYTES {
        return Err(ObserverError::MemoRejected(format!(
            "memo {} bytes > {MAX_MEMO_BYTES}",
            memo.len()
        )));
    }
    let mut parts = memo.split(':');
    let tag = parts.next().unwrap_or_default();
    if tag != "=" && !tag.eq_ignore_ascii_case("SWAP") {
        return Err(ObserverError::MemoRejected(format!(
            "not a swap memo (tag {tag:?})"
        )));
    }
    let asset = parts.next().unwrap_or_default();
    if !asset.eq_ignore_ascii_case(swap_back_asset) {
        return Err(ObserverError::MemoRejected(format!(
            "asset {asset:?} != pinned swap-back asset {swap_back_asset:?}"
        )));
    }
    let dest = parts.next().unwrap_or_default();
    let expected = format!("{recovery:#x}");
    if !dest.eq_ignore_ascii_case(&expected) {
        return Err(ObserverError::MemoRejected(format!(
            "destination {dest:?} != pinned recovery {expected}"
        )));
    }
    // RUST-001 (audit 2026-06-20): the grammar is TOTAL, not prefix-only.
    // Field 3 (LIM / `lim/interval/quantity` stream spec) is executor-
    // controlled but only affects slippage — it can grief a refund, never
    // redirect funds. Everything past it CAN steer the swap output away
    // from the pinned recovery sink: THORChain parses field 4 = affiliate
    // THORName/address and field 5 = affiliate fee bps capped at 100%
    // (`constants.MaxBasisPts` = 10_000), plus dex-aggregator fields 6-8. So
    // `=:ETH.USDT:<recovery>:0:<attacker>:10000` would skim 100% to an
    // attacker affiliate while the visible destination stays honest. Cap at
    // 4 colon-fields to make affiliate/dex injection impossible.
    let _lim = parts.next();
    if parts.next().is_some() {
        return Err(ObserverError::MemoRejected(format!(
            "swap-back memo carries affiliate/dex fields (> 4 colon-fields): {memo:?}"
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
    use xindex_shared::eip712::{
        acquire_cancel_signing_hash, ric_signing_hash, AcquireCancelCertificate,
        RedemptionIntentCertificate,
    };
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

    fn recovery() -> Address {
        Address::repeat_byte(0xaa)
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
            cancel_recovery_dest: Some(recovery()),
            swap_back_asset: "ETH.USDT".to_string(),
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

    // ── CTD-1 Slice C tail: certify_acc ────────────────────────────

    const CANCEL_ID: B256 = B256::repeat_byte(0xac);
    const INTENT_ID: B256 = B256::repeat_byte(0x1d);

    fn swap_back_memo() -> String {
        format!("=:ETH.USDT:{:#x}:0", recovery())
    }

    fn acc_req(memo: String) -> ObserverCertifyAccRequest {
        ObserverCertifyAccRequest {
            chain_id: ChainId::Btc,
            cancel_id: format!("{CANCEL_ID:#x}"),
            amount: "50000000".to_string(),
            memo,
            vault_resolved_at: NOW,
        }
    }

    fn observed_cancel<L: RedeemLegSource, S: RicSigner, G: HaltSource>(
        observer: &Observer<L, S, G>,
        observed_at: u64,
    ) {
        observer.cancel_source().insert(
            CANCEL_ID,
            CancelFacts {
                intent_id: INTENT_ID,
                slot_index: 1,
            },
            observed_at,
        );
    }

    /// Happy path: the certified ACC binds the observer's OWN event
    /// record (intent/slot), its OWN Asgard resolution, and its OWN
    /// pinned recovery destination; the signature recovers to the Set-B
    /// signer over the independently-rebuilt ACC digest.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_certifies_and_signature_recovers() {
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
        observed_cancel(&observer, NOW);
        let resp = observer
            .certify_acc(&acc_req(swap_back_memo()), NOW)
            .await
            .expect("must certify");

        assert_eq!(resp.asgard_address, ASGARD_BTC);
        assert_eq!(resp.intent_id, format!("{INTENT_ID:#x}"));
        assert_eq!(resp.slot_index, "1");
        assert_eq!(
            resp.final_destination_hash,
            format!("{:#x}", keccak256(recovery().as_slice()))
        );

        let btc_addr = bitcoin::Address::from_str(ASGARD_BTC)
            .expect("addr")
            .require_network(Network::Bitcoin)
            .expect("net");
        let expect_target = keccak256(btc_addr.script_pubkey().as_bytes());
        let acc = AcquireCancelCertificate {
            cancelId: CANCEL_ID,
            intentId: INTENT_ID,
            slotIndex: U256::from(1u64),
            assetId: ChainId::Btc.asset_id_hash(),
            amount: U256::from(50_000_000u64),
            amountDecimals: 8,
            immediateTargetHash: expect_target,
            memoHash: keccak256(swap_back_memo().as_bytes()),
            finalDestinationHash: keccak256(recovery().as_slice()),
            vaultResolvedAt: NOW,
        };
        let digest = acquire_cancel_signing_hash(&acc, &attestation_oracle_domain(1, oracle()));
        let sig_bytes =
            alloy_primitives::hex::decode(resp.signature.trim_start_matches("0x")).expect("hex");
        let sig =
            alloy_primitives::PrimitiveSignature::try_from(sig_bytes.as_slice()).expect("sig");
        let recovered = sig.recover_address_from_prehash(&digest).expect("recover");
        assert_eq!(format!("{recovered:#x}"), resp.signer_address);
        assert_eq!(recovered, signer().signer_address());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_unseen_cancel_is_not_found() {
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
            .certify_acc(&acc_req(swap_back_memo()), NOW)
            .await
            .expect_err("must 404");
        assert_eq!(err.error_code(), error_codes::OBSERVER_EVENT_NOT_FOUND);
    }

    /// THE Slice-C teeth: a memo steering the swapped-back USDT to any
    /// destination except this operator's pinned recovery address is
    /// refused, regardless of what the coordinator proposes.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_memo_steered_destination_rejected() {
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
        observed_cancel(&observer, NOW);
        let attacker = format!("=:ETH.USDT:{:#x}:0", Address::repeat_byte(0x66));
        let err = observer
            .certify_acc(&acc_req(attacker), NOW)
            .await
            .expect_err("must refuse");
        assert_eq!(err.error_code(), error_codes::OBSERVER_MEMO_REJECTED);
    }

    /// RUST-001 regression (external audit 2026-06-20): a swap-back memo
    /// whose VISIBLE destination IS the pinned recovery sink but which
    /// appends a `THORChain` affiliate field —
    /// `=:ETH.USDT:<recovery>:0:<attacker_thorname>:10000` — must be
    /// REJECTED. Per `THORNode` `x/thorchain/memo/memo_swap.go` the affiliate
    /// is field 4 and the fee bps is field 5, capped at
    /// `constants.MaxBasisPts = 10_000` (= 100%); `THORChain` skims that fee
    /// from the swap output to the affiliate. Before the fix the validator
    /// pinned only fields 0-2 and ignored 4+, so a compromised coordinator
    /// could redirect up to 100% of the recovered USDT with NO operator-key
    /// compromise (redirectable THEFT, defeating the Slice-C "coordinator
    /// cannot steer the swapped-back USDT" invariant). The fix caps the memo
    /// at 4 colon-fields; both the validator and the end-to-end certify path
    /// now refuse it. Contrast `acc_memo_wrong_asset_rejected`: there the
    /// destination/asset check fires; here the theft rode the affiliate field.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn rust001_affiliate_skim_memo_rejected() {
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
        observed_cancel(&observer, NOW);

        let malicious = format!("=:ETH.USDT:{:#x}:0:attacker:10000", recovery());
        assert!(
            malicious.len() <= MAX_MEMO_BYTES,
            "affiliate-skim memo fits the OP_RETURN cap ({} bytes)",
            malicious.len()
        );

        // (1) The validator refuses the affiliate-skim memo outright.
        assert!(
            validate_swap_back_memo(&malicious, "ETH.USDT", recovery()).is_err(),
            "validate_swap_back_memo must reject a 100%-affiliate-skim memo"
        );

        // (2) End-to-end: certify_acc refuses to sign an ACC over it, so the
        // 100% affiliate skim can never reach a custody daemon.
        let err = observer
            .certify_acc(&acc_req(malicious), NOW)
            .await
            .expect_err("affiliate-skim memo must be rejected");
        assert_eq!(err.error_code(), error_codes::OBSERVER_MEMO_REJECTED);
    }

    /// RUST-001 must NOT over-reject: the executor legitimately controls the
    /// LIM (field 3), including a streaming `lim/interval/quantity` spec
    /// (slash-separated, so still ONE colon-field). Both the bare
    /// `=:<asset>:<recovery>` and a 4-field streaming memo are accepted, while
    /// a stray 5th colon-field is refused.
    #[test]
    fn rust001_lim_and_streaming_memo_accepted() {
        let no_lim = format!("=:ETH.USDT:{:#x}", recovery());
        assert!(validate_swap_back_memo(&no_lim, "ETH.USDT", recovery()).is_ok());

        let streamed = format!("=:ETH.USDT:{:#x}:120/3/10", recovery());
        assert!(
            validate_swap_back_memo(&streamed, "ETH.USDT", recovery()).is_ok(),
            "a streaming LIM spec is one colon-field and must be allowed"
        );

        let extra = format!("=:ETH.USDT:{:#x}:0:", recovery());
        assert!(
            validate_swap_back_memo(&extra, "ETH.USDT", recovery()).is_err(),
            "a 5th colon-field (even empty) must be refused"
        );
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_memo_wrong_asset_rejected() {
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
        observed_cancel(&observer, NOW);
        let wrong = format!("=:BTC.BTC:{:#x}", recovery());
        let err = observer
            .certify_acc(&acc_req(wrong), NOW)
            .await
            .expect_err("must refuse");
        assert_eq!(err.error_code(), error_codes::OBSERVER_MEMO_REJECTED);
    }

    /// No recovery destination configured ⇒ the ACC path is disabled —
    /// there is no safe default sink.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_disabled_without_recovery_dest() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let mut cfg = config();
        cfg.cancel_recovery_dest = None;
        let observer = Observer::new(
            cfg,
            agreement(&[&a, &b]),
            FakeLegs {
                facts: None,
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        observed_cancel(&observer, NOW);
        let err = observer
            .certify_acc(&acc_req(swap_back_memo()), NOW)
            .await
            .expect_err("must refuse");
        assert_eq!(err.error_code(), error_codes::OBSERVER_CANCEL_DISABLED);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_zero_amount_rejected() {
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
        observed_cancel(&observer, NOW);
        let mut req = acc_req(swap_back_memo());
        req.amount = "0".to_string();
        let err = observer
            .certify_acc(&req, NOW)
            .await
            .expect_err("must refuse");
        assert_eq!(err.error_code(), error_codes::INTENT_PROOF_INVALID);
    }

    /// DL-CTD-E E2 applies to swap-backs too: a large proposed amount
    /// waits out the fraud window measured from the FIRST observation
    /// of the cancel event, then certifies.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_large_swap_back_waits_out_fraud_window() {
        let a = btc_source(ASGARD_BTC, false).await;
        let b = btc_source(ASGARD_BTC, false).await;
        let mut cfg = config();
        cfg.large_spend_threshold = Some(U256::from(10_000_000u64));
        let observer = Observer::new(
            cfg,
            agreement(&[&a, &b]),
            FakeLegs {
                facts: None,
                observed_at: NOW,
            },
            signer(),
            NeverHalted,
        );
        let observed_at = NOW - 100;
        observed_cancel(&observer, observed_at);
        let err = observer
            .certify_acc(&acc_req(swap_back_memo()), NOW)
            .await
            .expect_err("window open");
        assert_eq!(err.error_code(), error_codes::OBSERVER_FRAUD_WINDOW);
        let ObserverError::FraudWindowActive { until } = err else {
            unreachable!()
        };
        assert_eq!(until, observed_at + 1_800);

        // Retry once the window opens — with a FRESH stamp, as a real
        // re-certify round proposes (the original stamp is now outside
        // the observer's clock window).
        let mut later = acc_req(swap_back_memo());
        later.vault_resolved_at = observed_at + 1_801;
        observer
            .certify_acc(&later, observed_at + 1_801)
            .await
            .expect("window elapsed");
    }

    /// DL-CTD-E: an active halt vetoes ACC certification exactly as it
    /// vetoes RIC certification.
    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn acc_halted_guard_refuses() {
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
            FakeHalt { halted: Some(true) },
        );
        observed_cancel(&observer, NOW);
        let err = observer
            .certify_acc(&acc_req(swap_back_memo()), NOW)
            .await
            .expect_err("halt vetoes");
        assert_eq!(err.error_code(), error_codes::OBSERVER_HALTED);
    }
}
