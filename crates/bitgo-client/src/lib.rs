//! Bounded authenticated transport for the reviewed `BitGo` wallet boundary.
//!
//! The pure `xindex-bitgo-adapter` remains transport- and credential-free.
//! This crate owns the fixed `BitGo` origins, version-pinned HMAC request and
//! response authentication, bounded response reads, typed provider captures,
//! and durable orchestration. It never accepts private keys; the irreversible
//! send is exposed only by [`BitGoCoordinator`] after a write-ahead reservation.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::consensus::deserialize;
use bitcoin::psbt::Psbt;
use bitcoin::{Transaction, Txid};
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xindex_bitgo_adapter::{
    build_request, validate_unsigned, BitGoCoin, BuildRequest, PolicyError, SendRequest,
    SpendPolicy, WalletPolicy,
};
use xindex_ops::network::{
    async_client_builder, read_bounded_async, HttpClientPolicy, NetworkError,
};

mod coordinator;
mod evidence;
#[cfg(test)]
mod test_support;
mod workflow;

pub use coordinator::{BitGoCoordinator, CoordinatorError, SubmitOutcome};
pub use evidence::{EvidenceArtifact, EvidenceError, EvidenceManifest};
pub use workflow::{
    BitGoWorkflowStore, BuildReservation, SendReservation, WorkflowError, WorkflowPhase,
    WorkflowRecord,
};

const TEST_ORIGIN: &str = "https://app.bitgo-test.com";
const PRODUCTION_ORIGIN: &str = "https://app.bitgo.com";
const MAX_ACCESS_TOKEN_BYTES: usize = 4 * 1024;
const MAX_PROVIDER_IDENTIFIER_BYTES: usize = 256;
const RESPONSE_BACKWARD_VALIDITY_MILLIS: u64 = 5 * 60 * 1_000;
const RESPONSE_FORWARD_VALIDITY_MILLIS: u64 = 60 * 1_000;
const AUTHENTICATED_RESPONSE_SCHEMA: &str = "xindex.bitgo.authenticated-response.v1";
#[cfg(test)]
const OFFICIAL_FINAL_TXID: &str =
    "5ea8d2b93997ed9fa3597a2f3113817c8216f573a0278c2533bb5db50fdb0dff";
#[cfg(test)]
const OFFICIAL_FINAL_TX: &str = "010000000001010e4d3af014f9efe311062965d561b67f78a1759e7016605cd506ddd7041762d50000000023220020510ded26d712922bbb61bc68ef6766f836a03527820cbdc8b1551914eb467dafffffffff02102700000000000017a9145a581567fd2a630e61e34a696ab3bb887972886d87ad0f010000000000225120850d0ab466d15cb1565dd528d4d9709f3e46f41d41fe6d94aa01378e626983990400483045022100db45a8d94ee2144f7e29baa855d94a2bf0120707a7ab2fc93734ed94af972c460220558d00b91275aafc7805dfaaf9ab796adbe9f4e66dc467f7eb93b790671a323201473044022049e20c0073f42c9636408efc6c833ebf0e1a8ef13e8cb818dde2f4e2af7f7b7f022000cb3a321d65605b9d51d7f87e34306169607646c8d54a44011b021eff3dbe500169522103c10ac628c880629ed0fd2a0563a898f4882baca45e15668a4d3064cf1ea379882103e56f84be4460080618ef869bb7b07096880760f748ba23efab533c2359f923bd21020ae81372264b5eac5c9dc7fe0b9a32bad00771c3a2c71f6e2c971823c3182ed653ae00000000";

/// `BitGo` environment fixed to one official origin and compatible Bitcoin coin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitGoEnvironment {
    /// `BitGo` test environment; only `tbtc4` is accepted.
    Test,
    /// `BitGo` production environment; only `btc` is accepted.
    Production,
}

impl BitGoEnvironment {
    const fn origin(self) -> &'static str {
        match self {
            Self::Test => TEST_ORIGIN,
            Self::Production => PRODUCTION_ORIGIN,
        }
    }

    const fn accepts(self, coin: BitGoCoin) -> bool {
        matches!(
            (self, coin),
            (Self::Test, BitGoCoin::Tbtc4) | (Self::Production, BitGoCoin::Btc)
        )
    }
}

/// `BitGo` HMAC protocol version explicitly bound to every request and response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitGoAuthVersion {
    /// `BitGo` Auth V2: `timestamp|path|body` request subjects.
    V2,
    /// `BitGo` Auth V3: method- and version-bound request subjects.
    V3,
}

impl BitGoAuthVersion {
    const fn header(self) -> &'static str {
        match self {
            Self::V2 => "2.0",
            Self::V3 => "3.0",
        }
    }
}

/// Stable, redacted failure from the `BitGo` transport boundary.
#[derive(Debug, thiserror::Error)]
pub enum BitGoClientError {
    /// Access token cannot form one bounded authorization header.
    #[error("BitGo access token is invalid (value redacted)")]
    InvalidAccessToken,
    /// Fixed or test-only origin cannot be used as an HTTP base URL.
    #[error("BitGo API origin is invalid")]
    InvalidOrigin,
    /// A mainnet/testnet policy was presented to the wrong `BitGo` environment.
    #[error("BitGo environment does not match the wallet coin")]
    EnvironmentCoinMismatch,
    /// Bounded HTTP client construction failed.
    #[error("BitGo HTTP client construction failed")]
    ClientBuild,
    /// The local clock cannot produce the millisecond timestamp required by `BitGo`.
    #[error("BitGo authentication clock failed")]
    Clock,
    /// A typed request could not be serialized exactly once for HMAC and transport.
    #[error("BitGo request encoding failed")]
    RequestEncoding,
    /// Request transport failed. Provider URLs and response text are omitted.
    #[error("BitGo HTTP request failed")]
    Transport,
    /// The response body could not be read inside the configured cap.
    #[error("BitGo response body failed: {0}")]
    ResponseBody(#[source] NetworkError),
    /// `BitGo` rejected the request; only stable bounded identifiers are retained.
    #[error("BitGo returned HTTP {status}; code={name:?}; request_id={request_id:?}")]
    Provider {
        /// HTTP status code.
        status: u16,
        /// Stable provider error name, when safely encoded.
        name: Option<String>,
        /// Provider request correlation, when safely encoded.
        request_id: Option<String>,
    },
    /// A success response was not valid JSON.
    #[error("BitGo success response is not valid JSON")]
    InvalidJson,
    /// The provider response omitted, expired, or failed its configured HMAC.
    #[error("BitGo response authentication failed")]
    ResponseAuthentication,
    /// A required provider field or topology invariant was missing or invalid.
    #[error("BitGo success response has invalid field {field}")]
    InvalidResponse {
        /// Stable local field label; never provider-controlled text.
        field: &'static str,
    },
    /// A returned `txHex` was not hexadecimal BIP-174 data.
    #[error("BitGo build response does not contain a valid hexadecimal PSBT")]
    InvalidPsbt,
    /// Existing provider-independent policy validation rejected the capture.
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

/// Parsed provider object plus the exact bounded response body retained for evidence.
pub struct CapturedResponse<T> {
    value: T,
    raw_body: Vec<u8>,
    authenticated_evidence: Vec<u8>,
}

impl<T: fmt::Debug> fmt::Debug for CapturedResponse<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedResponse")
            .field("value", &self.value)
            .field("raw_body", &format_args!("<{} bytes>", self.raw_body.len()))
            .field(
                "authenticated_evidence",
                &format_args!("<{} bytes>", self.authenticated_evidence.len()),
            )
            .finish()
    }
}

impl<T> CapturedResponse<T> {
    /// Parsed, locally validated response value.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Exact bounded provider body for an owner-only evidence sink.
    #[must_use]
    pub fn raw_body(&self) -> &[u8] {
        &self.raw_body
    }

    /// Canonical envelope containing the verified response HMAC metadata and
    /// exact bounded body. This is channel-authentication evidence, not an
    /// asymmetric provider signature.
    #[must_use]
    pub fn authenticated_evidence(&self) -> &[u8] {
        &self.authenticated_evidence
    }

    /// Consume the capture into its validated value and exact provider bytes.
    #[must_use]
    pub fn into_parts(self) -> (T, Vec<u8>) {
        (self.value, self.raw_body)
    }

    /// Consume the capture into its validated value and canonical authenticated
    /// response envelope for durable evidence storage.
    #[must_use]
    pub fn into_evidence_parts(self) -> (T, Vec<u8>) {
        (self.value, self.authenticated_evidence)
    }
}

/// Reviewed wallet metadata corroborated through `BitGo`'s wallet endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSnapshot {
    wallet_id: String,
    coin: BitGoCoin,
    key_ids: [String; 3],
}

impl WalletSnapshot {
    /// Provider wallet identifier equal to the reviewed wallet policy.
    #[must_use]
    pub fn wallet_id(&self) -> &str {
        &self.wallet_id
    }

    /// Provider coin equal to the reviewed environment.
    #[must_use]
    pub const fn coin(&self) -> BitGoCoin {
        self.coin
    }

    /// User, backup, and `BitGo` provider key IDs in provider order.
    #[must_use]
    pub fn key_ids(&self) -> &[String; 3] {
        &self.key_ids
    }
}

/// Exact generated build request and provider-returned PSBT after policy validation.
#[derive(Debug, Clone)]
pub struct BuildCapture {
    request: BuildRequest,
    psbt: Psbt,
}

pub(crate) enum ProviderSendOutcome {
    Broadcast {
        transfer_id: String,
        txid: Txid,
        transaction: Transaction,
    },
    PendingApproval {
        approval_id: String,
    },
}

impl BuildCapture {
    /// Exact request generated from independent spend policy.
    #[must_use]
    pub const fn request(&self) -> &BuildRequest {
        &self.request
    }

    /// Unsigned PSBT that passed the complete provider-independent policy.
    #[must_use]
    pub const fn psbt(&self) -> &Psbt {
        &self.psbt
    }
}

/// `BitGo` transfer state used by idempotent sequence reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferState {
    /// Initialized but not yet signed.
    Initialized,
    /// Waiting for wallet/enterprise approval.
    PendingApproval,
    /// Signed and pending chain progress.
    Signed,
    /// In the mempool or provider delivery path.
    Unconfirmed,
    /// Confirmed on chain.
    Confirmed,
    /// Provider or chain processing failed.
    Failed,
    /// An approver rejected the transfer.
    Rejected,
    /// Removed from the mempool or chain view.
    Removed,
    /// Replaced by another transaction.
    Replaced,
}

/// Minimal transfer identity returned by exact sequence-ID lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferSnapshot {
    transfer_id: String,
    state: TransferState,
    txid: Option<String>,
}

impl TransferSnapshot {
    /// Provider transfer identifier.
    #[must_use]
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    /// Current provider transfer state.
    #[must_use]
    pub const fn state(&self) -> TransferState {
        self.state
    }

    /// Bitcoin transaction ID, once assigned.
    #[must_use]
    pub fn txid(&self) -> Option<&str> {
        self.txid.as_deref()
    }
}

/// Read-only state returned by the pending-approval endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalSnapshot {
    /// Approval or provider signing is still outstanding.
    Pending {
        /// Exact provider approval identifier.
        approval_id: String,
    },
    /// Approval resolved and exposes a final signed transaction.
    Approved {
        /// Exact provider approval identifier.
        approval_id: String,
        /// Transaction ID corroborated by the approval response.
        txid: Txid,
        /// Exact provider-finalized transaction.
        transaction: Transaction,
    },
    /// An independent approver rejected the transaction.
    Rejected {
        /// Exact provider approval identifier.
        approval_id: String,
    },
}

impl ApprovalSnapshot {
    /// Exact provider approval identifier.
    #[must_use]
    pub fn approval_id(&self) -> &str {
        match self {
            Self::Pending { approval_id }
            | Self::Approved { approval_id, .. }
            | Self::Rejected { approval_id } => approval_id,
        }
    }
}

/// Bounded `BitGo` REST client. Debug output deliberately omits origin and token.
#[derive(Clone)]
pub struct BitGoClient {
    environment: BitGoEnvironment,
    auth_version: BitGoAuthVersion,
    origin: Url,
    access_token: Arc<str>,
    authorization: HeaderValue,
    http: reqwest::Client,
    max_response_bytes: usize,
}

impl fmt::Debug for BitGoClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitGoClient")
            .field("environment", &self.environment)
            .field("auth_version", &self.auth_version)
            .field("origin", &"<redacted>")
            .field("access_token", &"<redacted>")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

struct VerifiedHttpResponse {
    status: StatusCode,
    body: Vec<u8>,
    authenticated_evidence: Vec<u8>,
}

impl VerifiedHttpResponse {
    fn capture<T>(self, value: T) -> CapturedResponse<T> {
        CapturedResponse {
            value,
            raw_body: self.body,
            authenticated_evidence: self.authenticated_evidence,
        }
    }
}

impl BitGoClient {
    /// Build a client for one official `BitGo` environment.
    ///
    /// # Errors
    /// Invalid token/policy or bounded-client construction failure.
    pub fn new(
        environment: BitGoEnvironment,
        auth_version: BitGoAuthVersion,
        access_token: &str,
        policy: HttpClientPolicy,
    ) -> Result<Self, BitGoClientError> {
        Self::from_origin(
            environment,
            auth_version,
            environment.origin(),
            access_token,
            policy,
        )
    }

    fn from_origin(
        environment: BitGoEnvironment,
        auth_version: BitGoAuthVersion,
        raw_origin: &str,
        access_token: &str,
        policy: HttpClientPolicy,
    ) -> Result<Self, BitGoClientError> {
        let origin = Url::parse(raw_origin).map_err(|_| BitGoClientError::InvalidOrigin)?;
        if origin.cannot_be_a_base()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(BitGoClientError::InvalidOrigin);
        }
        if access_token.is_empty()
            || access_token.len() > MAX_ACCESS_TOKEN_BYTES
            || access_token.trim() != access_token
            || access_token.chars().any(char::is_control)
        {
            return Err(BitGoClientError::InvalidAccessToken);
        }
        let token_hash = alloy_primitives::hex::encode(Sha256::digest(access_token.as_bytes()));
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token_hash}"))
            .map_err(|_| BitGoClientError::InvalidAccessToken)?;
        authorization.set_sensitive(true);
        let max_response_bytes = policy.max_response_bytes;
        let http = async_client_builder(policy)
            .map_err(|_| BitGoClientError::ClientBuild)?
            .no_proxy()
            .build()
            .map_err(|_| BitGoClientError::ClientBuild)?;
        Ok(Self {
            environment,
            auth_version,
            origin,
            access_token: Arc::from(access_token),
            authorization,
            http,
            max_response_bytes,
        })
    }

    /// Corroborate the fixed wallet ID, coin, hot/on-chain 2-of-3 topology,
    /// and three distinct provider key IDs.
    ///
    /// # Errors
    /// Environment mismatch, transport/provider failure, or invalid topology.
    pub async fn wallet(
        &self,
        policy: &WalletPolicy,
    ) -> Result<CapturedResponse<WalletSnapshot>, BitGoClientError> {
        self.ensure_coin(policy.coin())?;
        let url = self.wallet_endpoint(policy, &[])?;
        let response = self.get(url).await?;
        Self::require_status(response.status, StatusCode::OK, &response.body)?;
        let wire: WalletWire = decode_json(&response.body)?;
        let snapshot = validate_wallet_wire(wire, policy)?;
        Ok(response.capture(snapshot))
    }

    /// Generate the exact request, call `BitGo`'s multisig build endpoint, and
    /// validate the returned unsigned PSBT before returning it.
    ///
    /// # Errors
    /// Environment, transport, response decoding, or spend-policy failure.
    pub async fn build_transaction(
        &self,
        policy: &SpendPolicy,
    ) -> Result<CapturedResponse<BuildCapture>, BitGoClientError> {
        self.ensure_coin(policy.wallet().coin())?;
        let request = build_request(policy)?;
        let url = self.wallet_endpoint(policy.wallet(), &["tx", "build"])?;
        let response = self.post(url, &request).await?;
        Self::require_status(response.status, StatusCode::OK, &response.body)?;
        let wire: BuildWire = decode_json(&response.body)?;
        let psbt_bytes = alloy_primitives::hex::decode(wire.tx_hex.trim_start_matches("0x"))
            .map_err(|_| BitGoClientError::InvalidPsbt)?;
        let psbt = Psbt::deserialize(&psbt_bytes).map_err(|_| BitGoClientError::InvalidPsbt)?;
        validate_unsigned(&psbt, policy)?;
        Ok(response.capture(BuildCapture { request, psbt }))
    }

    /// Reconcile one unique sequence ID without creating another transaction.
    ///
    /// # Errors
    /// Environment, transport/provider failure, or mismatched transfer data.
    pub async fn transfer_by_sequence_id(
        &self,
        policy: &SpendPolicy,
    ) -> Result<CapturedResponse<TransferSnapshot>, BitGoClientError> {
        self.ensure_coin(policy.wallet().coin())?;
        let url = self.wallet_endpoint(
            policy.wallet(),
            &["transfer", "sequenceId", policy.sequence_id()],
        )?;
        let response = self.get(url).await?;
        if !matches!(
            response.status,
            StatusCode::OK | StatusCode::PARTIAL_CONTENT
        ) {
            return Err(Self::provider_error(response.status, &response.body));
        }
        let wire: TransferWire = decode_json(&response.body)?;
        let snapshot = validate_transfer_wire(wire, policy, true)?;
        Ok(response.capture(snapshot))
    }

    /// Read one pending approval without resolving or mutating it.
    ///
    /// # Errors
    /// Environment, transport/provider failure, identity mismatch, or an
    /// invalid final-transaction/hash pair.
    pub async fn pending_approval(
        &self,
        policy: &SpendPolicy,
        approval_id: &str,
    ) -> Result<CapturedResponse<ApprovalSnapshot>, BitGoClientError> {
        self.ensure_coin(policy.wallet().coin())?;
        let url = self.pending_approval_endpoint(approval_id, false)?;
        let response = self.get(url).await?;
        Self::require_status(response.status, StatusCode::OK, &response.body)?;
        let wire: ApprovalWire = decode_json(&response.body)?;
        let snapshot = validate_approval_wire(wire, policy, approval_id)?;
        Ok(response.capture(snapshot))
    }

    /// Read the transfer created for one approved request without mutating it.
    ///
    /// # Errors
    /// Environment, transport/provider failure, or transfer/approval mismatch.
    pub async fn transfer_by_approval_id(
        &self,
        policy: &SpendPolicy,
        approval_id: &str,
    ) -> Result<CapturedResponse<TransferSnapshot>, BitGoClientError> {
        self.ensure_coin(policy.wallet().coin())?;
        let url = self.pending_approval_endpoint(approval_id, true)?;
        let response = self.get(url).await?;
        Self::require_status(response.status, StatusCode::OK, &response.body)?;
        let wire: ApprovalTransferWire = decode_json(&response.body)?;
        if wire.transfer.pending_approval.as_deref() != Some(approval_id) {
            return Err(BitGoClientError::InvalidResponse {
                field: "transfer.pendingApproval",
            });
        }
        let snapshot = validate_transfer_wire(wire.transfer, policy, true)?;
        Ok(response.capture(snapshot))
    }

    async fn send_transaction(
        &self,
        policy: &SpendPolicy,
        request: &SendRequest,
    ) -> Result<CapturedResponse<ProviderSendOutcome>, BitGoClientError> {
        self.ensure_coin(policy.wallet().coin())?;
        if request.sequence_id() != policy.sequence_id() {
            return Err(BitGoClientError::InvalidResponse {
                field: "send.sequenceId",
            });
        }
        let url = self.wallet_endpoint(policy.wallet(), &["tx", "send"])?;
        let response = self.post(url, request).await?;
        let value = match response.status {
            StatusCode::OK => {
                let wire: TransactionResponseWire = decode_json(&response.body)?;
                validate_transaction_response(wire, policy)?
            }
            StatusCode::ACCEPTED => {
                let wire: PendingApprovalWire = decode_json(&response.body)?;
                validate_pending_approval(wire, policy)?
            }
            _ => return Err(Self::provider_error(response.status, &response.body)),
        };
        Ok(response.capture(value))
    }

    fn ensure_coin(&self, coin: BitGoCoin) -> Result<(), BitGoClientError> {
        if self.environment.accepts(coin) {
            Ok(())
        } else {
            Err(BitGoClientError::EnvironmentCoinMismatch)
        }
    }

    const fn environment(&self) -> BitGoEnvironment {
        self.environment
    }

    const fn auth_version(&self) -> BitGoAuthVersion {
        self.auth_version
    }

    fn wallet_endpoint(
        &self,
        wallet: &WalletPolicy,
        suffix: &[&str],
    ) -> Result<Url, BitGoClientError> {
        let mut url = self.origin.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| BitGoClientError::InvalidOrigin)?;
            segments.clear();
            segments.extend([
                "api",
                "v2",
                wallet.coin().as_str(),
                "wallet",
                wallet.wallet_id(),
            ]);
            segments.extend(suffix.iter().copied());
        }
        Ok(url)
    }

    fn pending_approval_endpoint(
        &self,
        approval_id: &str,
        include_transfer: bool,
    ) -> Result<Url, BitGoClientError> {
        if !safe_path_identifier(approval_id) {
            return Err(BitGoClientError::InvalidResponse {
                field: "pendingApproval.id",
            });
        }
        let mut url = self.origin.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| BitGoClientError::InvalidOrigin)?;
            segments.clear();
            segments.extend(["api", "v2", "pendingapprovals", approval_id]);
            if include_transfer {
                segments.push("transfer");
            }
        }
        Ok(url)
    }

    async fn get(&self, url: Url) -> Result<VerifiedHttpResponse, BitGoClientError> {
        self.request(Method::GET, url, &[], false).await
    }

    async fn post<T: Serialize + ?Sized>(
        &self,
        url: Url,
        body: &T,
    ) -> Result<VerifiedHttpResponse, BitGoClientError> {
        let body = serde_json::to_vec(body).map_err(|_| BitGoClientError::RequestEncoding)?;
        self.request(Method::POST, url, &body, true).await
    }

    async fn request(
        &self,
        method: Method,
        url: Url,
        body: &[u8],
        json_body: bool,
    ) -> Result<VerifiedHttpResponse, BitGoClientError> {
        let timestamp_millis = unix_time_millis()?;
        let authenticator = hmac_authenticator(
            self.access_token.as_bytes(),
            self.auth_version,
            &method,
            timestamp_millis,
            &url,
            None,
            body,
        )?;
        let hmac = alloy_primitives::hex::encode(authenticator.finalize().into_bytes());
        let mut request = self
            .http
            .request(method.clone(), url.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .header("auth-timestamp", timestamp_millis.to_string())
            .header("hmac", hmac)
            .header("bitgo-auth-version", self.auth_version.header());
        if json_body {
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let response = request
            .send()
            .await
            .map_err(|_| BitGoClientError::Transport)?;
        self.read(&method, &url, response).await
    }

    async fn read(
        &self,
        method: &Method,
        url: &Url,
        response: reqwest::Response,
    ) -> Result<VerifiedHttpResponse, BitGoClientError> {
        let status = response.status();
        let timestamp_millis = response
            .headers()
            .get("timestamp")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(BitGoClientError::ResponseAuthentication)?;
        let hmac = response
            .headers()
            .get("hmac")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| alloy_primitives::hex::decode(value).ok())
            .filter(|value| value.len() == 32)
            .ok_or(BitGoClientError::ResponseAuthentication)?;
        let body = read_bounded_async(response, self.max_response_bytes)
            .await
            .map_err(BitGoClientError::ResponseBody)?;
        let now_millis = unix_time_millis()?;
        if timestamp_millis < now_millis.saturating_sub(RESPONSE_BACKWARD_VALIDITY_MILLIS)
            || timestamp_millis > now_millis.saturating_add(RESPONSE_FORWARD_VALIDITY_MILLIS)
        {
            return Err(BitGoClientError::ResponseAuthentication);
        }
        let authenticator = hmac_authenticator(
            self.access_token.as_bytes(),
            self.auth_version,
            method,
            timestamp_millis,
            url,
            Some(status.as_u16()),
            &body,
        )?;
        authenticator
            .verify_slice(&hmac)
            .map_err(|_| BitGoClientError::ResponseAuthentication)?;
        let path_and_query = path_and_query(url);
        let evidence = AuthenticatedResponseEvidence {
            schema: AUTHENTICATED_RESPONSE_SCHEMA,
            auth_version: self.auth_version.header(),
            method: method.as_str(),
            path_and_query: &path_and_query,
            status: status.as_u16(),
            timestamp_millis,
            hmac_sha256: alloy_primitives::hex::encode(&hmac),
            body_sha256: alloy_primitives::hex::encode(Sha256::digest(&body)),
            body_hex: alloy_primitives::hex::encode(&body),
        };
        let authenticated_evidence =
            serde_json::to_vec(&evidence).map_err(|_| BitGoClientError::ResponseAuthentication)?;
        Ok(VerifiedHttpResponse {
            status,
            body,
            authenticated_evidence,
        })
    }

    fn require_status(
        actual: StatusCode,
        expected: StatusCode,
        body: &[u8],
    ) -> Result<(), BitGoClientError> {
        if actual == expected {
            return Ok(());
        }
        Err(Self::provider_error(actual, body))
    }

    fn provider_error(status: StatusCode, body: &[u8]) -> BitGoClientError {
        let provider = serde_json::from_slice::<ProviderErrorWire>(body).unwrap_or_default();
        BitGoClientError::Provider {
            status: status.as_u16(),
            name: safe_provider_identifier(provider.name),
            request_id: safe_provider_identifier(provider.request_id),
        }
    }

    #[cfg(test)]
    fn new_for_test(
        environment: BitGoEnvironment,
        origin: &str,
        access_token: &str,
        policy: HttpClientPolicy,
    ) -> Result<Self, BitGoClientError> {
        Self::from_origin(
            environment,
            BitGoAuthVersion::V2,
            origin,
            access_token,
            policy,
        )
    }
}

#[derive(Serialize)]
struct AuthenticatedResponseEvidence<'a> {
    schema: &'static str,
    auth_version: &'static str,
    method: &'a str,
    path_and_query: &'a str,
    status: u16,
    timestamp_millis: u64,
    hmac_sha256: String,
    body_sha256: String,
    body_hex: String,
}

fn unix_time_millis() -> Result<u64, BitGoClientError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BitGoClientError::Clock)?
        .as_millis();
    u64::try_from(millis).map_err(|_| BitGoClientError::Clock)
}

fn path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

fn hmac_authenticator(
    token: &[u8],
    auth_version: BitGoAuthVersion,
    method: &Method,
    timestamp_millis: u64,
    url: &Url,
    status: Option<u16>,
    body: &[u8],
) -> Result<Hmac<Sha256>, BitGoClientError> {
    let path = path_and_query(url);
    let prefix = match (auth_version, status) {
        (BitGoAuthVersion::V2, None) => format!("{timestamp_millis}|{path}|"),
        (BitGoAuthVersion::V2, Some(status)) => {
            format!("{timestamp_millis}|{path}|{status}|")
        }
        (BitGoAuthVersion::V3, None) => format!(
            "{}|{timestamp_millis}|3.0|{path}|",
            method.as_str().to_ascii_uppercase()
        ),
        (BitGoAuthVersion::V3, Some(status)) => format!(
            "{}|{timestamp_millis}|{path}|{status}|",
            method.as_str().to_ascii_uppercase()
        ),
    };
    let mut authenticator =
        Hmac::<Sha256>::new_from_slice(token).map_err(|_| BitGoClientError::InvalidAccessToken)?;
    authenticator.update(prefix.as_bytes());
    authenticator.update(body);
    Ok(authenticator)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletWire {
    id: String,
    coin: String,
    #[serde(rename = "type")]
    wallet_type: String,
    multisig_type: String,
    m: u8,
    n: u8,
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BuildWire {
    tx_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferWire {
    id: String,
    coin: String,
    wallet: String,
    state: TransferState,
    sequence_id: Option<String>,
    txid: Option<String>,
    pending_approval: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApprovalTransferWire {
    transfer: TransferWire,
}

#[derive(Debug, Deserialize)]
struct ApprovalWire {
    id: String,
    coin: String,
    wallet: String,
    info: ApprovalInfoWire,
    state: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalInfoWire {
    #[serde(rename = "type")]
    request_type: String,
    transaction_request: ApprovalTransactionRequestWire,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalTransactionRequestWire {
    source_wallet: String,
    valid_transaction: Option<String>,
    valid_transaction_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransactionResponseWire {
    transfer: TransferWire,
    txid: String,
    tx: String,
    status: TransferState,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PendingApprovalWire {
    Envelope {
        #[serde(rename = "pendingApproval")]
        pending_approval: PendingApprovalDetailsWire,
    },
    Direct(PendingApprovalDetailsWire),
}

#[derive(Debug, Deserialize)]
struct PendingApprovalDetailsWire {
    id: String,
    coin: String,
    wallet: String,
    state: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderErrorWire {
    name: Option<String>,
    request_id: Option<String>,
}

fn decode_json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, BitGoClientError> {
    serde_json::from_slice(body).map_err(|_| BitGoClientError::InvalidJson)
}

fn safe_provider_identifier(value: Option<String>) -> Option<String> {
    value.filter(|candidate| {
        !candidate.is_empty()
            && candidate.len() <= MAX_PROVIDER_IDENTIFIER_BYTES
            && candidate.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
    })
}

fn validate_wallet_wire(
    wire: WalletWire,
    policy: &WalletPolicy,
) -> Result<WalletSnapshot, BitGoClientError> {
    if wire.id != policy.wallet_id() {
        return Err(BitGoClientError::InvalidResponse { field: "wallet.id" });
    }
    if wire.coin != policy.coin().as_str() {
        return Err(BitGoClientError::InvalidResponse {
            field: "wallet.coin",
        });
    }
    if wire.wallet_type != "hot" {
        return Err(BitGoClientError::InvalidResponse {
            field: "wallet.type",
        });
    }
    if wire.multisig_type != "onchain" {
        return Err(BitGoClientError::InvalidResponse {
            field: "wallet.multisigType",
        });
    }
    if wire.m != 2 || wire.n != 3 {
        return Err(BitGoClientError::InvalidResponse {
            field: "wallet.threshold",
        });
    }
    let key_ids: [String; 3] =
        wire.keys
            .try_into()
            .map_err(|_| BitGoClientError::InvalidResponse {
                field: "wallet.keys",
            })?;
    if key_ids.iter().any(|key| !safe_path_identifier(key))
        || key_ids[0] == key_ids[1]
        || key_ids[0] == key_ids[2]
        || key_ids[1] == key_ids[2]
    {
        return Err(BitGoClientError::InvalidResponse {
            field: "wallet.keys",
        });
    }
    Ok(WalletSnapshot {
        wallet_id: wire.id,
        coin: policy.coin(),
        key_ids,
    })
}

fn validate_transfer_wire(
    wire: TransferWire,
    policy: &SpendPolicy,
    require_sequence: bool,
) -> Result<TransferSnapshot, BitGoClientError> {
    if !safe_path_identifier(&wire.id) {
        return Err(BitGoClientError::InvalidResponse {
            field: "transfer.id",
        });
    }
    if wire.coin != policy.wallet().coin().as_str() {
        return Err(BitGoClientError::InvalidResponse {
            field: "transfer.coin",
        });
    }
    if wire.wallet != policy.wallet().wallet_id() {
        return Err(BitGoClientError::InvalidResponse {
            field: "transfer.wallet",
        });
    }
    if wire
        .sequence_id
        .as_deref()
        .is_some_and(|sequence_id| sequence_id != policy.sequence_id())
        || (require_sequence && wire.sequence_id.is_none())
    {
        return Err(BitGoClientError::InvalidResponse {
            field: "transfer.sequenceId",
        });
    }
    if wire
        .txid
        .as_ref()
        .is_some_and(|txid| txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(BitGoClientError::InvalidResponse {
            field: "transfer.txid",
        });
    }
    if wire
        .pending_approval
        .as_deref()
        .is_some_and(|approval_id| !safe_path_identifier(approval_id))
    {
        return Err(BitGoClientError::InvalidResponse {
            field: "transfer.pendingApproval",
        });
    }
    Ok(TransferSnapshot {
        transfer_id: wire.id,
        state: wire.state,
        txid: wire.txid,
    })
}

fn validate_approval_wire(
    wire: ApprovalWire,
    policy: &SpendPolicy,
    expected_approval_id: &str,
) -> Result<ApprovalSnapshot, BitGoClientError> {
    if !safe_path_identifier(&wire.id) || wire.id != expected_approval_id {
        return Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.id",
        });
    }
    if wire.coin != policy.wallet().coin().as_str() {
        return Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.coin",
        });
    }
    if wire.wallet != policy.wallet().wallet_id() {
        return Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.wallet",
        });
    }
    if wire.info.request_type != "transactionRequest" {
        return Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.info.type",
        });
    }
    let request = wire.info.transaction_request;
    if request.source_wallet != policy.wallet().wallet_id() {
        return Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.info.transactionRequest.sourceWallet",
        });
    }
    match wire.state.as_str() {
        "pending"
        | "pendingApproval"
        | "awaitingSignature"
        | "pendingFinalApproval"
        | "pendingCustodianApproval"
        | "pendingVideoApproval"
        | "pendingIdVerification"
        | "processing" => Ok(ApprovalSnapshot::Pending {
            approval_id: wire.id,
        }),
        "rejected" => Ok(ApprovalSnapshot::Rejected {
            approval_id: wire.id,
        }),
        "approved" => {
            let encoded = request
                .valid_transaction
                .ok_or(BitGoClientError::InvalidResponse {
                    field: "pendingApproval.info.transactionRequest.validTransaction",
                })?;
            let expected_txid =
                request
                    .valid_transaction_hash
                    .ok_or(BitGoClientError::InvalidResponse {
                        field: "pendingApproval.info.transactionRequest.validTransactionHash",
                    })?;
            let txid =
                Txid::from_str(&expected_txid).map_err(|_| BitGoClientError::InvalidResponse {
                    field: "pendingApproval.info.transactionRequest.validTransactionHash",
                })?;
            let bytes =
                alloy_primitives::hex::decode(encoded.trim_start_matches("0x")).map_err(|_| {
                    BitGoClientError::InvalidResponse {
                        field: "pendingApproval.info.transactionRequest.validTransaction",
                    }
                })?;
            let transaction = deserialize::<Transaction>(&bytes).map_err(|_| {
                BitGoClientError::InvalidResponse {
                    field: "pendingApproval.info.transactionRequest.validTransaction",
                }
            })?;
            if transaction.compute_txid() != txid {
                return Err(BitGoClientError::InvalidResponse {
                    field: "pendingApproval.info.transactionRequest.validTransaction",
                });
            }
            Ok(ApprovalSnapshot::Approved {
                approval_id: wire.id,
                txid,
                transaction,
            })
        }
        _ => Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.state",
        }),
    }
}

fn validate_transaction_response(
    wire: TransactionResponseWire,
    policy: &SpendPolicy,
) -> Result<ProviderSendOutcome, BitGoClientError> {
    let transfer = validate_transfer_wire(wire.transfer, policy, false)?;
    if wire.status != transfer.state() {
        return Err(BitGoClientError::InvalidResponse {
            field: "transaction.status",
        });
    }
    if !matches!(
        transfer.state(),
        TransferState::Signed | TransferState::Unconfirmed | TransferState::Confirmed
    ) {
        return Err(BitGoClientError::InvalidResponse {
            field: "transaction.status",
        });
    }
    if transfer.txid() != Some(wire.txid.as_str()) {
        return Err(BitGoClientError::InvalidResponse {
            field: "transaction.txid",
        });
    }
    let txid = Txid::from_str(&wire.txid).map_err(|_| BitGoClientError::InvalidResponse {
        field: "transaction.txid",
    })?;
    let transaction_bytes = alloy_primitives::hex::decode(wire.tx.trim_start_matches("0x"))
        .map_err(|_| BitGoClientError::InvalidResponse {
            field: "transaction.tx",
        })?;
    let transaction = deserialize::<Transaction>(&transaction_bytes).map_err(|_| {
        BitGoClientError::InvalidResponse {
            field: "transaction.tx",
        }
    })?;
    if transaction.compute_txid() != txid {
        return Err(BitGoClientError::InvalidResponse {
            field: "transaction.tx",
        });
    }
    Ok(ProviderSendOutcome::Broadcast {
        transfer_id: transfer.transfer_id,
        txid,
        transaction,
    })
}

fn validate_pending_approval(
    wire: PendingApprovalWire,
    policy: &SpendPolicy,
) -> Result<ProviderSendOutcome, BitGoClientError> {
    let wire = match wire {
        PendingApprovalWire::Envelope { pending_approval }
        | PendingApprovalWire::Direct(pending_approval) => pending_approval,
    };
    if !safe_path_identifier(&wire.id) {
        return Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.id",
        });
    }
    if wire.coin != policy.wallet().coin().as_str() {
        return Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.coin",
        });
    }
    if wire.wallet != policy.wallet().wallet_id() {
        return Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.wallet",
        });
    }
    if !matches!(wire.state.as_str(), "pending" | "pendingApproval") {
        return Err(BitGoClientError::InvalidResponse {
            field: "pendingApproval.state",
        });
    }
    Ok(ProviderSendOutcome::PendingApproval {
        approval_id: wire.id,
    })
}

fn safe_path_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions and fixtures")]

    use std::str::FromStr;
    use std::time::Duration;

    use bitcoin::hashes::Hash as _;
    use bitcoin::opcodes::all::OP_CHECKMULTISIG;
    use bitcoin::script::Builder;
    use bitcoin::{
        absolute::LockTime, psbt::Psbt, transaction::Version, Address, Amount, OutPoint, ScriptBuf,
        Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use hmac::Mac as _;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use xindex_bitgo_adapter::{
        build_request, parse_compressed_public_key, BitGoCoin, InputPolicy, SpendPolicy,
        WalletPolicy, P2WSH_EXTERNAL_CHAIN_CODE,
    };

    use super::{
        hmac_authenticator, unix_time_millis, validate_approval_wire, validate_pending_approval,
        validate_transaction_response, ApprovalSnapshot, ApprovalWire, BitGoAuthVersion,
        BitGoClient, BitGoClientError, BitGoEnvironment, PendingApprovalWire, ProviderSendOutcome,
        TransactionResponseWire, TransferState, OFFICIAL_FINAL_TX, OFFICIAL_FINAL_TXID,
    };
    use xindex_ops::network::HttpClientPolicy;

    const USER_PUBKEY: &str = "03c10ac628c880629ed0fd2a0563a898f4882baca45e15668a4d3064cf1ea37988";
    const BACKUP_PUBKEY: &str =
        "03e56f84be4460080618ef869bb7b07096880760f748ba23efab533c2359f923bd";
    const BITGO_PUBKEY: &str = "020ae81372264b5eac5c9dc7fe0b9a32bad00771c3a2c71f6e2c971823c3182ed6";

    const fn http_policy(max_response_bytes: usize) -> HttpClientPolicy {
        HttpClientPolicy {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(3),
            max_response_bytes,
        }
    }

    #[expect(clippy::expect_used, reason = "test fixture")]
    fn spend_policy(coin: BitGoCoin) -> SpendPolicy {
        let user = parse_compressed_public_key(USER_PUBKEY).expect("user key");
        let backup = parse_compressed_public_key(BACKUP_PUBKEY).expect("backup key");
        let bitgo = parse_compressed_public_key(BITGO_PUBKEY).expect("BitGo key");
        let witness_script = Builder::new()
            .push_int(2)
            .push_key(&user)
            .push_key(&backup)
            .push_key(&bitgo)
            .push_int(3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let wallet = WalletPolicy::new(
            coin,
            "wallet-1",
            P2WSH_EXTERNAL_CHAIN_CODE,
            user,
            backup,
            bitgo,
            witness_script,
        )
        .expect("wallet policy");
        let input = InputPolicy::new(
            OutPoint {
                txid: Txid::from_byte_array([0x22; 32]),
                vout: 0,
            },
            200_000,
        )
        .expect("input policy");
        let payout_network = coin.network();
        let payout = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xaa; 20]));
        let _ = Address::from_script(&payout, payout_network).expect("payout address");
        SpendPolicy::new(
            wallet,
            input,
            payout,
            100_000,
            b"=:ETH.USDT:0xrecipient:990000".to_vec(),
            20_000,
            "xindex-redemption-1",
            true,
        )
        .expect("spend policy")
    }

    #[expect(clippy::expect_used, reason = "test fixture")]
    fn psbt(policy: &SpendPolicy, memo_before_change: bool) -> Psbt {
        let request = build_request(policy).expect("build request");
        let payout = Address::from_str(&request.recipients[0].address)
            .expect("payout address")
            .require_network(policy.wallet().coin().network())
            .expect("payout network")
            .script_pubkey();
        let memo = ScriptBuf::from_bytes(
            alloy_primitives::hex::decode(
                request.recipients[1]
                    .address
                    .strip_prefix("scriptPubKey:")
                    .expect("memo prefix"),
            )
            .expect("memo script"),
        );
        let payout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: payout,
        };
        let change = TxOut {
            value: Amount::from_sat(89_000),
            script_pubkey: policy.wallet().custody_script_pubkey().clone(),
        };
        let memo = TxOut {
            value: Amount::ZERO,
            script_pubkey: memo,
        };
        let output = if memo_before_change {
            vec![payout, memo, change]
        } else {
            vec![payout, change, memo]
        };
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: policy.input().outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output,
        };
        let mut psbt = Psbt::from_unsigned_tx(transaction).expect("PSBT");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(policy.input().value_sats()),
            script_pubkey: policy.wallet().custody_script_pubkey().clone(),
        });
        psbt.inputs[0].witness_script = Some(policy.wallet().witness_script().clone());
        psbt
    }

    #[expect(clippy::expect_used, reason = "test fixture")]
    fn client(server: &MockServer, max_response_bytes: usize) -> BitGoClient {
        BitGoClient::new_for_test(
            BitGoEnvironment::Test,
            &server.uri(),
            "test-token",
            http_policy(max_response_bytes),
        )
        .expect("client")
    }

    #[test]
    fn production_constructor_pins_origin_and_redacts_token() {
        let client = BitGoClient::new(
            BitGoEnvironment::Test,
            BitGoAuthVersion::V2,
            "test-token",
            http_policy(1024),
        );
        assert!(client.is_ok());
        let debug = format!("{:?}", client.unwrap_or_else(|_| unreachable!()));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("test-token"));
        assert!(!debug.contains("bitgo-test.com"));
    }

    #[test]
    fn access_token_rejects_whitespace_without_echoing_it() {
        let token = " secret-token ";
        let error = BitGoClient::new(
            BitGoEnvironment::Test,
            BitGoAuthVersion::V2,
            token,
            http_policy(1024),
        )
        .expect_err("whitespace token");
        assert!(matches!(error, BitGoClientError::InvalidAccessToken));
        assert!(!error.to_string().contains(token));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test fixture")]
    async fn wallet_lookup_authenticates_and_requires_exact_topology() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/tbtc4/wallet/wallet-1"))
            .and(header(
                "authorization",
                crate::test_support::test_authorization(),
            ))
            .and(header("bitgo-auth-version", "2.0"))
            .respond_with(crate::test_support::signed_json_response(
                200,
                json!({
                    "id": "wallet-1",
                    "coin": "tbtc4",
                    "type": "hot",
                    "multisigType": "onchain",
                    "m": 2,
                    "n": 3,
                    "keys": ["user-key", "backup-key", "bitgo-key"]
                }),
            ))
            .mount(&server)
            .await;
        let policy = spend_policy(BitGoCoin::Tbtc4);
        let capture = client(&server, 4096)
            .wallet(policy.wallet())
            .await
            .expect("wallet lookup");
        assert_eq!(capture.value().wallet_id(), "wallet-1");
        assert_eq!(capture.value().coin(), BitGoCoin::Tbtc4);
        assert_eq!(capture.value().key_ids()[2], "bitgo-key");
        assert!(!capture.raw_body().is_empty());
        let evidence: serde_json::Value =
            serde_json::from_slice(capture.authenticated_evidence()).expect("evidence JSON");
        assert_eq!(evidence["schema"], "xindex.bitgo.authenticated-response.v1");
        assert_eq!(evidence["auth_version"], "2.0");
        assert_eq!(evidence["method"], "GET");
        assert_eq!(evidence["path_and_query"], "/api/v2/tbtc4/wallet/wallet-1");
        assert_eq!(
            evidence["body_hex"],
            alloy_primitives::hex::encode(capture.raw_body())
        );
        assert!(!String::from_utf8_lossy(capture.authenticated_evidence()).contains("test-token"));
    }

    #[test]
    fn hmac_subjects_match_static_v2_and_v3_vectors() {
        let url = reqwest::Url::parse("https://app.bitgo-test.com/api/v2/tbtc4/wallet/wallet-1")
            .expect("URL");
        let timestamp = 1_700_000_000_123;
        let cases = [
            (
                BitGoAuthVersion::V2,
                None,
                &[][..],
                "5a8677ac58dca9b00fc6b95b87d4ca81cb5c99f03b8b97aa88d435848ffceb79",
            ),
            (
                BitGoAuthVersion::V3,
                None,
                &[][..],
                "b5000fc62439a1e60901f7cf57addeca4ebfe2c7644641862a83259745f3de46",
            ),
            (
                BitGoAuthVersion::V2,
                Some(200),
                &b"{}"[..],
                "dd6da76f39de393a720036e1dfebcc68e10cffd9e2c7b52f984ece32e1e321bf",
            ),
            (
                BitGoAuthVersion::V3,
                Some(200),
                &b"{}"[..],
                "5c83c01cc93543746c4e36a00d1258888ad7ad0475176fccc4484e5f3528e518",
            ),
        ];
        for (version, status, body, expected) in cases {
            let authenticator = hmac_authenticator(
                b"test-token",
                version,
                &reqwest::Method::GET,
                timestamp,
                &url,
                status,
                body,
            )
            .expect("HMAC");
            assert_eq!(
                alloy_primitives::hex::encode(authenticator.finalize().into_bytes()),
                expected
            );
        }
    }

    #[tokio::test]
    async fn response_hmac_mismatch_fails_closed_before_json_use() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/tbtc4/wallet/wallet-1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("timestamp", unix_time_millis().expect("clock").to_string())
                    .insert_header("hmac", "00".repeat(32))
                    .set_body_json(json!({
                        "id": "wallet-1",
                        "coin": "tbtc4",
                        "type": "hot",
                        "multisigType": "onchain",
                        "m": 2,
                        "n": 3,
                        "keys": ["user-key", "backup-key", "bitgo-key"]
                    })),
            )
            .mount(&server)
            .await;
        let policy = spend_policy(BitGoCoin::Tbtc4);
        let error = client(&server, 4096)
            .wallet(policy.wallet())
            .await
            .expect_err("invalid response HMAC");
        assert!(matches!(error, BitGoClientError::ResponseAuthentication));
    }

    #[tokio::test]
    async fn environment_mismatch_fails_before_network() {
        let server = MockServer::start().await;
        let policy = spend_policy(BitGoCoin::Btc);
        let error = client(&server, 4096)
            .wallet(policy.wallet())
            .await
            .expect_err("coin mismatch");
        assert!(matches!(error, BitGoClientError::EnvironmentCoinMismatch));
        assert!(server
            .received_requests()
            .await
            .is_some_and(|requests| requests.is_empty()));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test fixture")]
    async fn build_posts_generated_request_and_validates_returned_psbt() {
        let server = MockServer::start().await;
        let policy = spend_policy(BitGoCoin::Tbtc4);
        let expected_request = build_request(&policy).expect("build request");
        let tx_hex = alloy_primitives::hex::encode(psbt(&policy, false).serialize());
        Mock::given(method("POST"))
            .and(path("/api/v2/tbtc4/wallet/wallet-1/tx/build"))
            .and(header(
                "authorization",
                crate::test_support::test_authorization(),
            ))
            .and(header("bitgo-auth-version", "2.0"))
            .and(body_json(&expected_request))
            .respond_with(crate::test_support::signed_json_response(
                200,
                json!({ "txHex": tx_hex }),
            ))
            .mount(&server)
            .await;
        let capture = client(&server, 32 * 1024)
            .build_transaction(&policy)
            .await
            .expect("validated build");
        assert_eq!(capture.value().request(), &expected_request);
        assert_eq!(capture.value().psbt().unsigned_tx.output.len(), 3);
    }

    #[tokio::test]
    async fn build_rejects_provider_output_reordering() {
        let server = MockServer::start().await;
        let policy = spend_policy(BitGoCoin::Tbtc4);
        let tx_hex = alloy_primitives::hex::encode(psbt(&policy, true).serialize());
        Mock::given(method("POST"))
            .and(path("/api/v2/tbtc4/wallet/wallet-1/tx/build"))
            .respond_with(crate::test_support::signed_json_response(
                200,
                json!({ "txHex": tx_hex }),
            ))
            .mount(&server)
            .await;
        let error = client(&server, 32 * 1024)
            .build_transaction(&policy)
            .await
            .expect_err("reordered outputs");
        assert!(matches!(error, BitGoClientError::Policy(_)));
    }

    #[tokio::test]
    async fn provider_error_retains_only_safe_code_and_request_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/tbtc4/wallet/wallet-1"))
            .respond_with(crate::test_support::signed_json_response(
                400,
                json!({
                    "error": "echoed secret-token and transaction material",
                    "name": "InvalidWalletId",
                    "requestId": "request-1"
                }),
            ))
            .mount(&server)
            .await;
        let policy = spend_policy(BitGoCoin::Tbtc4);
        let error = client(&server, 4096)
            .wallet(policy.wallet())
            .await
            .expect_err("provider error");
        let rendered = error.to_string();
        assert!(rendered.contains("InvalidWalletId"));
        assert!(rendered.contains("request-1"));
        assert!(!rendered.contains("transaction material"));
        assert!(!rendered.contains("secret-token"));
    }

    #[tokio::test]
    async fn response_body_is_bounded_before_json_decode() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/tbtc4/wallet/wallet-1"))
            .respond_with(crate::test_support::signed_response(
                200,
                vec![b'x'; 1024],
                "text/plain",
            ))
            .mount(&server)
            .await;
        let policy = spend_policy(BitGoCoin::Tbtc4);
        let error = client(&server, 64)
            .wallet(policy.wallet())
            .await
            .expect_err("oversized response");
        assert!(matches!(error, BitGoClientError::ResponseBody(_)));
    }

    #[tokio::test]
    async fn sequence_lookup_reconciles_exact_wallet_and_sequence() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v2/tbtc4/wallet/wallet-1/transfer/sequenceId/xindex-redemption-1",
            ))
            .respond_with(crate::test_support::signed_json_response(
                206,
                json!({
                    "id": "transfer-1",
                    "coin": "tbtc4",
                    "wallet": "wallet-1",
                    "state": "signed",
                    "sequenceId": "xindex-redemption-1",
                    "txid": "11".repeat(32)
                }),
            ))
            .mount(&server)
            .await;
        let policy = spend_policy(BitGoCoin::Tbtc4);
        let capture = client(&server, 4096)
            .transfer_by_sequence_id(&policy)
            .await
            .expect("sequence lookup");
        assert_eq!(capture.value().transfer_id(), "transfer-1");
        assert_eq!(capture.value().state(), TransferState::Signed);
        let expected_txid = "11".repeat(32);
        assert_eq!(capture.value().txid(), Some(expected_txid.as_str()));
    }

    #[test]
    fn wrapped_pending_approval_binds_wallet_coin_and_state() {
        let policy = spend_policy(BitGoCoin::Tbtc4);
        let wire: PendingApprovalWire = serde_json::from_value(json!({
            "error": "triggered all transactions policy",
            "pendingApproval": {
                "id": "approval-1",
                "coin": "tbtc4",
                "wallet": "wallet-1",
                "state": "pendingApproval"
            },
            "triggeredPolicy": "policy-1"
        }))
        .expect("pending approval");
        assert!(matches!(
            validate_pending_approval(wire, &policy),
            Ok(ProviderSendOutcome::PendingApproval { approval_id })
                if approval_id == "approval-1"
        ));

        let wrong_wallet: PendingApprovalWire = serde_json::from_value(json!({
            "pendingApproval": {
                "id": "approval-1",
                "coin": "tbtc4",
                "wallet": "another-wallet",
                "state": "pendingApproval"
            }
        }))
        .expect("pending approval");
        assert!(matches!(
            validate_pending_approval(wrong_wallet, &policy),
            Err(BitGoClientError::InvalidResponse {
                field: "pendingApproval.wallet"
            })
        ));
    }

    #[test]
    fn official_final_response_shape_binds_txid_without_sequence_echo() {
        // Static public response vector from BitGo's manual self-custody
        // multisig guide. This parses existing signatures and uses no key.
        let wire: TransactionResponseWire = serde_json::from_value(json!({
            "transfer": {
                "id": "transfer-1",
                "coin": "tbtc4",
                "wallet": "wallet-1",
                "state": "signed",
                "txid": OFFICIAL_FINAL_TXID
            },
            "txid": OFFICIAL_FINAL_TXID,
            "tx": OFFICIAL_FINAL_TX,
            "status": "signed"
        }))
        .expect("transaction response");
        assert!(matches!(
            validate_transaction_response(wire, &spend_policy(BitGoCoin::Tbtc4)),
            Ok(ProviderSendOutcome::Broadcast {
                transfer_id,
                txid: observed,
                ..
            }) if transfer_id == "transfer-1" && observed.to_string() == OFFICIAL_FINAL_TXID
        ));
    }

    #[test]
    fn terminal_failure_state_cannot_be_recorded_as_broadcast() {
        let wire: TransactionResponseWire = serde_json::from_value(json!({
            "transfer": {
                "id": "transfer-1",
                "coin": "tbtc4",
                "wallet": "wallet-1",
                "state": "failed",
                "txid": OFFICIAL_FINAL_TXID
            },
            "txid": OFFICIAL_FINAL_TXID,
            "tx": OFFICIAL_FINAL_TX,
            "status": "failed"
        }))
        .expect("transaction response");

        assert!(matches!(
            validate_transaction_response(wire, &spend_policy(BitGoCoin::Tbtc4)),
            Err(BitGoClientError::InvalidResponse {
                field: "transaction.status"
            })
        ));
    }

    #[test]
    fn approved_approval_binds_source_wallet_and_final_transaction() {
        let wire: ApprovalWire = serde_json::from_value(json!({
            "id": "approval-1",
            "coin": "tbtc4",
            "wallet": "wallet-1",
            "info": {
                "type": "transactionRequest",
                "transactionRequest": {
                    "sourceWallet": "wallet-1",
                    "validTransaction": OFFICIAL_FINAL_TX,
                    "validTransactionHash": OFFICIAL_FINAL_TXID
                }
            },
            "state": "approved"
        }))
        .expect("approval response");
        assert!(matches!(
            validate_approval_wire(wire, &spend_policy(BitGoCoin::Tbtc4), "approval-1"),
            Ok(ApprovalSnapshot::Approved { txid, .. })
                if txid.to_string() == OFFICIAL_FINAL_TXID
        ));

        let wrong_source: ApprovalWire = serde_json::from_value(json!({
            "id": "approval-1",
            "coin": "tbtc4",
            "wallet": "wallet-1",
            "info": {
                "type": "transactionRequest",
                "transactionRequest": { "sourceWallet": "another-wallet" }
            },
            "state": "pending"
        }))
        .expect("approval response");
        assert!(matches!(
            validate_approval_wire(wrong_source, &spend_policy(BitGoCoin::Tbtc4), "approval-1"),
            Err(BitGoClientError::InvalidResponse {
                field: "pendingApproval.info.transactionRequest.sourceWallet"
            })
        ));
    }
}
