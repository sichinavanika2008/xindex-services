//! Exact-peer Vultisig verifier and relay orchestration.
//!
//! The reviewed verifier snapshot (`0c84b9b34ff46289679aad292905ceac2bd810f7`)
//! does not provide a request-digest-bound idempotency receipt: duplicate
//! sessions return an empty success, task IDs are random, and session-store
//! failure does not stop enqueue. An uncertain verifier POST is therefore
//! never retransmitted here. The adapter-owned target-bound journal persists
//! the sealed authorization, exact session, phase, and verifier outcomes before
//! any unsafe POST. Ordinary failures retain the live capability; cancellation
//! or process loss releases only that in-memory claim, so restart recovery can
//! reconstruct an observation-only pending operation without a second POST.
//! Its V3 target identity also binds each configured verifier's reviewed source
//! manifest, exact binary, and declared signer-side derivation capabilities;
//! this detects configuration drift but does not remotely attest the process.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use alloy_primitives::hex;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use futures_util::future::{join_all, try_join_all};
use md5::{Digest as _, Md5};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::time::{sleep, Instant};
use xindex_ops::network::{read_bounded_async, HttpClientPolicy};
use xindex_ops::tls::{exact_pinned_https_async_client_builder, PinnedCertStore};
use xindex_vultisig_adapter::{
    finalize_vultisig_keysign, AuthorizedVultisigKeysign, SqliteVultisigKeysignJournal,
    VerifiedVultisigTransaction, VultisigBitcoinRecoveryMaterial, VultisigHashDerivation,
    VultisigKeysignJournalClaim, VultisigKeysignJournalError, VultisigKeysignResponse,
    VultisigKeysignTerminalReceipt, VultisigParticipantIdentity, VultisigPluginKeysignRequest,
    VultisigResponseError, VultisigSessionContext,
};

const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_TOKEN_BYTES: usize = 4 * 1024;
const MAX_PARTY_BYTES: usize = 256;
const MIN_VERIFIERS: usize = 2;
const SESSION_TIMEOUT: Duration = Duration::from_secs(190);
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const CONNECTOR_TARGET_ID_DOMAIN: &[u8] = b"XINDEX/VULTISIG/CONNECTOR-TARGET/V3";
const KEYSIGN_COMPLETION_ID_DOMAIN: &[u8] = b"XINDEX/VULTISIG/KEYSIGN-COMPLETION/V1";
const DURABLE_REMOTE_SCHEMA: &str = "xindex-vultisig-connector-session-v1";
const MAX_TASK_ID_BYTES: usize = 1024;
const UPSTREAM_HASH_DERIVATION_CAPABILITY: u8 = 1 << 0;
const COSMOS_DIRECT_HASH_DERIVATION_CAPABILITY: u8 = 1 << 1;

const fn http_policy() -> HttpClientPolicy {
    HttpClientPolicy {
        connect_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(15),
        max_response_bytes: MAX_RESPONSE_BYTES,
    }
}

/// Independently reviewed signer-side hash derivation supplied by one exact
/// verifier release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VultisigVerifierCapability {
    /// Hash derivation implemented by the pinned upstream Verifier and Recipes
    /// release for its existing qualified chain switch.
    UpstreamHashDerivation,
    /// Xindex-reviewed direct-sign Cosmos derivation for Gaia and Noble. The
    /// verifier must bind `TxRaw` body/auth-info bytes to the supplied
    /// `SignDoc` before hashing it.
    CosmosDirectHashDerivation,
}

impl VultisigVerifierCapability {
    const fn bit(self) -> u8 {
        match self {
            Self::UpstreamHashDerivation => UPSTREAM_HASH_DERIVATION_CAPABILITY,
            Self::CosmosDirectHashDerivation => COSMOS_DIRECT_HASH_DERIVATION_CAPABILITY,
        }
    }
}

/// Reviewed source-manifest and binary identity for one verifier release.
///
/// The external manifest is expected to bind the exact source/dependency graph,
/// build toolchain and licence review represented by this configuration.
/// The connector binds these declared identities into its durable target ID;
/// it does not remotely attest the running process. Operator/release review
/// must establish that the endpoint actually runs the identified binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewedVultisigVerifierRelease {
    source_manifest_sha256: [u8; 32],
    binary_sha256: [u8; 32],
    capabilities: u8,
}

impl ReviewedVultisigVerifierRelease {
    /// Construct an externally reviewed exact release identity.
    ///
    /// # Errors
    /// Zero identities or an empty capability set fail closed.
    pub fn new(
        source_manifest_sha256: [u8; 32],
        binary_sha256: [u8; 32],
        capabilities: &[VultisigVerifierCapability],
    ) -> Result<Self, VultisigConnectorError> {
        if source_manifest_sha256 == [0; 32] {
            return Err(VultisigConnectorError::Config(
                "verifier source-manifest identity must not be zero",
            ));
        }
        if binary_sha256 == [0; 32] {
            return Err(VultisigConnectorError::Config(
                "verifier binary identity must not be zero",
            ));
        }
        let capabilities = capabilities
            .iter()
            .fold(0, |bits, capability| bits | capability.bit());
        if capabilities == 0 {
            return Err(VultisigConnectorError::Config(
                "verifier release must declare a reviewed capability",
            ));
        }
        Ok(Self {
            source_manifest_sha256,
            binary_sha256,
            capabilities,
        })
    }

    /// SHA-256 of the reviewed release manifest.
    #[must_use]
    pub const fn source_manifest_sha256(self) -> [u8; 32] {
        self.source_manifest_sha256
    }

    /// SHA-256 of the exact reviewed verifier executable.
    #[must_use]
    pub const fn binary_sha256(self) -> [u8; 32] {
        self.binary_sha256
    }

    const fn supports(self, capability: VultisigVerifierCapability) -> bool {
        self.capabilities & capability.bit() != 0
    }
}

/// One exact-pinned verifier API, release, and party-id namespace it owns.
pub struct PinnedVultisigVerifier {
    base_url: Url,
    bearer_token: String,
    party_id_prefix: String,
    participant_identity_sha256: [u8; 32],
    pin_set_id: [u8; 32],
    release: ReviewedVultisigVerifierRelease,
    client: Client,
}

impl fmt::Debug for PinnedVultisigVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedVultisigVerifier")
            .field("base_url", &"<redacted>")
            .field("bearer_token", &"<redacted>")
            .field("party_id_prefix", &self.party_id_prefix)
            .field(
                "participant_identity_sha256",
                &self.participant_identity_sha256,
            )
            .field("pin_set_id", &self.pin_set_id)
            .field("release", &self.release)
            .field("client", &"<redacted>")
            .finish()
    }
}

impl PinnedVultisigVerifier {
    /// Construct one production verifier using normal `WebPKI` authentication,
    /// an exact reviewed leaf-certificate pin, and the reviewed source/binary
    /// release identity declared by `release`.
    ///
    /// # Errors
    /// Unsafe URL/token/prefix, pin configuration, or client construction.
    pub fn new(
        base_url: &str,
        bearer_token: impl Into<String>,
        party_id_prefix: impl Into<String>,
        participant_identity_sha256: [u8; 32],
        pinned_server: PinnedCertStore,
        release: ReviewedVultisigVerifierRelease,
    ) -> Result<Self, VultisigConnectorError> {
        let base_url = normalize_url(base_url, false)?;
        let bearer_token = bearer_token.into();
        validate_token(&bearer_token)?;
        let party_id_prefix = party_id_prefix.into();
        validate_party_prefix(&party_id_prefix)?;
        if participant_identity_sha256 == [0; 32] {
            return Err(VultisigConnectorError::Config(
                "verifier participant identity must not be zero",
            ));
        }
        let pin_set_id = pinned_server.exact_leaf_pin_set_id();
        let client = exact_pinned_https_async_client_builder(http_policy(), pinned_server)
            .map_err(|_| VultisigConnectorError::Config("invalid verifier TLS pins"))?
            .build()
            .map_err(|_| VultisigConnectorError::Config("invalid verifier HTTP client"))?;
        Ok(Self {
            base_url,
            bearer_token,
            party_id_prefix,
            participant_identity_sha256,
            pin_set_id,
            release,
            client,
        })
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn new_loopback(
        base_url: &str,
        bearer_token: &str,
        party_id_prefix: &str,
    ) -> Result<Self, VultisigConnectorError> {
        Self::new_loopback_with_release(
            base_url,
            bearer_token,
            party_id_prefix,
            ReviewedVultisigVerifierRelease {
                source_manifest_sha256: [0xa1; 32],
                binary_sha256: [0xb2; 32],
                capabilities: UPSTREAM_HASH_DERIVATION_CAPABILITY,
            },
        )
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn new_loopback_with_release(
        base_url: &str,
        bearer_token: &str,
        party_id_prefix: &str,
        release: ReviewedVultisigVerifierRelease,
    ) -> Result<Self, VultisigConnectorError> {
        validate_token(bearer_token)?;
        validate_party_prefix(party_id_prefix)?;
        let participant_identity_sha256: [u8; 32] =
            Sha256::digest(party_id_prefix.as_bytes()).into();
        Ok(Self {
            base_url: normalize_url(base_url, true)?,
            bearer_token: bearer_token.to_string(),
            party_id_prefix: party_id_prefix.to_string(),
            participant_identity_sha256,
            pin_set_id: [0; 32],
            release,
            client: xindex_ops::network::async_client(http_policy())
                .map_err(|_| VultisigConnectorError::Config("invalid loopback HTTP client"))?,
        })
    }
}

/// One exact-pinned Vultisig relay API.
pub struct PinnedVultisigRelay {
    base_url: Url,
    pin_set_id: [u8; 32],
    client: Client,
}

impl fmt::Debug for PinnedVultisigRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedVultisigRelay")
            .field("base_url", &"<redacted>")
            .field("pin_set_id", &self.pin_set_id)
            .field("client", &"<redacted>")
            .finish()
    }
}

impl PinnedVultisigRelay {
    /// Construct one production relay using normal `WebPKI` authentication plus
    /// an exact reviewed leaf-certificate pin.
    ///
    /// # Errors
    /// Unsafe URL, pin configuration, or client construction.
    pub fn new(
        base_url: &str,
        pinned_server: PinnedCertStore,
    ) -> Result<Self, VultisigConnectorError> {
        let base_url = normalize_url(base_url, false)?;
        let pin_set_id = pinned_server.exact_leaf_pin_set_id();
        let client = exact_pinned_https_async_client_builder(http_policy(), pinned_server)
            .map_err(|_| VultisigConnectorError::Config("invalid relay TLS pins"))?
            .build()
            .map_err(|_| VultisigConnectorError::Config("invalid relay HTTP client"))?;
        Ok(Self {
            base_url,
            pin_set_id,
            client,
        })
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn new_loopback(base_url: &str) -> Result<Self, VultisigConnectorError> {
        Ok(Self {
            base_url: normalize_url(base_url, true)?,
            pin_set_id: [0; 32],
            client: xindex_ops::network::async_client(http_policy())
                .map_err(|_| VultisigConnectorError::Config("invalid loopback HTTP client"))?,
        })
    }
}

/// Exact verifier/relay orchestration with a fixed party topology.
#[derive(Debug)]
pub struct VultisigConnector {
    relay: PinnedVultisigRelay,
    verifiers: Vec<PinnedVultisigVerifier>,
    target_id: [u8; 32],
    journal: Option<SqliteVultisigKeysignJournal>,
    session_timeout: Duration,
    poll_interval: Duration,
}

/// Recovery phase for one exact Vultisig signing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VultisigKeysignPhase {
    /// At least one verifier POST may have been accepted. It must not be sent
    /// again without an upstream idempotency proof.
    VerifierSubmissionUncertain,
    /// Every verifier acknowledged its task; relay parties are not complete.
    WaitingForParties,
    /// Relay `/start` may have been accepted and must not be repeated.
    SessionStartUncertain,
    /// Relay start was acknowledged; participant completion is pending.
    WaitingForCompletion,
    /// The completed session's per-message responses are being retrieved.
    FetchingResponses,
    /// Remote responses exist and strict local finalization is pending.
    Finalizing,
}

/// Opaque, non-cloneable signing operation prepared before any network send.
///
/// The exact `UUIDv4` and encryption key are generated once and retained with
/// the sealed request. Only this type can enter [`VultisigConnector::sign`];
/// once a verifier POST is attempted, failures return
/// [`PendingVultisigKeysign`] instead so an uncertain request cannot be sent a
/// second time accidentally.
///
/// ```compile_fail
/// use xindex_vultisig_connector::PreparedVultisigKeysign;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PreparedVultisigKeysign>();
/// ```
#[expect(
    missing_debug_implementations,
    reason = "Debug is deliberately omitted from the sealed request and session material"
)]
pub struct PreparedVultisigKeysign {
    request: AuthorizedVultisigKeysign,
    wire: VultisigPluginKeysignRequest,
    remote: RemoteSessionState,
    journal_claim: VultisigKeysignJournalClaim,
}

impl PreparedVultisigKeysign {
    /// Exact `UUIDv4` that will identify this remote signing session.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.remote.session.session_id
    }

    /// Strict Bitcoin operation identity, when this is the integrated BTC
    /// profile rather than a generic cross-chain request.
    #[must_use]
    pub fn bitcoin_operation_id(&self) -> Option<[u8; 32]> {
        self.request.bitcoin_operation_id()
    }
}

/// Preparation failure that retains the original authorized request.
pub struct VultisigKeysignPreparationFailure {
    request: Box<AuthorizedVultisigKeysign>,
    error: VultisigConnectorError,
}

impl fmt::Debug for VultisigKeysignPreparationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VultisigKeysignPreparationFailure")
            .field("request", &"<redacted>")
            .field("error", &self.error)
            .finish()
    }
}

impl VultisigKeysignPreparationFailure {
    /// Borrow the retained authorization capability.
    #[must_use]
    pub fn request(&self) -> &AuthorizedVultisigKeysign {
        &self.request
    }

    /// Inspect the preparation error.
    #[must_use]
    pub const fn error(&self) -> &VultisigConnectorError {
        &self.error
    }

    /// Recover the original authorization capability for a fresh preparation.
    #[must_use]
    pub fn into_request(self) -> AuthorizedVultisigKeysign {
        *self.request
    }

    /// Recover the original request and failure reason together.
    #[must_use]
    pub fn into_parts(self) -> (AuthorizedVultisigKeysign, VultisigConnectorError) {
        (*self.request, self.error)
    }
}

impl fmt::Display for VultisigKeysignPreparationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for VultisigKeysignPreparationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Opaque, non-cloneable request and exact session retained after a possible
/// network acceptance.
///
/// This type cannot be passed back to [`VultisigConnector::sign`]. Recovery is
/// observation-only through [`VultisigConnector::resume`]: it waits for the
/// same relay session and never repeats an uncertain verifier or relay-start
/// POST.
#[expect(
    missing_debug_implementations,
    reason = "Debug is deliberately omitted from the sealed request and session material"
)]
pub struct PendingVultisigKeysign {
    request: AuthorizedVultisigKeysign,
    remote: RemoteSessionState,
    journal_claim: VultisigKeysignJournalClaim,
}

impl PendingVultisigKeysign {
    /// Exact `UUIDv4` retained from the original attempt.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.remote.session.session_id
    }

    /// Current same-session recovery phase.
    #[must_use]
    pub const fn phase(&self) -> VultisigKeysignPhase {
        self.remote.phase
    }

    /// One acknowledged task ID per configured verifier. `None` means the
    /// response was uncertain; it does not mean the verifier rejected it.
    #[must_use]
    pub fn verifier_task_ids(&self) -> &[Option<String>] {
        &self.remote.verifier_task_ids
    }

    /// Strict Bitcoin operation identity retained by the durable request.
    #[must_use]
    pub fn bitcoin_operation_id(&self) -> Option<[u8; 32]> {
        self.request.bitcoin_operation_id()
    }

    /// Non-authorizing material used to re-cross current Bitcoin policy after
    /// a process restart.
    ///
    /// # Errors
    /// Corrupt durable Bitcoin request metadata fails closed.
    pub fn bitcoin_recovery_material(
        &self,
    ) -> Result<Option<VultisigBitcoinRecoveryMaterial>, VultisigConnectorError> {
        self.request
            .bitcoin_recovery_material()
            .map_err(|_| VultisigConnectorError::Protocol("durable Bitcoin recovery is invalid"))
    }
}

/// Ordinary connector failure that retains the exact pending operation.
pub struct VultisigKeysignFailure {
    pending: Box<PendingVultisigKeysign>,
    error: VultisigConnectorError,
}

impl fmt::Debug for VultisigKeysignFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VultisigKeysignFailure")
            .field("pending", &"<redacted>")
            .field("error", &self.error)
            .finish()
    }
}

impl VultisigKeysignFailure {
    /// Borrow the retained same-session recovery capability.
    #[must_use]
    pub const fn pending(&self) -> &PendingVultisigKeysign {
        &self.pending
    }

    /// Inspect the fail-closed reason.
    #[must_use]
    pub const fn error(&self) -> &VultisigConnectorError {
        &self.error
    }

    /// Recover the pending operation for observation-only resume.
    #[must_use]
    pub fn into_pending(self) -> PendingVultisigKeysign {
        *self.pending
    }

    /// Recover the pending operation and failure reason together.
    #[must_use]
    pub fn into_parts(self) -> (PendingVultisigKeysign, VultisigConnectorError) {
        (*self.pending, self.error)
    }
}

impl fmt::Display for VultisigKeysignFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for VultisigKeysignFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl VultisigConnector {
    /// Open a durable connector. At least two non-overlapping configured party
    /// namespaces are required, and the journal is permanently bound to the
    /// normalized URLs, exact leaf-pin sets, source/binary releases, verifier
    /// order, and party namespaces.
    ///
    /// # Errors
    /// Unsafe topology/storage or a journal bound to another target fails
    /// closed.
    pub async fn open(
        relay: PinnedVultisigRelay,
        verifiers: Vec<PinnedVultisigVerifier>,
        journal_path: impl AsRef<Path>,
    ) -> Result<Self, VultisigConnectorError> {
        validate_topology(&verifiers)?;
        let target_id = connector_target_id(&relay, &verifiers);
        let journal = SqliteVultisigKeysignJournal::connect(journal_path, target_id).await?;
        Ok(Self {
            relay,
            verifiers,
            target_id,
            journal: Some(journal),
            session_timeout: SESSION_TIMEOUT,
            poll_interval: POLL_INTERVAL,
        })
    }

    #[cfg(test)]
    fn new(
        relay: PinnedVultisigRelay,
        verifiers: Vec<PinnedVultisigVerifier>,
    ) -> Result<Self, VultisigConnectorError> {
        validate_topology(&verifiers)?;
        let target_id = connector_target_id(&relay, &verifiers);
        Ok(Self {
            relay,
            verifiers,
            target_id,
            journal: None,
            session_timeout: SESSION_TIMEOUT,
            poll_interval: POLL_INTERVAL,
        })
    }

    /// Domain-separated identity of the exact relay/verifier target bound to
    /// this connector's durable journal.
    #[must_use]
    pub const fn target_id(&self) -> [u8; 32] {
        self.target_id
    }

    /// Bind fresh session material to a sealed request and durably persist its
    /// pessimistic pre-POST recovery state before returning.
    ///
    /// # Errors
    /// An unqualified signer-side hash-derivation profile, randomness failure,
    /// wire construction failure, or durable write failure retains the original
    /// request. No network request is made.
    pub async fn prepare(
        &self,
        request: AuthorizedVultisigKeysign,
    ) -> Result<PreparedVultisigKeysign, VultisigKeysignPreparationFailure> {
        if let Err(error) =
            require_qualified_hash_derivation(request.profile().hash_derivation(), &self.verifiers)
        {
            return Err(VultisigKeysignPreparationFailure {
                request: Box::new(request),
                error,
            });
        }
        let session = match SessionMaterial::fresh() {
            Ok(session) => session,
            Err(error) => {
                return Err(VultisigKeysignPreparationFailure {
                    request: Box::new(request),
                    error,
                });
            }
        };
        let Ok(wire) = request.wire_request(&session.session_id, session.encryption_key) else {
            return Err(VultisigKeysignPreparationFailure {
                request: Box::new(request),
                error: VultisigConnectorError::Request("wire request construction failed"),
            });
        };
        let Ok(wire_bytes) = serde_json::to_vec(&wire) else {
            return Err(VultisigKeysignPreparationFailure {
                request: Box::new(request),
                error: VultisigConnectorError::Request("wire request serialization failed"),
            });
        };
        let wire_sha256: [u8; 32] = Sha256::digest(wire_bytes).into();
        let messages = request
            .payloads()
            .iter()
            .map(|payload| BASE64.encode(payload.message()))
            .collect::<Vec<_>>();
        let remote = RemoteSessionState::new(session, messages, self.verifiers.len(), wire_sha256);
        let connector_state = match encode_durable_remote(&remote) {
            Ok(state) => state,
            Err(error) => {
                return Err(VultisigKeysignPreparationFailure {
                    request: Box::new(request),
                    error,
                });
            }
        };
        let journal = match self.journal() {
            Ok(journal) => journal,
            Err(error) => {
                return Err(VultisigKeysignPreparationFailure {
                    request: Box::new(request),
                    error,
                });
            }
        };
        let journal_claim = match journal
            .persist(&remote.session.session_id, &request, &connector_state)
            .await
        {
            Ok(claim) => claim,
            Err(error) => {
                return Err(VultisigKeysignPreparationFailure {
                    request: Box::new(request),
                    error: VultisigConnectorError::Journal(error),
                });
            }
        };
        Ok(PreparedVultisigKeysign {
            request,
            wire,
            remote,
            journal_claim,
        })
    }

    /// List durable inactive sessions that can be recovered without repeating
    /// a verifier or ambiguous relay-start POST.
    ///
    /// # Errors
    /// Journal storage or integrity failure.
    pub async fn recoverable_sessions(&self) -> Result<Vec<String>, VultisigConnectorError> {
        Ok(self.journal()?.recoverable_sessions().await?)
    }

    /// Recover one durable operation as observation-only pending state.
    ///
    /// This method never returns [`PreparedVultisigKeysign`], even when a crash
    /// happened before the first POST. The journal's pessimistic phase prevents
    /// an unprovable resend.
    ///
    /// # Errors
    /// Missing/active/corrupt journal state or disagreement with the current
    /// exact connector topology.
    pub async fn recover(
        &self,
        session_id: &str,
    ) -> Result<PendingVultisigKeysign, VultisigConnectorError> {
        let recovered = self.journal()?.recover(session_id).await?;
        let (request, connector_state, journal_claim) = recovered.into_parts();
        let remote = decode_durable_remote(&connector_state)?;
        self.validate_recovered_remote(&request, &remote)?;
        Ok(PendingVultisigKeysign {
            request,
            remote,
            journal_claim,
        })
    }

    /// Read a terminal commitment-only handoff receipt after a cancelled call
    /// or process restart.
    ///
    /// # Errors
    /// Journal storage or integrity failure.
    pub async fn terminal_handoff(
        &self,
        session_id: &str,
    ) -> Result<Option<VultisigKeysignTerminalReceipt>, VultisigConnectorError> {
        Ok(self.journal()?.terminal_handoff(session_id).await?)
    }

    /// Acknowledge an exact downstream durable receipt, atomically redact the
    /// secret-bearing live connector row, and install a commitment-only
    /// terminal tombstone.
    ///
    /// The caller must persist [`CompletedVultisigKeysign::transaction`] and
    /// [`CompletedVultisigKeysign::receipt`] before invoking this method. A
    /// mismatch or ordinary storage failure retains the completed capability;
    /// cancellation before commit leaves the row recoverable, while
    /// cancellation after commit is reconciled through [`Self::terminal_handoff`].
    ///
    /// # Errors
    /// Completion mismatch, foreign/stale claim, journal corruption, or
    /// storage failure retains the completed capability.
    pub async fn acknowledge_handoff(
        &self,
        completed: CompletedVultisigKeysign,
        acknowledgement: VultisigKeysignHandoffAcknowledgement,
    ) -> Result<AcknowledgedVultisigKeysign, VultisigKeysignHandoffFailure> {
        let CompletedVultisigKeysign {
            transaction,
            receipt,
            completion_id,
            bitcoin_session_context,
            bitcoin_operation_id,
            journal_claim,
        } = completed;
        if acknowledgement.completion != completion_id {
            return Err(VultisigKeysignHandoffFailure {
                completed: Box::new(CompletedVultisigKeysign {
                    transaction,
                    receipt,
                    completion_id,
                    bitcoin_session_context,
                    bitcoin_operation_id,
                    journal_claim,
                }),
                error: VultisigConnectorError::Protocol(
                    "downstream acknowledgement names another completion",
                ),
            });
        }

        let result = match self.journal() {
            Ok(journal) => journal
                .acknowledge_handoff(
                    &journal_claim,
                    completion_id,
                    acknowledgement.downstream_consumer,
                    acknowledgement.downstream_receipt,
                )
                .await
                .map_err(VultisigConnectorError::Journal),
            Err(error) => Err(error),
        };
        match result {
            Ok(terminal_receipt) => {
                drop(journal_claim);
                Ok(AcknowledgedVultisigKeysign {
                    transaction,
                    receipt,
                    terminal_receipt,
                })
            }
            Err(error) => Err(VultisigKeysignHandoffFailure {
                completed: Box::new(CompletedVultisigKeysign {
                    transaction,
                    receipt,
                    completion_id,
                    bitcoin_session_context,
                    bitcoin_operation_id,
                    journal_claim,
                }),
                error,
            }),
        }
    }

    /// Close the durable journal after every outstanding prepared, pending, or
    /// completed capability has been dropped.
    pub async fn close(self) {
        if let Some(journal) = self.journal {
            journal.close().await;
        }
    }

    fn journal(&self) -> Result<&SqliteVultisigKeysignJournal, VultisigConnectorError> {
        self.journal.as_ref().ok_or(VultisigConnectorError::Config(
            "connector has no durable journal",
        ))
    }

    /// Attempt every configured verifier exactly once, then drive the exact
    /// relay session through strict local finalization.
    ///
    /// The prepared type is consumed before the first POST. Every ordinary
    /// failure after that point returns an opaque pending capability; it cannot
    /// be passed to this method again.
    ///
    /// The durable row is committed before this future can issue a POST.
    /// Cancelling the future drops only its in-process claim; explicit restart
    /// recovery remains observation-only for the same session.
    ///
    /// ```compile_fail
    /// use xindex_vultisig_connector::{
    ///     PendingVultisigKeysign, VultisigConnector,
    /// };
    ///
    /// async fn cannot_resubmit(
    ///     connector: &VultisigConnector,
    ///     pending: PendingVultisigKeysign,
    /// ) {
    ///     let _ = connector.sign(pending).await;
    /// }
    /// ```
    ///
    /// # Errors
    /// Verifier/relay transport, topology/session disagreement, or local
    /// signature/finalization failure retains the exact pending operation.
    pub async fn sign(
        &self,
        prepared: PreparedVultisigKeysign,
    ) -> Result<CompletedVultisigKeysign, VultisigKeysignFailure> {
        let PreparedVultisigKeysign {
            request,
            wire,
            remote,
            journal_claim,
        } = prepared;
        let mut pending = PendingVultisigKeysign {
            request,
            remote,
            journal_claim,
        };
        if let Err(error) = self
            .checkpoint_remote(&pending.remote, Some(&pending.journal_claim))
            .await
        {
            return Err(VultisigKeysignFailure {
                pending: Box::new(pending),
                error,
            });
        }
        if let Err(error) = self
            .submit_verifiers(&mut pending.remote, &wire, Some(&pending.journal_claim))
            .await
        {
            return Err(VultisigKeysignFailure {
                pending: Box::new(pending),
                error,
            });
        }
        self.finish_pending(pending).await
    }

    /// Resume only the original relay session after an ordinary failure.
    ///
    /// This method never calls a verifier POST. When relay `/start` itself was
    /// uncertain, it also does not repeat that POST; it observes completion of
    /// the same session and otherwise remains fail-closed.
    /// Cancelling this future releases its in-process claim; the latest
    /// pre-transition journal state remains explicitly recoverable.
    ///
    /// # Errors
    /// Relay observation, response retrieval, or finalization failure retains
    /// the same pending capability again.
    pub async fn resume(
        &self,
        pending: PendingVultisigKeysign,
    ) -> Result<CompletedVultisigKeysign, VultisigKeysignFailure> {
        self.finish_pending(pending).await
    }

    async fn finish_pending(
        &self,
        mut pending: PendingVultisigKeysign,
    ) -> Result<CompletedVultisigKeysign, VultisigKeysignFailure> {
        if let Err(error) = self
            .checkpoint_remote(&pending.remote, Some(&pending.journal_claim))
            .await
        {
            return Err(VultisigKeysignFailure {
                pending: Box::new(pending),
                error,
            });
        }
        let (responses, receipt) = match self
            .continue_remote_session(&mut pending.remote, Some(&pending.journal_claim))
            .await
        {
            Ok(result) => result,
            Err(error) => {
                return Err(VultisigKeysignFailure {
                    pending: Box::new(pending),
                    error,
                });
            }
        };
        let PendingVultisigKeysign {
            request,
            remote,
            journal_claim,
        } = pending;
        let bitcoin_session_context = match self.bitcoin_session_context(&request, &receipt) {
            Ok(context) => context,
            Err(error) => {
                return Err(VultisigKeysignFailure {
                    pending: Box::new(PendingVultisigKeysign {
                        request,
                        remote,
                        journal_claim,
                    }),
                    error,
                });
            }
        };
        let bitcoin_operation_id = request.bitcoin_operation_id();
        match finalize_vultisig_keysign(request, responses) {
            Ok(transaction) => {
                let completion_id = keysign_completion_id(self.target_id, &transaction, &receipt);
                Ok(CompletedVultisigKeysign {
                    transaction,
                    receipt,
                    completion_id,
                    bitcoin_session_context,
                    bitcoin_operation_id,
                    journal_claim,
                })
            }
            Err(failure) => {
                let (request, error) = failure.into_parts();
                Err(VultisigKeysignFailure {
                    pending: Box::new(PendingVultisigKeysign {
                        request,
                        remote,
                        journal_claim,
                    }),
                    error: VultisigConnectorError::Finalization(error),
                })
            }
        }
    }

    fn bitcoin_session_context(
        &self,
        request: &AuthorizedVultisigKeysign,
        receipt: &VultisigSessionReceipt,
    ) -> Result<Option<VultisigSessionContext>, VultisigConnectorError> {
        self.bitcoin_session_context_from_evidence(request.bitcoin_evidence_config(), receipt)
    }

    fn bitcoin_session_context_from_evidence(
        &self,
        evidence: Option<&xindex_vultisig_adapter::VultisigBitcoinEvidenceConfig>,
        receipt: &VultisigSessionReceipt,
    ) -> Result<Option<VultisigSessionContext>, VultisigConnectorError> {
        let Some(evidence) = evidence else {
            return Ok(None);
        };
        let exact = exact_configured_parties(&receipt.parties, &self.verifiers)?.ok_or(
            VultisigConnectorError::Protocol(
                "completed Bitcoin session does not contain the exact verifier party set",
            ),
        )?;
        let participants = exact
            .iter()
            .map(|party| {
                let verifier = self
                    .verifiers
                    .iter()
                    .find(|verifier| party.starts_with(&verifier.party_id_prefix))
                    .ok_or(VultisigConnectorError::Protocol(
                        "completed Bitcoin party has no exact verifier identity",
                    ))?;
                VultisigParticipantIdentity::new(
                    party.clone(),
                    verifier.participant_identity_sha256,
                )
                .map_err(|_| {
                    VultisigConnectorError::Protocol(
                        "completed Bitcoin participant identity is invalid",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        VultisigSessionContext::new(
            evidence.upstream_release_manifest_sha256(),
            evidence.vault_id(),
            participants,
            evidence.threshold(),
            receipt.session_id(),
            evidence.reshare_epoch(),
        )
        .map(Some)
        .map_err(|_| {
            VultisigConnectorError::Protocol("completed Bitcoin evidence topology is invalid")
        })
    }

    async fn submit_verifiers<T: Serialize + Sync>(
        &self,
        remote: &mut RemoteSessionState,
        wire: &T,
        journal_claim: Option<&VultisigKeysignJournalClaim>,
    ) -> Result<(), VultisigConnectorError> {
        remote.phase = VultisigKeysignPhase::VerifierSubmissionUncertain;
        let outcomes = join_all(
            self.verifiers
                .iter()
                .map(|verifier| post_verifier(verifier, wire)),
        )
        .await;
        let mut first_error = None;
        for (slot, outcome) in remote.verifier_task_ids.iter_mut().zip(outcomes) {
            match outcome {
                Ok(task_id) => *slot = Some(task_id),
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if first_error.is_none() {
            remote.phase = VultisigKeysignPhase::WaitingForParties;
        }
        self.checkpoint_remote(remote, journal_claim).await?;
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    async fn continue_remote_session(
        &self,
        remote: &mut RemoteSessionState,
        journal_claim: Option<&VultisigKeysignJournalClaim>,
    ) -> Result<(Vec<VultisigKeysignResponse>, VultisigSessionReceipt), VultisigConnectorError>
    {
        let deadline = Instant::now() + self.session_timeout;
        loop {
            match remote.phase {
                VultisigKeysignPhase::VerifierSubmissionUncertain
                | VultisigKeysignPhase::WaitingForParties => {
                    let parties = self
                        .wait_for_parties(&remote.session.session_id, deadline)
                        .await?;
                    remote.parties = Some(parties.clone());
                    remote.phase = VultisigKeysignPhase::SessionStartUncertain;
                    self.checkpoint_remote(remote, journal_claim).await?;
                    self.start_session(&remote.session.session_id, &parties)
                        .await?;
                    remote.phase = VultisigKeysignPhase::WaitingForCompletion;
                    self.checkpoint_remote(remote, journal_claim).await?;
                }
                VultisigKeysignPhase::SessionStartUncertain
                | VultisigKeysignPhase::WaitingForCompletion => {
                    let parties =
                        remote
                            .parties
                            .as_deref()
                            .ok_or(VultisigConnectorError::Protocol(
                                "session completion has no retained party set",
                            ))?;
                    self.wait_for_completion(&remote.session.session_id, parties, deadline)
                        .await?;
                    remote.phase = VultisigKeysignPhase::FetchingResponses;
                    self.checkpoint_remote(remote, journal_claim).await?;
                }
                VultisigKeysignPhase::FetchingResponses => {
                    let responses = try_join_all(remote.messages_base64.iter().map(|message| {
                        self.fetch_keysign_response(&remote.session.session_id, message)
                    }))
                    .await?;
                    remote.responses = Some(responses);
                    remote.phase = VultisigKeysignPhase::Finalizing;
                    self.checkpoint_remote(remote, journal_claim).await?;
                }
                VultisigKeysignPhase::Finalizing => {
                    let responses =
                        remote
                            .responses
                            .clone()
                            .ok_or(VultisigConnectorError::Protocol(
                                "finalizing session has no durable response set",
                            ))?;
                    let parties =
                        remote
                            .parties
                            .clone()
                            .ok_or(VultisigConnectorError::Protocol(
                                "session finalization has no retained party set",
                            ))?;
                    return Ok((
                        responses,
                        VultisigSessionReceipt {
                            session_id: remote.session.session_id.clone(),
                            parties,
                            verifier_task_ids: remote.verifier_task_ids.clone(),
                            wire_sha256: remote.wire_sha256,
                        },
                    ));
                }
            }
        }
    }

    async fn checkpoint_remote(
        &self,
        remote: &RemoteSessionState,
        journal_claim: Option<&VultisigKeysignJournalClaim>,
    ) -> Result<(), VultisigConnectorError> {
        let Some(claim) = journal_claim else {
            #[cfg(test)]
            return Ok(());
            #[cfg(not(test))]
            return Err(VultisigConnectorError::Config(
                "network transition has no durable journal claim",
            ));
        };
        let state = encode_durable_remote(remote)?;
        self.journal()?.checkpoint(claim, &state).await?;
        Ok(())
    }

    fn validate_recovered_remote(
        &self,
        request: &AuthorizedVultisigKeysign,
        remote: &RemoteSessionState,
    ) -> Result<(), VultisigConnectorError> {
        require_qualified_hash_derivation(request.profile().hash_derivation(), &self.verifiers)?;
        if !is_uuid_v4(&remote.session.session_id)
            || remote.session.encryption_key == [0; 16]
            || remote.wire_sha256 == [0; 32]
        {
            return Err(VultisigConnectorError::Protocol(
                "durable session material is invalid",
            ));
        }
        let expected_messages = request
            .payloads()
            .iter()
            .map(|payload| BASE64.encode(payload.message()))
            .collect::<Vec<_>>();
        if remote.messages_base64 != expected_messages || expected_messages.is_empty() {
            return Err(VultisigConnectorError::Protocol(
                "durable message set differs from the authorization",
            ));
        }
        if remote.verifier_task_ids.len() != self.verifiers.len()
            || remote.verifier_task_ids.iter().flatten().any(|task_id| {
                task_id.is_empty()
                    || task_id.len() > MAX_TASK_ID_BYTES
                    || !task_id.bytes().all(|byte| byte.is_ascii_graphic())
            })
        {
            return Err(VultisigConnectorError::Protocol(
                "durable verifier outcomes are invalid",
            ));
        }
        let wire = request
            .wire_request(&remote.session.session_id, remote.session.encryption_key)
            .map_err(|_| {
                VultisigConnectorError::Protocol(
                    "durable session cannot reconstruct its wire request",
                )
            })?;
        let wire_bytes = serde_json::to_vec(&wire).map_err(|_| {
            VultisigConnectorError::Protocol("durable session wire request serialization failed")
        })?;
        let wire_sha256: [u8; 32] = Sha256::digest(wire_bytes).into();
        if wire_sha256 != remote.wire_sha256 {
            return Err(VultisigConnectorError::Protocol(
                "durable wire-request commitment is invalid",
            ));
        }
        validate_durable_responses(remote)?;
        match remote.phase {
            VultisigKeysignPhase::VerifierSubmissionUncertain => {
                if remote.parties.is_some() || remote.responses.is_some() {
                    return Err(VultisigConnectorError::Protocol(
                        "verifier-submission phase carries later relay state",
                    ));
                }
            }
            VultisigKeysignPhase::WaitingForParties => {
                if remote.parties.is_some()
                    || remote.responses.is_some()
                    || remote.verifier_task_ids.iter().any(Option::is_none)
                {
                    return Err(VultisigConnectorError::Protocol(
                        "party-wait phase has incomplete verifier state",
                    ));
                }
            }
            VultisigKeysignPhase::SessionStartUncertain
            | VultisigKeysignPhase::WaitingForCompletion
            | VultisigKeysignPhase::FetchingResponses
            | VultisigKeysignPhase::Finalizing => {
                let parties = remote
                    .parties
                    .as_deref()
                    .ok_or(VultisigConnectorError::Protocol(
                        "post-party durable phase has no relay party set",
                    ))?;
                let exact = exact_configured_parties(parties, &self.verifiers)?.ok_or(
                    VultisigConnectorError::Protocol("durable relay party set is incomplete"),
                )?;
                if exact != parties {
                    return Err(VultisigConnectorError::Protocol(
                        "durable relay party set is not canonical",
                    ));
                }
            }
        }
        Ok(())
    }

    async fn wait_for_parties(
        &self,
        session_id: &str,
        deadline: Instant,
    ) -> Result<Vec<String>, VultisigConnectorError> {
        loop {
            let parties = self
                .relay_string_list(session_id, "session parties")
                .await?;
            if let Some(parties) = exact_configured_parties(&parties, &self.verifiers)? {
                return Ok(parties);
            }
            wait_until_next_poll(deadline, self.poll_interval, "session parties").await?;
        }
    }

    async fn start_session(
        &self,
        session_id: &str,
        parties: &[String],
    ) -> Result<(), VultisigConnectorError> {
        let url = join_url(&self.relay.base_url, &format!("start/{session_id}"))?;
        let response = self
            .relay
            .client
            .post(url)
            .json(parties)
            .send()
            .await
            .map_err(|_| VultisigConnectorError::Transport("relay start"))?;
        require_empty_success(response, "relay start").await
    }

    async fn wait_for_completion(
        &self,
        session_id: &str,
        parties: &[String],
        deadline: Instant,
    ) -> Result<(), VultisigConnectorError> {
        loop {
            let completed = self
                .relay_string_list(&format!("complete/{session_id}"), "session completion")
                .await?;
            validate_party_strings(&completed)?;
            if completed
                .iter()
                .any(|party| !parties.iter().any(|expected| expected == party))
                || has_duplicates(&completed)
            {
                return Err(VultisigConnectorError::Protocol(
                    "relay completion contains an unexpected party",
                ));
            }
            if completed.len() == parties.len() {
                return Ok(());
            }
            wait_until_next_poll(deadline, self.poll_interval, "session completion").await?;
        }
    }

    async fn relay_string_list(
        &self,
        path: &str,
        role: &'static str,
    ) -> Result<Vec<String>, VultisigConnectorError> {
        let url = join_url(&self.relay.base_url, path)?;
        let response = self
            .relay
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| VultisigConnectorError::Transport(role))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        let body = require_success_body(response, role).await?;
        serde_json::from_slice(&body).map_err(|_| VultisigConnectorError::Response(role))
    }

    async fn fetch_keysign_response(
        &self,
        session_id: &str,
        message_base64: &str,
    ) -> Result<VultisigKeysignResponse, VultisigConnectorError> {
        let url = join_url(
            &self.relay.base_url,
            &format!("complete/{session_id}/keysign"),
        )?;
        let message_id = hex::encode(Md5::digest(message_base64.as_bytes()));
        let response = self
            .relay
            .client
            .get(url)
            .header("message_id", message_id)
            .send()
            .await
            .map_err(|_| VultisigConnectorError::Transport("keysign result"))?;
        let body = require_success_body(response, "keysign result").await?;
        serde_json::from_slice(&body)
            .map_err(|_| VultisigConnectorError::Response("keysign result"))
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_timing(mut self) -> Self {
        self.session_timeout = Duration::from_secs(2);
        self.poll_interval = Duration::from_millis(5);
        self
    }
}

/// Exact durable downstream statement for one completed keysign handoff.
///
/// The downstream consumer must persist the completed transaction and session
/// receipt before constructing this value. The connector checks the supplied
/// completion identity and only then atomically redacts its live journal row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VultisigKeysignHandoffAcknowledgement {
    completion: [u8; 32],
    downstream_consumer: [u8; 32],
    downstream_receipt: [u8; 32],
}

impl VultisigKeysignHandoffAcknowledgement {
    /// Bind one exact completion to a stable downstream consumer and its
    /// durable receipt.
    ///
    /// # Errors
    /// Placeholder zero identities are rejected.
    pub fn new(
        completion_id: [u8; 32],
        downstream_consumer_id: [u8; 32],
        downstream_receipt_id: [u8; 32],
    ) -> Result<Self, VultisigConnectorError> {
        if completion_id == [0; 32]
            || downstream_consumer_id == [0; 32]
            || downstream_receipt_id == [0; 32]
        {
            return Err(VultisigConnectorError::Config(
                "terminal handoff identities must be non-zero",
            ));
        }
        Ok(Self {
            completion: completion_id,
            downstream_consumer: downstream_consumer_id,
            downstream_receipt: downstream_receipt_id,
        })
    }

    /// Exact connector completion being acknowledged.
    #[must_use]
    pub const fn completion_id(self) -> [u8; 32] {
        self.completion
    }

    /// Stable downstream persistence-boundary identity.
    #[must_use]
    pub const fn downstream_consumer_id(self) -> [u8; 32] {
        self.downstream_consumer
    }

    /// Durable receipt issued by the downstream boundary.
    #[must_use]
    pub const fn downstream_receipt_id(self) -> [u8; 32] {
        self.downstream_receipt
    }
}

/// Successful local finalization plus the exact remote session evidence.
///
/// Dropping this value keeps the durable `Finalizing` row recoverable. The
/// transaction cannot be extracted until
/// [`VultisigConnector::acknowledge_handoff`] atomically installs a terminal
/// tombstone and removes the secret-bearing live row.
///
/// ```compile_fail
/// use xindex_vultisig_connector::CompletedVultisigKeysign;
///
/// fn cannot_bypass_terminal_handoff(completed: CompletedVultisigKeysign) {
///     let _ = completed.into_parts();
/// }
/// ```
#[expect(
    missing_debug_implementations,
    reason = "Debug is deliberately omitted from the durable completion claim"
)]
pub struct CompletedVultisigKeysign {
    transaction: VerifiedVultisigTransaction,
    receipt: VultisigSessionReceipt,
    completion_id: [u8; 32],
    bitcoin_session_context: Option<VultisigSessionContext>,
    bitcoin_operation_id: Option<[u8; 32]>,
    journal_claim: VultisigKeysignJournalClaim,
}

impl CompletedVultisigKeysign {
    /// Locally verified canonical transaction bytes.
    #[must_use]
    pub const fn transaction(&self) -> &VerifiedVultisigTransaction {
        &self.transaction
    }

    /// Exact relay/verifier session receipt.
    #[must_use]
    pub const fn receipt(&self) -> &VultisigSessionReceipt {
        &self.receipt
    }

    /// Domain-separated commitment to the target, chain, exact transaction,
    /// session, party set, and verifier outcomes.
    #[must_use]
    pub const fn completion_id(&self) -> [u8; 32] {
        self.completion_id
    }

    /// Actual connector party set bound to reviewed Bitcoin participant
    /// identities. Generic cross-chain completions return `None`.
    #[must_use]
    pub const fn bitcoin_session_context(&self) -> Option<&VultisigSessionContext> {
        self.bitcoin_session_context.as_ref()
    }

    /// Strict pre-signing Bitcoin operation identity retained through local
    /// signature verification.
    #[must_use]
    pub const fn bitcoin_operation_id(&self) -> Option<[u8; 32]> {
        self.bitcoin_operation_id
    }
}

/// Completed keysign released only after terminal journal cleanup succeeds.
#[expect(
    missing_debug_implementations,
    reason = "Debug is deliberately omitted from verified transaction bytes"
)]
pub struct AcknowledgedVultisigKeysign {
    transaction: VerifiedVultisigTransaction,
    receipt: VultisigSessionReceipt,
    terminal_receipt: VultisigKeysignTerminalReceipt,
}

impl AcknowledgedVultisigKeysign {
    /// Locally verified canonical transaction bytes.
    #[must_use]
    pub const fn transaction(&self) -> &VerifiedVultisigTransaction {
        &self.transaction
    }

    /// Exact relay/verifier session receipt.
    #[must_use]
    pub const fn receipt(&self) -> &VultisigSessionReceipt {
        &self.receipt
    }

    /// Durable commitment-only cleanup receipt.
    #[must_use]
    pub const fn terminal_receipt(&self) -> &VultisigKeysignTerminalReceipt {
        &self.terminal_receipt
    }

    /// Consume the acknowledged handoff into its verified transaction,
    /// session evidence, and terminal receipt.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        VerifiedVultisigTransaction,
        VultisigSessionReceipt,
        VultisigKeysignTerminalReceipt,
    ) {
        (self.transaction, self.receipt, self.terminal_receipt)
    }
}

/// Terminal handoff failure retaining the exact completed capability.
pub struct VultisigKeysignHandoffFailure {
    completed: Box<CompletedVultisigKeysign>,
    error: VultisigConnectorError,
}

impl fmt::Debug for VultisigKeysignHandoffFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VultisigKeysignHandoffFailure")
            .field("completed", &"<redacted>")
            .field("error", &self.error)
            .finish()
    }
}

impl VultisigKeysignHandoffFailure {
    /// Borrow the retained completed capability.
    #[must_use]
    pub const fn completed(&self) -> &CompletedVultisigKeysign {
        &self.completed
    }

    /// Inspect the fail-closed handoff error.
    #[must_use]
    pub const fn error(&self) -> &VultisigConnectorError {
        &self.error
    }

    /// Recover the completed capability for acknowledgement retry.
    #[must_use]
    pub fn into_completed(self) -> CompletedVultisigKeysign {
        *self.completed
    }

    /// Recover the completed capability and failure reason together.
    #[must_use]
    pub fn into_parts(self) -> (CompletedVultisigKeysign, VultisigConnectorError) {
        (*self.completed, self.error)
    }
}

impl fmt::Display for VultisigKeysignHandoffFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for VultisigKeysignHandoffFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Exact session, party set and acknowledged task IDs in verifier order.
#[derive(Debug)]
pub struct VultisigSessionReceipt {
    session_id: String,
    parties: Vec<String>,
    verifier_task_ids: Vec<Option<String>>,
    wire_sha256: [u8; 32],
}

impl VultisigSessionReceipt {
    /// Canonical `UUIDv4` relay session identifier.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Canonical exact participant list supplied to `/start`.
    #[must_use]
    pub fn parties(&self) -> &[String] {
        &self.parties
    }

    /// Verifier task IDs in configured-verifier order. A missing ID means the
    /// POST response was uncertain even though the exact relay session later
    /// completed; no ID is guessed or recovered from an unrelated request.
    #[must_use]
    pub fn verifier_task_ids(&self) -> &[Option<String>] {
        &self.verifier_task_ids
    }

    /// SHA-256 commitment to the exact serialized plugin keysign request.
    #[must_use]
    pub const fn wire_sha256(&self) -> [u8; 32] {
        self.wire_sha256
    }
}

/// Fail-closed connector failure. Endpoint and token values are never included.
#[derive(Debug, thiserror::Error)]
pub enum VultisigConnectorError {
    /// Static endpoint/topology configuration is unsafe.
    #[error("invalid Vultisig connector configuration: {0}")]
    Config(&'static str),
    /// OS randomness failed.
    #[error("Vultisig session randomness failed")]
    Random,
    /// Sealed wire request construction failed.
    #[error("Vultisig request failed: {0}")]
    Request(&'static str),
    /// Redacted transport failure.
    #[error("Vultisig transport failed during {0}")]
    Transport(&'static str),
    /// Unexpected HTTP status.
    #[error("Vultisig peer returned HTTP {status} during {role}")]
    HttpStatus {
        /// Redacted protocol role.
        role: &'static str,
        /// Numeric status.
        status: u16,
    },
    /// Bounded response did not match the exact schema.
    #[error("invalid Vultisig response during {0}")]
    Response(&'static str),
    /// Session/topology state violates the configured protocol.
    #[error("invalid Vultisig protocol state: {0}")]
    Protocol(&'static str),
    /// Overall session phase timed out.
    #[error("Vultisig session timed out during {0}")]
    Timeout(&'static str),
    /// Target-bound durable journal failure.
    #[error(transparent)]
    Journal(#[from] VultisigKeysignJournalError),
    /// Strict local signature/family finalization rejected the result.
    #[error(transparent)]
    Finalization(#[from] VultisigResponseError),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionMaterial {
    session_id: String,
    encryption_key: [u8; 16],
}

impl SessionMaterial {
    fn fresh() -> Result<Self, VultisigConnectorError> {
        let mut uuid = [0u8; 16];
        let mut encryption_key = [0u8; 16];
        getrandom::fill(&mut uuid).map_err(|_| VultisigConnectorError::Random)?;
        getrandom::fill(&mut encryption_key).map_err(|_| VultisigConnectorError::Random)?;
        if encryption_key == [0; 16] {
            return Err(VultisigConnectorError::Random);
        }
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        let encoded = hex::encode(uuid);
        let session_id = format!(
            "{}-{}-{}-{}-{}",
            &encoded[0..8],
            &encoded[8..12],
            &encoded[12..16],
            &encoded[16..20],
            &encoded[20..32]
        );
        Ok(Self {
            session_id,
            encryption_key,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteSessionState {
    session: SessionMaterial,
    messages_base64: Vec<String>,
    verifier_task_ids: Vec<Option<String>>,
    parties: Option<Vec<String>>,
    phase: VultisigKeysignPhase,
    wire_sha256: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    responses: Option<Vec<VultisigKeysignResponse>>,
}

impl RemoteSessionState {
    fn new(
        session: SessionMaterial,
        messages_base64: Vec<String>,
        verifier_count: usize,
        wire_sha256: [u8; 32],
    ) -> Self {
        Self {
            session,
            messages_base64,
            verifier_task_ids: vec![None; verifier_count],
            parties: None,
            phase: VultisigKeysignPhase::VerifierSubmissionUncertain,
            wire_sha256,
            responses: None,
        }
    }

    #[cfg(test)]
    fn fresh(
        messages_base64: Vec<String>,
        verifier_count: usize,
    ) -> Result<Self, VultisigConnectorError> {
        Ok(Self::new(
            SessionMaterial::fresh()?,
            messages_base64,
            verifier_count,
            [1; 32],
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableRemoteSession {
    schema: String,
    remote: RemoteSessionState,
}

fn encode_durable_remote(remote: &RemoteSessionState) -> Result<Vec<u8>, VultisigConnectorError> {
    serde_json::to_vec(&DurableRemoteSession {
        schema: DURABLE_REMOTE_SCHEMA.to_string(),
        remote: RemoteSessionState {
            session: SessionMaterial {
                session_id: remote.session.session_id.clone(),
                encryption_key: remote.session.encryption_key,
            },
            messages_base64: remote.messages_base64.clone(),
            verifier_task_ids: remote.verifier_task_ids.clone(),
            parties: remote.parties.clone(),
            phase: remote.phase,
            wire_sha256: remote.wire_sha256,
            responses: remote.responses.clone(),
        },
    })
    .map_err(|_| VultisigConnectorError::Protocol("durable session serialization failed"))
}

fn decode_durable_remote(bytes: &[u8]) -> Result<RemoteSessionState, VultisigConnectorError> {
    let durable = serde_json::from_slice::<DurableRemoteSession>(bytes)
        .map_err(|_| VultisigConnectorError::Protocol("durable session decoding failed"))?;
    if durable.schema != DURABLE_REMOTE_SCHEMA {
        return Err(VultisigConnectorError::Protocol(
            "durable session schema is unsupported",
        ));
    }
    Ok(durable.remote)
}

fn validate_durable_responses(remote: &RemoteSessionState) -> Result<(), VultisigConnectorError> {
    if remote.phase != VultisigKeysignPhase::Finalizing && remote.responses.is_some() {
        return Err(VultisigConnectorError::Protocol(
            "pre-finalization phase already carries signing responses",
        ));
    }
    if remote.phase == VultisigKeysignPhase::Finalizing && remote.responses.is_none() {
        return Err(VultisigConnectorError::Protocol(
            "finalizing phase has no durable signing responses",
        ));
    }
    if remote
        .responses
        .as_ref()
        .is_some_and(|responses| responses.len() != remote.messages_base64.len())
    {
        return Err(VultisigConnectorError::Protocol(
            "durable signing-response count is invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierApiResponse {
    data: VerifierTaskIds,
    error: VerifierApiError,
    status: u16,
    timestamp: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierTaskIds {
    task_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierApiError {
    #[serde(default)]
    message: String,
    #[serde(default)]
    details: String,
}

async fn post_verifier<T: Serialize + Sync>(
    verifier: &PinnedVultisigVerifier,
    wire: &T,
) -> Result<String, VultisigConnectorError> {
    let url = join_url(&verifier.base_url, "plugin-signer/sign")?;
    let response = verifier
        .client
        .post(url)
        .bearer_auth(&verifier.bearer_token)
        .json(wire)
        .send()
        .await
        .map_err(|_| VultisigConnectorError::Transport("verifier submit"))?;
    let body = require_success_body(response, "verifier submit").await?;
    let response: VerifierApiResponse = serde_json::from_slice(&body)
        .map_err(|_| VultisigConnectorError::Response("verifier submit"))?;
    if response.status != 200
        || response.version != "1.0.0"
        || response.timestamp.is_empty()
        || !response.error.message.is_empty()
        || !response.error.details.is_empty()
        || response.data.task_ids.len() != 1
    {
        return Err(VultisigConnectorError::Response("verifier submit"));
    }
    let task_id = response
        .data
        .task_ids
        .into_iter()
        .next()
        .ok_or(VultisigConnectorError::Response("verifier submit"))?;
    if task_id.is_empty()
        || task_id.len() > MAX_PARTY_BYTES
        || !task_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(VultisigConnectorError::Response("verifier submit"));
    }
    Ok(task_id)
}

async fn require_success_body(
    response: reqwest::Response,
    role: &'static str,
) -> Result<Vec<u8>, VultisigConnectorError> {
    let status = response.status();
    let body = read_bounded_async(response, MAX_RESPONSE_BYTES)
        .await
        .map_err(|_| VultisigConnectorError::Response(role))?;
    if status != StatusCode::OK {
        return Err(VultisigConnectorError::HttpStatus {
            role,
            status: status.as_u16(),
        });
    }
    Ok(body)
}

async fn require_empty_success(
    response: reqwest::Response,
    role: &'static str,
) -> Result<(), VultisigConnectorError> {
    let body = require_success_body(response, role).await?;
    if !body.is_empty() {
        return Err(VultisigConnectorError::Response(role));
    }
    Ok(())
}

async fn wait_until_next_poll(
    deadline: Instant,
    poll_interval: Duration,
    phase: &'static str,
) -> Result<(), VultisigConnectorError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(VultisigConnectorError::Timeout(phase));
    }
    sleep(poll_interval.min(deadline - now)).await;
    Ok(())
}

fn exact_configured_parties(
    parties: &[String],
    verifiers: &[PinnedVultisigVerifier],
) -> Result<Option<Vec<String>>, VultisigConnectorError> {
    validate_party_strings(parties)?;
    if has_duplicates(parties) {
        return Err(VultisigConnectorError::Protocol(
            "relay session contains duplicate parties",
        ));
    }
    let mut matched = vec![None; verifiers.len()];
    for party in parties {
        let matches = verifiers
            .iter()
            .enumerate()
            .filter(|(_, verifier)| party.starts_with(&verifier.party_id_prefix))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(VultisigConnectorError::Protocol(
                "relay session contains an unexpected party",
            ));
        }
        let index = matches[0];
        if matched[index].replace(party.clone()).is_some() {
            return Err(VultisigConnectorError::Protocol(
                "relay session contains multiple parties for one verifier",
            ));
        }
    }
    if matched.iter().any(Option::is_none) {
        return Ok(None);
    }
    let mut exact = matched.into_iter().flatten().collect::<Vec<_>>();
    exact.sort_unstable();
    Ok(Some(exact))
}

fn validate_topology(verifiers: &[PinnedVultisigVerifier]) -> Result<(), VultisigConnectorError> {
    if verifiers.len() < MIN_VERIFIERS {
        return Err(VultisigConnectorError::Config(
            "at least two verifiers are required",
        ));
    }
    for (index, verifier) in verifiers.iter().enumerate() {
        validate_party_prefix(&verifier.party_id_prefix)?;
        if verifier.participant_identity_sha256 == [0; 32] {
            return Err(VultisigConnectorError::Config(
                "verifier participant identity must not be zero",
            ));
        }
        for other in &verifiers[index + 1..] {
            if verifier.party_id_prefix.starts_with(&other.party_id_prefix)
                || other.party_id_prefix.starts_with(&verifier.party_id_prefix)
            {
                return Err(VultisigConnectorError::Config(
                    "verifier party prefixes overlap",
                ));
            }
            if verifier.participant_identity_sha256 == other.participant_identity_sha256 {
                return Err(VultisigConnectorError::Config(
                    "verifier participant identities must be distinct",
                ));
            }
        }
    }
    Ok(())
}

fn connector_target_id(
    relay: &PinnedVultisigRelay,
    verifiers: &[PinnedVultisigVerifier],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONNECTOR_TARGET_ID_DOMAIN);
    hash_target_field(&mut hasher, relay.base_url.as_str().as_bytes());
    hash_target_field(&mut hasher, &relay.pin_set_id);
    hasher.update(
        u64::try_from(verifiers.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for verifier in verifiers {
        hash_target_field(&mut hasher, verifier.base_url.as_str().as_bytes());
        hash_target_field(&mut hasher, &verifier.pin_set_id);
        hash_target_field(&mut hasher, verifier.party_id_prefix.as_bytes());
        hash_target_field(&mut hasher, &verifier.participant_identity_sha256);
        hash_target_field(&mut hasher, &verifier.release.source_manifest_sha256);
        hash_target_field(&mut hasher, &verifier.release.binary_sha256);
        hasher.update([verifier.release.capabilities]);
    }
    hasher.finalize().into()
}

fn keysign_completion_id(
    target_id: [u8; 32],
    transaction: &VerifiedVultisigTransaction,
    receipt: &VultisigSessionReceipt,
) -> [u8; 32] {
    keysign_completion_id_from_parts(
        target_id,
        transaction.chain().as_str(),
        transaction.bytes(),
        receipt,
    )
}

fn keysign_completion_id_from_parts(
    target_id: [u8; 32],
    chain: &str,
    transaction_bytes: &[u8],
    receipt: &VultisigSessionReceipt,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEYSIGN_COMPLETION_ID_DOMAIN);
    hash_target_field(&mut hasher, &target_id);
    hash_target_field(&mut hasher, chain.as_bytes());
    hash_target_field(&mut hasher, transaction_bytes);
    hash_target_field(&mut hasher, receipt.session_id.as_bytes());
    hash_target_field(&mut hasher, &receipt.wire_sha256);
    hasher.update(
        u64::try_from(receipt.parties.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for party in &receipt.parties {
        hash_target_field(&mut hasher, party.as_bytes());
    }
    hasher.update(
        u64::try_from(receipt.verifier_task_ids.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for task_id in &receipt.verifier_task_ids {
        match task_id {
            Some(task_id) => {
                hasher.update([1]);
                hash_target_field(&mut hasher, task_id.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hasher.finalize().into()
}

fn hash_target_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn is_uuid_v4(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
        && value.as_bytes()[14] == b'4'
        && matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}

fn require_qualified_hash_derivation(
    derivation: VultisigHashDerivation,
    verifiers: &[PinnedVultisigVerifier],
) -> Result<(), VultisigConnectorError> {
    let required = match derivation {
        VultisigHashDerivation::UpstreamVerifier => {
            Some(VultisigVerifierCapability::UpstreamHashDerivation)
        }
        VultisigHashDerivation::XindexCosmosExtension => {
            Some(VultisigVerifierCapability::CosmosDirectHashDerivation)
        }
        VultisigHashDerivation::UnqualifiedZcashMetadata => None,
    };
    if let Some(required) = required {
        if !verifiers.is_empty()
            && verifiers
                .iter()
                .all(|verifier| verifier.release.supports(required))
        {
            return Ok(());
        }
    }
    Err(VultisigConnectorError::Config(
        "chain profile lacks independently reviewed verifier hash derivation",
    ))
}

fn validate_party_prefix(prefix: &str) -> Result<(), VultisigConnectorError> {
    if prefix.is_empty()
        || prefix.len() > 128
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
    {
        return Err(VultisigConnectorError::Config(
            "invalid verifier party prefix",
        ));
    }
    Ok(())
}

fn validate_party_strings(parties: &[String]) -> Result<(), VultisigConnectorError> {
    if parties.iter().any(|party| {
        party.is_empty()
            || party.len() > MAX_PARTY_BYTES
            || !party.bytes().all(|byte| byte.is_ascii_graphic())
    }) {
        return Err(VultisigConnectorError::Protocol(
            "relay returned an invalid party id",
        ));
    }
    Ok(())
}

fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[index + 1..].iter().any(|other| other == value))
}

fn validate_token(token: &str) -> Result<(), VultisigConnectorError> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(VultisigConnectorError::Config(
            "invalid verifier bearer token",
        ));
    }
    Ok(())
}

fn join_url(base: &Url, path: &str) -> Result<Url, VultisigConnectorError> {
    base.join(path)
        .map_err(|_| VultisigConnectorError::Config("invalid endpoint path"))
}

fn normalize_url(raw: &str, allow_loopback_http: bool) -> Result<Url, VultisigConnectorError> {
    let mut url =
        Url::parse(raw).map_err(|_| VultisigConnectorError::Config("endpoint URL is invalid"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(VultisigConnectorError::Config(
            "endpoint URL contains credentials, query, or fragment",
        ));
    }
    let host = url
        .host_str()
        .ok_or(VultisigConnectorError::Config("endpoint URL has no host"))?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    let is_localhost = host == "localhost" || host.ends_with(".localhost");
    let loopback_http = allow_loopback_http
        && url.scheme() == "http"
        && (host == "127.0.0.1" || host == "::1" || is_localhost);
    if !loopback_http && url.scheme() != "https" {
        return Err(VultisigConnectorError::Config(
            "production endpoint must use HTTPS",
        ));
    }
    if !allow_loopback_http && (is_ip || is_localhost) {
        return Err(VultisigConnectorError::Config(
            "production endpoint requires a DNS identity",
        ));
    }
    if allow_loopback_http && url.scheme() == "http" && !loopback_http {
        return Err(VultisigConnectorError::Config(
            "test HTTP endpoint must be loopback-only",
        ));
    }
    if url.path().to_ascii_lowercase().contains("%2f")
        || url.path().to_ascii_lowercase().contains("%5c")
    {
        return Err(VultisigConnectorError::Config(
            "endpoint path contains an encoded separator",
        ));
    }
    url.set_host(Some(&host))
        .map_err(|_| VultisigConnectorError::Config("endpoint hostname is invalid"))?;
    if url.scheme() == "https" && url.port() == Some(443) {
        url.set_port(None)
            .map_err(|()| VultisigConnectorError::Config("endpoint port is invalid"))?;
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "protocol tests")]

    use serde_json::json;
    use wiremock::matchers::{header, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn test_release(cosmos_direct: bool) -> ReviewedVultisigVerifierRelease {
        let capabilities: &[VultisigVerifierCapability] = if cosmos_direct {
            &[
                VultisigVerifierCapability::UpstreamHashDerivation,
                VultisigVerifierCapability::CosmosDirectHashDerivation,
            ]
        } else {
            &[VultisigVerifierCapability::UpstreamHashDerivation]
        };
        ReviewedVultisigVerifierRelease::new([0x31; 32], [0x42; 32], capabilities)
            .expect("reviewed test release")
    }

    fn test_verifiers(
        first_release: ReviewedVultisigVerifierRelease,
        second_release: ReviewedVultisigVerifierRelease,
    ) -> Vec<PinnedVultisigVerifier> {
        let server = "http://127.0.0.1:12345";
        vec![
            PinnedVultisigVerifier::new_loopback_with_release(
                server,
                "token-a",
                "verifier-a-",
                first_release,
            )
            .expect("first verifier"),
            PinnedVultisigVerifier::new_loopback_with_release(
                server,
                "token-b",
                "verifier-b-",
                second_release,
            )
            .expect("second verifier"),
        ]
    }

    #[test]
    fn session_material_is_uuid_v4_and_uses_a_distinct_random_key() {
        let session = SessionMaterial::fresh().expect("session randomness");
        assert_eq!(session.session_id.len(), 36);
        assert_eq!(session.session_id.as_bytes()[14], b'4');
        assert!(matches!(
            session.session_id.as_bytes()[19],
            b'8' | b'9' | b'a' | b'b'
        ));
        assert_ne!(session.encryption_key, [0; 16]);
    }

    #[test]
    fn unsafe_urls_and_overlapping_party_namespaces_reject() {
        assert!(PinnedVultisigRelay::new_loopback("http://example.com").is_err());
        let server = "http://127.0.0.1:12345";
        let relay = PinnedVultisigRelay::new_loopback(server).expect("relay");
        let verifiers = vec![
            PinnedVultisigVerifier::new_loopback(server, "token-a", "party").expect("verifier"),
            PinnedVultisigVerifier::new_loopback(server, "token-b", "party-two").expect("verifier"),
        ];
        assert!(VultisigConnector::new(relay, verifiers).is_err());
    }

    #[test]
    fn connector_refuses_profiles_without_independent_verifier_hash_derivation() {
        let upstream = test_verifiers(test_release(false), test_release(false));
        assert!(require_qualified_hash_derivation(
            VultisigHashDerivation::UpstreamVerifier,
            &upstream,
        )
        .is_ok());
        assert!(require_qualified_hash_derivation(
            VultisigHashDerivation::XindexCosmosExtension,
            &upstream,
        )
        .is_err());

        let cosmos = test_verifiers(test_release(true), test_release(true));
        assert!(require_qualified_hash_derivation(
            VultisigHashDerivation::XindexCosmosExtension,
            &cosmos,
        )
        .is_ok());
        assert!(require_qualified_hash_derivation(
            VultisigHashDerivation::UnqualifiedZcashMetadata,
            &cosmos,
        )
        .is_err());

        let mixed = test_verifiers(test_release(true), test_release(false));
        assert!(require_qualified_hash_derivation(
            VultisigHashDerivation::XindexCosmosExtension,
            &mixed,
        )
        .is_err());
    }

    #[test]
    fn bitcoin_session_context_binds_actual_parties_to_connector_identities() {
        let server = "http://127.0.0.1:12345";
        let relay = PinnedVultisigRelay::new_loopback(server).expect("relay");
        let verifiers = test_verifiers(test_release(false), test_release(false));
        let connector = VultisigConnector::new(relay, verifiers).expect("connector");
        let receipt = VultisigSessionReceipt {
            session_id: "123e4567-e89b-42d3-a456-426614174002".to_string(),
            parties: vec!["verifier-b-node".to_string(), "verifier-a-node".to_string()],
            verifier_task_ids: vec![Some("task-a".to_string()), Some("task-b".to_string())],
            wire_sha256: [0x51; 32],
        };
        let evidence = xindex_vultisig_adapter::VultisigBitcoinEvidenceConfig::new(
            [0x52; 32],
            "vault-testnet4-runtime",
            2,
            9,
        )
        .expect("evidence config");
        let context = connector
            .bitcoin_session_context_from_evidence(Some(&evidence), &receipt)
            .expect("bound context")
            .expect("Bitcoin context");

        assert_eq!(context.vault_id(), "vault-testnet4-runtime");
        assert_eq!(context.threshold(), 2);
        assert_eq!(context.reshare_epoch(), 9);
        assert_eq!(context.session_id(), receipt.session_id());
        assert_eq!(
            context
                .participants()
                .iter()
                .map(VultisigParticipantIdentity::party_id)
                .collect::<Vec<_>>(),
            ["verifier-a-node", "verifier-b-node"]
        );
        assert_eq!(
            context.participants()[0].identity_sha256(),
            <[u8; 32]>::from(Sha256::digest(b"verifier-a-"))
        );
        assert_eq!(
            context.participants()[1].identity_sha256(),
            <[u8; 32]>::from(Sha256::digest(b"verifier-b-"))
        );
    }

    #[test]
    fn verifier_release_rejects_missing_identity_or_capability() {
        let manifest = [0x31; 32];
        let binary = [0x42; 32];
        assert!(ReviewedVultisigVerifierRelease::new(
            [0; 32],
            binary,
            &[VultisigVerifierCapability::UpstreamHashDerivation],
        )
        .is_err());
        assert!(ReviewedVultisigVerifierRelease::new(
            manifest,
            [0; 32],
            &[VultisigVerifierCapability::UpstreamHashDerivation],
        )
        .is_err());
        assert!(ReviewedVultisigVerifierRelease::new(manifest, binary, &[]).is_err());

        let release = ReviewedVultisigVerifierRelease::new(
            manifest,
            binary,
            &[VultisigVerifierCapability::UpstreamHashDerivation],
        )
        .expect("complete release identity");
        assert_eq!(release.source_manifest_sha256(), manifest);
        assert_eq!(release.binary_sha256(), binary);
    }

    #[test]
    fn connector_target_identity_binds_normalized_peer_topology() {
        let build = |relay_path: &str,
                     first_prefix: &str,
                     reverse: bool,
                     first_release: ReviewedVultisigVerifierRelease| {
            let server = "http://127.0.0.1:12345";
            let relay = PinnedVultisigRelay::new_loopback(&format!("{server}/{relay_path}"))
                .expect("relay");
            let first = PinnedVultisigVerifier::new_loopback_with_release(
                &format!("{server}/verifier-a"),
                "token-a",
                first_prefix,
                first_release,
            )
            .expect("first verifier");
            let second = PinnedVultisigVerifier::new_loopback(
                &format!("{server}/verifier-b"),
                "token-b",
                "verifier-b-",
            )
            .expect("second verifier");
            let verifiers = if reverse {
                vec![second, first]
            } else {
                vec![first, second]
            };
            connector_target_id(&relay, &verifiers)
        };

        let upstream = test_release(false);
        let baseline = build("relay", "verifier-a-", false, upstream);
        assert_eq!(baseline, build("relay/", "verifier-a-", false, upstream));
        assert_ne!(
            baseline,
            build("other-relay", "verifier-a-", false, upstream)
        );
        assert_ne!(baseline, build("relay", "verifier-a-alt-", false, upstream));
        assert_ne!(baseline, build("relay", "verifier-a-", true, upstream));
        assert_ne!(
            baseline,
            build("relay", "verifier-a-", false, test_release(true))
        );
        let changed_manifest = ReviewedVultisigVerifierRelease::new(
            [0x32; 32],
            [0x42; 32],
            &[VultisigVerifierCapability::UpstreamHashDerivation],
        )
        .expect("changed manifest");
        assert_ne!(
            baseline,
            build("relay", "verifier-a-", false, changed_manifest)
        );
        let changed_binary = ReviewedVultisigVerifierRelease::new(
            [0x31; 32],
            [0x43; 32],
            &[VultisigVerifierCapability::UpstreamHashDerivation],
        )
        .expect("changed binary");
        assert_ne!(
            baseline,
            build("relay", "verifier-a-", false, changed_binary)
        );
    }

    #[test]
    fn durable_remote_state_roundtrips_and_rejects_unknown_fields() {
        let remote =
            RemoteSessionState::fresh(vec![BASE64.encode([1u8; 32])], 2).expect("session material");
        let encoded = encode_durable_remote(&remote).expect("encode durable state");
        let decoded = decode_durable_remote(&encoded).expect("decode durable state");
        assert_eq!(decoded.session.session_id, remote.session.session_id);
        assert_eq!(
            decoded.session.encryption_key,
            remote.session.encryption_key
        );
        assert_eq!(decoded.phase, remote.phase);
        assert_eq!(decoded.verifier_task_ids, remote.verifier_task_ids);

        let mut value =
            serde_json::from_slice::<serde_json::Value>(&encoded).expect("durable JSON fixture");
        value
            .as_object_mut()
            .expect("top-level object")
            .insert("unexpected".to_string(), json!(true));
        assert!(
            decode_durable_remote(&serde_json::to_vec(&value).expect("mutated durable JSON"))
                .is_err()
        );
    }

    #[test]
    fn finalizing_state_persists_exact_responses_for_restart_replay() {
        let response = serde_json::from_value::<VultisigKeysignResponse>(json!({
            "msg": BASE64.encode([1u8; 32]),
            "r": "01",
            "s": "02",
            "der_signature": "03",
            "recovery_id": "00"
        }))
        .expect("response fixture");
        let mut remote =
            RemoteSessionState::fresh(vec![BASE64.encode([1u8; 32])], 2).expect("session");
        remote.phase = VultisigKeysignPhase::Finalizing;
        remote.parties = Some(vec![
            "verifier-a-node".to_string(),
            "verifier-b-node".to_string(),
        ]);
        remote.responses = Some(vec![response.clone()]);

        let encoded = encode_durable_remote(&remote).expect("encode finalizing state");
        let mut decoded = decode_durable_remote(&encoded).expect("decode finalizing state");
        assert_eq!(decoded.responses, Some(vec![response]));
        assert!(validate_durable_responses(&decoded).is_ok());
        decoded.responses = None;
        assert!(validate_durable_responses(&decoded).is_err());
    }

    #[tokio::test]
    async fn resumed_finalizing_state_uses_durable_responses_without_network_refetch() {
        let server = "http://127.0.0.1:9";
        let relay = PinnedVultisigRelay::new_loopback(server).expect("relay");
        let verifiers = vec![
            PinnedVultisigVerifier::new_loopback(server, "token-a", "verifier-a-")
                .expect("verifier A"),
            PinnedVultisigVerifier::new_loopback(server, "token-b", "verifier-b-")
                .expect("verifier B"),
        ];
        let connector = VultisigConnector::new(relay, verifiers).expect("connector");
        let message = BASE64.encode([1u8; 32]);
        let response = serde_json::from_value::<VultisigKeysignResponse>(json!({
            "msg": message,
            "r": "01",
            "s": "02",
            "der_signature": "03",
            "recovery_id": "00"
        }))
        .expect("response fixture");
        let mut remote = RemoteSessionState::fresh(vec![message], 2).expect("session");
        remote.phase = VultisigKeysignPhase::Finalizing;
        remote.parties = Some(vec![
            "verifier-a-node".to_string(),
            "verifier-b-node".to_string(),
        ]);
        remote.responses = Some(vec![response.clone()]);

        let (responses, receipt) = connector
            .continue_remote_session(&mut remote, None)
            .await
            .expect("durable finalizing response replay");
        assert_eq!(responses, vec![response]);
        assert_eq!(receipt.session_id(), remote.session.session_id);
    }

    #[test]
    fn terminal_acknowledgement_and_completion_id_bind_every_handoff_identity() {
        let receipt = VultisigSessionReceipt {
            session_id: "123e4567-e89b-42d3-a456-426614174002".to_string(),
            parties: vec!["verifier-a-node".to_string(), "verifier-b-node".to_string()],
            verifier_task_ids: vec![Some("task-a".to_string()), None],
            wire_sha256: [0x50; 32],
        };
        let baseline =
            keysign_completion_id_from_parts([0x51; 32], "btc", b"transaction", &receipt);
        assert_ne!(baseline, [0; 32]);

        let mut changed_receipt = VultisigSessionReceipt {
            session_id: receipt.session_id.clone(),
            parties: receipt.parties.clone(),
            verifier_task_ids: receipt.verifier_task_ids.clone(),
            wire_sha256: receipt.wire_sha256,
        };
        changed_receipt.verifier_task_ids[1] = Some("task-b".to_string());
        assert_ne!(
            baseline,
            keysign_completion_id_from_parts([0x51; 32], "btc", b"transaction", &changed_receipt)
        );
        assert_ne!(
            baseline,
            keysign_completion_id_from_parts([0x52; 32], "btc", b"transaction", &receipt)
        );
        assert_ne!(
            baseline,
            keysign_completion_id_from_parts([0x51; 32], "eth", b"transaction", &receipt)
        );
        assert_ne!(
            baseline,
            keysign_completion_id_from_parts([0x51; 32], "btc", b"mutated", &receipt)
        );
        changed_receipt.verifier_task_ids[1] = None;
        changed_receipt.wire_sha256 = [0x53; 32];
        assert_ne!(
            baseline,
            keysign_completion_id_from_parts([0x51; 32], "btc", b"transaction", &changed_receipt)
        );

        let acknowledgement =
            VultisigKeysignHandoffAcknowledgement::new(baseline, [0x61; 32], [0x62; 32])
                .expect("bound downstream acknowledgement");
        assert_eq!(acknowledgement.completion_id(), baseline);
        assert_eq!(acknowledgement.downstream_consumer_id(), [0x61; 32]);
        assert_eq!(acknowledgement.downstream_receipt_id(), [0x62; 32]);
        for invalid in [
            ([0; 32], [1; 32], [2; 32]),
            ([1; 32], [0; 32], [2; 32]),
            ([1; 32], [2; 32], [0; 32]),
        ] {
            assert!(
                VultisigKeysignHandoffAcknowledgement::new(invalid.0, invalid.1, invalid.2)
                    .is_err()
            );
        }
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "complete verifier/relay transcript")]
    async fn exact_two_verifier_relay_lifecycle_returns_ordered_evidence() {
        let server = MockServer::start().await;
        let success = |task_id: &str| {
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {"task_ids": [task_id]},
                "error": {},
                "status": 200,
                "timestamp": "2026-07-20T00:00:00Z",
                "version": "1.0.0"
            }))
        };
        Mock::given(method("POST"))
            .and(path_regex(r"^/verifier-a/plugin-signer/sign$"))
            .and(header("authorization", "Bearer token-a"))
            .respond_with(success("task-a"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/verifier-b/plugin-signer/sign$"))
            .and(header("authorization", "Bearer token-b"))
            .respond_with(success("task-b"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/relay/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!(["verifier-b-node", "verifier-a-node"])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(
                r"^/relay/start/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/relay/complete/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                "verifier-a-node", "verifier-b-node"
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let message = BASE64.encode([1u8; 32]);
        let message_id = hex::encode(Md5::digest(message.as_bytes()));
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/relay/complete/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/keysign$",
            ))
            .and(header("message_id", message_id.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "msg": message,
                "r": "00",
                "s": "00",
                "der_signature": "",
                "recovery_id": ""
            })))
            .expect(1)
            .mount(&server)
            .await;

        let relay =
            PinnedVultisigRelay::new_loopback(&format!("{}/relay", server.uri())).expect("relay");
        let verifiers = vec![
            PinnedVultisigVerifier::new_loopback(
                &format!("{}/verifier-a", server.uri()),
                "token-a",
                "verifier-a-",
            )
            .expect("verifier A"),
            PinnedVultisigVerifier::new_loopback(
                &format!("{}/verifier-b", server.uri()),
                "token-b",
                "verifier-b-",
            )
            .expect("verifier B"),
        ];
        let connector = VultisigConnector::new(relay, verifiers)
            .expect("connector")
            .with_test_timing();
        let mut remote = RemoteSessionState::fresh(vec![message], 2).expect("session");
        connector
            .submit_verifiers(&mut remote, &json!({"request": "sealed"}), None)
            .await
            .expect("verifier submissions");
        let (_, receipt) = connector
            .continue_remote_session(&mut remote, None)
            .await
            .expect("protocol");

        assert_eq!(
            receipt.parties(),
            &["verifier-a-node".to_string(), "verifier-b-node".to_string()]
        );
        assert_eq!(
            receipt.verifier_task_ids(),
            &[Some("task-a".to_string()), Some("task-b".to_string())]
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "complete ambiguity recovery transcript"
    )]
    async fn uncertain_verifier_response_resumes_without_a_second_post() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/verifier-a/plugin-signer/sign"))
            .and(header("authorization", "Bearer token-a"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/verifier-b/plugin-signer/sign"))
            .and(header("authorization", "Bearer token-b"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"task_ids": ["task-b"]},
                "error": {},
                "status": 200,
                "timestamp": "2026-07-20T00:00:00Z",
                "version": "1.0.0"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let relay =
            PinnedVultisigRelay::new_loopback(&format!("{}/relay", server.uri())).expect("relay");
        let verifiers = vec![
            PinnedVultisigVerifier::new_loopback(
                &format!("{}/verifier-a", server.uri()),
                "token-a",
                "verifier-a-",
            )
            .expect("verifier A"),
            PinnedVultisigVerifier::new_loopback(
                &format!("{}/verifier-b", server.uri()),
                "token-b",
                "verifier-b-",
            )
            .expect("verifier B"),
        ];
        let connector = VultisigConnector::new(relay, verifiers)
            .expect("connector")
            .with_test_timing();
        let message = BASE64.encode([1u8; 32]);
        let mut remote =
            RemoteSessionState::fresh(vec![message.clone()], 2).expect("session material");
        let session_id = remote.session.session_id.clone();

        let submit_error = connector
            .submit_verifiers(&mut remote, &json!({"request": "sealed"}), None)
            .await
            .expect_err("one uncertain response must retain an ambiguous session");
        assert!(matches!(
            submit_error,
            VultisigConnectorError::Response("verifier submit")
        ));
        assert_eq!(
            remote.phase,
            VultisigKeysignPhase::VerifierSubmissionUncertain
        );
        assert_eq!(
            remote.verifier_task_ids,
            vec![None, Some("task-b".to_string())]
        );

        Mock::given(method("GET"))
            .and(path(format!("/relay/{session_id}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!(["verifier-b-node", "verifier-a-node"])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/relay/start/{session_id}")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/relay/complete/{session_id}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!(["verifier-a-node", "verifier-b-node"])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let message_id = hex::encode(Md5::digest(message.as_bytes()));
        Mock::given(method("GET"))
            .and(path(format!("/relay/complete/{session_id}/keysign")))
            .and(header("message_id", message_id.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "msg": message,
                "r": "00",
                "s": "00",
                "der_signature": "",
                "recovery_id": ""
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (_, receipt) = connector
            .continue_remote_session(&mut remote, None)
            .await
            .expect("same-session observation recovery");
        assert_eq!(receipt.session_id(), session_id);
        assert_eq!(
            receipt.verifier_task_ids(),
            &[None, Some("task-b".to_string())]
        );
    }

    #[tokio::test]
    async fn uncertain_relay_start_resumes_without_a_second_start_post() {
        let server = MockServer::start().await;
        let relay =
            PinnedVultisigRelay::new_loopback(&format!("{}/relay", server.uri())).expect("relay");
        let verifiers = vec![
            PinnedVultisigVerifier::new_loopback(
                &format!("{}/verifier-a", server.uri()),
                "token-a",
                "verifier-a-",
            )
            .expect("verifier A"),
            PinnedVultisigVerifier::new_loopback(
                &format!("{}/verifier-b", server.uri()),
                "token-b",
                "verifier-b-",
            )
            .expect("verifier B"),
        ];
        let connector = VultisigConnector::new(relay, verifiers)
            .expect("connector")
            .with_test_timing();
        let message = BASE64.encode([1u8; 32]);
        let mut remote =
            RemoteSessionState::fresh(vec![message.clone()], 2).expect("session material");
        remote.verifier_task_ids = vec![Some("task-a".to_string()), Some("task-b".to_string())];
        remote.phase = VultisigKeysignPhase::WaitingForParties;
        let session_id = remote.session.session_id.clone();

        Mock::given(method("GET"))
            .and(path(format!("/relay/{session_id}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!(["verifier-a-node", "verifier-b-node"])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/relay/start/{session_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_string("accepted-but-lost"))
            .expect(1)
            .mount(&server)
            .await;

        let start_error = connector
            .continue_remote_session(&mut remote, None)
            .await
            .expect_err("unusable start response must remain ambiguous");
        assert!(matches!(
            start_error,
            VultisigConnectorError::Response("relay start")
        ));
        assert_eq!(remote.phase, VultisigKeysignPhase::SessionStartUncertain);

        Mock::given(method("GET"))
            .and(path(format!("/relay/complete/{session_id}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!(["verifier-a-node", "verifier-b-node"])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let message_id = hex::encode(Md5::digest(message.as_bytes()));
        Mock::given(method("GET"))
            .and(path(format!("/relay/complete/{session_id}/keysign")))
            .and(header("message_id", message_id.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "msg": message,
                "r": "00",
                "s": "00",
                "der_signature": "",
                "recovery_id": ""
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (_, receipt) = connector
            .continue_remote_session(&mut remote, None)
            .await
            .expect("same-session completion observation");
        assert_eq!(receipt.session_id(), session_id);
    }
}
