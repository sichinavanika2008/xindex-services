//! One complete independent `THORNode` + `CometBFT` source poll.
//!
//! The caller persists [`RawSourcePoll`] before signing, records the returned
//! consensus tip in durable state, then converts it into a policy
//! [`SourceSnapshot`](crate::policy::SourceSnapshot). No partial poll is ever
//! returned: if any of inbound, Mimir, pools or consensus fails, the whole
//! source is unavailable for that round.

use crate::client::{RawResponse, ThorClient, ThorConsensusClient, ThorError};
use crate::policy::{SourceResponseHashes, SourceSnapshot, TipCheckpoint};
use crate::types::{ConsensusTip, InboundAddress, Mimir, Pool};
use crate::types::{SwapQuoteRequest, SwapQuoteResponse};

/// Configured pair of REST and consensus endpoints representing one source.
#[derive(Debug, Clone)]
pub struct ThorSourceClient {
    source_id: String,
    thor: ThorClient,
    consensus: ThorConsensusClient,
}

impl ThorSourceClient {
    #[must_use]
    pub fn new(
        source_id: impl Into<String>,
        thor: ThorClient,
        consensus: ThorConsensusClient,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            thor,
            consensus,
        }
    }

    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Fetch all four safety surfaces concurrently and return exact bodies.
    ///
    /// # Errors
    /// The first transport/HTTP/schema error from any required surface.
    pub async fn poll(&self, observed_at: u64) -> Result<RawSourcePoll, ThorError> {
        if observed_at == 0 {
            return Err(ThorError::Decode(
                "source observation time is zero".to_string(),
            ));
        }
        let (inbound, mimir, pools, consensus) = tokio::try_join!(
            self.thor.inbound_evidence(),
            self.thor.mimir_evidence(),
            self.thor.pools_evidence(),
            self.consensus.status(),
        )?;
        Ok(RawSourcePoll {
            source_id: self.source_id.clone(),
            observed_at,
            inbound,
            mimir,
            pools,
            consensus,
        })
    }

    /// Request one explicit swap quote from this same independent source.
    ///
    /// # Errors
    /// Transport/HTTP/schema or request-policy failure.
    pub async fn quote_swap(
        &self,
        request: &SwapQuoteRequest,
    ) -> Result<RawResponse<SwapQuoteResponse>, ThorError> {
        self.thor.quote_swap(request).await
    }
}

/// Exact source responses awaiting evidence persistence and durable tip
/// reconciliation.
#[derive(Debug, Clone)]
pub struct RawSourcePoll {
    pub source_id: String,
    pub observed_at: u64,
    pub inbound: RawResponse<Vec<InboundAddress>>,
    pub mimir: RawResponse<Mimir>,
    pub pools: RawResponse<Vec<Pool>>,
    pub consensus: RawResponse<ConsensusTip>,
}

impl RawSourcePoll {
    /// Convert persisted raw evidence into the deterministic policy shape.
    #[must_use]
    pub fn snapshot(&self, previous_tip: Option<TipCheckpoint>) -> SourceSnapshot {
        SourceSnapshot {
            source_id: self.source_id.clone(),
            observed_at: self.observed_at,
            consensus: self.consensus.value.clone(),
            previous_tip,
            inbound: self.inbound.value.clone(),
            mimir: self.mimir.value.clone(),
            pools: self.pools.value.clone(),
            response_hashes: SourceResponseHashes {
                inbound: self.inbound.response_hash,
                mimir: self.mimir.response_hash,
                pools: self.pools.response_hash,
                consensus: self.consensus.response_hash,
            },
        }
    }
}
