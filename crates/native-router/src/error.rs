use thiserror::Error;
use xindex_ops::network::NetworkError;

/// Every provider/API/encoding failure is terminal for that candidate.
#[derive(Debug, Error)]
pub enum NativeRouterError {
    #[error("invalid endpoint: HTTPS is required outside loopback tests")]
    InvalidEndpoint,
    #[error("invalid endpoint path")]
    InvalidEndpointPath,
    #[error("HTTP request failed")]
    HttpTransport,
    #[error("provider returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("bounded response read failed: {0}")]
    Network(#[from] NetworkError),
    #[error("provider response is not valid JSON")]
    InvalidJson,
    #[error("invalid provider data: {0}")]
    InvalidProviderData(&'static str),
    #[error("invalid provider field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("unsupported provider asset {0}")]
    UnsupportedAsset(String),
    #[error("provider asset {0} is not currently routable")]
    AssetUnavailable(String),
    #[error("provider sources disagree: {0}")]
    SourceDisagreement(&'static str),
    #[error("not enough independent provider sources: {supplied} < {required}")]
    InsufficientSources { supplied: usize, required: usize },
    #[error("ABI payload is malformed or non-canonical")]
    InvalidCalldata,
    #[error("route policy rejected candidate: {0}")]
    Policy(&'static str),
    #[error("no eligible route")]
    NoEligibleRoute,
}
