//! Exact-peer Vultisig verifier/relay orchestration.

mod connector;

pub use connector::{
    AcknowledgedVultisigKeysign, CompletedVultisigKeysign, PendingVultisigKeysign,
    PinnedVultisigRelay, PinnedVultisigVerifier, PreparedVultisigKeysign,
    ReviewedVultisigVerifierRelease, VultisigConnector, VultisigConnectorError,
    VultisigKeysignFailure, VultisigKeysignHandoffAcknowledgement, VultisigKeysignHandoffFailure,
    VultisigKeysignPhase, VultisigKeysignPreparationFailure, VultisigSessionReceipt,
    VultisigVerifierCapability,
};
pub use xindex_vultisig_adapter::VultisigKeysignTerminalReceipt;
