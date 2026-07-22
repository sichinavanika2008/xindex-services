//! Exact Xindex-to-Vultisig chain identities for the reviewed verifier stack.
//!
//! These names and derivation paths are wire values, not display labels. They
//! match `vultisig-go/common.Chain` at the verifier dependency pinned by the
//! reviewed upstream snapshot. An incorrect name selects no chain; an
//! incorrect path signs with a different child key.

use xindex_shared::chain_registry::ChainId;

/// Threshold-signature key family selected by Vultisig for a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VultisigSignatureScheme {
    /// DKLS secp256k1 ECDSA, using the chain's exact BIP-32 path.
    Secp256k1,
    /// Ed25519/EdDSA. Solana uses the vault's `EdDSA` public key and no BIP-32
    /// derivation path in the reviewed verifier.
    Ed25519,
}

/// Where the verifier release derives and binds the chain signing payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VultisigHashDerivation {
    /// Implemented by the reviewed upstream verifier switch and Recipes SDK.
    UpstreamVerifier,
    /// The reviewed Zcash Recipes SDK trusts `ZSH`-appended caller-provided
    /// hashes instead of recomputing ZIP-243 from the transaction. This profile
    /// is not qualified until an Xindex verifier extension derives them itself.
    UnqualifiedZcashMetadata,
    /// Must be supplied by the Xindex verifier extension. The reviewed
    /// verifier omits GAIA and Noble from its hash-derivation switch; silently
    /// routing either through another Cosmos chain is forbidden.
    XindexCosmosExtension,
}

/// Immutable Vultisig wire profile for one Xindex custody chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VultisigChainProfile {
    chain: ChainId,
    upstream_name: &'static str,
    derive_path: &'static str,
    signature_scheme: VultisigSignatureScheme,
    hash_derivation: VultisigHashDerivation,
}

impl VultisigChainProfile {
    /// Xindex chain identity.
    #[must_use]
    pub const fn chain(self) -> ChainId {
        self.chain
    }

    /// Exact JSON string accepted by `vultisig-go/common.Chain`.
    #[must_use]
    pub const fn upstream_name(self) -> &'static str {
        self.upstream_name
    }

    /// Exact upstream child-key derivation path. Empty only for `EdDSA` chains.
    #[must_use]
    pub const fn derive_path(self) -> &'static str {
        self.derive_path
    }

    /// Threshold-signature key family.
    #[must_use]
    pub const fn signature_scheme(self) -> VultisigSignatureScheme {
        self.signature_scheme
    }

    /// Reviewed verifier hash-derivation implementation used for this chain.
    #[must_use]
    pub const fn hash_derivation(self) -> VultisigHashDerivation {
        self.hash_derivation
    }
}

const fn secp(
    chain: ChainId,
    upstream_name: &'static str,
    derive_path: &'static str,
    hash_derivation: VultisigHashDerivation,
) -> VultisigChainProfile {
    VultisigChainProfile {
        chain,
        upstream_name,
        derive_path,
        signature_scheme: VultisigSignatureScheme::Secp256k1,
        hash_derivation,
    }
}

/// Return the exact reviewed Vultisig wire profile for every supported Xindex
/// chain.
///
/// The exhaustive match intentionally has no fallback: adding a `ChainId`
/// cannot compile until its signing family, upstream name, derivation path and
/// verifier coverage are reviewed.
#[must_use]
pub const fn vultisig_chain_profile(chain: ChainId) -> VultisigChainProfile {
    use VultisigHashDerivation::{
        UnqualifiedZcashMetadata, UpstreamVerifier, XindexCosmosExtension,
    };

    match chain {
        ChainId::Btc => secp(chain, "Bitcoin", "m/84'/0'/0'/0/0", UpstreamVerifier),
        ChainId::Ltc => secp(chain, "Litecoin", "m/84'/2'/0'/0/0", UpstreamVerifier),
        ChainId::Bch => secp(chain, "Bitcoin-Cash", "m/44'/145'/0'/0/0", UpstreamVerifier),
        ChainId::Doge => secp(chain, "Dogecoin", "m/44'/3'/0'/0/0", UpstreamVerifier),
        ChainId::Zec => secp(
            chain,
            "Zcash",
            "m/44'/133'/0'/0/0",
            UnqualifiedZcashMetadata,
        ),
        ChainId::Eth => secp(chain, "Ethereum", "m/44'/60'/0'/0/0", UpstreamVerifier),
        ChainId::Bsc => secp(chain, "BSC", "m/44'/60'/0'/0/0", UpstreamVerifier),
        ChainId::Avax => secp(chain, "Avalanche", "m/44'/60'/0'/0/0", UpstreamVerifier),
        ChainId::Base => secp(chain, "Base", "m/44'/60'/0'/0/0", UpstreamVerifier),
        ChainId::Pol => secp(chain, "Polygon", "m/44'/60'/0'/0/0", UpstreamVerifier),
        ChainId::Gaia => secp(chain, "Cosmos", "m/44'/118'/0'/0/0", XindexCosmosExtension),
        ChainId::Noble => secp(chain, "Noble", "m/44'/118'/0'/0/0", XindexCosmosExtension),
        ChainId::Xrp => secp(chain, "Ripple", "m/44'/144'/0'/0/0", UpstreamVerifier),
        ChainId::Sol => VultisigChainProfile {
            chain,
            upstream_name: "Solana",
            derive_path: "",
            signature_scheme: VultisigSignatureScheme::Ed25519,
            hash_derivation: UpstreamVerifier,
        },
        ChainId::Tron => secp(chain, "Tron", "m/44'/195'/0'/0/0", UpstreamVerifier),
    }
}
