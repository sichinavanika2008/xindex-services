use xindex_shared::chain_registry::{ChainId, ALL_CHAINS};
use xindex_vultisig_adapter::{
    vultisig_chain_profile, VultisigHashDerivation, VultisigSignatureScheme,
};

#[test]
fn every_xindex_chain_has_an_exact_vultisig_profile() {
    let expected = [
        (ChainId::Btc, "Bitcoin", "m/84'/0'/0'/0/0"),
        (ChainId::Ltc, "Litecoin", "m/84'/2'/0'/0/0"),
        (ChainId::Bch, "Bitcoin-Cash", "m/44'/145'/0'/0/0"),
        (ChainId::Doge, "Dogecoin", "m/44'/3'/0'/0/0"),
        (ChainId::Zec, "Zcash", "m/44'/133'/0'/0/0"),
        (ChainId::Eth, "Ethereum", "m/44'/60'/0'/0/0"),
        (ChainId::Bsc, "BSC", "m/44'/60'/0'/0/0"),
        (ChainId::Avax, "Avalanche", "m/44'/60'/0'/0/0"),
        (ChainId::Base, "Base", "m/44'/60'/0'/0/0"),
        (ChainId::Pol, "Polygon", "m/44'/60'/0'/0/0"),
        (ChainId::Gaia, "Cosmos", "m/44'/118'/0'/0/0"),
        (ChainId::Noble, "Noble", "m/44'/118'/0'/0/0"),
        (ChainId::Xrp, "Ripple", "m/44'/144'/0'/0/0"),
        (ChainId::Sol, "Solana", ""),
        (ChainId::Tron, "Tron", "m/44'/195'/0'/0/0"),
    ];

    assert_eq!(expected.len(), ALL_CHAINS.len());
    for (chain, upstream_name, derive_path) in expected {
        let profile = vultisig_chain_profile(chain);
        assert_eq!(profile.chain(), chain);
        assert_eq!(profile.upstream_name(), upstream_name, "{chain:?}");
        assert_eq!(profile.derive_path(), derive_path, "{chain:?}");
    }
}

#[test]
fn only_solana_uses_the_eddsa_vault_key() {
    for &chain in ALL_CHAINS {
        let expected = if chain == ChainId::Sol {
            VultisigSignatureScheme::Ed25519
        } else {
            VultisigSignatureScheme::Secp256k1
        };
        assert_eq!(
            vultisig_chain_profile(chain).signature_scheme(),
            expected,
            "{chain:?}"
        );
    }
}

#[test]
fn pinned_verifier_gaps_are_explicit_for_zcash_and_both_cosmos_chains() {
    for &chain in ALL_CHAINS {
        let expected = match chain {
            ChainId::Zec => VultisigHashDerivation::UnqualifiedZcashMetadata,
            ChainId::Gaia | ChainId::Noble => VultisigHashDerivation::XindexCosmosExtension,
            _ => VultisigHashDerivation::UpstreamVerifier,
        };
        assert_eq!(
            vultisig_chain_profile(chain).hash_derivation(),
            expected,
            "{chain:?}"
        );
    }
}
