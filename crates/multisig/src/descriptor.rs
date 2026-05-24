//! K-of-N P2WSH multisig descriptor construction + address derivation.
//!
//! Wraps `miniscript::Descriptor` with Xindex-specific defaults and a
//! tighter input shape (typed pubkeys + threshold; no descriptor-string
//! parsing footguns).

use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Address, Network, PublicKey};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MultisigError {
    #[error("threshold {0} exceeds pubkey count {1}")]
    ThresholdTooHigh(usize, usize),
    #[error("threshold must be ≥ 1")]
    ThresholdZero,
    #[error("must have ≥ 2 pubkeys for a multisig")]
    NotEnoughPubkeys,
    #[error("descriptor parse failure: {0}")]
    Parse(String),
    #[error("address derivation failure: {0}")]
    AddressDerive(String),
}

/// A K-of-N P2WSH multisig descriptor. Holds the parsed
/// `miniscript::Descriptor` so consumers can derive addresses and reuse
/// the same secp context.
#[derive(Debug, Clone)]
pub struct MultisigDescriptor {
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub threshold: usize,
    pub pubkey_count: usize,
    secp: Secp256k1<All>,
}

impl MultisigDescriptor {
    /// Build a `wsh(multi(K, pk_1, ..., pk_N))` descriptor from raw secp256k1
    /// public keys.
    ///
    /// # Errors
    /// - [`MultisigError::ThresholdZero`] if `threshold == 0`
    /// - [`MultisigError::ThresholdTooHigh`] if `threshold > pubkeys.len()`
    /// - [`MultisigError::NotEnoughPubkeys`] if fewer than 2 pubkeys
    /// - [`MultisigError::Parse`] if miniscript rejects the constructed string
    pub fn new(threshold: usize, pubkeys: &[PublicKey]) -> Result<Self, MultisigError> {
        if threshold == 0 {
            return Err(MultisigError::ThresholdZero);
        }
        if pubkeys.len() < 2 {
            return Err(MultisigError::NotEnoughPubkeys);
        }
        if threshold > pubkeys.len() {
            return Err(MultisigError::ThresholdTooHigh(threshold, pubkeys.len()));
        }

        // Construct a descriptor string, then parse — miniscript validates
        // bytes-on-the-wire while we keep the shape readable here.
        let key_list: Vec<String> = pubkeys
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let desc_str = format!("wsh(multi({},{}))", threshold, key_list.join(","));
        let descriptor: Descriptor<DescriptorPublicKey> = desc_str
            .parse()
            .map_err(|e: miniscript::Error| MultisigError::Parse(e.to_string()))?;

        Ok(Self {
            descriptor,
            threshold,
            pubkey_count: pubkeys.len(),
            secp: Secp256k1::new(),
        })
    }

    /// Derive the canonical P2WSH address on `network`. K-of-N multisig
    /// is a single-address descriptor (no derivation index needed).
    ///
    /// # Errors
    /// [`MultisigError::AddressDerive`] if miniscript cannot produce an
    /// address (e.g., the descriptor has unresolvable derivation paths).
    pub fn address(&self, network: Network) -> Result<Address, MultisigError> {
        // For static descriptors `derived_descriptor` at index 0 returns
        // the same descriptor; the explicit `at_derivation_index` keeps
        // the API uniform if we ever switch to a derived xpub variant.
        let derived = self
            .descriptor
            .at_derivation_index(0)
            .map_err(|e| MultisigError::AddressDerive(e.to_string()))?;
        derived
            .address(network)
            .map_err(|e| MultisigError::AddressDerive(e.to_string()))
    }

    /// Return the canonical descriptor string (BIP 380 form). Useful for
    /// off-chain monitoring tools and key-ceremony documentation.
    #[must_use]
    pub fn to_descriptor_string(&self) -> String {
        self.descriptor.to_string()
    }

    /// Reference to the shared secp context, so PSBT-signing helpers
    /// don't construct a new one per call.
    #[must_use]
    pub fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{rand, Secp256k1, SecretKey};

    fn random_pubkey(secp: &Secp256k1<All>) -> PublicKey {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = sk.public_key(secp);
        PublicKey::new(pk)
    }

    #[test]
    fn rejects_zero_threshold() {
        let secp = Secp256k1::new();
        let pks = vec![
            random_pubkey(&secp),
            random_pubkey(&secp),
            random_pubkey(&secp),
        ];
        assert!(matches!(
            MultisigDescriptor::new(0, &pks),
            Err(MultisigError::ThresholdZero)
        ));
    }

    #[test]
    fn rejects_threshold_too_high() {
        let secp = Secp256k1::new();
        let pks = vec![random_pubkey(&secp), random_pubkey(&secp)];
        assert!(matches!(
            MultisigDescriptor::new(3, &pks),
            Err(MultisigError::ThresholdTooHigh(3, 2))
        ));
    }

    #[test]
    fn rejects_too_few_pubkeys() {
        let secp = Secp256k1::new();
        let pks = vec![random_pubkey(&secp)];
        assert!(matches!(
            MultisigDescriptor::new(1, &pks),
            Err(MultisigError::NotEnoughPubkeys)
        ));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn three_of_five_descriptor_builds_and_derives_address() {
        let secp = Secp256k1::new();
        let pks: Vec<PublicKey> = (0..5).map(|_| random_pubkey(&secp)).collect();
        let descriptor = MultisigDescriptor::new(3, &pks).expect("descriptor");
        assert_eq!(descriptor.threshold, 3);
        assert_eq!(descriptor.pubkey_count, 5);
        let addr = descriptor.address(Network::Bitcoin).expect("address");
        // P2WSH addresses on mainnet start with bc1q...
        let s = addr.to_string();
        assert!(
            s.starts_with("bc1q"),
            "expected bech32 P2WSH mainnet address, got {s}"
        );
        // Descriptor string round-trip.
        let serialized = descriptor.to_descriptor_string();
        assert!(serialized.starts_with("wsh(multi(3,"));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn signet_address_uses_tb_prefix() {
        let secp = Secp256k1::new();
        let pks: Vec<PublicKey> = (0..3).map(|_| random_pubkey(&secp)).collect();
        let descriptor = MultisigDescriptor::new(2, &pks).expect("descriptor");
        let addr = descriptor.address(Network::Signet).expect("address");
        assert!(addr.to_string().starts_with("tb1q"));
    }
}
