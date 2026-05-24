//! K-of-N multisig descriptor construction + address derivation.
//!
//! Wraps `miniscript::Descriptor` with Xindex-specific defaults and a
//! tighter input shape (typed pubkeys + threshold; no descriptor-string
//! parsing footguns).
//!
//! Two template variants:
//! - [`MultisigDescriptor::new_p2wsh`] — `wsh(multi(K, pk_1, ..., pk_N))`
//!   for `SegWit`-bearing chains (BTC, LTC). BIP-143 sighash.
//! - [`MultisigDescriptor::new_p2sh_legacy`] — `sh(multi(...))` for
//!   legacy / no-`SegWit` chains (BCH, DOGE, ZEC). Pre-BIP-143
//!   legacy sighash (signed by U5).
//!
//! Address encoding for non-Bitcoin chains lives in the U6 codec
//! layer (`xindex-chain-utxo::codec`); this module exposes
//! [`script_pubkey`](MultisigDescriptor::script_pubkey) so the codec
//! can wrap an address around the same script.

use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Address, Network, PublicKey, ScriptBuf};
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
    /// Build a `wsh(multi(K, pk_1, ..., pk_N))` P2WSH descriptor from
    /// raw secp256k1 public keys. Used by `SegWit`-bearing UTXO chains
    /// (BTC, LTC). BIP-143 sighash at signing time.
    ///
    /// # Errors
    /// - [`MultisigError::ThresholdZero`] if `threshold == 0`
    /// - [`MultisigError::ThresholdTooHigh`] if `threshold > pubkeys.len()`
    /// - [`MultisigError::NotEnoughPubkeys`] if fewer than 2 pubkeys
    /// - [`MultisigError::Parse`] if miniscript rejects the constructed string
    pub fn new_p2wsh(threshold: usize, pubkeys: &[PublicKey]) -> Result<Self, MultisigError> {
        Self::build("wsh", threshold, pubkeys)
    }

    /// Build a `sh(multi(K, pk_1, ..., pk_N))` P2SH-legacy descriptor
    /// from raw secp256k1 public keys. Used by chains without `SegWit`:
    /// BCH (dropped `SegWit` post-2017 fork), DOGE (pre-`SegWit`), and
    /// ZEC transparent (t-addr layer is P2SH-only). Pre-BIP-143
    /// legacy sighash at signing time (U5).
    ///
    /// # Errors
    /// As [`MultisigDescriptor::new_p2wsh`].
    pub fn new_p2sh_legacy(threshold: usize, pubkeys: &[PublicKey]) -> Result<Self, MultisigError> {
        Self::build("sh", threshold, pubkeys)
    }

    /// Shared body. `kind` must be the miniscript template wrapper
    /// (`"wsh"` or `"sh"`); the caller picks the one matching the
    /// target chain's `ScriptKind`.
    fn build(kind: &str, threshold: usize, pubkeys: &[PublicKey]) -> Result<Self, MultisigError> {
        if threshold == 0 {
            return Err(MultisigError::ThresholdZero);
        }
        if pubkeys.len() < 2 {
            return Err(MultisigError::NotEnoughPubkeys);
        }
        if threshold > pubkeys.len() {
            return Err(MultisigError::ThresholdTooHigh(threshold, pubkeys.len()));
        }

        let key_list: Vec<String> = pubkeys
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let desc_str = format!("{}(multi({},{}))", kind, threshold, key_list.join(","));
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

    /// Outer `script_pubkey` (network-independent). For P2WSH this is
    /// `OP_0 <sha256(witness_script)>`; for P2SH-legacy it is
    /// `OP_HASH160 <ripemd160(sha256(redeem_script))> OP_EQUAL`. The
    /// U6 codec layer wraps this with per-chain address encoding for
    /// the non-Bitcoin chains where `bitcoin::Network` has no variant.
    ///
    /// # Errors
    /// [`MultisigError::AddressDerive`] if miniscript cannot derive
    /// at index 0 (unresolvable derivation paths).
    pub fn script_pubkey(&self) -> Result<ScriptBuf, MultisigError> {
        let derived = self
            .descriptor
            .at_derivation_index(0)
            .map_err(|e| MultisigError::AddressDerive(e.to_string()))?;
        Ok(derived.script_pubkey())
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
            MultisigDescriptor::new_p2wsh(0, &pks),
            Err(MultisigError::ThresholdZero)
        ));
    }

    #[test]
    fn rejects_threshold_too_high() {
        let secp = Secp256k1::new();
        let pks = vec![random_pubkey(&secp), random_pubkey(&secp)];
        assert!(matches!(
            MultisigDescriptor::new_p2wsh(3, &pks),
            Err(MultisigError::ThresholdTooHigh(3, 2))
        ));
    }

    #[test]
    fn rejects_too_few_pubkeys() {
        let secp = Secp256k1::new();
        let pks = vec![random_pubkey(&secp)];
        assert!(matches!(
            MultisigDescriptor::new_p2wsh(1, &pks),
            Err(MultisigError::NotEnoughPubkeys)
        ));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn three_of_five_descriptor_builds_and_derives_address() {
        let secp = Secp256k1::new();
        let pks: Vec<PublicKey> = (0..5).map(|_| random_pubkey(&secp)).collect();
        let descriptor = MultisigDescriptor::new_p2wsh(3, &pks).expect("descriptor");
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
        let descriptor = MultisigDescriptor::new_p2wsh(2, &pks).expect("descriptor");
        let addr = descriptor.address(Network::Signet).expect("address");
        assert!(addr.to_string().starts_with("tb1q"));
    }

    /// U4: P2SH-legacy variant builds a `sh(multi(...))` descriptor
    /// whose mainnet address starts with `3` (P2SH base58 prefix on
    /// `bitcoin::Network::Bitcoin`). Non-Bitcoin chains will encode
    /// the same `script_pubkey` via their codec in U6.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn p2sh_legacy_descriptor_builds_and_derives_mainnet_address() {
        let secp = Secp256k1::new();
        let pks: Vec<PublicKey> = (0..5).map(|_| random_pubkey(&secp)).collect();
        let descriptor = MultisigDescriptor::new_p2sh_legacy(3, &pks).expect("descriptor");
        assert_eq!(descriptor.threshold, 3);
        assert_eq!(descriptor.pubkey_count, 5);
        let serialized = descriptor.to_descriptor_string();
        assert!(
            serialized.starts_with("sh(multi(3,"),
            "expected sh(multi(... got {serialized}"
        );
        let addr = descriptor.address(Network::Bitcoin).expect("address");
        let s = addr.to_string();
        assert!(
            s.starts_with('3'),
            "expected P2SH mainnet address (3...), got {s}"
        );
    }

    /// U4: `script_pubkey()` for P2WSH yields a 34-byte SegWit-v0 SPK
    /// (`OP_0 <0x20> <32-byte sha256>`); for P2SH-legacy it yields a
    /// 23-byte SPK (`OP_HASH160 <0x14> <20-byte hash160> OP_EQUAL`).
    /// Both forms are network-independent — the U6 codec layer wraps
    /// these with the right per-chain address encoding.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn script_pubkey_lengths_per_template() {
        let secp = Secp256k1::new();
        let pks: Vec<PublicKey> = (0..3).map(|_| random_pubkey(&secp)).collect();

        let wsh = MultisigDescriptor::new_p2wsh(2, &pks).expect("wsh");
        let wsh_spk = wsh.script_pubkey().expect("wsh spk");
        assert_eq!(wsh_spk.len(), 34, "P2WSH SPK = 34 bytes");
        assert_eq!(wsh_spk.as_bytes()[0], 0x00, "P2WSH leading OP_0");
        assert_eq!(wsh_spk.as_bytes()[1], 0x20, "P2WSH push len 32");

        let sh = MultisigDescriptor::new_p2sh_legacy(2, &pks).expect("sh");
        let sh_spk = sh.script_pubkey().expect("sh spk");
        assert_eq!(sh_spk.len(), 23, "P2SH SPK = 23 bytes");
        assert_eq!(sh_spk.as_bytes()[0], 0xa9, "P2SH leading OP_HASH160");
        assert_eq!(sh_spk.as_bytes()[1], 0x14, "P2SH push len 20");
        assert_eq!(
            *sh_spk.as_bytes().last().expect("last byte"),
            0x87,
            "P2SH trailing OP_EQUAL"
        );
    }
}
