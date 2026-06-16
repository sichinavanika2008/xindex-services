//! Software-keyed [`HsmDigestSigner`] for dev / testnet ONLY (the one-box
//! rehearsal — `docs/runbooks/testnet-rehearsal-localhost.md`).
//!
//! Production daemons front a real `YubiHSM2` over [`HttpHsmClient`]
//! (`web3signer.rs`); the signing key never enters process memory. This
//! type is the explicit, LOUD exception: it holds the secp256k1 secret
//! keys IN process memory and signs locally, so one operator can stand up
//! all five daemons on a single machine for a functional rehearsal with no
//! HSM.
//!
//! It is gated three ways so it can never run a production signer by
//! accident:
//!   1. Construction fails closed unless `XINDEX_ALLOW_SOFTWARE_KEYS=1`.
//!   2. The daemon `main` only wires it when `hsm.kind = "software"`.
//!   3. `main` permits `hsm.kind = "software"` only under `--dev`, which is
//!      also the only mode that skips [`crate::server::DaemonState::assert_production_safe`].
//!
//! The signing math is byte-identical to the e2e loopback test's `SoftHsm`:
//! k256 recoverable ECDSA for the Ethereum (Set-B) digest (low-S,
//! `v = 27 + recid`, recovers under alloy's `recover_address_from_prehash`),
//! and `bitcoin::secp256k1` for the Bitcoin (Set-A) PSBT sighash
//! (`r ‖ s ‖ 27`, low-S per `BIP-62`). Routing mirrors the production HSM
//! contract: the `address` argument selects the key — the configured
//! Ethereum signer address takes the ETH key, anything else (the BTC alias
//! address) takes the BTC key.

use alloy_primitives::{keccak256, Address, B256};
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use k256::ecdsa::SigningKey;
use thiserror::Error;

use crate::web3signer::{HsmDigestSigner, HsmError};

/// The loud opt-out environment variable. Software keys must be a
/// deliberate, visible choice, never a silent fallback.
pub const SOFTWARE_KEYS_ENV: &str = "XINDEX_ALLOW_SOFTWARE_KEYS";

/// Why a [`SoftwareHsm`] could not be constructed.
#[derive(Debug, Error)]
pub enum SoftHsmError {
    /// The loud opt-out was not set to `1`. Fail closed.
    #[error(
        "software signing keys are disabled — set XINDEX_ALLOW_SOFTWARE_KEYS=1 to enable \
         (dev / testnet rehearsal ONLY; production fronts an HSM)"
    )]
    NotAllowed,
    /// A configured secret key was not a valid secp256k1 scalar.
    #[error("invalid {role} secret key: {detail}")]
    Key {
        /// Which key failed to parse (`ethereum` / `bitcoin`).
        role: &'static str,
        /// The underlying parse error.
        detail: String,
    },
}

/// In-memory software signer implementing [`HsmDigestSigner`]. Holds one
/// Ethereum (Set-B) key and one Bitcoin (Set-A) key. DEV / TESTNET ONLY —
/// see the module docs for the three-way gate.
pub struct SoftwareHsm {
    secp: Secp256k1<All>,
    btc_sk: SecretKey,
    eth_sk: SigningKey,
    eth_address: Address,
}

impl std::fmt::Debug for SoftwareHsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material — only the public Ethereum address.
        f.debug_struct("SoftwareHsm")
            .field("eth_address", &self.eth_address)
            .finish_non_exhaustive()
    }
}

/// True only when the loud opt-out env var is exactly `1`.
#[must_use]
fn software_keys_allowed() -> bool {
    std::env::var(SOFTWARE_KEYS_ENV).as_deref() == Ok("1")
}

impl SoftwareHsm {
    /// Construct from raw 32-byte Ethereum (Set-B) and Bitcoin (Set-A)
    /// secret keys. Fails closed unless `XINDEX_ALLOW_SOFTWARE_KEYS=1`.
    ///
    /// # Errors
    /// [`SoftHsmError::NotAllowed`] if the opt-out is unset;
    /// [`SoftHsmError::Key`] if either scalar is invalid.
    pub fn new(eth_sk: [u8; 32], btc_sk: [u8; 32]) -> Result<Self, SoftHsmError> {
        Self::new_gated(eth_sk, btc_sk, software_keys_allowed())
    }

    /// Gate decision injected so the fail-closed path is testable without
    /// touching process-global env state; [`Self::new`] sources `allowed`
    /// from [`software_keys_allowed`].
    fn new_gated(eth_sk: [u8; 32], btc_sk: [u8; 32], allowed: bool) -> Result<Self, SoftHsmError> {
        if !allowed {
            return Err(SoftHsmError::NotAllowed);
        }
        let eth_sk = SigningKey::from_slice(&eth_sk).map_err(|e| SoftHsmError::Key {
            role: "ethereum",
            detail: e.to_string(),
        })?;
        let btc_sk = SecretKey::from_slice(&btc_sk).map_err(|e| SoftHsmError::Key {
            role: "bitcoin",
            detail: e.to_string(),
        })?;
        let eth_address = k256_eoa_address(&eth_sk);
        tracing::warn!(
            eth_address = %eth_address,
            "SOFTWARE-KEY HSM ENABLED — signing keys live in process memory; \
             dev/testnet rehearsal ONLY, NEVER production"
        );
        Ok(Self {
            secp: Secp256k1::new(),
            btc_sk,
            eth_sk,
            eth_address,
        })
    }

    /// The Ethereum (Set-B) signer address derived from the ETH key — the
    /// daemon's `eth_address` and the routing discriminator in
    /// [`HsmDigestSigner::sign_digest`].
    #[must_use]
    pub fn eth_address(&self) -> Address {
        self.eth_address
    }
}

/// Derive the EOA address from a k256 signing key (keccak of the
/// uncompressed public key, low 20 bytes) — the standard Ethereum rule.
fn k256_eoa_address(sk: &SigningKey) -> Address {
    let encoded = sk.verifying_key().to_encoded_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}

#[async_trait::async_trait]
impl HsmDigestSigner for SoftwareHsm {
    async fn sign_digest(&self, address: Address, digest: B256) -> Result<[u8; 65], HsmError> {
        if address == self.eth_address {
            // Ethereum (Set-B) EIP-712 path: recoverable low-S ECDSA with
            // v = 27 + recid, identical to the e2e SoftHsm — recovers under
            // alloy's `recover_address_from_prehash`.
            let (sig, recid) = self
                .eth_sk
                .sign_prehash_recoverable(digest.as_slice())
                .map_err(|e| HsmError::Decode(format!("eth sign: {e}")))?;
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(sig.to_bytes().as_ref());
            out[64] = 27 + recid.to_byte();
            Ok(out)
        } else {
            // Bitcoin (Set-A) PSBT path: r ‖ s ‖ 27 (Bitcoin discards v),
            // low-S by construction. `address` is the BTC alias.
            let msg = Message::from_digest(digest.0);
            let sig = self.secp.sign_ecdsa(&msg, &self.btc_sk);
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(&sig.serialize_compact());
            out[64] = 27;
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Arbitrary valid secp256k1 scalars — no special address needed; the
    // recovery test checks against the address derived from the same key.
    const ETH_SK: [u8; 32] = [0x22; 32];
    const BTC_SK: [u8; 32] = [0x11; 32];

    #[test]
    fn construction_fails_closed_without_optout() {
        // The security property: gate off (allowed=false) → refuse. Race-free
        // — the gate decision is injected, not read from process env.
        assert!(matches!(
            SoftwareHsm::new_gated(ETH_SK, BTC_SK, false),
            Err(SoftHsmError::NotAllowed)
        ));
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn eth_path_signature_recovers_to_signer() {
        use alloy_primitives::PrimitiveSignature;
        let hsm = SoftwareHsm::new_gated(ETH_SK, BTC_SK, true).expect("gated on");
        let digest = B256::repeat_byte(0xcd);
        let sig = hsm
            .sign_digest(hsm.eth_address(), digest)
            .await
            .expect("sign");
        let recovered = PrimitiveSignature::try_from(sig.as_slice())
            .expect("65-byte signature")
            .recover_address_from_prehash(&digest)
            .expect("recover");
        assert_eq!(recovered, hsm.eth_address());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn btc_path_returns_v27() {
        let hsm = SoftwareHsm::new_gated(ETH_SK, BTC_SK, true).expect("gated on");
        // Any address other than the ETH signer routes to the BTC key.
        let btc_alias = Address::repeat_byte(0xcc);
        let sig = hsm
            .sign_digest(btc_alias, B256::repeat_byte(0x42))
            .await
            .expect("sign");
        assert_eq!(sig[64], 27, "Bitcoin path returns r‖s‖27");
    }
}
