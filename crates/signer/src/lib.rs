//! `xindex-signer` — k-of-n attestation signer.
//!
//! Provides:
//! - [`HsmBackend`] trait abstracting the key-storage backend.
//! - [`SoftwareSigner`] implementation backed by an in-memory secp256k1
//!   private key (for local development + Anvil end-to-end tests). Production
//!   path lands in M5 with a `YubiHSM2` backend implementing the same trait.
//! - [`aggregate_signatures`] helper that aggregates k-of-n signatures
//!   across multiple backends and produces the `signatures: bytes[]`
//!   argument `AttestationOracle.attest` expects.
//! - [`crosscheck`] module — production policy that REQUIRES both `THORChain`
//!   outbound observation AND a confirmed Bitcoin UTXO at our multisig
//!   before signing. The signer's #1 trust surface; never sign without it.

pub mod crosscheck;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy_primitives::{Address, B256};
use alloy_sol_types::Eip712Domain;
use thiserror::Error;
use xindex_shared::eip712::{attestation_signing_hash, Attestation};

/// Errors surfaced by signer operations. Concrete enough that callers
/// can distinguish "wrong key for this signer" from "transport failure"
/// without parsing strings.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The backend rejected the signing request (invalid input, locked
    /// HSM, network failure to a remote signer, etc.).
    #[error("backend signing failure: {0}")]
    Backend(String),
    /// The provided key material was malformed.
    #[error("invalid key material: {0}")]
    InvalidKey(String),
}

/// Abstraction over the key-storage backend. Implementations must produce
/// a 65-byte ECDSA signature (`r ‖ s ‖ v`, where `v ∈ {27, 28}`) over an
/// arbitrary 32-byte digest.
///
/// The on-chain `AttestationOracle.attest` accepts exactly this byte
/// layout (see `~/refs/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol`
/// `recover(bytes memory signature)` branch with `length == 65`).
pub trait HsmBackend {
    /// Address corresponding to this backend's key. Must match
    /// `_isSigner[recovered]` on `AttestationOracle` for the produced
    /// signatures to count toward the k-of-n threshold.
    fn signer_address(&self) -> Address;

    /// Sign a 32-byte digest, returning a 65-byte `r ‖ s ‖ v` payload.
    /// `v` MUST be `27` or `28` (Ethereum's pre-EIP-155 convention) for
    /// the on-chain ECDSA library to accept it.
    ///
    /// # Errors
    /// Returns [`SignerError::Backend`] if the backend rejects the
    /// signing request (locked HSM, transport failure, etc.).
    fn sign_digest(&self, digest: B256) -> Result<[u8; 65], SignerError>;
}

/// Software-backed [`HsmBackend`] holding a raw secp256k1 private key in
/// process memory.
///
/// # ⚠ DEV / TEST USE ONLY — NEVER FOR PRODUCTION FUNDS
///
/// The private key sits in regular Rust heap memory and is **not zeroized
/// on drop**. After the process exits the bytes can persist in:
/// - swap files (if the page was paged out)
/// - core dumps (if the process crashes)
/// - heap snapshots (debugger or memory profiler attached)
/// - sibling-process address-space scrapes (compromised host)
///
/// Production keys MUST live inside a `YubiHSM2` (or equivalent HSM)
/// implementing [`HsmBackend`]; the key never enters this process's
/// address space. That backend lands in M5.
///
/// Acceptable callers today:
/// - Local Anvil end-to-end tests (`xindex-attest` driving a 31337 chain)
/// - The signature round-trip property test
///
/// Unacceptable:
/// - Sepolia / mainnet / any chain holding real value
/// - CI environments where the key file is committed
pub struct SoftwareSigner {
    inner: PrivateKeySigner,
}

impl std::fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareSigner")
            .field("address", &self.inner.address())
            .finish_non_exhaustive()
    }
}

impl SoftwareSigner {
    /// Construct from a hex-encoded private key (`0x`-prefix optional).
    /// Typical inputs: Anvil's deterministic accounts, `cast wallet new`
    /// raw output.
    ///
    /// # Errors
    /// Returns [`SignerError::InvalidKey`] if the hex string does not
    /// decode to exactly 32 bytes or is not a valid secp256k1 scalar.
    /// The error message is intentionally generic — we never echo the
    /// caller's input back into a log to avoid leaking partial key bytes
    /// from a malformed-but-recoverable hex string.
    pub fn from_hex(hex: &str) -> Result<Self, SignerError> {
        let inner: PrivateKeySigner =
            hex.parse()
                .map_err(|_: alloy::signers::local::LocalSignerError| {
                    SignerError::InvalidKey("invalid private key hex".to_string())
                })?;
        Ok(Self { inner })
    }
}

impl HsmBackend for SoftwareSigner {
    fn signer_address(&self) -> Address {
        self.inner.address()
    }

    fn sign_digest(&self, digest: B256) -> Result<[u8; 65], SignerError> {
        let sig = self
            .inner
            .sign_hash_sync(&digest)
            .map_err(|e| SignerError::Backend(e.to_string()))?;
        Ok(sig.as_bytes())
    }
}

/// Compute the EIP-712 attestation digest and dispatch the sign call to
/// `backend`. Convenience wrapper for `xindex-attest` and tests.
///
/// # Errors
/// Forwards any [`SignerError`] from the backend.
pub fn sign_attestation<H: HsmBackend>(
    backend: &H,
    domain: &Eip712Domain,
    attestation: &Attestation,
) -> Result<[u8; 65], SignerError> {
    let digest = attestation_signing_hash(attestation, domain);
    backend.sign_digest(digest)
}

/// Aggregates signatures from N backends, returning the
/// `Vec<Vec<u8>>` payload `AttestationOracle.attest` expects in its
/// `signatures: bytes[]` argument.
///
/// # Errors
/// Forwards the first [`SignerError`] encountered. Stops on first failure
/// (no partial aggregation).
pub fn aggregate_signatures<H: HsmBackend>(
    backends: &[&H],
    domain: &Eip712Domain,
    attestation: &Attestation,
) -> Result<Vec<Vec<u8>>, SignerError> {
    let mut sigs = Vec::with_capacity(backends.len());
    for b in backends {
        let sig = sign_attestation(*b, domain, attestation)?;
        sigs.push(sig.to_vec());
    }
    Ok(sigs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{PrimitiveSignature, U256};
    use xindex_shared::eip712::{attestation, attestation_oracle_domain};

    /// Anvil's first deterministic private key (account 0).
    const ANVIL_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    /// The address derived from `ANVIL_KEY_0`. Captured from
    /// `cast wallet address --private-key 0xac0974…`.
    const ANVIL_ADDR_0: Address = Address::new([
        0xf3, 0x9f, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xf6, 0xf4, 0xce, 0x6a, 0xb8, 0x82, 0x72, 0x79,
        0xcf, 0xff, 0xb9, 0x22, 0x66,
    ]);

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test code: panic on bad fixture is fine"
    )]
    fn software_signer_address_matches_anvil() {
        let s = SoftwareSigner::from_hex(ANVIL_KEY_0).expect("valid Anvil key");
        assert_eq!(s.signer_address(), ANVIL_ADDR_0);
    }

    /// Signature round-trip: sign an attestation digest in Rust, then
    /// recover the signer address using the same secp256k1 math
    /// `AttestationOracle.attest` runs (`ECDSA.recover` → `ecrecover`).
    /// If this passes, the on-chain `_isSigner[recovered]` lookup will
    /// match for any properly-registered software signer.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test code: panic on bad fixture is fine"
    )]
    fn signature_recovers_to_signer_address() {
        let s = SoftwareSigner::from_hex(ANVIL_KEY_0).expect("valid Anvil key");
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = attestation(
            B256::repeat_byte(0xcd),
            U256::from(0u8),
            U256::from(1_000_000u32),
        );
        let digest = attestation_signing_hash(&a, &domain);

        let sig_bytes = s.sign_digest(digest).expect("sign");
        // Parse the 65-byte payload via alloy's primitive signature, which
        // uses the exact same recovery convention as Solidity ECDSA.
        let sig = PrimitiveSignature::try_from(sig_bytes.as_slice()).expect("65-byte sig");
        let recovered = sig.recover_address_from_prehash(&digest).expect("recover");
        assert_eq!(
            recovered,
            s.signer_address(),
            "recovered address must match signer's own address"
        );
    }

    /// `aggregate_signatures` produces N 65-byte payloads in input order.
    /// The on-chain `attest` loop iterates the array and checks each is
    /// 65 bytes (`AttestationOracle.sol:113`); anything else reverts.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test code: panic on bad fixture is fine"
    )]
    fn aggregate_produces_well_formed_signatures() {
        const ANVIL_KEY_1: &str =
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
        let s0 = SoftwareSigner::from_hex(ANVIL_KEY_0).expect("k0");
        let s1 = SoftwareSigner::from_hex(ANVIL_KEY_1).expect("k1");
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = attestation(
            B256::repeat_byte(0xcd),
            U256::from(0u8),
            U256::from(1_000_000u32),
        );

        let backends: Vec<&SoftwareSigner> = vec![&s0, &s1];
        let sigs = aggregate_signatures(&backends, &domain, &a).expect("aggregate");
        assert_eq!(sigs.len(), 2);
        for (i, sig) in sigs.iter().enumerate() {
            assert_eq!(sig.len(), 65, "signature {i} must be 65 bytes");
        }
    }
}
