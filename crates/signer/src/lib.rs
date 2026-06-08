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
pub mod remote;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy_primitives::{Address, B256};
use alloy_sol_types::Eip712Domain;
use thiserror::Error;
use xindex_shared::eip712::{
    attestation_signing_hash, redemption_attestation_signing_hash, refund_attestation_signing_hash,
    streamed_settlement_signing_hash, AsyncLegDeliveryAttestation, AsyncLegRefundAttestation,
    AsyncLegStreamedSettlement, Attestation,
};

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

    /// Sign a typed mint [`Attestation`]. Default impl computes the
    /// EIP-712 digest locally and delegates to [`Self::sign_digest`].
    /// Remote/daemon backends override this to send the typed payload
    /// to the daemon's `/api/v1/sign/eip712-attestation` endpoint —
    /// the daemon computes the digest itself (PART 5 / DL-M5-3: the
    /// daemon never trusts a coordinator-supplied digest).
    ///
    /// # Errors
    /// Forwards any [`SignerError`] from the underlying backend.
    fn sign_attestation_msg(
        &self,
        domain: &Eip712Domain,
        attestation: &Attestation,
    ) -> Result<[u8; 65], SignerError> {
        self.sign_digest(attestation_signing_hash(attestation, domain))
    }

    /// Sign a typed per-leg [`AsyncLegDeliveryAttestation`] (burn → USDT
    /// delivery for one leg of a multi-leg redemption). Default impl =
    /// digest-then-`sign_digest`; remote daemons override.
    ///
    /// # Errors
    /// Forwards any [`SignerError`].
    fn sign_redemption_attestation_msg(
        &self,
        domain: &Eip712Domain,
        attestation: &AsyncLegDeliveryAttestation,
    ) -> Result<[u8; 65], SignerError> {
        self.sign_digest(redemption_attestation_signing_hash(attestation, domain))
    }

    /// Sign a typed per-leg [`AsyncLegRefundAttestation`] (burn → native
    /// asset refund for one leg of a multi-leg redemption). Default impl
    /// = digest-then-`sign_digest`; remote daemons override.
    ///
    /// # Errors
    /// Forwards any [`SignerError`].
    fn sign_refund_attestation_msg(
        &self,
        domain: &Eip712Domain,
        attestation: &AsyncLegRefundAttestation,
    ) -> Result<[u8; 65], SignerError> {
        self.sign_digest(refund_attestation_signing_hash(attestation, domain))
    }

    /// Sign a typed per-leg [`AsyncLegStreamedSettlement`] (re-audit-gated
    /// burn-side streaming: a partially-filled redeem swap that delivered
    /// USDT AND refunded native on one leg). FOURTH distinct typehash.
    /// Default impl = digest-then-`sign_digest`; remote daemons override.
    ///
    /// # Errors
    /// Forwards any [`SignerError`].
    fn sign_streamed_settlement_msg(
        &self,
        domain: &Eip712Domain,
        attestation: &AsyncLegStreamedSettlement,
    ) -> Result<[u8; 65], SignerError> {
        self.sign_digest(streamed_settlement_signing_hash(attestation, domain))
    }
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
    // Delegates to the trait method so remote/daemon backends can
    // override to send the typed payload over HTTP. Software backends
    // keep the digest-then-sign default.
    backend.sign_attestation_msg(domain, attestation)
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

/// Sign a per-leg `AsyncLegDeliveryAttestation` (burn → USDT delivery
/// for one leg). Separate typehash ⇒ a mint signature can never satisfy
/// `attestRedemption`.
///
/// # Errors
/// Forwards any [`SignerError`] from the backend.
pub fn sign_redemption_attestation<H: HsmBackend>(
    backend: &H,
    domain: &Eip712Domain,
    attestation: &AsyncLegDeliveryAttestation,
) -> Result<[u8; 65], SignerError> {
    backend.sign_redemption_attestation_msg(domain, attestation)
}

/// Aggregate k-of-n signatures for an `AsyncLegDeliveryAttestation` →
/// `AttestationOracle.attestRedemption`'s `signatures: bytes[]`.
///
/// # Errors
/// Forwards the first [`SignerError`]; stops on first failure.
pub fn aggregate_redemption_signatures<H: HsmBackend>(
    backends: &[&H],
    domain: &Eip712Domain,
    attestation: &AsyncLegDeliveryAttestation,
) -> Result<Vec<Vec<u8>>, SignerError> {
    let mut sigs = Vec::with_capacity(backends.len());
    for b in backends {
        sigs.push(sign_redemption_attestation(*b, domain, attestation)?.to_vec());
    }
    Ok(sigs)
}

/// Sign a per-leg `AsyncLegRefundAttestation` (burn → native asset
/// refund for one leg). Third separate typehash; mutually exclusive with
/// the delivery path on-chain (per-leg mutex).
///
/// # Errors
/// Forwards any [`SignerError`] from the backend.
pub fn sign_refund_attestation<H: HsmBackend>(
    backend: &H,
    domain: &Eip712Domain,
    attestation: &AsyncLegRefundAttestation,
) -> Result<[u8; 65], SignerError> {
    backend.sign_refund_attestation_msg(domain, attestation)
}

/// Aggregate k-of-n signatures for an `AsyncLegRefundAttestation` →
/// `AttestationOracle.attestRefund`'s `signatures: bytes[]`.
///
/// # Errors
/// Forwards the first [`SignerError`]; stops on first failure.
pub fn aggregate_refund_signatures<H: HsmBackend>(
    backends: &[&H],
    domain: &Eip712Domain,
    attestation: &AsyncLegRefundAttestation,
) -> Result<Vec<Vec<u8>>, SignerError> {
    let mut sigs = Vec::with_capacity(backends.len());
    for b in backends {
        sigs.push(sign_refund_attestation(*b, domain, attestation)?.to_vec());
    }
    Ok(sigs)
}

/// Sign a per-leg `AsyncLegStreamedSettlement` (re-audit-gated burn-side
/// streaming: a partially-filled redeem swap that delivered USDT AND
/// refunded native on one leg). FOURTH separate typehash.
///
/// # Errors
/// Forwards any [`SignerError`] from the backend.
pub fn sign_streamed_settlement<H: HsmBackend>(
    backend: &H,
    domain: &Eip712Domain,
    attestation: &AsyncLegStreamedSettlement,
) -> Result<[u8; 65], SignerError> {
    backend.sign_streamed_settlement_msg(domain, attestation)
}

/// Aggregate k-of-n signatures for an `AsyncLegStreamedSettlement` →
/// `AttestationOracle.attestStreamedSettlement`'s `signatures: bytes[]`.
///
/// # Errors
/// Forwards the first [`SignerError`]; stops on first failure.
pub fn aggregate_streamed_settlement_signatures<H: HsmBackend>(
    backends: &[&H],
    domain: &Eip712Domain,
    attestation: &AsyncLegStreamedSettlement,
) -> Result<Vec<Vec<u8>>, SignerError> {
    let mut sigs = Vec::with_capacity(backends.len());
    for b in backends {
        sigs.push(sign_streamed_settlement(*b, domain, attestation)?.to_vec());
    }
    Ok(sigs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{PrimitiveSignature, U256};
    use xindex_shared::eip712::{
        attestation, attestation_oracle_domain, redemption_attestation,
        redemption_attestation_signing_hash, refund_attestation, refund_attestation_signing_hash,
        streamed_settlement, streamed_settlement_signing_hash,
    };

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

    /// `sign_attestation` produces a 65-byte signature that recovers
    /// back to the signer's own address — closes the mutation-testing
    /// gap where `Ok([0; 65])` (a zero-signature stub) passed all
    /// existing tests because length and 65-byte checks don't validate
    /// signature correctness. Without this test, a bug in the digest
    /// computation (wrong domain separator, swapped fields) would slip
    /// through every other unit test.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test code: panic on bad fixture is fine"
    )]
    fn sign_attestation_recovers_to_signer_address() {
        let s = SoftwareSigner::from_hex(ANVIL_KEY_0).expect("valid Anvil key");
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = attestation(
            B256::repeat_byte(0xcd),
            U256::from(0u8),
            U256::from(1_000_000u32),
        );

        let sig_bytes = sign_attestation(&s, &domain, &a).expect("sign_attestation");
        let digest = attestation_signing_hash(&a, &domain);
        let sig = PrimitiveSignature::try_from(sig_bytes.as_slice()).expect("65-byte sig");
        let recovered = sig.recover_address_from_prehash(&digest).expect("recover");
        assert_eq!(
            recovered,
            s.signer_address(),
            "sign_attestation output must recover to the signer address"
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

    const ANVIL_KEY_1: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    /// `sign_redemption_attestation` must recover to the signer address
    /// under the SEPARATE redemption typehash digest — closes the
    /// mutation gap where `Ok([0;65])`/`Ok([1;65])` passed (length-only
    /// checks don't validate correctness) and proves the redemption
    /// digest (domain + typehash + fields) is wired correctly so the
    /// on-chain `attestRedemption` `_isSigner` lookup will match.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test code: panic on bad fixture is fine"
    )]
    fn sign_redemption_attestation_recovers_to_signer_address() {
        let s = SoftwareSigner::from_hex(ANVIL_KEY_0).expect("valid Anvil key");
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = redemption_attestation(
            B256::repeat_byte(0xcd),
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(1_000_000u32),
        );

        let sig_bytes = sign_redemption_attestation(&s, &domain, &a).expect("sign");
        let digest = redemption_attestation_signing_hash(&a, &domain);
        let sig = PrimitiveSignature::try_from(sig_bytes.as_slice()).expect("65-byte sig");
        let recovered = sig.recover_address_from_prehash(&digest).expect("recover");
        assert_eq!(recovered, s.signer_address());
    }

    /// Same closure for the refund leg (third typehash). A delivery
    /// signature must not satisfy this digest and vice-versa; the
    /// recovery proves the refund digest is independently correct.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test code: panic on bad fixture is fine"
    )]
    fn sign_refund_attestation_recovers_to_signer_address() {
        let s = SoftwareSigner::from_hex(ANVIL_KEY_0).expect("valid Anvil key");
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = refund_attestation(
            B256::repeat_byte(0xef),
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(99_999u32),
        );

        let sig_bytes = sign_refund_attestation(&s, &domain, &a).expect("sign");
        let digest = refund_attestation_signing_hash(&a, &domain);
        let sig = PrimitiveSignature::try_from(sig_bytes.as_slice()).expect("65-byte sig");
        let recovered = sig.recover_address_from_prehash(&digest).expect("recover");
        assert_eq!(recovered, s.signer_address());

        // Cross-typehash negative: a redemption signature over the same
        // ids must NOT recover to the signer under the refund digest.
        let r = redemption_attestation(
            B256::repeat_byte(0xef),
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(99_999u32),
        );
        let r_sig = sign_redemption_attestation(&s, &domain, &r).expect("sign");
        let r_parsed = PrimitiveSignature::try_from(r_sig.as_slice()).expect("65-byte");
        let r_recovered = r_parsed
            .recover_address_from_prehash(&digest)
            .expect("recover");
        assert_ne!(
            r_recovered,
            s.signer_address(),
            "redemption sig must not verify under the refund digest"
        );
    }

    /// Same closure for the combined streamed-settlement leg (fourth
    /// typehash). Proves the streamed digest is independently correct and
    /// that a delivery signature does not satisfy it.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test code: panic on bad fixture is fine"
    )]
    fn sign_streamed_settlement_recovers_to_signer_address() {
        let s = SoftwareSigner::from_hex(ANVIL_KEY_0).expect("valid Anvil key");
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let a = streamed_settlement(
            B256::repeat_byte(0xc0),
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(60_000_000u32),
            U256::from(30_000_000u32),
        );

        let sig_bytes = sign_streamed_settlement(&s, &domain, &a).expect("sign");
        let digest = streamed_settlement_signing_hash(&a, &domain);
        let sig = PrimitiveSignature::try_from(sig_bytes.as_slice()).expect("65-byte sig");
        let recovered = sig.recover_address_from_prehash(&digest).expect("recover");
        assert_eq!(recovered, s.signer_address());

        // Cross-typehash negative: a delivery signature over the same ids
        // must NOT recover to the signer under the streamed digest.
        let r = redemption_attestation(
            B256::repeat_byte(0xc0),
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(60_000_000u32),
        );
        let r_sig = sign_redemption_attestation(&s, &domain, &r).expect("sign");
        let r_parsed = PrimitiveSignature::try_from(r_sig.as_slice()).expect("65-byte");
        let r_recovered = r_parsed
            .recover_address_from_prehash(&digest)
            .expect("recover");
        assert_ne!(
            r_recovered,
            s.signer_address(),
            "delivery sig must not verify under the streamed digest"
        );
    }

    /// `aggregate_redemption_signatures` / `aggregate_refund_signatures`
    /// produce N order-preserving signatures that each recover to the
    /// matching signer — closes the `Ok(vec![..])` aggregation mutants
    /// (empty / single / wrong-content stubs that length checks miss).
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test code: panic on bad fixture is fine"
    )]
    fn aggregate_redemption_and_refund_recover_in_order() {
        let s0 = SoftwareSigner::from_hex(ANVIL_KEY_0).expect("k0");
        let s1 = SoftwareSigner::from_hex(ANVIL_KEY_1).expect("k1");
        let domain = attestation_oracle_domain(31337, Address::repeat_byte(0xab));
        let backends: Vec<&SoftwareSigner> = vec![&s0, &s1];

        let red = redemption_attestation(
            B256::repeat_byte(0x11),
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(7u32),
        );
        let red_d = redemption_attestation_signing_hash(&red, &domain);
        let red_sigs = aggregate_redemption_signatures(&backends, &domain, &red).expect("agg red");
        assert_eq!(red_sigs.len(), 2);
        for (i, b) in [&s0, &s1].iter().enumerate() {
            let sig = PrimitiveSignature::try_from(red_sigs[i].as_slice()).expect("65");
            assert_eq!(
                sig.recover_address_from_prehash(&red_d).expect("rec"),
                b.signer_address(),
                "redemption sig {i} must recover to backend {i} (order preserved)"
            );
        }

        let refu = refund_attestation(
            B256::repeat_byte(0x22),
            U256::ZERO,
            B256::repeat_byte(0xa1),
            U256::from(8u32),
        );
        let refu_d = refund_attestation_signing_hash(&refu, &domain);
        let refu_sigs = aggregate_refund_signatures(&backends, &domain, &refu).expect("agg ref");
        assert_eq!(refu_sigs.len(), 2);
        for (i, b) in [&s0, &s1].iter().enumerate() {
            let sig = PrimitiveSignature::try_from(refu_sigs[i].as_slice()).expect("65");
            assert_eq!(
                sig.recover_address_from_prehash(&refu_d).expect("rec"),
                b.signer_address(),
                "refund sig {i} must recover to backend {i} (order preserved)"
            );
        }
    }
}
