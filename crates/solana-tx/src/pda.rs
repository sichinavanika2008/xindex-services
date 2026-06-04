//! Program-derived address (PDA) derivation.
//!
//! A PDA is `SHA-256(seed_0 ‖ … ‖ seed_n ‖ program_id ‖
//! "ProgramDerivedAddress")` that lands **off** the ed25519 curve (so no
//! private key can sign for it — only the owning program, via
//! `invoke_signed`). `find_program_address` walks a one-byte "bump" seed
//! from 255 down until the hash is off-curve.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

use crate::{Pubkey, SolanaTxError};

/// The domain-separation marker hashed last in every PDA preimage.
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// True if `bytes` is a valid compressed ed25519 (Edwards) point — i.e. a
/// real, key-addressable account. A PDA must NOT be on the curve.
#[must_use]
pub fn is_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// Derive a PDA for an explicit seed set (the caller supplies the bump as
/// the final seed). Returns `None` if the derived address is on the curve
/// (an invalid PDA for these exact seeds).
#[must_use]
pub fn create_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<Pubkey> {
    let mut h = Sha256::new();
    for seed in seeds {
        h.update(seed);
    }
    h.update(program_id.as_bytes());
    h.update(PDA_MARKER);
    let hash: [u8; 32] = h.finalize().into();
    if is_on_curve(&hash) {
        None
    } else {
        Some(Pubkey::new(hash))
    }
}

/// Find the canonical PDA + bump for `seeds`: the highest bump in
/// `255..=0` whose derived address is off-curve.
///
/// # Errors
/// Returns [`SolanaTxError::PdaNotFound`] if no bump yields an off-curve
/// address (cryptographically negligible).
pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: &Pubkey,
) -> Result<(Pubkey, u8), SolanaTxError> {
    let mut bump: u8 = 255;
    loop {
        let bump_seed = [bump];
        let mut with_bump: Vec<&[u8]> = Vec::with_capacity(seeds.len() + 1);
        with_bump.extend_from_slice(seeds);
        with_bump.push(&bump_seed);
        if let Some(pda) = create_program_address(&with_bump, program_id) {
            return Ok((pda, bump));
        }
        if bump == 0 {
            return Err(SolanaTxError::PdaNotFound);
        }
        bump -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigs;

    #[test]
    fn real_pubkey_is_on_curve() {
        // Any ed25519 public key is, by construction, a valid curve point.
        let pk = sigs::pubkey_from_seed(&[3u8; 32]);
        assert!(is_on_curve(pk.as_bytes()));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn pda_is_off_curve_and_reproducible() {
        let program =
            Pubkey::from_base58("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf").expect("program id");
        let (pda, bump) =
            find_program_address(&[b"multisig", b"vault", &[0u8]], &program).expect("pda");
        // The derived address must be off the curve.
        assert!(!is_on_curve(pda.as_bytes()));
        // Re-deriving with the discovered bump reproduces the same address.
        let again = create_program_address(&[b"multisig", b"vault", &[0u8], &[bump]], &program)
            .expect("reproduce");
        assert_eq!(again, pda);
    }
}
