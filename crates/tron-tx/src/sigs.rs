//! secp256k1 RECOVERABLE signing + the weight-threshold aggregation.
//!
//! TRON signatures are 65-byte recoverable ECDSA (`r ‖ s ‖ v`, v = the raw
//! recovery id 0/1, go-ethereum style) over the 32-byte `txID`. The node
//! validates a multisig tx by recovering each `signature[]` entry to its
//! signer address, looking the address up in the account's `Active`
//! `Permission`, and summing weights until the threshold is met. We mirror
//! that exactly: [`recover_evm20`] recovers the 20-byte signer address and
//! [`aggregate_verified`] enforces membership + no-duplicates + threshold.
//!
//! Unlike XRP (per-signer blob → per-signer digest) every TRON member
//! signs the IDENTICAL `txID`, so the partials are interchangeable and we
//! only need recovery (not a per-signer re-derivation).

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

use crate::{TronMultisig, TronTxError};

/// Normalize a recovery byte to the 0/1 form `RecoveryId` expects.
///
/// Accepts the raw recovery id (0/1, our own + go-ethereum output) and the
/// EVM `v` convention (27/28, what an HSM frontend may emit). Rejects the
/// EIP-155 range — a custody signature is never EIP-155-encoded.
fn normalize_recid(v: u8) -> Result<u8, TronTxError> {
    match v {
        0 | 1 => Ok(v),
        27 | 28 => Ok(v - 27),
        _ => Err(TronTxError::BadSignature),
    }
}

/// Recover the 20-byte EVM-style signer address from a `txID` + a 65-byte
/// recoverable signature.
///
/// # Errors
/// [`TronTxError::BadSignature`] if the signature does not parse, the
/// recovery id is out of range, or recovery fails.
pub fn recover_evm20(txid: &[u8; 32], sig65: &[u8; 65]) -> Result<[u8; 20], TronTxError> {
    let sig = Signature::from_slice(&sig65[..64]).map_err(|_| TronTxError::BadSignature)?;
    let recid =
        RecoveryId::from_byte(normalize_recid(sig65[64])?).ok_or(TronTxError::BadSignature)?;
    let vk = VerifyingKey::recover_from_prehash(txid, &sig, recid)
        .map_err(|_| TronTxError::BadSignature)?;
    let comp = vk.to_encoded_point(true);
    let mut pk = [0u8; 33];
    pk.copy_from_slice(comp.as_bytes());
    crate::addr::evm_address(&pk)
}

/// Recoverable-sign a `txID` with a secp256k1 key, returning the TRON
/// 65-byte `r ‖ s ‖ v` form (v = recovery id 0/1, low-S normalized by
/// k256). The custody path signs in the HSM; this is the test / dev /
/// ceremony helper (the analogue of `xrp-tx`'s `der_low_s`).
///
/// # Errors
/// [`TronTxError::SignFailed`] if deterministic signing fails.
pub fn sign_recoverable(sk: &SigningKey, txid: &[u8; 32]) -> Result<[u8; 65], TronTxError> {
    let (sig, recid) = sk
        .sign_prehash_recoverable(txid)
        .map_err(|_| TronTxError::SignFailed)?;
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = recid.to_byte();
    Ok(out)
}

/// Recover + verify every partial against the descriptor: each must
/// recover to a distinct permission member; the summed member weight must
/// reach the threshold. Returns the signatures **sorted by signer address
/// ascending** — the deterministic `signature[]` assembly order.
///
/// # Errors
/// [`TronTxError`] if a signature fails to recover, recovers to a
/// non-member, two recover to the same member, or the summed weight does
/// not reach the threshold.
pub fn aggregate_verified(
    descriptor: &TronMultisig,
    txid: &[u8; 32],
    sigs: &[[u8; 65]],
) -> Result<Vec<[u8; 65]>, TronTxError> {
    let mut chosen: Vec<([u8; 20], [u8; 65])> = Vec::with_capacity(sigs.len());
    let mut weight: u64 = 0;
    for sig in sigs {
        let addr = recover_evm20(txid, sig)?;
        let member = descriptor
            .member_by_address(&addr)
            .ok_or(TronTxError::NotAMember)?;
        if chosen.iter().any(|(a, _)| *a == addr) {
            return Err(TronTxError::DuplicateSigner);
        }
        weight += member.weight;
        chosen.push((addr, *sig));
    }
    if weight < descriptor.threshold() {
        return Err(TronTxError::ThresholdNotMet {
            got: weight,
            need: descriptor.threshold(),
        });
    }
    chosen.sort_by_key(|x| x.0);
    Ok(chosen.into_iter().map(|(_, s)| s).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> (SigningKey, [u8; 33]) {
        #[expect(clippy::expect_used, reason = "test code")]
        let sk = SigningKey::from_slice(&[seed; 32]).expect("key");
        let ep = sk.verifying_key().to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(ep.as_bytes());
        (sk, pk)
    }

    /// Sign → recover round-trips to the signer's own address.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn sign_recover_round_trip() {
        let (sk, pk) = key(7);
        let txid = [0x42u8; 32];
        let sig = sign_recoverable(&sk, &txid).expect("sign");
        let recovered = recover_evm20(&txid, &sig).expect("recover");
        assert_eq!(recovered, crate::addr::evm_address(&pk).expect("addr"));
        // Wrong digest recovers a DIFFERENT address (not the signer).
        let other = recover_evm20(&[0x43u8; 32], &sig).expect("recover other");
        assert_ne!(other, recovered);
    }

    /// `v = 27` (EVM convention) is accepted and recovers the same address
    /// as `v = 0`.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn accepts_evm_v_convention() {
        let (sk, _pk) = key(5);
        let txid = [0x11u8; 32];
        let mut sig = sign_recoverable(&sk, &txid).expect("sign");
        let base = recover_evm20(&txid, &sig).expect("recover");
        if sig[64] == 0 {
            sig[64] = 27;
        } else {
            sig[64] = 28;
        }
        assert_eq!(recover_evm20(&txid, &sig).expect("recover v27"), base);
    }

    /// 3-of-5: three valid partials reach the threshold and are returned
    /// address-sorted regardless of input order.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn aggregate_reaches_threshold_and_sorts() {
        let keys: Vec<(SigningKey, [u8; 33])> = (1..=5).map(key).collect();
        let ms = TronMultisig::new(3, 2, keys.iter().map(|(_, pk)| (*pk, 1u64)).collect())
            .expect("descriptor");
        let txid = [0x99u8; 32];
        // Members 0,1,2 sign; pass them out of order.
        let sigs: Vec<[u8; 65]> = [2usize, 0, 1]
            .iter()
            .map(|&i| sign_recoverable(&keys[i].0, &txid).expect("sign"))
            .collect();
        let agg = aggregate_verified(&ms, &txid, &sigs).expect("aggregate");
        assert_eq!(agg.len(), 3);
        // Sorted by recovered address ascending.
        let addrs: Vec<[u8; 20]> = agg
            .iter()
            .map(|s| recover_evm20(&txid, s).expect("recover"))
            .collect();
        let mut sorted = addrs.clone();
        sorted.sort_unstable();
        assert_eq!(addrs, sorted);
    }

    /// Sub-threshold, non-member, and duplicate-signer all reject.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn aggregate_rejects_subthreshold_nonmember_and_duplicate() {
        let keys: Vec<(SigningKey, [u8; 33])> = (1..=5).map(key).collect();
        let ms = TronMultisig::new(3, 2, keys.iter().map(|(_, pk)| (*pk, 1u64)).collect())
            .expect("descriptor");
        let txid = [0x77u8; 32];

        // Only two members → below the threshold of 3.
        let two: Vec<[u8; 65]> = [0usize, 1]
            .iter()
            .map(|&i| sign_recoverable(&keys[i].0, &txid).expect("sign"))
            .collect();
        assert_eq!(
            aggregate_verified(&ms, &txid, &two),
            Err(TronTxError::ThresholdNotMet { got: 2, need: 3 })
        );

        // Non-member (a 6th key not in the permission).
        let (outsider, _) = key(8);
        let mut with_outsider = two.clone();
        with_outsider.push(sign_recoverable(&outsider, &txid).expect("sign"));
        assert_eq!(
            aggregate_verified(&ms, &txid, &with_outsider),
            Err(TronTxError::NotAMember)
        );

        // Duplicate signer (member 0 twice + member 1).
        let dup = vec![
            sign_recoverable(&keys[0].0, &txid).expect("sign"),
            sign_recoverable(&keys[0].0, &txid).expect("sign"),
            sign_recoverable(&keys[1].0, &txid).expect("sign"),
        ];
        assert_eq!(
            aggregate_verified(&ms, &txid, &dup),
            Err(TronTxError::DuplicateSigner)
        );
    }
}
