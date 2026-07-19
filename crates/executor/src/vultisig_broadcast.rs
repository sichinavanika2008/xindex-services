//! Key-free write-ahead preparation for a future Vultisig Bitcoin broadcaster.
//!
//! This module deliberately stops before any irreversible network action. It
//! consumes the non-forgeable [`VultisigBitcoinEvidence`] capability, repeats
//! the exact Testnet4/canonical-byte/txid/wtxid checks at the executor boundary,
//! requires a write-ahead sink to accept the complete evidence and bytes, and
//! returns an opaque, non-cloneable preparation capability.
//!
//! It is **not** a broadcaster, mandatory runtime wiring, or production
//! approval. In particular, it does not yet bind an authenticated Testnet4
//! broadcast endpoint, prove durable sink behavior, submit bytes, reconcile an
//! ambiguous submission, or recover after process failure. A later broadcaster
//! must consume [`PreparedVultisigBitcoinBroadcast`] and close those boundaries
//! without reintroducing a raw-transaction path.
//!
//! The legacy P2WSH executor remains separate. Vultisig custody is aggregate-key
//! P2WPKH, and a legacy transaction, PSBT, or byte buffer cannot be converted
//! into the capability accepted here.

use std::error::Error;
use std::fmt;

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::{Transaction, Txid, Wtxid};
use xindex_vultisig_adapter::{VultisigBitcoinEvidence, VultisigBitcoinEvidenceRecord};

/// Required synchronous write-ahead boundary for Vultisig evidence.
///
/// Implementations are part of the trusted computing base. They must atomically
/// and durably persist both arguments before returning `Ok(())`. The record's
/// `evidence_id_sha256` is the idempotency key: retrying identical evidence and
/// bytes must succeed without creating a second logical operation, while the
/// same evidence ID paired with different content or bytes must fail closed.
///
/// This trait cannot itself prove that an implementation flushed durable state.
/// No in-memory or optional fallback is supplied by this module.
pub trait VultisigEvidenceWriteAheadSink: Send + Sync {
    /// Storage error surfaced without discarding the original evidence.
    type Error: Error + Send + Sync + 'static;

    /// Persist the complete record and exact canonical transaction bytes.
    ///
    /// # Errors
    /// Returns an error unless the idempotent durable write has completed.
    fn persist_before_broadcast(
        &self,
        record: &VultisigBitcoinEvidenceRecord,
        exact_transaction_bytes: &[u8],
    ) -> Result<(), Self::Error>;
}

/// Opaque evidence capability that passed executor-side validation and the
/// configured write-ahead boundary.
///
/// This type is intentionally non-cloneable, exposes no transaction bytes, and
/// has no public constructor. It does not prove that a durable sink conformed to
/// its contract and does not represent a broadcast, mempool acceptance,
/// confirmation, settlement, or finality.
///
/// ```compile_fail
/// use xindex_executor::PreparedVultisigBitcoinBroadcast;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PreparedVultisigBitcoinBroadcast>();
/// ```
///
/// ```compile_fail
/// use xindex_executor::PreparedVultisigBitcoinBroadcast;
///
/// fn cannot_extract_bytes(prepared: &PreparedVultisigBitcoinBroadcast) {
///     let _ = &prepared.evidence;
/// }
/// ```
///
/// ```compile_fail
/// use std::fmt::Debug;
/// use xindex_executor::PreparedVultisigBitcoinBroadcast;
///
/// fn requires_debug<T: Debug>() {}
/// requires_debug::<PreparedVultisigBitcoinBroadcast>();
/// ```
#[expect(
    missing_debug_implementations,
    reason = "Debug would expose the nested signed transaction bytes and bypass this opaque capability"
)]
pub struct PreparedVultisigBitcoinBroadcast {
    evidence: Box<VultisigBitcoinEvidence>,
    txid: Txid,
    wtxid: Wtxid,
    evidence_id: [u8; 32],
}

impl PreparedVultisigBitcoinBroadcast {
    /// Exact Testnet4 chain identity carried by the validated evidence.
    #[must_use]
    pub const fn chain_hash(&self) -> ChainHash {
        self.evidence.chain_hash()
    }

    /// Locally recomputed transaction ID.
    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.txid
    }

    /// Locally recomputed witness transaction ID.
    #[must_use]
    pub const fn wtxid(&self) -> Wtxid {
        self.wtxid
    }

    /// Domain-separated content identity of the write-ahead evidence record.
    #[must_use]
    pub const fn evidence_id(&self) -> [u8; 32] {
        self.evidence_id
    }
}

/// Fail-closed reason for refusing Vultisig broadcast preparation.
#[derive(Debug)]
pub enum VultisigBroadcastPreparationError<E> {
    /// The evidence did not carry the exact Bitcoin Testnet4 genesis hash.
    WrongChain {
        /// Chain hash carried by the evidence.
        actual: ChainHash,
    },
    /// Exact evidence bytes were not one complete consensus transaction.
    Decode {
        /// Decoder detail for operator diagnosis.
        message: String,
    },
    /// Decoding and consensus re-encoding did not reproduce the exact bytes.
    NonCanonicalEncoding,
    /// The locally recomputed non-witness transaction ID differed from evidence.
    TxidMismatch {
        /// Transaction ID committed by the evidence.
        expected: Txid,
        /// Transaction ID recomputed from the exact bytes.
        actual: Txid,
    },
    /// The locally recomputed witness transaction ID differed from evidence.
    WtxidMismatch {
        /// Witness transaction ID committed by the evidence.
        expected: Wtxid,
        /// Witness transaction ID recomputed from the exact bytes.
        actual: Wtxid,
    },
    /// The required write-ahead sink failed.
    Persistence(E),
}

impl<E: fmt::Display> fmt::Display for VultisigBroadcastPreparationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongChain { actual } => write!(
                formatter,
                "Vultisig Bitcoin preparation requires Testnet4 chain hash {}, found {actual}",
                ChainHash::TESTNET4
            ),
            Self::Decode { message } => {
                write!(
                    formatter,
                    "Vultisig Bitcoin transaction decode failed: {message}"
                )
            }
            Self::NonCanonicalEncoding => formatter.write_str(
                "Vultisig Bitcoin transaction bytes are not canonical consensus encoding",
            ),
            Self::TxidMismatch { expected, actual } => write!(
                formatter,
                "Vultisig evidence txid mismatch: expected {expected}, recomputed {actual}"
            ),
            Self::WtxidMismatch { expected, actual } => write!(
                formatter,
                "Vultisig evidence wtxid mismatch: expected {expected}, recomputed {actual}"
            ),
            Self::Persistence(error) => write!(
                formatter,
                "Vultisig evidence write-ahead persistence failed: {error}"
            ),
        }
    }
}

impl<E: Error + 'static> Error for VultisigBroadcastPreparationError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Persistence(error) => Some(error),
            Self::WrongChain { .. }
            | Self::Decode { .. }
            | Self::NonCanonicalEncoding
            | Self::TxidMismatch { .. }
            | Self::WtxidMismatch { .. } => None,
        }
    }
}

/// A preparation failure that retains the original evidence capability.
///
/// Ordinary returned errors preserve the evidence. Panics, aborts, hangs, and
/// process or host failure are outside this in-memory guarantee and require the
/// future durable recovery state machine.
pub struct VultisigBroadcastPreparationFailure<E> {
    evidence: Box<VultisigBitcoinEvidence>,
    error: VultisigBroadcastPreparationError<E>,
}

impl<E: fmt::Debug> fmt::Debug for VultisigBroadcastPreparationFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VultisigBroadcastPreparationFailure")
            .field("evidence", &"<redacted>")
            .field("error", &self.error)
            .finish()
    }
}

impl<E> VultisigBroadcastPreparationFailure<E> {
    /// Borrow the original, non-cloneable evidence capability.
    #[must_use]
    pub fn evidence(&self) -> &VultisigBitcoinEvidence {
        &self.evidence
    }

    /// Inspect the fail-closed reason without surrendering the evidence.
    #[must_use]
    pub const fn error(&self) -> &VultisigBroadcastPreparationError<E> {
        &self.error
    }

    /// Recover ownership of the original evidence for reconciliation or retry.
    #[must_use]
    pub fn into_evidence(self) -> VultisigBitcoinEvidence {
        *self.evidence
    }

    /// Recover both the original evidence and the failure reason.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        VultisigBitcoinEvidence,
        VultisigBroadcastPreparationError<E>,
    ) {
        (*self.evidence, self.error)
    }
}

impl<E: fmt::Display> fmt::Display for VultisigBroadcastPreparationFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl<E: Error + 'static> Error for VultisigBroadcastPreparationFailure<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

struct PreparationCandidate<'a, R> {
    chain_hash: ChainHash,
    transaction_bytes: &'a [u8],
    expected_txid: Txid,
    expected_wtxid: Wtxid,
    evidence_id: [u8; 32],
    record: &'a R,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PreparedIdentities {
    txid: Txid,
    wtxid: Wtxid,
    evidence_id: [u8; 32],
}

/// Consume validated Vultisig evidence and pass it through the configured
/// write-ahead boundary without broadcasting it.
///
/// Validation is repeated locally: exact Testnet4 identity, complete consensus
/// decoding, byte-identical consensus re-encoding, and both transaction IDs
/// must match before the sink is called.
///
/// A bare transaction cannot substitute for the evidence capability:
///
/// ```compile_fail
/// use bitcoin::Transaction;
/// use xindex_executor::{
///     prepare_vultisig_bitcoin_broadcast, VultisigEvidenceWriteAheadSink,
/// };
///
/// fn cannot_prepare_bare_transaction<S>(transaction: Transaction, sink: &S)
/// where
///     S: VultisigEvidenceWriteAheadSink,
/// {
///     let _ = prepare_vultisig_bitcoin_broadcast(transaction, sink);
/// }
/// ```
///
/// # Errors
/// Every ordinary returned error owns the original evidence. No network or
/// broadcast action occurs on either success or failure.
pub fn prepare_vultisig_bitcoin_broadcast<S>(
    evidence: VultisigBitcoinEvidence,
    sink: &S,
) -> Result<PreparedVultisigBitcoinBroadcast, VultisigBroadcastPreparationFailure<S::Error>>
where
    S: VultisigEvidenceWriteAheadSink + ?Sized,
{
    let candidate = PreparationCandidate {
        chain_hash: evidence.chain_hash(),
        transaction_bytes: evidence.transaction_bytes(),
        expected_txid: Txid::from_byte_array(evidence.txid()),
        expected_wtxid: Wtxid::from_byte_array(evidence.wtxid()),
        evidence_id: evidence.record().evidence_id_sha256(),
        record: evidence.record(),
    };
    let result = validate_and_persist(&candidate, |record, exact_bytes| {
        sink.persist_before_broadcast(record, exact_bytes)
    });
    match result {
        Ok(identities) => Ok(PreparedVultisigBitcoinBroadcast {
            evidence: Box::new(evidence),
            txid: identities.txid,
            wtxid: identities.wtxid,
            evidence_id: identities.evidence_id,
        }),
        Err(error) => Err(VultisigBroadcastPreparationFailure {
            evidence: Box::new(evidence),
            error,
        }),
    }
}

fn validate_and_persist<R, P, E>(
    candidate: &PreparationCandidate<'_, R>,
    persist: P,
) -> Result<PreparedIdentities, VultisigBroadcastPreparationError<E>>
where
    P: FnOnce(&R, &[u8]) -> Result<(), E>,
{
    if candidate.chain_hash != ChainHash::TESTNET4 {
        return Err(VultisigBroadcastPreparationError::WrongChain {
            actual: candidate.chain_hash,
        });
    }

    let transaction = deserialize::<Transaction>(candidate.transaction_bytes).map_err(|error| {
        VultisigBroadcastPreparationError::Decode {
            message: error.to_string(),
        }
    })?;
    require_canonical_encoding(candidate.transaction_bytes, &transaction)?;

    let txid = transaction.compute_txid();
    if txid != candidate.expected_txid {
        return Err(VultisigBroadcastPreparationError::TxidMismatch {
            expected: candidate.expected_txid,
            actual: txid,
        });
    }
    let wtxid = transaction.compute_wtxid();
    if wtxid != candidate.expected_wtxid {
        return Err(VultisigBroadcastPreparationError::WtxidMismatch {
            expected: candidate.expected_wtxid,
            actual: wtxid,
        });
    }

    persist(candidate.record, candidate.transaction_bytes)
        .map_err(VultisigBroadcastPreparationError::Persistence)?;

    Ok(PreparedIdentities {
        txid,
        wtxid,
        evidence_id: candidate.evidence_id,
    })
}

fn require_canonical_encoding<E>(
    transaction_bytes: &[u8],
    transaction: &Transaction,
) -> Result<(), VultisigBroadcastPreparationError<E>> {
    if serialize(transaction).as_slice() != transaction_bytes {
        return Err(VultisigBroadcastPreparationError::NonCanonicalEncoding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]

    use std::cell::Cell;

    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct TestRecord {
        id: [u8; 32],
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TestSinkError(&'static str);

    impl fmt::Display for TestSinkError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for TestSinkError {}

    fn synthetic_transaction() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x11; 32]), 1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[&[0x01, 0x02][..], &[0x03][..]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(42_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn candidate<'a>(
        transaction: &Transaction,
        bytes: &'a [u8],
        record: &'a TestRecord,
    ) -> PreparationCandidate<'a, TestRecord> {
        PreparationCandidate {
            chain_hash: ChainHash::TESTNET4,
            transaction_bytes: bytes,
            expected_txid: transaction.compute_txid(),
            expected_wtxid: transaction.compute_wtxid(),
            evidence_id: record.id,
            record,
        }
    }

    #[test]
    fn successful_preparation_persists_exact_bytes_and_identities() {
        let transaction = synthetic_transaction();
        let bytes = serialize(&transaction);
        let record = TestRecord { id: [0x22; 32] };
        let persist_calls = Cell::new(0usize);

        let identities = validate_and_persist(
            &candidate(&transaction, &bytes, &record),
            |persisted_record, persisted_bytes| {
                persist_calls.set(persist_calls.get() + 1);
                assert_eq!(persisted_record, &record);
                assert_eq!(persisted_bytes, bytes);
                Ok::<(), TestSinkError>(())
            },
        )
        .expect("valid evidence view must prepare");

        assert_eq!(persist_calls.get(), 1);
        assert_eq!(identities.txid, transaction.compute_txid());
        assert_eq!(identities.wtxid, transaction.compute_wtxid());
        assert_eq!(identities.evidence_id, record.id);
        assert_ne!(
            identities.txid.to_byte_array(),
            identities.wtxid.to_byte_array()
        );
    }

    #[test]
    fn persistence_failure_fails_closed() {
        let transaction = synthetic_transaction();
        let bytes = serialize(&transaction);
        let record = TestRecord { id: [0x33; 32] };
        let persist_calls = Cell::new(0usize);

        let error = validate_and_persist(&candidate(&transaction, &bytes, &record), |_, _| {
            persist_calls.set(persist_calls.get() + 1);
            Err(TestSinkError("disk unavailable"))
        })
        .expect_err("persistence failure must fail closed");

        assert!(matches!(
            error,
            VultisigBroadcastPreparationError::Persistence(TestSinkError("disk unavailable"))
        ));
        assert_eq!(persist_calls.get(), 1);
    }

    #[test]
    fn exact_testnet4_chain_is_required_before_persistence() {
        let transaction = synthetic_transaction();
        let bytes = serialize(&transaction);
        let record = TestRecord { id: [0x44; 32] };
        let mut wrong_chain = candidate(&transaction, &bytes, &record);
        wrong_chain.chain_hash = ChainHash::TESTNET3;
        let persist_calls = Cell::new(0usize);

        let error = validate_and_persist(&wrong_chain, |_, _| {
            persist_calls.set(persist_calls.get() + 1);
            Ok::<(), TestSinkError>(())
        })
        .expect_err("Testnet3 evidence must fail");

        assert!(matches!(
            error,
            VultisigBroadcastPreparationError::WrongChain {
                actual: ChainHash::TESTNET3
            }
        ));
        assert_eq!(persist_calls.get(), 0);
    }

    #[test]
    fn evidence_txid_and_wtxid_mismatches_fail_before_persistence() {
        let transaction = synthetic_transaction();
        let bytes = serialize(&transaction);
        let record = TestRecord { id: [0x55; 32] };
        let persist_calls = Cell::new(0usize);

        let mut wrong_txid = candidate(&transaction, &bytes, &record);
        wrong_txid.expected_txid = Txid::from_byte_array([0x66; 32]);
        let txid_error = validate_and_persist(&wrong_txid, |_, _| {
            persist_calls.set(persist_calls.get() + 1);
            Ok::<(), TestSinkError>(())
        })
        .expect_err("substituted evidence txid must fail");
        assert!(matches!(
            txid_error,
            VultisigBroadcastPreparationError::TxidMismatch { .. }
        ));

        let mut wrong_wtxid = candidate(&transaction, &bytes, &record);
        wrong_wtxid.expected_wtxid = Wtxid::from_byte_array([0x77; 32]);
        let wtxid_error = validate_and_persist(&wrong_wtxid, |_, _| {
            persist_calls.set(persist_calls.get() + 1);
            Ok::<(), TestSinkError>(())
        })
        .expect_err("substituted evidence wtxid must fail");
        assert!(matches!(
            wtxid_error,
            VultisigBroadcastPreparationError::WtxidMismatch { .. }
        ));
        assert_eq!(persist_calls.get(), 0);
    }

    #[test]
    fn malformed_and_noncanonical_encodings_fail_closed() {
        let transaction = synthetic_transaction();
        let record = TestRecord { id: [0x88; 32] };
        let malformed = [0xff];
        let persist_calls = Cell::new(0usize);
        let malformed_candidate = PreparationCandidate {
            chain_hash: ChainHash::TESTNET4,
            transaction_bytes: &malformed,
            expected_txid: transaction.compute_txid(),
            expected_wtxid: transaction.compute_wtxid(),
            evidence_id: record.id,
            record: &record,
        };

        let malformed_error = validate_and_persist(&malformed_candidate, |_, _| {
            persist_calls.set(persist_calls.get() + 1);
            Ok::<(), TestSinkError>(())
        })
        .expect_err("malformed consensus bytes must fail");
        assert!(matches!(
            malformed_error,
            VultisigBroadcastPreparationError::Decode { .. }
        ));

        // rust-bitcoin's decoder rejects known non-minimal encodings before
        // this comparison. Exercise the independent re-encoding guard directly
        // so it cannot silently disappear if decoder behavior later changes.
        let mut noncanonical = serialize(&transaction);
        noncanonical.push(0x00);
        let canonical_error =
            require_canonical_encoding::<TestSinkError>(noncanonical.as_slice(), &transaction)
                .expect_err("byte mismatch must fail canonicality");
        assert!(matches!(
            canonical_error,
            VultisigBroadcastPreparationError::NonCanonicalEncoding
        ));
        assert_eq!(persist_calls.get(), 0);
    }
}
