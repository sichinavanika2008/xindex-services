//! Reverse-direction redemption execution (burn → single-token USDT).
//!
//! Decodes the new `RedeemDispatched` event, builds + signs + broadcasts
//! a Bitcoin spend from our 3-of-5 multisig to the `THORChain` BTC Asgard
//! inbound vault, carrying the contract-emitted swap memo
//! (`=:ETH.USDT:<indexToken>:<minOut>`) in an `OP_RETURN`. `THORChain` swaps
//! the BTC→USDT and delivers the USDT to the `IndexToken` contract (R1);
//! signers later attest delivery (or a slip-refund).
//!
//! The OLD direction (BTC → user address) is removed — burns no longer
//! return native BTC to users; they return one consolidated USDT amount
//! on Ethereum (plan §19).

use alloy_primitives::{B256, U256};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, Network, Transaction, Txid};
use thiserror::Error;
use tracing::{debug, info};

use xindex_chain_btc::{BitcoinChainClient, BitcoinError, BitcoinUtxo};
use xindex_chain_eth::bindings::ThorchainAdapter;
use xindex_multisig::{
    build_spending_psbt, sign_psbt_input, MultisigDescriptor, MultisigUtxo, SignError,
    MAX_OP_RETURN_BYTES,
};

/// Errors surfaced during a single redemption execution.
#[derive(Debug, Error)]
pub enum ExecuteError {
    /// The contract-emitted memo is empty or exceeds the 80-byte
    /// `OP_RETURN` standard-relay limit. We trust the memo verbatim (the
    /// Solidity adapter builds the canonical
    /// `=:ETH.USDT:<indexToken>:<minOut>`); we only sanity-bound it so a
    /// malformed event can't produce a non-standard tx.
    #[error("invalid memo: {0}")]
    InvalidMemo(String),
    /// Redeem amount converted to satoshis exceeds `u64::MAX` or is zero.
    #[error("invalid amount: {0}")]
    InvalidAmount(String),
    /// No multisig UTXO covers the requested redeem amount + fee budget.
    #[error("no UTXO covers amount {needed_sats} sats (have {available_sats})")]
    InsufficientFunds {
        needed_sats: u64,
        available_sats: u64,
    },
    /// PSBT construction or signing failed.
    #[error("psbt error: {0}")]
    Psbt(#[from] SignError),
    /// Bitcoin chain access failed.
    #[error("bitcoin chain error: {0}")]
    Chain(#[from] BitcoinError),
    /// Insufficient signers configured (< K of K-of-N).
    #[error("threshold {threshold} requires {threshold} keys, got {got}")]
    InsufficientSigners { threshold: usize, got: usize },
}

/// Decoded form of one [`ThorchainAdapter::RedeemDispatched`] log.
///
/// There is no Bitcoin recipient here — the destination is the `THORChain`
/// BTC Asgard inbound vault, resolved LIVE by the binary (and rejected
/// if the registry is stale / halted), passed into
/// [`InProcessExecutor::execute_capturing_tx`]. The `memo` is the
/// contract-built swap memo, trusted verbatim.
#[derive(Debug, Clone)]
pub struct RedeemTask {
    /// Per-adapter unique dispatch id (executor-dedup key for the
    /// broadcast registry).
    pub dispatch_id: B256,
    /// `IntentQueue` redemption id — the F2 correlation key the signer
    /// looks up to find this BTC inbound.
    pub redemption_id: B256,
    /// The async (BTC) slot's target-token sentinel (informational).
    pub target_token: alloy_primitives::Address,
    /// BTC amount to send from the multisig to Asgard, in 8-decimal
    /// native sats (the Solidity side stores sats).
    pub amount: U256,
    /// `THORChain` swap memo, emitted by the contract. Trusted verbatim;
    /// only length-bounded here.
    pub memo: Vec<u8>,
}

/// Either we're streaming events live, or replaying from a database; the
/// decoder is the same. Tests construct [`RedeemTask`] directly.
#[derive(Debug, Clone, Copy)]
pub enum RedeemTaskSource {
    Live,
    Replay,
}

/// Decode a `RedeemDispatched` event into a [`RedeemTask`].
///
/// # Errors
/// [`ExecuteError::InvalidMemo`] if the memo is empty or longer than
/// [`MAX_OP_RETURN_BYTES`].
pub fn decode_redeem_event(
    event: &ThorchainAdapter::RedeemDispatched,
) -> Result<RedeemTask, ExecuteError> {
    let memo = event.memo.as_bytes().to_vec();
    if memo.is_empty() {
        return Err(ExecuteError::InvalidMemo("empty".to_string()));
    }
    if memo.len() > MAX_OP_RETURN_BYTES {
        return Err(ExecuteError::InvalidMemo(format!(
            "{} bytes > {MAX_OP_RETURN_BYTES}",
            memo.len()
        )));
    }
    Ok(RedeemTask {
        dispatch_id: event.dispatchId,
        redemption_id: event.redemptionId,
        target_token: event.targetToken,
        amount: event.amount,
        memo,
    })
}

/// In-process executor: holds K signing keys directly. Used by
/// integration tests + dev environments where the K signer daemons are
/// running on the same machine. Production replaces this layer with a
/// [`MultisigCosigner`] backend whose impl talks to N independent
/// signer daemons via the M5 wire protocol.
///
/// # ⚠ DEV / TEST USE ONLY — NEVER FOR PRODUCTION FUNDS
///
/// The K secret keys sit in regular Rust heap memory and are **not
/// zeroized on drop**. After the process exits or crashes the bytes
/// can persist in swap files, core dumps, heap snapshots, or
/// sibling-process scrapes.
///
/// **The risk here is higher than [`xindex_signer::SoftwareSigner`]'s
/// because these keys spend Bitcoin from our 3-of-5 P2WSH multisig — a
/// leak compromises real BTC.** Production keys MUST live inside
/// YubiHSM2-backed daemons implementing [`MultisigCosigner`] (M5).
/// Internal signing backend. `LocalKeys` is the dev/staging path —
/// keys live in this process's heap (NEVER for mainnet). `Cosigners`
/// is the production path — each entry is one HSM-backed remote
/// signer-daemon implementing [`MultisigCosigner`] (M5 / PART 5).
enum SigningBackend {
    LocalKeys(Vec<SecretKey>),
    Cosigners(Vec<Box<dyn MultisigCosigner>>),
}

impl std::fmt::Debug for SigningBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose key counts (let alone bytes) past this Debug
        // surface — a leaked log line should reveal nothing exploitable.
        match self {
            Self::LocalKeys(_) => f.write_str("LocalKeys(<redacted>)"),
            Self::Cosigners(_) => f.write_str("Cosigners(<redacted>)"),
        }
    }
}

#[derive(Debug)]
pub struct InProcessExecutor<C: BitcoinChainClient> {
    descriptor: MultisigDescriptor,
    backend: SigningBackend,
    chain: C,
    network: Network,
    fee_sats: u64,
}

/// Production trait: K independent signer daemons each hold one HSM-
/// backed key. **Lands in M5.** [`InProcessExecutor`] is the dev-only
/// stand-in while the wire protocol + HSM integration are absent.
pub trait MultisigCosigner: Send + Sync {
    /// Public key of the cosigner — must match a descriptor pubkey.
    fn cosigner_pubkey(&self) -> bitcoin::PublicKey;

    /// Sign a single PSBT input with the HSM-held key.
    ///
    /// # Errors
    /// Returns the cosigner's transport / HSM / authorization error.
    fn sign_input(
        &self,
        psbt: &bitcoin::psbt::Psbt,
        input_index: usize,
    ) -> Result<(bitcoin::PublicKey, bitcoin::ecdsa::Signature), ExecuteError>;
}

impl<C: BitcoinChainClient> InProcessExecutor<C> {
    /// `keys` must contain ≥ `descriptor.threshold` secret keys whose
    /// pubkeys appear in the multisig descriptor.
    ///
    /// # Errors
    /// [`ExecuteError::InsufficientSigners`] if `keys.len() < threshold`.
    pub fn new(
        descriptor: MultisigDescriptor,
        keys: Vec<SecretKey>,
        chain: C,
        network: Network,
        fee_sats: u64,
    ) -> Result<Self, ExecuteError> {
        if keys.len() < descriptor.threshold {
            return Err(ExecuteError::InsufficientSigners {
                threshold: descriptor.threshold,
                got: keys.len(),
            });
        }
        Ok(Self {
            descriptor,
            backend: SigningBackend::LocalKeys(keys),
            chain,
            network,
            fee_sats,
        })
    }

    /// Production constructor: take pre-built remote cosigners
    /// (typically [`crate::remote_cosigner::RemoteMultisigCosigner`]
    /// instances pointing at one signer-daemon each). Coordinator holds
    /// **zero** key material — each cosigner forwards typed PSBT
    /// requests over HTTP to a daemon that owns its HSM-backed key.
    ///
    /// # Errors
    /// [`ExecuteError::InsufficientSigners`] if fewer cosigners than
    /// the descriptor's threshold.
    pub fn with_cosigners(
        descriptor: MultisigDescriptor,
        cosigners: Vec<Box<dyn MultisigCosigner>>,
        chain: C,
        network: Network,
        fee_sats: u64,
    ) -> Result<Self, ExecuteError> {
        if cosigners.len() < descriptor.threshold {
            return Err(ExecuteError::InsufficientSigners {
                threshold: descriptor.threshold,
                got: cosigners.len(),
            });
        }
        Ok(Self {
            descriptor,
            backend: SigningBackend::Cosigners(cosigners),
            chain,
            network,
            fee_sats,
        })
    }

    /// Convert the on-chain `amount` to a Bitcoin [`Amount`] (sats).
    fn amount_to_sats(amount: U256) -> Result<Amount, ExecuteError> {
        let sats: u64 = amount
            .try_into()
            .map_err(|e| ExecuteError::InvalidAmount(format!("> u64::MAX: {e}")))?;
        if sats == 0 {
            return Err(ExecuteError::InvalidAmount("zero".to_string()));
        }
        Ok(Amount::from_sat(sats))
    }

    /// Pick the smallest UTXO that covers `value + fee_sats`.
    fn select_utxo(utxos: &[BitcoinUtxo], needed: Amount) -> Result<&BitcoinUtxo, ExecuteError> {
        let mut chosen: Option<&BitcoinUtxo> = None;
        let mut total_available: u64 = 0;
        for utxo in utxos {
            total_available = total_available.saturating_add(utxo.value.to_sat());
            if utxo.value >= needed && chosen.is_none_or(|existing| utxo.value < existing.value) {
                chosen = Some(utxo);
            }
        }
        chosen.ok_or(ExecuteError::InsufficientFunds {
            needed_sats: needed.to_sat(),
            available_sats: total_available,
        })
    }

    /// End-to-end: select UTXO → build PSBT (Asgard out, `OP_RETURN` memo,
    /// change) → sign with K keys → finalize → broadcast. Returns the
    /// broadcast txid.
    ///
    /// `asgard` is the `THORChain` BTC inbound vault, resolved live by the
    /// caller (rejected upstream if the registry is stale / halted).
    ///
    /// # Errors
    /// Any of the variants in [`ExecuteError`].
    pub fn execute(&self, task: &RedeemTask, asgard: &Address) -> Result<Txid, ExecuteError> {
        let (txid, _tx) = self.execute_capturing_tx(task, asgard)?;
        Ok(txid)
    }

    /// Same as [`InProcessExecutor::execute`] but also returns the
    /// finalized [`Transaction`] for the reorg-aware re-broadcast
    /// registry (which must store the exact tx — rebuilding would risk a
    /// different UTXO/txid).
    ///
    /// **`vin[0]` invariant:** the sole input is a multisig UTXO, so
    /// `THORChain`'s `getSender` resolves any slip-refund back to our
    /// multisig (verify-the-refund depends on this). Asserted by
    /// `vin0_is_multisig_utxo`.
    ///
    /// # Errors
    /// Any of the variants in [`ExecuteError`].
    pub fn execute_capturing_tx(
        &self,
        task: &RedeemTask,
        asgard: &Address,
    ) -> Result<(Txid, Transaction), ExecuteError> {
        let recipient_value = Self::amount_to_sats(task.amount)?;
        let needed = recipient_value
            .checked_add(Amount::from_sat(self.fee_sats))
            .ok_or_else(|| ExecuteError::InvalidAmount("overflow".to_string()))?;

        let multisig_address = self
            .descriptor
            .address(self.network)
            .map_err(|e| ExecuteError::Psbt(SignError::Sighash(e.to_string())))?;
        let utxos = self.chain.get_address_utxos(&multisig_address)?;
        let selected = Self::select_utxo(&utxos, needed)?;
        let derived = self
            .descriptor
            .descriptor
            .at_derivation_index(0)
            .map_err(|e| ExecuteError::Psbt(SignError::Sighash(e.to_string())))?;
        let witness_script = derived
            .explicit_script()
            .map_err(|e| ExecuteError::Psbt(SignError::Sighash(e.to_string())))?;

        let multisig_utxo = MultisigUtxo {
            outpoint: bitcoin::OutPoint {
                txid: selected.txid,
                vout: selected.vout,
            },
            value: selected.value,
            script_pubkey: multisig_address.script_pubkey(),
            witness_script,
        };
        let change_value = selected.value.checked_sub(needed).unwrap_or(Amount::ZERO);

        // Outputs: [Asgard vault, OP_RETURN(memo), change→multisig].
        // Single input ⇒ vin[0] is the multisig UTXO (refund-to-sender).
        let mut psbt = build_spending_psbt(
            std::slice::from_ref(&multisig_utxo),
            asgard,
            recipient_value,
            Some(&multisig_address),
            change_value,
            Some(&task.memo),
        )?;

        // Collect K partial signatures. LocalKeys path uses the
        // existing audited `sign_psbt_input` (computes sighash, signs,
        // inserts partial_sig). Cosigners path posts the PSBT to each
        // daemon over HTTP; daemon owns the sighash + replay-DB +
        // HSM. Both paths insert into `partial_sigs` and the descriptor
        // finalizer produces the same valid witness.
        match &self.backend {
            SigningBackend::LocalKeys(keys) => {
                for (i, sk) in keys.iter().take(self.descriptor.threshold).enumerate() {
                    sign_psbt_input(&mut psbt, 0, sk, self.descriptor.secp())?;
                    debug!(signer = i, "added partial sig (local key)");
                }
            }
            SigningBackend::Cosigners(cosigners) => {
                for (i, cosigner) in cosigners.iter().take(self.descriptor.threshold).enumerate() {
                    let (pk, sig) = cosigner.sign_input(&psbt, 0)?;
                    // Daemon-side already verified the descriptor +
                    // vin[0] invariant + signature recovery. Coordinator
                    // pins per-response pubkey; if it didn't match, the
                    // cosigner returned an Err above.
                    psbt.inputs[0].partial_sigs.insert(pk, sig);
                    debug!(signer = i, %pk, "added partial sig (remote cosigner)");
                }
            }
        }

        let tx: Transaction = xindex_multisig::psbt::finalize_psbt(&mut psbt, &self.descriptor)?;
        debug_assert!(
            tx.input[0].previous_output.txid == selected.txid
                && tx.input[0].previous_output.vout == selected.vout,
            "vin[0] must be the selected multisig UTXO (THORChain refund-to-sender)"
        );
        let txid = self.chain.broadcast(&tx)?;
        info!(
            redemption_id = %task.redemption_id,
            %txid,
            "BTC→Asgard redemption deposit broadcast"
        );
        Ok((txid, tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address as EvmAddress;
    use bitcoin::secp256k1::{rand, Secp256k1};
    use bitcoin::PublicKey;
    use std::str::FromStr;

    #[derive(Debug, Default)]
    struct FakeBtc {
        utxos: std::sync::Mutex<Vec<BitcoinUtxo>>,
        broadcasts: std::sync::Mutex<Vec<Transaction>>,
    }

    impl BitcoinChainClient for FakeBtc {
        fn get_address_utxos(&self, _addr: &Address) -> Result<Vec<BitcoinUtxo>, BitcoinError> {
            Ok(self
                .utxos
                .lock()
                .map_err(|e| BitcoinError::Upstream(e.to_string()))?
                .clone())
        }
        fn get_tx_status(
            &self,
            _txid: &Txid,
        ) -> Result<xindex_chain_btc::BitcoinTxStatus, BitcoinError> {
            Err(BitcoinError::Upstream("not used in this test".to_string()))
        }
        fn get_tip_height(&self) -> Result<u32, BitcoinError> {
            Ok(800_000)
        }
        fn broadcast(&self, tx: &Transaction) -> Result<Txid, BitcoinError> {
            let txid = tx.compute_txid();
            self.broadcasts
                .lock()
                .map_err(|e| BitcoinError::Upstream(e.to_string()))?
                .push(tx.clone());
            Ok(txid)
        }
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn test_descriptor(k: usize, n: usize) -> (MultisigDescriptor, Vec<SecretKey>) {
        let secp = Secp256k1::new();
        let sks: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::new(&mut rand::thread_rng()))
            .collect();
        let pks: Vec<PublicKey> = sks
            .iter()
            .map(|sk| PublicKey::new(sk.public_key(&secp)))
            .collect();
        (MultisigDescriptor::new(k, &pks).expect("descriptor"), sks)
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn asgard() -> Address {
        Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
            .expect("addr")
            .require_network(Network::Bitcoin)
            .expect("network")
    }

    fn task(amount: u64, memo: &str) -> RedeemTask {
        RedeemTask {
            dispatch_id: B256::ZERO,
            redemption_id: B256::repeat_byte(0x11),
            target_token: EvmAddress::ZERO,
            amount: U256::from(amount),
            memo: memo.as_bytes().to_vec(),
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn rejects_insufficient_signers() {
        let (desc, sks) = test_descriptor(3, 5);
        let err = InProcessExecutor::new(
            desc,
            sks[..2].to_vec(),
            FakeBtc::default(),
            Network::Bitcoin,
            5_000,
        )
        .expect_err("should reject");
        assert!(matches!(
            err,
            ExecuteError::InsufficientSigners {
                threshold: 3,
                got: 2
            }
        ));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn rejects_zero_amount() {
        let (desc, sks) = test_descriptor(2, 3);
        let exec = InProcessExecutor::new(desc, sks, FakeBtc::default(), Network::Bitcoin, 5_000)
            .expect("executor");
        let err = exec
            .execute(&task(0, "=:ETH.USDT:0xabc:1"), &asgard())
            .expect_err("should reject");
        assert!(matches!(err, ExecuteError::InvalidAmount(_)));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn rejects_when_no_utxo_covers_amount() {
        let (desc, sks) = test_descriptor(2, 3);
        let exec = InProcessExecutor::new(desc, sks, FakeBtc::default(), Network::Bitcoin, 5_000)
            .expect("executor");
        let err = exec
            .execute(&task(1_000_000, "=:ETH.USDT:0xabc:1"), &asgard())
            .expect_err("should reject");
        assert!(matches!(err, ExecuteError::InsufficientFunds { .. }));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn decode_rejects_empty_memo() {
        let event = ThorchainAdapter::RedeemDispatched {
            dispatchId: B256::ZERO,
            redemptionId: B256::ZERO,
            targetToken: EvmAddress::ZERO,
            amount: U256::from(100u64),
            destination: EvmAddress::ZERO,
            memo: String::new(),
        };
        let err = decode_redeem_event(&event).expect_err("should reject");
        assert!(matches!(err, ExecuteError::InvalidMemo(_)));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn decode_rejects_oversize_memo() {
        let event = ThorchainAdapter::RedeemDispatched {
            dispatchId: B256::ZERO,
            redemptionId: B256::ZERO,
            targetToken: EvmAddress::ZERO,
            amount: U256::from(100u64),
            destination: EvmAddress::ZERO,
            memo: "x".repeat(MAX_OP_RETURN_BYTES + 1),
        };
        let err = decode_redeem_event(&event).expect_err("should reject");
        assert!(matches!(err, ExecuteError::InvalidMemo(_)));
    }

    /// Boundary: a memo of EXACTLY `MAX_OP_RETURN_BYTES` is valid (the
    /// gate is `>`, not `>=`). Kills the `>`→`>=` mutation that would
    /// reject a maximal-but-legal memo.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn decode_accepts_exact_max_memo() {
        let event = ThorchainAdapter::RedeemDispatched {
            dispatchId: B256::ZERO,
            redemptionId: B256::ZERO,
            targetToken: EvmAddress::ZERO,
            amount: U256::from(100u64),
            destination: EvmAddress::ZERO,
            memo: "x".repeat(MAX_OP_RETURN_BYTES),
        };
        let task = decode_redeem_event(&event).expect("exact-max memo is valid");
        assert_eq!(task.memo.len(), MAX_OP_RETURN_BYTES);
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn utxo(value_sats: u64, vout: u32) -> BitcoinUtxo {
        BitcoinUtxo {
            txid: Txid::from_str(
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .expect("txid"),
            vout,
            value: Amount::from_sat(value_sats),
            confirmations: 6,
            block_hash: None,
        }
    }

    /// `select_utxo` must pick the SMALLEST UTXO that still covers
    /// `needed`, never a larger one and never one below `needed`.
    /// Kills: `<`→`>`/`==` (would pick the largest / first) and the
    /// `&&`→`||` mutation (would pick a too-small UTXO since the
    /// smaller-than-existing clause alone would then suffice).
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn select_utxo_picks_smallest_covering() {
        let utxos = vec![utxo(100_000, 0), utxo(50_000, 1), utxo(30_000, 2)];
        let chosen = InProcessExecutor::<FakeBtc>::select_utxo(&utxos, Amount::from_sat(40_000))
            .expect("a covering utxo exists");
        assert_eq!(
            chosen.value,
            Amount::from_sat(50_000),
            "smallest UTXO ≥ needed, not the largest and not the sub-needed one"
        );
    }

    /// Two equal-value covering UTXOs: the FIRST encountered is kept
    /// (strict `<`, not `<=`). Kills `<`→`<=` which would switch to the
    /// later equal-value UTXO.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn select_utxo_keeps_first_of_equal_value() {
        let utxos = vec![utxo(50_000, 7), utxo(50_000, 9)];
        let chosen = InProcessExecutor::<FakeBtc>::select_utxo(&utxos, Amount::from_sat(40_000))
            .expect("a covering utxo exists");
        assert_eq!(
            chosen.vout, 7,
            "first equal-value UTXO retained, not swapped"
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn end_to_end_builds_asgard_deposit_with_memo_and_vin0_multisig() {
        let (desc, sks) = test_descriptor(2, 3);
        let chain = FakeBtc::default();
        let multisig_addr = desc.address(Network::Bitcoin).expect("addr");

        let utxo_txid =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .expect("txid");
        chain.utxos.lock().expect("lock").push(BitcoinUtxo {
            txid: utxo_txid,
            vout: 0,
            value: Amount::from_sat(100_000_000),
            confirmations: 6,
            block_hash: None,
        });

        let exec =
            InProcessExecutor::new(desc, sks, chain, Network::Bitcoin, 5_000).expect("executor");
        let memo = "=:ETH.USDT:0x000000000000000000000000000000000000dead:1000000";
        let (txid, tx) = exec
            .execute_capturing_tx(&task(50_000_000, memo), &asgard())
            .expect("execute");

        let captured = exec.chain.broadcasts.lock().expect("lock");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].compute_txid(), txid);

        // vin[0] is the multisig UTXO (THORChain refund-to-sender).
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output.txid, utxo_txid);

        // Outputs: [Asgard, OP_RETURN(memo), change→multisig].
        assert_eq!(tx.output.len(), 3);
        assert_eq!(tx.output[0].value, Amount::from_sat(50_000_000));
        assert_eq!(tx.output[0].script_pubkey, asgard().script_pubkey());
        assert!(tx.output[1].script_pubkey.is_op_return());
        assert_eq!(tx.output[1].value, Amount::ZERO);
        // OP_RETURN carries the exact contract memo.
        let op_return_bytes: Vec<u8> = tx.output[1]
            .script_pubkey
            .as_bytes()
            .iter()
            .copied()
            .skip(2) // OP_RETURN + pushlen
            .collect();
        assert_eq!(op_return_bytes, memo.as_bytes());
        assert_eq!(tx.output[2].script_pubkey, multisig_addr.script_pubkey());
    }
}
