//! CTD-1 Slice C: the mint-cancel BTC swap-back EXECUTION flow.
//!
//! When a mint intent is cancelled AFTER its USDT→BTC swap completed,
//! the acquired BTC sits orphaned at our custody multisig. This module
//! drives the recovery: spend the orphaned sats to the observers'
//! AGREED `THORChain` Asgard inbound carrying the recovery memo
//! (`=:<asset>:<recovery destination>[:<lim>]`, destination pinned to
//! the protocol ops/treasury Safe per `DL-CTD-C-1`), authorized by the
//! k-of-n Acquire-Cancel Certificate collected from the per-operator
//! observers ([`crate::ric_collector::RicCollector::collect_acc`]).
//!
//! Trust model is identical to the redeem path: the executor is
//! UNTRUSTED — every custody daemon re-verifies the attached ACC
//! statelessly, binds the spend's outputs to the certified
//! destination/amount/memo (exact-set), and one-shots per
//! `(chain, cancel_id)`. A compromised executor can fail the round but
//! cannot steer it.
//!
//! Sizing honesty (CTD-C-R1): the swap-back `amount` is OPERATOR-
//! supplied from custody observation — `AcquireCancelled.amount` is
//! explicitly non-authoritative USDT units (Xindex A1/A5) and must
//! never size this spend. The observers bound the proposal (E2 fraud
//! window + Slice-E volume window) rather than derive it.

use alloy_primitives::{B256, U256};
use bitcoin::{Address, Transaction, Txid};
use tracing::info;
use xindex_chain_utxo::UtxoChainClient;
use xindex_multisig::MAX_OP_RETURN_BYTES;
use xindex_shared::signer_wire::AcquireCancelProof;

use crate::redeem::{ExecuteError, InProcessExecutor, SpendCertificate};

/// One mint-cancel swap-back: spend `amount` sats of orphaned custody
/// BTC to the agreed Asgard inbound under a k-of-n ACC.
#[derive(Debug, Clone)]
pub struct SwapBackTask {
    /// The `AcquireCancelled` cancel id — the custody daemons' one-shot
    /// key (`(chain, cancel_id)`); a re-drive with a different
    /// certificate is a 409 at every honest daemon.
    pub cancel_id: B256,
    /// Sats to swap back. Operator-supplied from custody observation,
    /// bounded not derived (CTD-C-R1).
    pub amount: U256,
    /// The exact memo bytes the observers certified (destination
    /// pinned to the recovery sink; `keccak(memo)` is the certified
    /// `memo_hash` the daemons bind the `OP_RETURN` to).
    pub memo: Vec<u8>,
    /// The k-of-n Acquire-Cancel proof from `collect_acc`. REQUIRED —
    /// unlike the redeem path there is no pre-certificate stage.
    pub proof: AcquireCancelProof,
}

impl<C: UtxoChainClient> InProcessExecutor<C> {
    /// Execute one swap-back end-to-end: select UTXO → build PSBT
    /// (Asgard out, change-to-self, `OP_RETURN` memo) → collect K
    /// cosigner partials (each daemon re-verifies the ACC) → finalize →
    /// broadcast. Returns the broadcast txid.
    ///
    /// `asgard` MUST be the observers' agreed inbound (parse
    /// [`crate::ric_collector::CollectedAcc::asgard_address`]) — paying
    /// anywhere else is refused by every daemon's output bind.
    ///
    /// # Errors
    /// Any of the variants in [`ExecuteError`].
    pub fn execute_swap_back(
        &self,
        task: &SwapBackTask,
        asgard: &Address,
    ) -> Result<Txid, ExecuteError> {
        let (txid, _tx) = self.execute_swap_back_capturing_tx(task, asgard)?;
        Ok(txid)
    }

    /// As [`InProcessExecutor::execute_swap_back`] but also returns the
    /// finalized [`Transaction`] (re-broadcast registry material).
    ///
    /// # Errors
    /// Any of the variants in [`ExecuteError`].
    pub fn execute_swap_back_capturing_tx(
        &self,
        task: &SwapBackTask,
        asgard: &Address,
    ) -> Result<(Txid, Transaction), ExecuteError> {
        if task.memo.is_empty() {
            return Err(ExecuteError::InvalidMemo("empty".to_string()));
        }
        if task.memo.len() > MAX_OP_RETURN_BYTES {
            return Err(ExecuteError::InvalidMemo(format!(
                "{} bytes > {MAX_OP_RETURN_BYTES}",
                task.memo.len()
            )));
        }
        let certificate = SpendCertificate::Acc(task.proof.clone());
        let (txid, tx) = self.execute_spend(task.amount, &task.memo, asgard, Some(&certificate))?;
        info!(
            cancel_id = %task.cancel_id,
            %txid,
            "BTC swap-back deposit broadcast (mint-cancel recovery)"
        );
        Ok((txid, tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redeem::{ExpectedOutputs, MultisigCosigner};
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{rand, Secp256k1, SecretKey};
    use bitcoin::{Amount, Network, PublicKey};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use xindex_chain_utxo::{UtxoEntry, UtxoError, UtxoTxStatus};
    use xindex_multisig::{sign_psbt_input, MultisigDescriptor};

    /// Arc-backed so the test keeps a handle after moving a clone into
    /// the executor (the executor's fields are private to `redeem`).
    #[derive(Debug, Clone, Default)]
    struct FakeBtc {
        utxos: Arc<Mutex<Vec<UtxoEntry>>>,
        broadcasts: Arc<Mutex<Vec<Transaction>>>,
    }

    impl UtxoChainClient for FakeBtc {
        fn get_address_utxos(&self, _addr: &Address) -> Result<Vec<UtxoEntry>, UtxoError> {
            Ok(self
                .utxos
                .lock()
                .map_err(|e| UtxoError::Upstream(e.to_string()))?
                .clone())
        }
        fn get_tx_status(&self, _txid: &Txid) -> Result<UtxoTxStatus, UtxoError> {
            Err(UtxoError::Upstream("not used in this test".to_string()))
        }
        fn get_tip_height(&self) -> Result<u32, UtxoError> {
            Ok(800_000)
        }
        fn broadcast(&self, tx: &Transaction) -> Result<Txid, UtxoError> {
            let txid = tx.compute_txid();
            self.broadcasts
                .lock()
                .map_err(|e| UtxoError::Upstream(e.to_string()))?
                .push(tx.clone());
            Ok(txid)
        }
    }

    /// Test cosigner: records the certificate it was handed into a
    /// test-held `Arc` slot, then produces a REAL partial signature
    /// with its local key (what a daemon would return after its ACC
    /// gate passed) so the descriptor finalizer succeeds.
    struct RecordingCosigner {
        sk: SecretKey,
        pk: PublicKey,
        seen: Arc<Mutex<Vec<Option<SpendCertificate>>>>,
    }

    impl MultisigCosigner for RecordingCosigner {
        fn cosigner_pubkey(&self) -> PublicKey {
            self.pk
        }

        #[expect(clippy::expect_used, reason = "test code")]
        fn sign_input(
            &self,
            psbt: &Psbt,
            input_index: usize,
            _expected: Option<&ExpectedOutputs>,
            certificate: Option<&SpendCertificate>,
        ) -> Result<(PublicKey, bitcoin::ecdsa::Signature), ExecuteError> {
            self.seen.lock().expect("lock").push(certificate.cloned());
            let secp = Secp256k1::new();
            let mut clone = psbt.clone();
            sign_psbt_input(&mut clone, input_index, &self.sk, &secp)?;
            // Return THIS cosigner's own signature. The executor threads one
            // accumulating PSBT through every cosigner, so by the time later
            // cosigners run, `partial_sigs` already holds earlier signers' sigs;
            // `.iter().next()` would return the lexicographically-smallest
            // pubkey's sig (an earlier signer's) ~half the time with random
            // keys, duplicating one signer and leaving `multi(K, …)`
            // unsatisfiable (CouldNotSatisfy). Key off `self.pk` instead.
            let sig = *clone.inputs[input_index]
                .partial_sigs
                .get(&self.pk)
                .expect("own partial sig inserted");
            Ok((self.pk, sig))
        }
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn descriptor_with_keys(k: usize, n: usize) -> (MultisigDescriptor, Vec<SecretKey>) {
        let secp = Secp256k1::new();
        let sks: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::new(&mut rand::thread_rng()))
            .collect();
        let pks: Vec<PublicKey> = sks
            .iter()
            .map(|sk| PublicKey::new(sk.public_key(&secp)))
            .collect();
        (
            MultisigDescriptor::new_p2wsh(k, &pks).expect("descriptor"),
            sks,
        )
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn asgard() -> Address {
        Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
            .expect("addr")
            .require_network(Network::Bitcoin)
            .expect("network")
    }

    fn proof(cancel: u8) -> AcquireCancelProof {
        AcquireCancelProof {
            cancel_id: format!("0x{}", format!("{cancel:02x}").repeat(32)),
            intent_id: format!("0x{}", "1d".repeat(32)),
            slot_index: "1".to_string(),
            asset_id: format!("0x{}", "a1".repeat(32)),
            amount: "50000000".to_string(),
            amount_decimals: 8,
            immediate_target_hash: format!("0x{}", "cd".repeat(32)),
            memo_hash: format!("0x{}", "ef".repeat(32)),
            final_destination_hash: format!("0x{}", "12".repeat(32)),
            vault_resolved_at: 1_750_000_000,
            signatures: vec![format!("0x{}", "aa".repeat(65))],
        }
    }

    fn task(amount: u64, memo: &str) -> SwapBackTask {
        SwapBackTask {
            cancel_id: B256::repeat_byte(0xac),
            amount: U256::from(amount),
            memo: memo.as_bytes().to_vec(),
            proof: proof(0xac),
        }
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn fund(chain: &FakeBtc, sats: u64) {
        chain.utxos.lock().expect("lock").push(UtxoEntry {
            txid: Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("txid"),
            vout: 0,
            value: Amount::from_sat(sats),
            confirmations: 6,
            block_hash: None,
        });
    }

    /// End-to-end (local keys): the swap-back builds the same exact-set
    /// spend shape as the redeem path — `[Asgard payout, change→multisig,
    /// OP_RETURN(memo)]` with `vin[0]` the multisig UTXO.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn swap_back_builds_asgard_deposit_with_memo_and_change() {
        let (desc, sks) = descriptor_with_keys(2, 3);
        let chain = FakeBtc::default();
        fund(&chain, 100_000_000);
        let multisig_addr = desc.address(Network::Bitcoin).expect("addr");
        let exec = InProcessExecutor::new(desc, sks, chain.clone(), Network::Bitcoin, 5_000)
            .expect("executor");

        let memo = "=:ETH.USDT:0x00000000000000000000000000000000000000aa:0";
        let (txid, tx) = exec
            .execute_swap_back_capturing_tx(&task(50_000_000, memo), &asgard())
            .expect("execute");

        let captured = chain.broadcasts.lock().expect("lock");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].compute_txid(), txid);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 3);
        assert_eq!(tx.output[0].value, Amount::from_sat(50_000_000));
        assert_eq!(tx.output[0].script_pubkey, asgard().script_pubkey());
        assert_eq!(tx.output[1].script_pubkey, multisig_addr.script_pubkey());
        assert!(tx.output[2].script_pubkey.is_op_return());
        assert_eq!(tx.output[2].value, Amount::ZERO);
        // OP_RETURN carries the exact certified memo bytes.
        let op_return_bytes: Vec<u8> = tx.output[2]
            .script_pubkey
            .as_bytes()
            .iter()
            .copied()
            .skip(2)
            .collect();
        assert_eq!(op_return_bytes, memo.as_bytes());
    }

    /// The cosigner path hands every daemon the ACC arm (never a RIC,
    /// never `None`) — the certificate the daemons' XOR gate expects
    /// for a mint-cancel swap-back.
    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn swap_back_forwards_acc_certificate_to_every_cosigner() {
        let (desc, sks) = descriptor_with_keys(2, 3);
        let secp = Secp256k1::new();
        let seen: Arc<Mutex<Vec<Option<SpendCertificate>>>> = Arc::new(Mutex::new(Vec::new()));
        let cosigners: Vec<Box<dyn MultisigCosigner>> = sks
            .iter()
            .take(2)
            .map(|sk| {
                Box::new(RecordingCosigner {
                    sk: *sk,
                    pk: PublicKey::new(sk.public_key(&secp)),
                    seen: Arc::clone(&seen),
                }) as Box<dyn MultisigCosigner>
            })
            .collect();
        let chain = FakeBtc::default();
        fund(&chain, 100_000_000);
        let exec =
            InProcessExecutor::with_cosigners(desc, cosigners, chain, Network::Bitcoin, 5_000)
                .expect("executor");

        let memo = "=:ETH.USDT:0x00000000000000000000000000000000000000aa:0";
        exec.execute_swap_back_capturing_tx(&task(50_000_000, memo), &asgard())
            .expect("execute");

        let seen = seen.lock().expect("lock");
        assert_eq!(seen.len(), 2, "both threshold cosigners signed once each");
        for cert in seen.iter() {
            // A RIC here would mean the swap-back path mis-wired the
            // certificate kind — the daemons' XOR gate would refuse it.
            let SpendCertificate::Acc(p) = cert.as_ref().expect("certificate attached") else {
                unreachable!("swap-back must carry an ACC, not a RIC")
            };
            assert_eq!(p.cancel_id, format!("0x{}", "ac".repeat(32)));
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn swap_back_rejects_empty_memo() {
        let (desc, sks) = descriptor_with_keys(2, 3);
        let exec = InProcessExecutor::new(desc, sks, FakeBtc::default(), Network::Bitcoin, 5_000)
            .expect("executor");
        let err = exec
            .execute_swap_back_capturing_tx(&task(50_000_000, ""), &asgard())
            .expect_err("must reject");
        assert!(matches!(err, ExecuteError::InvalidMemo(_)));
    }
}
