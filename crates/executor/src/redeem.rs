//! Redemption execution: decode `RedeemDispatched` events, build + sign
//! + broadcast Bitcoin spends from the multisig.

use std::str::FromStr;

use alloy_primitives::{B256, U256};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, Network, Transaction, Txid};
use thiserror::Error;
use tracing::{debug, info};

use xindex_chain_btc::{BitcoinChainClient, BitcoinError, BitcoinUtxo};
use xindex_chain_eth::bindings::ThorchainAdapter;
use xindex_multisig::{
    build_spending_psbt, sign_psbt_input, MultisigDescriptor, MultisigUtxo, SignError,
};

/// Errors surfaced during a single redemption execution.
#[derive(Debug, Error)]
pub enum ExecuteError {
    /// `nativeRecipient` did not parse as a valid Bitcoin address for the
    /// configured network.
    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),
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
/// `native_recipient` is exactly what the contract emitted — UTF-8 bytes
/// containing a chain-native address string (e.g., `bc1q…`). The decoder
/// validates UTF-8 and Bitcoin-address shape here.
#[derive(Debug, Clone)]
pub struct RedeemTask {
    pub intent_id: B256,
    pub target_token: alloy_primitives::Address,
    /// Pro-rata amount as a U256 (the contract's native unit). Caller is
    /// responsible for converting to satoshis based on `target_token`'s
    /// decimal convention. For BTC.BTC the contract stores 8-decimal sats.
    pub amount: U256,
    /// Parsed Bitcoin address (network-validated by the decoder).
    pub recipient: Address,
}

/// Either we're streaming events live, or replaying from a database; the
/// decoder is the same. Tests construct [`RedeemTask`] directly.
#[derive(Debug, Clone, Copy)]
pub enum RedeemTaskSource {
    Live,
    Replay,
}

/// Decode a `RedeemDispatched` event tuple into a [`RedeemTask`].
///
/// `network` is the Bitcoin network the configured multisig lives on
/// (mainnet or signet). The recipient must validate against that network
/// — sending mainnet BTC to a `tb1q…` testnet address would burn funds.
///
/// # Errors
/// [`ExecuteError::InvalidRecipient`] if the bytes aren't valid UTF-8 or
/// the parsed address belongs to a different network.
pub fn decode_redeem_event(
    event: &ThorchainAdapter::RedeemDispatched,
    network: Network,
) -> Result<RedeemTask, ExecuteError> {
    let recipient_str = std::str::from_utf8(&event.nativeRecipient)
        .map_err(|e| ExecuteError::InvalidRecipient(format!("non-utf8: {e}")))?;
    let unchecked = Address::from_str(recipient_str)
        .map_err(|e| ExecuteError::InvalidRecipient(format!("parse: {e}")))?;
    let recipient = unchecked
        .require_network(network)
        .map_err(|e| ExecuteError::InvalidRecipient(format!("wrong network: {e}")))?;

    Ok(RedeemTask {
        intent_id: event.intentId,
        target_token: event.targetToken,
        amount: event.amount,
        recipient,
    })
}

/// In-process executor: holds K signing keys directly. Used by
/// integration tests + dev environments where the K signer daemons are
/// running on the same machine. Production replaces this layer with a
/// `MultisigCosigner` trait whose impl talks to N independent signer
/// daemons via the M5 wire protocol.
///
/// Each call to [`InProcessExecutor::execute`] is one redemption:
/// select a UTXO, build PSBT, sign with K keys, finalize, broadcast.
#[derive(Debug)]
pub struct InProcessExecutor<C: BitcoinChainClient> {
    descriptor: MultisigDescriptor,
    keys: Vec<SecretKey>,
    chain: C,
    network: Network,
    fee_sats: u64,
}

impl<C: BitcoinChainClient> InProcessExecutor<C> {
    /// `keys` must contain ≥ `descriptor.threshold` secret keys whose
    /// pubkeys appear in the multisig descriptor.
    ///
    /// `fee_sats` is the flat fee subtracted from the spent UTXO before
    /// computing change. Until the production fee-estimator lands, we
    /// pass a conservative constant (e.g., 5 000 sats for a 2-output
    /// P2WSH spend).
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
            keys,
            chain,
            network,
            fee_sats,
        })
    }

    /// Convert the on-chain `amount` to a Bitcoin [`Amount`] (sats).
    /// The Solidity side stores BTC values in 8-decimal native units, so
    /// the U256 fits in `u64` for any reasonable redemption.
    fn amount_to_sats(amount: U256) -> Result<Amount, ExecuteError> {
        let sats: u64 = amount
            .try_into()
            .map_err(|e| ExecuteError::InvalidAmount(format!("> u64::MAX: {e}")))?;
        if sats == 0 {
            return Err(ExecuteError::InvalidAmount("zero".to_string()));
        }
        Ok(Amount::from_sat(sats))
    }

    /// Pick the smallest UTXO that covers `value + fee_sats`. Naive
    /// strategy is fine for v1 (one redemption ≈ one UTXO). Smarter
    /// coin-selection lands when bundle redemptions appear.
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

    /// End-to-end: decode → select UTXO → build PSBT → sign with K keys →
    /// finalize → broadcast. Returns the broadcast txid.
    ///
    /// # Errors
    /// Any of the variants in [`ExecuteError`].
    pub fn execute(&self, task: &RedeemTask) -> Result<Txid, ExecuteError> {
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

        let mut psbt = build_spending_psbt(
            std::slice::from_ref(&multisig_utxo),
            &task.recipient,
            recipient_value,
            Some(&multisig_address),
            change_value,
        )?;

        // Collect K partial sigs (in-process). Production splits this
        // step across N daemons.
        for (i, sk) in self.keys.iter().take(self.descriptor.threshold).enumerate() {
            sign_psbt_input(&mut psbt, 0, sk, self.descriptor.secp())?;
            debug!(signer = i, "added partial sig");
        }

        // Finalize with miniscript's standard machinery (combines partial
        // sigs into the final P2WSH witness).
        let tx: Transaction = xindex_multisig::psbt::finalize_psbt(&mut psbt, &self.descriptor)?;
        let txid = self.chain.broadcast(&tx)?;
        info!(intent_id = %task.intent_id, %txid, "redemption broadcast");
        Ok(txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address as EvmAddress, Bytes};
    use bitcoin::secp256k1::{rand, Secp256k1};
    use bitcoin::PublicKey;

    /// Fake Bitcoin client returning a fixed UTXO set + capturing
    /// broadcasts. Sufficient for executor unit tests; a richer impl
    /// lives in `xindex-chain-btc::watcher::tests`.
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

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn rejects_insufficient_signers() {
        let (desc, sks) = test_descriptor(3, 5);
        let chain = FakeBtc::default();
        let err = InProcessExecutor::new(desc, sks[..2].to_vec(), chain, Network::Bitcoin, 5_000)
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
        let chain = FakeBtc::default();
        let exec =
            InProcessExecutor::new(desc, sks, chain, Network::Bitcoin, 5_000).expect("executor");
        let task = RedeemTask {
            intent_id: B256::ZERO,
            target_token: EvmAddress::ZERO,
            amount: U256::ZERO,
            recipient: Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
                .expect("addr")
                .require_network(Network::Bitcoin)
                .expect("network"),
        };
        let err = exec.execute(&task).expect_err("should reject");
        assert!(matches!(err, ExecuteError::InvalidAmount(_)));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn rejects_when_no_utxo_covers_amount() {
        let (desc, sks) = test_descriptor(2, 3);
        let chain = FakeBtc::default();
        // No UTXOs in the fake.
        let exec =
            InProcessExecutor::new(desc, sks, chain, Network::Bitcoin, 5_000).expect("executor");
        let task = RedeemTask {
            intent_id: B256::ZERO,
            target_token: EvmAddress::ZERO,
            amount: U256::from(1_000_000u64),
            recipient: Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
                .expect("addr")
                .require_network(Network::Bitcoin)
                .expect("network"),
        };
        let err = exec.execute(&task).expect_err("should reject");
        assert!(matches!(err, ExecuteError::InsufficientFunds { .. }));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn end_to_end_finalizes_and_broadcasts() {
        let (desc, sks) = test_descriptor(2, 3);
        let chain = FakeBtc::default();
        let multisig_addr = desc.address(Network::Bitcoin).expect("addr");

        // Seed the fake with one UTXO worth 1 BTC at a known outpoint.
        let txid =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .expect("txid");
        chain.utxos.lock().expect("lock").push(BitcoinUtxo {
            txid,
            vout: 0,
            value: Amount::from_sat(100_000_000),
            confirmations: 6,
            block_hash: None,
        });

        let exec =
            InProcessExecutor::new(desc, sks, chain, Network::Bitcoin, 5_000).expect("executor");

        // Redeem 0.5 BTC.
        let task = RedeemTask {
            intent_id: B256::ZERO,
            target_token: EvmAddress::ZERO,
            amount: U256::from(50_000_000u64),
            recipient: Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
                .expect("addr")
                .require_network(Network::Bitcoin)
                .expect("network"),
        };

        let broadcast_txid = exec.execute(&task).expect("execute");

        // Inspect captured tx.
        let captured = exec.chain.broadcasts.lock().expect("lock");
        assert_eq!(captured.len(), 1, "expected exactly one broadcast");
        assert_eq!(captured[0].compute_txid(), broadcast_txid);
        // Outputs: recipient + change to multisig.
        assert_eq!(captured[0].output.len(), 2);
        assert_eq!(captured[0].output[0].value, Amount::from_sat(50_000_000));
        assert_eq!(
            captured[0].output[1].script_pubkey,
            multisig_addr.script_pubkey()
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn decode_event_rejects_wrong_network() {
        let event = ThorchainAdapter::RedeemDispatched {
            intentId: B256::ZERO,
            targetToken: EvmAddress::ZERO,
            amount: U256::from(100u64),
            // tb1q… is signet/testnet; we ask for mainnet decoding.
            nativeRecipient: Bytes::from(
                "tb1qar0srrr7xfkvy5l643lydnw9re59gtzzh5cnym"
                    .as_bytes()
                    .to_vec(),
            ),
        };
        let err = decode_redeem_event(&event, Network::Bitcoin).expect_err("should reject");
        assert!(matches!(err, ExecuteError::InvalidRecipient(_)));
    }
}
