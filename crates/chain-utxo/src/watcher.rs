//! High-level Bitcoin observation helpers built on the
//! [`UtxoChainClient`] trait.
//!
//! The signer's cross-check use case: "did at least `min_amount` worth
//! of BTC arrive at our multisig with at least `min_confirmations`
//! confirmations?" — answered by [`find_arrival`].

use bitcoin::{Address, Amount};

use crate::client::{UtxoChainClient, UtxoError};
use crate::types::UtxoEntry;

/// Search the address's UTXO set for the first UTXO that satisfies BOTH:
/// - `value >= min_amount`
/// - `confirmations >= min_confirmations`
///
/// Returns `Ok(None)` when no qualifying UTXO exists yet (signer should
/// poll again later). Returns `Err` only on transport / network issues.
///
/// **Why "first" rather than "sum"**: each Xindex async-mint intent
/// triggers exactly one `THORChain` swap → one outbound tx → one UTXO at
/// our multisig. Aggregating across UTXOs would conflate distinct
/// intents. The signer must match the UTXO 1:1 with the intent's
/// expected amount.
///
/// # Errors
/// Forwards [`UtxoError`] from the underlying client.
pub fn find_arrival<C: UtxoChainClient>(
    client: &C,
    address: &Address,
    min_amount: Amount,
    min_confirmations: u32,
) -> Result<Option<UtxoEntry>, UtxoError> {
    let utxos = client.get_address_utxos(address)?;
    Ok(utxos
        .into_iter()
        .find(|u| u.value >= min_amount && u.confirmations >= min_confirmations))
}

/// Convenience: confirmation count for a specific txid as reported by
/// the chain client. Wraps `get_tx_status().confirmations`.
///
/// # Errors
/// Forwards [`UtxoError`] from the underlying client.
pub fn confirmations_for_tx<C: UtxoChainClient>(
    client: &C,
    txid: &bitcoin::Txid,
) -> Result<u32, UtxoError> {
    client.get_tx_status(txid).map(|s| s.confirmations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{UtxoEntry, UtxoTxStatus};
    use bitcoin::{Network, Transaction, Txid};
    use std::str::FromStr;

    /// In-memory fake [`UtxoChainClient`] for unit tests.
    /// Mutating helpers (`set_utxos`, `add_utxo`) seed deterministic state.
    #[derive(Default)]
    struct FakeClient {
        utxos: std::sync::Mutex<Vec<UtxoEntry>>,
        tip_height: std::sync::Mutex<u32>,
    }

    impl FakeClient {
        fn set_utxos(&self, utxos: Vec<UtxoEntry>) {
            #[expect(clippy::expect_used, reason = "test code")]
            {
                *self.utxos.lock().expect("mutex") = utxos;
            }
        }
    }

    impl UtxoChainClient for FakeClient {
        fn get_address_utxos(&self, _address: &Address) -> Result<Vec<UtxoEntry>, UtxoError> {
            #[expect(clippy::expect_used, reason = "test code")]
            Ok(self.utxos.lock().expect("mutex").clone())
        }
        fn get_tx_status(&self, txid: &Txid) -> Result<UtxoTxStatus, UtxoError> {
            Ok(UtxoTxStatus {
                txid: *txid,
                confirmed: true,
                block_height: Some(800_000),
                block_hash: None,
                confirmations: 6,
            })
        }
        fn get_tip_height(&self) -> Result<u32, UtxoError> {
            #[expect(clippy::expect_used, reason = "test code")]
            Ok(*self.tip_height.lock().expect("mutex"))
        }
        fn broadcast(&self, _tx: &Transaction) -> Result<Txid, UtxoError> {
            #[expect(clippy::expect_used, reason = "test code")]
            Ok(
                Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                    .expect("txid literal"),
            )
        }
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn dummy_address() -> Address {
        // Mainnet P2WPKH address — only used as an opaque key in the
        // FakeClient, so any well-formed address works.
        let addr = bitcoin::Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .expect("address parse");
        addr.require_network(Network::Bitcoin).expect("network")
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn dummy_utxo(amount_sat: u64, confirmations: u32) -> UtxoEntry {
        UtxoEntry {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .expect("txid"),
            vout: 0,
            value: Amount::from_sat(amount_sat),
            confirmations,
            block_hash: None,
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn find_arrival_returns_none_when_empty() {
        let client = FakeClient::default();
        let result = find_arrival(&client, &dummy_address(), Amount::from_sat(100_000_000), 6)
            .expect("query");
        assert!(result.is_none());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn find_arrival_skips_under_amount() {
        let client = FakeClient::default();
        client.set_utxos(vec![dummy_utxo(50_000_000, 10)]);
        let result = find_arrival(&client, &dummy_address(), Amount::from_sat(100_000_000), 6)
            .expect("query");
        assert!(result.is_none(), "below-min-amount UTXO must not match");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn find_arrival_skips_under_confirmations() {
        let client = FakeClient::default();
        client.set_utxos(vec![dummy_utxo(100_000_000, 2)]);
        let result = find_arrival(&client, &dummy_address(), Amount::from_sat(100_000_000), 6)
            .expect("query");
        assert!(result.is_none(), "below-min-conf UTXO must not match");
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn find_arrival_returns_qualifying_utxo() {
        let client = FakeClient::default();
        let target = dummy_utxo(100_000_000, 6);
        client.set_utxos(vec![dummy_utxo(50_000_000, 10), target.clone()]);
        let result = find_arrival(&client, &dummy_address(), Amount::from_sat(100_000_000), 6)
            .expect("query");
        assert_eq!(result, Some(target));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn confirmations_for_tx_returns_status_count() {
        let client = FakeClient::default();
        let txid =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000003")
                .expect("txid");
        let confs = confirmations_for_tx(&client, &txid).expect("query");
        assert_eq!(confs, 6);
    }
}
