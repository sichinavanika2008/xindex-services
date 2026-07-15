//! TK-01 / TK-02 — approver-side payload reconstruction + fee cap.
//!
//! Before the family decision core runs, the approver INDEPENDENTLY rebuilds
//! the unsigned transaction from the RIC-bound + declared prepared fields
//! (using the SAME builders the executor signs with), recomputes its signing
//! hash, and asserts it equals the payload the enclave is being asked to sign
//! (`prepare_key`). A coordinator that writes both the store key and the
//! provider signing request therefore cannot pair an honest bound context with a
//! signature over a different message (TK-01). The same pass range-checks the
//! declared fee against the per-chain cap (TK-02). Any reconstruction failure,
//! payload mismatch, or fee breach is a fail-closed REJECT.

use bitcoin::hashes::Hash;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};

use xindex_cosmos_tx::amino::CosmosSendSignDoc;
use xindex_custody_core::evm_tx::{evm_signing_hash, EvmUnsignedParams};
use xindex_custody_core::prepare::{
    AccountPrepared, AccountSigning, BindContext, EvmPrepared, PreparedSpend,
};
use xindex_shared::chain_registry::{ChainId, EvmTxType};
use xindex_shared::signer_wire::TronAssetKind;
use xindex_solana_tx::message::build_transfer_message;
use xindex_solana_tx::Pubkey;
use xindex_tron_tx::addr::{decode_base58check, decode_to_evm20};
use xindex_tron_tx::tx::{
    build_trx_raw_data, build_usdt_raw_data, txid, Tapos, TrxTransfer, UsdtTransfer,
};
use xindex_xrp_tx::addr::decode_classic_address;
use xindex_xrp_tx::signing::single_sign_digest;
use xindex_xrp_tx::tx::{serialize_single_sign, PaymentBody};

/// A fail-closed rejection reason `(code, message)`.
pub type Rejection = (&'static str, String);

fn reject(code: &'static str, msg: impl Into<String>) -> Rejection {
    (code, msg.into())
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(bytes))
}

/// Case/prefix-insensitive equality of two `0x…`-hex payloads.
fn payloads_equal(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim_start_matches("0x").to_ascii_lowercase();
    norm(a) == norm(b)
}

/// Reconstruct the payload from the prepared fields, assert it equals
/// `prepare_key`, and enforce the per-chain fee cap (TK-01/TK-02).
///
/// # Errors
/// [`Rejection`] on a reconstruction failure, payload mismatch, or fee breach —
/// the caller maps it to a fail-closed REJECT.
pub fn verify_payload_and_fee(spend: &PreparedSpend, prepare_key: &str) -> Result<(), Rejection> {
    match spend {
        PreparedSpend::Btc(ctx) => verify_btc(ctx, prepare_key),
        PreparedSpend::Evm(e) => verify_evm(e, prepare_key),
        PreparedSpend::Account(a) => verify_account(a, prepare_key),
    }
}

/// Enforce the per-chain redeem-fee cap on a declared fee (base units).
fn enforce_fee_cap(chain: ChainId, declared: u128) -> Result<(), Rejection> {
    let cap = u128::from(chain.max_redeem_fee_base_units());
    if declared > cap {
        return Err(reject(
            "fee_exceeds_cap",
            format!("declared fee {declared} exceeds chain {chain:?} cap {cap} (TK-02)"),
        ));
    }
    Ok(())
}

fn verify_evm(e: &EvmPrepared, prepare_key: &str) -> Result<(), Rejection> {
    let hash = evm_signing_hash(&EvmUnsignedParams {
        chain: e.chain,
        nonce: e.signing.nonce,
        gas_limit: e.signing.gas_limit,
        max_fee_per_gas: e.signing.max_fee_per_gas,
        max_priority_fee_per_gas: e.signing.max_priority_fee_per_gas,
        gas_price: e.signing.gas_price,
        to: e.to,
        value: e.value,
        data: &e.data,
    })
    .ok_or_else(|| {
        reject(
            "payload_recompute_failed",
            format!("chain {:?} is not an EVM custody chain", e.chain),
        )
    })?;
    if !payloads_equal(&hex0x(hash.as_slice()), prepare_key) {
        return Err(reject(
            "payload_binding_mismatch",
            "recomputed EVM signing hash does not equal the signing payload (TK-01)",
        ));
    }
    // TK-02: bound the max gas spend. EIP-1559 uses max_fee_per_gas; legacy uses
    // gas_price.
    let per_gas = match e.chain.tx_type() {
        Some(EvmTxType::Legacy) => e.signing.gas_price,
        _ => e.signing.max_fee_per_gas,
    };
    let max_spend = u128::from(e.signing.gas_limit).saturating_mul(per_gas);
    enforce_fee_cap(e.chain, max_spend)
}

fn verify_account(a: &AccountPrepared, prepare_key: &str) -> Result<(), Rejection> {
    let recomputed = recompute_account_payload(a)?;
    if !payloads_equal(&recomputed, prepare_key) {
        return Err(reject(
            "payload_binding_mismatch",
            format!(
                "recomputed {:?} signing payload does not equal the signing request (TK-01)",
                a.chain
            ),
        ));
    }
    if let Some(fee) = a.signing.declared_fee_base_units() {
        enforce_fee_cap(a.chain, fee)?;
    }
    Ok(())
}

fn recompute_account_payload(a: &AccountPrepared) -> Result<String, Rejection> {
    match &a.signing {
        AccountSigning::Cosmos { .. } => recompute_cosmos(a),
        AccountSigning::Xrp { .. } => recompute_xrp(a),
        AccountSigning::Tron { .. } => recompute_tron(a),
        AccountSigning::Solana { .. } => recompute_solana(a),
    }
}

fn recompute_cosmos(a: &AccountPrepared) -> Result<String, Rejection> {
    let AccountSigning::Cosmos {
        from_address,
        cosmos_chain_id,
        account_number,
        sequence,
        denom,
        fee_amount,
        gas_limit,
    } = &a.signing
    else {
        return Err(reject("payload_recompute_failed", "not a cosmos signing"));
    };
    let doc = CosmosSendSignDoc {
        account_number: &account_number.to_string(),
        chain_id: cosmos_chain_id,
        fee_amount: &fee_amount.to_string(),
        gas: &gas_limit.to_string(),
        memo: &a.memo,
        from_address,
        to_address: &a.to_address,
        amount: &a.amount_dec,
        denom,
    };
    let digest = doc
        .sign_bytes_sha256(&sequence.to_string())
        .map_err(|e| reject("payload_recompute_failed", format!("cosmos amino: {e}")))?;
    Ok(hex0x(&digest))
}

fn recompute_xrp(a: &AccountPrepared) -> Result<String, Rejection> {
    let AccountSigning::Xrp {
        account_address,
        signing_pub_key,
        sequence,
        last_ledger_sequence,
        fee_drops,
    } = &a.signing
    else {
        return Err(reject("payload_recompute_failed", "not an xrp signing"));
    };
    let amount_drops = a
        .amount_dec
        .parse::<u64>()
        .map_err(|e| reject("payload_recompute_failed", format!("xrp amount: {e}")))?;
    let fee = u64::try_from(*fee_drops)
        .map_err(|_| reject("payload_recompute_failed", "xrp fee > u64 drops"))?;
    let account = decode_classic_address(account_address)
        .map_err(|e| reject("payload_recompute_failed", format!("xrp account: {e}")))?;
    let destination = decode_classic_address(&a.to_address)
        .map_err(|e| reject("payload_recompute_failed", format!("xrp dest: {e}")))?;
    let pubkey: [u8; 33] = signing_pub_key.as_slice().try_into().map_err(|_| {
        reject(
            "payload_recompute_failed",
            "xrp SigningPubKey is not 33 bytes",
        )
    })?;
    let body = PaymentBody {
        account,
        destination,
        amount_drops,
        fee_drops: fee,
        sequence: *sequence,
        last_ledger_sequence: Some(*last_ledger_sequence),
        network_id: None,
        memo: a.memo.clone().into_bytes(),
    };
    let serialized = serialize_single_sign(&body, &pubkey)
        .map_err(|e| reject("payload_recompute_failed", format!("xrp serialize: {e}")))?;
    Ok(hex0x(&single_sign_digest(&serialized)))
}

fn recompute_tron(a: &AccountPrepared) -> Result<String, Rejection> {
    let AccountSigning::Tron {
        owner_address,
        asset,
        contract_address,
        ref_block_bytes,
        ref_block_hash,
        expiration,
        timestamp,
        fee_limit,
        permission_id,
    } = &a.signing
    else {
        return Err(reject("payload_recompute_failed", "not a tron signing"));
    };
    let amount = a
        .amount_dec
        .parse::<u64>()
        .map_err(|e| reject("payload_recompute_failed", format!("tron amount: {e}")))?;
    let owner = decode_base58check(owner_address)
        .map_err(|e| reject("payload_recompute_failed", format!("tron owner: {e}")))?;
    let tapos = Tapos {
        ref_block_bytes: *ref_block_bytes,
        ref_block_hash: *ref_block_hash,
        expiration: *expiration,
        timestamp: *timestamp,
        fee_limit: *fee_limit,
        memo: Vec::new(),
        permission_id: *permission_id,
    };
    let raw_data = match asset {
        TronAssetKind::Trx => {
            let to = decode_base58check(&a.to_address)
                .map_err(|e| reject("payload_recompute_failed", format!("tron dest: {e}")))?;
            build_trx_raw_data(&TrxTransfer { owner, to, amount }, &tapos)
        }
        TronAssetKind::Usdt => {
            let contract_str = contract_address.as_deref().ok_or_else(|| {
                reject("payload_recompute_failed", "tron usdt: no contract address")
            })?;
            let contract = decode_base58check(contract_str)
                .map_err(|e| reject("payload_recompute_failed", format!("tron contract: {e}")))?;
            let to_evm20 = decode_to_evm20(&a.to_address)
                .map_err(|e| reject("payload_recompute_failed", format!("tron dest evm20: {e}")))?;
            build_usdt_raw_data(
                &UsdtTransfer {
                    owner,
                    contract,
                    to_evm20,
                    amount,
                },
                &tapos,
            )
        }
    };
    Ok(hex0x(&txid(&raw_data)))
}

fn recompute_solana(a: &AccountPrepared) -> Result<String, Rejection> {
    let AccountSigning::Solana {
        from_pubkey,
        recent_blockhash,
    } = &a.signing
    else {
        return Err(reject("payload_recompute_failed", "not a solana signing"));
    };
    let lamports = a
        .amount_dec
        .parse::<u64>()
        .map_err(|e| reject("payload_recompute_failed", format!("solana amount: {e}")))?;
    let from = Pubkey::new(*from_pubkey);
    let destination = Pubkey::from_base58(&a.to_address)
        .map_err(|e| reject("payload_recompute_failed", format!("solana dest: {e}")))?;
    let (_message, bytes) =
        build_transfer_message(from, destination, lamports, &a.memo, *recent_blockhash)
            .map_err(|e| reject("payload_recompute_failed", format!("solana message: {e}")))?;
    Ok(hex0x(&bytes))
}

fn verify_btc(ctx: &BindContext, prepare_key: &str) -> Result<(), Rejection> {
    let tx = &ctx.psbt.unsigned_tx;
    let mut cache = SighashCache::new(tx);
    let mut sum_in: u64 = 0;
    let mut matched = false;
    for (i, input) in ctx.psbt.inputs.iter().enumerate() {
        let wu = input.witness_utxo.as_ref().ok_or_else(|| {
            reject(
                "payload_recompute_failed",
                format!("BTC input {i} has no witness_utxo (cannot recompute sighash)"),
            )
        })?;
        sum_in = sum_in.saturating_add(wu.value.to_sat());
        let sighash = cache
            .p2wpkh_signature_hash(i, &wu.script_pubkey, wu.value, EcdsaSighashType::All)
            .map_err(|e| {
                reject(
                    "payload_recompute_failed",
                    format!("BTC sighash input {i}: {e}"),
                )
            })?;
        if payloads_equal(&hex0x(&sighash.to_byte_array()), prepare_key) {
            matched = true;
        }
    }
    if !matched {
        return Err(reject(
            "payload_binding_mismatch",
            "signing payload is not a BIP-143 sighash of any PSBT input (TK-01)",
        ));
    }
    // TK-02: implied miner fee = Σinputs − Σoutputs must be within the cap.
    let sum_out = tx
        .output
        .iter()
        .fold(0u64, |acc, o| acc.saturating_add(o.value.to_sat()));
    let implied_fee = sum_in
        .checked_sub(sum_out)
        .ok_or_else(|| reject("btc_fee_underflow", "BTC outputs exceed inputs"))?;
    enforce_fee_cap(ctx.chain, u128::from(implied_fee))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]
    use super::*;
    use bitcoin::psbt::Psbt;
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid, Witness,
    };
    use xindex_custody_core::prepare::AccountPrepared;

    const MEMO: &str = "=:ETH.USDT:0xrecipient:990000";

    fn cosmos_prepared(fee_amount: u128) -> AccountPrepared {
        AccountPrepared {
            chain: ChainId::Gaia,
            to_address: "cosmos1asgardvault".to_string(),
            amount_dec: "5000000".to_string(),
            memo: MEMO.to_string(),
            signing: AccountSigning::Cosmos {
                from_address: "cosmos1custody".to_string(),
                cosmos_chain_id: "cosmoshub-4".to_string(),
                account_number: 42,
                sequence: 7,
                denom: "uatom".to_string(),
                fee_amount,
                gas_limit: 200_000,
            },
            ric: None,
            spend_identity: 7u64.to_be_bytes().to_vec(),
        }
    }

    /// The recompute reproduces the exact amino sign-bytes the executor signs,
    /// so an honest cosmos spend under its true key passes the payload check.
    #[test]
    fn cosmos_recompute_matches_key() {
        let a = cosmos_prepared(5_000);
        let key = recompute_account_payload(&a).expect("recompute");
        assert!(verify_payload_and_fee(&PreparedSpend::Account(a), &key).is_ok());
    }

    /// TK-02: an honest-payload cosmos spend whose fee exceeds the per-chain cap
    /// is rejected (Gaia cap = 1e6 uatom).
    #[test]
    fn cosmos_fee_over_cap_rejects() {
        let a = cosmos_prepared(2_000_000); // > 1_000_000 cap
        let key = recompute_account_payload(&a).expect("recompute");
        let err = verify_payload_and_fee(&PreparedSpend::Account(a), &key).expect_err("cap");
        assert_eq!(err.0, "fee_exceeds_cap");
    }

    /// TK-01: a cosmos spend whose signing payload is NOT its recomputed hash is
    /// rejected before any bind.
    #[test]
    fn cosmos_wrong_payload_rejects() {
        let a = cosmos_prepared(5_000);
        let err =
            verify_payload_and_fee(&PreparedSpend::Account(a), "0xnotthehash").expect_err("bind");
        assert_eq!(err.0, "payload_binding_mismatch");
    }

    fn p2wpkh_spk(tag: u8) -> ScriptBuf {
        let mut v = vec![0x00u8, 0x14];
        v.extend_from_slice(&[tag; 20]);
        ScriptBuf::from_bytes(v)
    }

    /// Build a single-input P2WPKH redeem PSBT and its input-0 sighash key.
    fn btc_ctx(input_value: u64, payout: u64, change: u64) -> (BindContext, String) {
        let custody = p2wpkh_spk(0xcc);
        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(payout),
                    script_pubkey: p2wpkh_spk(0xaa),
                },
                TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: custody.clone(),
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("psbt");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(input_value),
            script_pubkey: custody.clone(),
        });
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .p2wpkh_signature_hash(
                0,
                &custody,
                Amount::from_sat(input_value),
                EcdsaSighashType::All,
            )
            .expect("sighash")
            .to_byte_array();
        let key = hex0x(&sighash);
        (
            BindContext {
                chain: ChainId::Btc,
                psbt,
                ric: None,
                acc: None,
            },
            key,
        )
    }

    /// TK-01: the recompute matches input-0's BIP-143 sighash under an honest key
    /// and an in-cap implied fee.
    #[test]
    fn btc_recompute_matches_input_sighash() {
        let (ctx, key) = btc_ctx(200_000, 150_000, 49_000); // implied fee 1_000
        assert!(verify_btc(&ctx, &key).is_ok());
    }

    /// TK-01: a BTC payload that is not any input's sighash is rejected.
    #[test]
    fn btc_wrong_payload_rejects() {
        let (ctx, _key) = btc_ctx(200_000, 150_000, 49_000);
        let err = verify_btc(&ctx, "0xdeadbeef").expect_err("bind");
        assert_eq!(err.0, "payload_binding_mismatch");
    }

    /// TK-02: an implied miner fee above the per-chain cap is rejected (BTC cap
    /// = 1e6 sats).
    #[test]
    fn btc_implied_fee_over_cap_rejects() {
        // inputs 3_000_000 − outputs 500_000 = 2_500_000 sats implied fee > 1e6.
        let (ctx, key) = btc_ctx(3_000_000, 400_000, 100_000);
        let err = verify_btc(&ctx, &key).expect_err("cap");
        assert_eq!(err.0, "fee_exceeds_cap");
    }
}
