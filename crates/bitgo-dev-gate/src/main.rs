//! Offline-first `BitGo` Testnet4 capture validator for the Xindex BTC path.
//!
//! This binary never creates a wallet, generates a key, signs, broadcasts, or
//! calls `BitGo`. It validates the internal consistency of a caller-supplied
//! capture and checks that the unsigned PSBT, user-signed artifact, and final
//! transaction preserve the exact Xindex/THORChain input and ordered-output
//! policy. It cannot authenticate that the supplied role keys, responses, or
//! identifiers originated from `BitGo`; live corroboration therefore remains
//! blocked until an independently pinned provider envelope is implemented.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{keccak256, U256};
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bitcoin::consensus::deserialize;
use bitcoin::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::psbt::Psbt;
use bitcoin::script::Builder;
use bitcoin::{Address, Network, OutPoint, PublicKey, ScriptBuf, Transaction, Txid};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use xindex_bitgo_adapter::{
    validate_build_request as validate_adapter_build_request,
    validate_final_transaction as validate_adapter_final_transaction,
    validate_unsigned as validate_adapter_unsigned,
    validate_user_signed_psbt as validate_adapter_user_psbt,
    validate_user_signed_transaction as validate_adapter_user_transaction, BitGoCoin,
    BuildRecipient as AdapterRecipient, BuildRequest as AdapterBuildRequest, ChangeAddressType,
    InputPolicy as AdapterInputPolicy, SpendPolicy as AdapterSpendPolicy, TxFormat,
    WalletPolicy as AdapterWalletPolicy,
};
use xindex_custody_core::btc_bind::{
    bind_outputs_to_cert, canonical_op_return_script, parse_canonical_op_return_payload,
};
use xindex_custody_core::gates::CertifiedSpend;

const EVIDENCE_SCHEMA_VERSION: u32 = 2;
const REPORT_SCHEMA_VERSION: u32 = 1;
const PROVIDER: &str = "bitgo";
const ENVIRONMENT: &str = "test";
const COIN: &str = "tbtc4";
const MAX_MEMO_BYTES: usize = 80;

#[derive(Debug, Parser)]
#[command(
    name = "xindex-bitgo-dev-gate",
    about = "Validate captured BitGo Testnet4 PSBT/signing evidence without using keys or a network"
)]
struct Args {
    /// Private, caller-supplied JSON capture following the evidence template.
    #[arg(long)]
    evidence: PathBuf,
    /// Also write the machine-readable report to this path.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum GateStatus {
    Pass,
    Fail,
    Blocked,
}

#[derive(Debug, Serialize)]
struct Check {
    id: &'static str,
    required: bool,
    status: GateStatus,
    detail: String,
}

impl Check {
    fn pass(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            required: true,
            status: GateStatus::Pass,
            detail: detail.into(),
        }
    }

    fn fail(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            required: true,
            status: GateStatus::Fail,
            detail: detail.into(),
        }
    }

    fn blocked(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            required: true,
            status: GateStatus::Blocked,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct GateReport {
    schema_version: u32,
    provider: &'static str,
    environment: &'static str,
    coin: &'static str,
    wallet_id: String,
    generated_at_unix: u64,
    scope: &'static str,
    evidence_sha256: String,
    overall: GateStatus,
    checks: Vec<Check>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema_version: u32,
    provider: String,
    environment: String,
    coin: String,
    wallet: WalletEvidence,
    build_request: BuildRequestEvidence,
    expected: ExpectedTransaction,
    unsigned_psbt: EncodedArtifact,
    #[serde(default)]
    user_signed_artifact: Option<SignedArtifact>,
    #[serde(default)]
    final_transaction_hex: Option<String>,
    live: LiveEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletEvidence {
    wallet_id: String,
    wallet_type: String,
    multisig_type: String,
    custody_model: String,
    address_type: String,
    address_chain_code: u32,
    m: u32,
    n: u32,
    user_pubkey_hex: String,
    backup_pubkey_hex: String,
    bitgo_pubkey_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRequestEvidence {
    tx_format: String,
    no_split_change: bool,
    change_address_type: String,
    is_replaceable_by_fee: bool,
    sequence_id: String,
    change_address: String,
    unspents: Vec<String>,
    recipients: Vec<RecipientEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientEvidence {
    address: String,
    amount_sats: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedTransaction {
    inputs: Vec<ExpectedInput>,
    payout_script_pubkey_hex: String,
    payout_sats: u64,
    vin0_script_pubkey_hex: String,
    memo_hex: String,
    max_fee_sats: u64,
    require_change: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedInput {
    outpoint: String,
    value_sats: u64,
    script_pubkey_hex: String,
    witness_script_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedArtifact {
    encoding: String,
    data: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedArtifact {
    format: String,
    encoding: String,
    data: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveEvidence {
    wallet_lookup_corroborated: bool,
    build_correlation_id: String,
    build_response_captured: bool,
    bitgo_cosign_completed: bool,
    transfer_id: String,
    final_transaction_id: String,
}

#[derive(Debug)]
struct ParsedExpected {
    inputs: Vec<ParsedInput>,
    payout_spk: ScriptBuf,
    vin0_spk: ScriptBuf,
    memo: Vec<u8>,
    memo_spk: ScriptBuf,
}

#[derive(Debug)]
struct ParsedInput {
    outpoint: OutPoint,
    value_sats: u64,
    script_pubkey: ScriptBuf,
    witness_script: ScriptBuf,
}

#[derive(Debug)]
struct ParsedWallet {
    user: PublicKey,
    backup: PublicKey,
    bitgo: PublicKey,
}

fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>> {
    alloy_primitives::hex::decode(value.trim_start_matches("0x"))
        .with_context(|| format!("{label} is not valid hex"))
}

fn parse_wallet(wallet: &WalletEvidence) -> Result<ParsedWallet> {
    if wallet.wallet_id.trim().is_empty()
        || !wallet.wallet_type.eq_ignore_ascii_case("hot")
        || !wallet.multisig_type.eq_ignore_ascii_case("onchain")
        || !wallet.custody_model.eq_ignore_ascii_case("self-custody")
        || !wallet.address_type.eq_ignore_ascii_case("p2wsh")
        || wallet.address_chain_code != 20
        || wallet.m != 2
        || wallet.n != 3
    {
        anyhow::bail!(
            "wallet must be self-custody/hot/onchain 2-of-3 with address_type=p2wsh and external chain code 20"
        );
    }

    let user = PublicKey::from_str(&wallet.user_pubkey_hex)
        .context("wallet.user_pubkey_hex is not a compressed Bitcoin public key")?;
    let backup = PublicKey::from_str(&wallet.backup_pubkey_hex)
        .context("wallet.backup_pubkey_hex is not a compressed Bitcoin public key")?;
    let bitgo = PublicKey::from_str(&wallet.bitgo_pubkey_hex)
        .context("wallet.bitgo_pubkey_hex is not a compressed Bitcoin public key")?;
    if !user.compressed || !backup.compressed || !bitgo.compressed {
        anyhow::bail!("wallet role keys must all be compressed public keys");
    }
    if user == backup || user == bitgo || backup == bitgo {
        anyhow::bail!("wallet user, backup and BitGo public keys must be distinct");
    }
    Ok(ParsedWallet {
        user,
        backup,
        bitgo,
    })
}

fn multisig_witness_script(pubkeys: &[PublicKey; 3]) -> ScriptBuf {
    Builder::new()
        .push_int(2)
        .push_key(&pubkeys[0])
        .push_key(&pubkeys[1])
        .push_key(&pubkeys[2])
        .push_int(3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

fn ordered_wallet_keys_for_script(
    wallet: &ParsedWallet,
    witness_script: &ScriptBuf,
) -> Option<[PublicKey; 3]> {
    const PERMUTATIONS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let keys = [wallet.user, wallet.backup, wallet.bitgo];
    PERMUTATIONS.into_iter().find_map(|order| {
        let ordered = [keys[order[0]], keys[order[1]], keys[order[2]]];
        (multisig_witness_script(&ordered) == *witness_script).then_some(ordered)
    })
}

fn parse_expected(expected: &ExpectedTransaction, wallet: &ParsedWallet) -> Result<ParsedExpected> {
    if expected.inputs.len() != 1 {
        anyhow::bail!(
            "the reviewed BitGo/THORChain qualification profile requires exactly one VIN0 input, found {}",
            expected.inputs.len()
        );
    }
    if !expected.require_change {
        anyhow::bail!("the qualification must require and exercise a real VIN0 change output");
    }
    let inputs = expected
        .inputs
        .iter()
        .map(|input| {
            let outpoint = parse_outpoint(&input.outpoint)?;
            let script_pubkey = ScriptBuf::from_bytes(decode_hex(
                "expected input script_pubkey_hex",
                &input.script_pubkey_hex,
            )?);
            let witness_script = ScriptBuf::from_bytes(decode_hex(
                "expected input witness_script_hex",
                &input.witness_script_hex,
            )?);
            if !script_pubkey.is_p2wsh()
                || ScriptBuf::new_p2wsh(&witness_script.wscript_hash()) != script_pubkey
            {
                anyhow::bail!(
                    "expected input witness script does not commit to its native P2WSH scriptPubKey"
                );
            }
            ordered_wallet_keys_for_script(wallet, &witness_script)
                .context("expected witness script is not the captured user/backup/BitGo 2-of-3")?;
            Ok(ParsedInput {
                outpoint,
                value_sats: input.value_sats,
                script_pubkey,
                witness_script,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let payout_spk = ScriptBuf::from_bytes(decode_hex(
        "payout_script_pubkey_hex",
        &expected.payout_script_pubkey_hex,
    )?);
    let vin0_spk = ScriptBuf::from_bytes(decode_hex(
        "vin0_script_pubkey_hex",
        &expected.vin0_script_pubkey_hex,
    )?);
    if vin0_spk != inputs[0].script_pubkey {
        anyhow::bail!(
            "expected VIN0 script does not equal the independently captured input script"
        );
    }
    if expected.payout_sats == 0 || expected.max_fee_sats == 0 {
        anyhow::bail!("expected payout and max fee must both be non-zero");
    }
    let memo = decode_hex("memo_hex", &expected.memo_hex)?;
    if memo.is_empty() || memo.len() > MAX_MEMO_BYTES {
        anyhow::bail!(
            "memo must contain 1..={MAX_MEMO_BYTES} bytes, found {}",
            memo.len()
        );
    }
    let memo_spk =
        canonical_op_return_script(&memo).context("memo is not a canonical non-empty data push")?;
    Ok(ParsedExpected {
        inputs,
        payout_spk,
        vin0_spk,
        memo,
        memo_spk,
    })
}

fn adapter_policy(
    evidence: &Evidence,
    wallet: &ParsedWallet,
    parsed: &ParsedExpected,
) -> Result<AdapterSpendPolicy> {
    let adapter_wallet = AdapterWalletPolicy::new(
        BitGoCoin::Tbtc4,
        evidence.wallet.wallet_id.clone(),
        evidence.wallet.address_chain_code,
        wallet.user,
        wallet.backup,
        wallet.bitgo,
        parsed.inputs[0].witness_script.clone(),
    )?;
    let input = AdapterInputPolicy::new(parsed.inputs[0].outpoint, parsed.inputs[0].value_sats)?;
    Ok(AdapterSpendPolicy::new(
        adapter_wallet,
        input,
        parsed.payout_spk.clone(),
        evidence.expected.payout_sats,
        parsed.memo.clone(),
        evidence.expected.max_fee_sats,
        evidence.build_request.sequence_id.clone(),
        evidence.expected.require_change,
    )?)
}

fn parse_outpoint(value: &str) -> Result<OutPoint> {
    let (txid, vout) = value
        .rsplit_once(':')
        .with_context(|| format!("outpoint {value:?} is not txid:vout"))?;
    Ok(OutPoint {
        txid: Txid::from_str(txid).with_context(|| format!("invalid txid in {value:?}"))?,
        vout: vout
            .parse::<u32>()
            .with_context(|| format!("invalid vout in {value:?}"))?,
    })
}

fn decode_psbt(artifact: &EncodedArtifact) -> Result<Psbt> {
    let bytes = decode_artifact("PSBT", &artifact.encoding, &artifact.data)?;
    Psbt::deserialize(&bytes).context("invalid BIP-174 PSBT")
}

fn decode_artifact(label: &str, encoding: &str, data: &str) -> Result<Vec<u8>> {
    match encoding {
        "base64" => B64
            .decode(data.trim())
            .with_context(|| format!("invalid {label} base64")),
        "hex" => decode_hex(label, data),
        other => anyhow::bail!("unsupported {label} encoding {other:?}; expected base64 or hex"),
    }
}

fn expected_address(script: &ScriptBuf) -> Result<String> {
    Address::from_script(script, Network::Testnet)
        .context("scriptPubKey cannot be represented as a Testnet4 address")
        .map(|address| address.to_string())
}

fn validate_identity(evidence: &Evidence) -> Check {
    let ok = evidence.schema_version == EVIDENCE_SCHEMA_VERSION
        && evidence.provider == PROVIDER
        && evidence.environment == ENVIRONMENT
        && evidence.coin == COIN;
    if ok {
        Check::pass(
            "identity",
            "schema/provider/environment/coin are pinned to BitGo Testnet4",
        )
    } else {
        Check::fail(
            "identity",
            format!(
                "expected schema={EVIDENCE_SCHEMA_VERSION}, provider={PROVIDER}, environment={ENVIRONMENT}, coin={COIN}"
            ),
        )
    }
}

fn validate_wallet(wallet: &WalletEvidence) -> Check {
    match parse_wallet(wallet) {
        Ok(_) => Check::pass(
            "wallet_topology",
            "captured wallet is self-custody hot native-P2WSH on-chain 2-of-3 with distinct user, backup and BitGo keys",
        ),
        Err(error) => Check::fail("wallet_topology", error.to_string()),
    }
}

fn validate_build_request(
    request: &BuildRequestEvidence,
    expected: &ExpectedTransaction,
    parsed: &ParsedExpected,
    adapter_policy: &AdapterSpendPolicy,
) -> Check {
    let payout_address = match expected_address(&parsed.payout_spk) {
        Ok(address) => address,
        Err(error) => return Check::fail("build_request", error.to_string()),
    };
    let change_address = match expected_address(&parsed.vin0_spk) {
        Ok(address) => address,
        Err(error) => return Check::fail("build_request", error.to_string()),
    };
    let expected_unspents: Vec<String> = expected
        .inputs
        .iter()
        .map(|input| input.outpoint.clone())
        .collect();
    let op_return_address = format!(
        "scriptPubKey:{}",
        alloy_primitives::hex::encode(parsed.memo_spk.as_bytes())
    );
    let recipients_ok = request.recipients.len() == 2
        && request.recipients[0].address == payout_address
        && request.recipients[0].amount_sats == expected.payout_sats
        && request.recipients[1]
            .address
            .eq_ignore_ascii_case(&op_return_address)
        && request.recipients[1].amount_sats == 0;
    let ok = request.tx_format.eq_ignore_ascii_case("psbt")
        && request.no_split_change
        && request.change_address_type.eq_ignore_ascii_case("p2wsh")
        && !request.is_replaceable_by_fee
        && !request.sequence_id.trim().is_empty()
        && request.change_address == change_address
        && request.unspents == expected_unspents
        && recipients_ok;
    let adapter_request = AdapterBuildRequest {
        recipients: request
            .recipients
            .iter()
            .map(|recipient| AdapterRecipient {
                address: recipient.address.clone(),
                amount: recipient.amount_sats.to_string(),
            })
            .collect(),
        sequence_id: request.sequence_id.clone(),
        no_split_change: request.no_split_change,
        unspents: request.unspents.clone(),
        change_address: request.change_address.clone(),
        change_address_type: ChangeAddressType::P2wsh,
        tx_format: TxFormat::Psbt,
        is_replaceable_by_fee: request.is_replaceable_by_fee,
    };
    let adapter_result = ok
        .then(|| validate_adapter_build_request(&adapter_request, adapter_policy))
        .transpose();
    if ok && adapter_result == Ok(Some(())) {
        Check::pass(
            "build_request",
            "sequence, explicit inputs, VIN0 P2WSH change, non-RBF, noSplitChange, payout, OP_RETURN and PSBT format match the reusable adapter payload",
        )
    } else {
        let detail = adapter_result.err().map_or_else(
            || {
                "captured BitGo build parameters do not exactly match the expected Xindex spend"
                    .to_string()
            },
            |error| error.to_string(),
        );
        Check::fail("build_request", detail)
    }
}

fn validate_inputs(
    psbt: &Psbt,
    parsed: &ParsedExpected,
    adapter_policy: &AdapterSpendPolicy,
) -> Check {
    if psbt.unsigned_tx.input.len() != parsed.inputs.len()
        || psbt.inputs.len() != parsed.inputs.len()
    {
        return Check::fail(
            "inputs",
            format!(
                "PSBT has {} tx inputs/{} metadata inputs; expected {}",
                psbt.unsigned_tx.input.len(),
                psbt.inputs.len(),
                parsed.inputs.len()
            ),
        );
    }
    for (index, (expected, txin)) in parsed
        .inputs
        .iter()
        .zip(&psbt.unsigned_tx.input)
        .enumerate()
    {
        if txin.previous_output != expected.outpoint {
            return Check::fail(
                "inputs",
                format!("VIN/input order mismatch at index {index}"),
            );
        }
        if txin.sequence.is_rbf() {
            return Check::fail("inputs", format!("input {index} opts into replace-by-fee"));
        }
        if !txin.script_sig.is_empty() {
            return Check::fail(
                "inputs",
                format!("input {index} is not a native-P2WSH input (scriptSig is non-empty)"),
            );
        }
        let Some(witness_utxo) = psbt.inputs[index].witness_utxo.as_ref() else {
            return Check::fail("inputs", format!("input {index} has no witness_utxo"));
        };
        if witness_utxo.value.to_sat() != expected.value_sats
            || witness_utxo.script_pubkey != expected.script_pubkey
        {
            return Check::fail(
                "inputs",
                format!(
                    "input {index} witness_utxo value/script does not match independent evidence"
                ),
            );
        }
        let Some(witness_script) = psbt.inputs[index].witness_script.as_ref() else {
            return Check::fail(
                "inputs",
                format!("input {index} has no P2WSH witness_script"),
            );
        };
        if witness_script != &expected.witness_script
            || !witness_utxo.script_pubkey.is_p2wsh()
            || ScriptBuf::new_p2wsh(&witness_script.wscript_hash()) != witness_utxo.script_pubkey
        {
            return Check::fail(
                "inputs",
                format!(
                    "input {index} witness_script is not byte-exact to independent evidence or does not commit to its P2WSH scriptPubKey"
                ),
            );
        }
        let metadata = &psbt.inputs[index];
        if !metadata.partial_sigs.is_empty()
            || metadata.final_script_sig.is_some()
            || metadata.final_script_witness.is_some()
        {
            return Check::fail(
                "inputs",
                format!("unsigned PSBT input {index} already contains signature/finalization data"),
            );
        }
    }
    if parsed.inputs[0].script_pubkey != parsed.vin0_spk {
        return Check::fail(
            "inputs",
            "expected VIN0 script does not equal input[0] witness_utxo script",
        );
    }
    if let Err(error) = validate_adapter_unsigned(psbt, adapter_policy) {
        return Check::fail("inputs", error.to_string());
    }
    Check::pass(
        "inputs",
        "single VIN0 input, order, value, exact 2-of-3 P2WSH script, non-RBF sequence and unsigned state match independent evidence",
    )
}

fn validate_layout(psbt: &Psbt, expected: &ExpectedTransaction, parsed: &ParsedExpected) -> Check {
    if expected.require_change && psbt.unsigned_tx.output.len() != 3 {
        return Check::fail(
            "thorchain_layout",
            "qualification capture must exercise a real VOUT1 change output",
        );
    }
    let outputs = &psbt.unsigned_tx.output;
    if outputs.first().map(|output| &output.script_pubkey) != Some(&parsed.payout_spk) {
        return Check::fail(
            "thorchain_layout",
            "payout scriptPubKey is not byte-exact to independent evidence",
        );
    }
    let Some(memo_output) = outputs.last() else {
        return Check::fail("thorchain_layout", "transaction has no OP_RETURN output");
    };
    match parse_canonical_op_return_payload(&memo_output.script_pubkey) {
        Ok(payload) if payload.as_ref() == parsed.memo => {}
        Ok(_) => {
            return Check::fail(
                "thorchain_layout",
                "OP_RETURN payload is not byte-exact to independent evidence",
            );
        }
        Err(error) => {
            return Check::fail(
                "thorchain_layout",
                format!("OP_RETURN script is non-canonical: {error}"),
            );
        }
    }
    let certified = CertifiedSpend {
        amount: U256::from(expected.payout_sats),
        immediate_target_hash: keccak256(parsed.payout_spk.as_bytes()),
        memo_hash: keccak256(&parsed.memo),
        mismatch_code: "bitgo_thorchain_mismatch",
    };
    match bind_outputs_to_cert(psbt, &parsed.vin0_spk, &certified) {
        Ok(()) => Check::pass(
            "thorchain_layout",
            "VOUT0=payout, VOUT1=VIN0 change and VOUT2=exact zero-value OP_RETURN",
        ),
        Err(error) => Check::fail("thorchain_layout", error.message),
    }
}

fn validate_fee(psbt: &Psbt, expected: &ExpectedTransaction) -> Check {
    let sum_in = psbt.inputs.iter().try_fold(0u64, |sum, input| {
        input
            .witness_utxo
            .as_ref()
            .and_then(|utxo| sum.checked_add(utxo.value.to_sat()))
    });
    let sum_out = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()));
    let fee = sum_in
        .zip(sum_out)
        .and_then(|(inputs, outputs)| inputs.checked_sub(outputs));
    match fee {
        Some(value) if value > 0 && value <= expected.max_fee_sats => Check::pass(
            "fee",
            format!(
                "implied miner fee {value} sats is within cap {}",
                expected.max_fee_sats
            ),
        ),
        Some(0) => Check::fail("fee", "implied miner fee is zero"),
        Some(value) => Check::fail(
            "fee",
            format!(
                "implied miner fee {value} exceeds cap {}",
                expected.max_fee_sats
            ),
        ),
        None => Check::fail("fee", "cannot compute a non-negative bounded PSBT fee"),
    }
}

fn validate_user_signed(
    unsigned: &Psbt,
    signed: Option<&SignedArtifact>,
    adapter_policy: &AdapterSpendPolicy,
) -> Check {
    let Some(artifact) = signed else {
        return Check::blocked(
            "user_signature_preservation",
            "no user-signed BitGo PSBT or half-signed transaction capture supplied",
        );
    };
    match artifact.format.as_str() {
        "psbt" => {
            let encoded = EncodedArtifact {
                encoding: artifact.encoding.clone(),
                data: artifact.data.clone(),
            };
            let signed = match decode_psbt(&encoded) {
                Ok(psbt) => psbt,
                Err(error) => return Check::fail("user_signature_preservation", error.to_string()),
            };
            if let Err(error) = validate_adapter_user_psbt(unsigned, &signed, adapter_policy) {
                return Check::fail("user_signature_preservation", error.to_string());
            }
            Check::pass(
                "user_signature_preservation",
                "user-signed PSBT preserves the exact policy metadata and carries one valid SIGHASH_ALL signature from the captured user key per input",
            )
        }
        "transaction" => {
            let bytes = match decode_artifact(
                "half-signed transaction",
                &artifact.encoding,
                &artifact.data,
            ) {
                Ok(bytes) => bytes,
                Err(error) => return Check::fail("user_signature_preservation", error.to_string()),
            };
            let half_signed: Transaction = match deserialize(&bytes) {
                Ok(tx) => tx,
                Err(error) => {
                    return Check::fail(
                        "user_signature_preservation",
                        format!("invalid half-signed Bitcoin transaction: {error}"),
                    )
                }
            };
            if let Err(error) =
                validate_adapter_user_transaction(unsigned, &half_signed, adapter_policy)
            {
                return Check::fail("user_signature_preservation", error.to_string());
            }
            Check::pass(
                "user_signature_preservation",
                "half-signed transaction preserves the unsigned skeleton and carries exactly one valid user SIGHASH_ALL signature per input",
            )
        }
        other => Check::fail(
            "user_signature_preservation",
            format!("unsupported user-signed format {other:?}; expected psbt or transaction"),
        ),
    }
}

fn validate_final_transaction(
    unsigned: &Psbt,
    final_hex: Option<&str>,
    expected_txid: &str,
    adapter_policy: &AdapterSpendPolicy,
) -> Check {
    let Some(final_hex) = final_hex else {
        return Check::blocked(
            "bitgo_cosign_preservation",
            "no BitGo-cosigned final transaction capture supplied",
        );
    };
    let bytes = match decode_hex("final_transaction_hex", final_hex) {
        Ok(bytes) => bytes,
        Err(error) => return Check::fail("bitgo_cosign_preservation", error.to_string()),
    };
    let final_tx: Transaction = match deserialize(&bytes) {
        Ok(tx) => tx,
        Err(error) => {
            return Check::fail(
                "bitgo_cosign_preservation",
                format!("invalid final Bitcoin transaction: {error}"),
            )
        }
    };
    let expected_txid = match Txid::from_str(expected_txid) {
        Ok(txid) => txid,
        Err(error) => {
            return Check::fail(
                "bitgo_cosign_preservation",
                format!("captured BitGo transaction id is invalid: {error}"),
            )
        }
    };
    if let Err(error) =
        validate_adapter_final_transaction(unsigned, &final_tx, expected_txid, adapter_policy)
    {
        return Check::fail("bitgo_cosign_preservation", error.to_string());
    }
    Check::pass(
        "bitgo_cosign_preservation",
        "BitGo finalization preserves the unsigned skeleton and carries exactly the valid user + BitGo SIGHASH_ALL signatures",
    )
}

fn validate_live(live: &LiveEvidence, request: &BuildRequestEvidence) -> Check {
    let claims_complete = live.wallet_lookup_corroborated
        && live.build_response_captured
        && live.bitgo_cosign_completed
        && live.build_correlation_id == request.sequence_id
        && !live.transfer_id.trim().is_empty()
        && !live.final_transaction_id.trim().is_empty();
    if claims_complete {
        Check::blocked(
            "live_corroboration",
            "caller-supplied wallet, build, transfer, cosign and transaction claims lack authenticated provider provenance; format-valid identifiers cannot prove a BitGo Testnet4 interaction",
        )
    } else {
        Check::blocked(
            "live_corroboration",
            "live BitGo wallet/build/cosign corroboration is incomplete",
        )
    }
}

fn evaluate(evidence: &Evidence, evidence_sha256: String) -> GateReport {
    let wallet_id = evidence.wallet.wallet_id.clone();
    let mut checks = vec![
        validate_identity(evidence),
        validate_wallet(&evidence.wallet),
    ];
    let Ok(wallet) = parse_wallet(&evidence.wallet) else {
        return report(checks, evidence_sha256, wallet_id);
    };
    let parsed = match parse_expected(&evidence.expected, &wallet) {
        Ok(parsed) => parsed,
        Err(error) => {
            checks.push(Check::fail("expected_transaction", error.to_string()));
            return report(checks, evidence_sha256, wallet_id);
        }
    };
    let adapter_policy = match adapter_policy(evidence, &wallet, &parsed) {
        Ok(policy) => policy,
        Err(error) => {
            checks.push(Check::fail("expected_transaction", error.to_string()));
            return report(checks, evidence_sha256, wallet_id);
        }
    };
    checks.push(Check::pass(
        "expected_transaction",
        "independent expected inputs, payout, VIN0 and memo form a reusable native-P2WSH adapter policy",
    ));
    checks.push(validate_build_request(
        &evidence.build_request,
        &evidence.expected,
        &parsed,
        &adapter_policy,
    ));
    let unsigned = match decode_psbt(&evidence.unsigned_psbt) {
        Ok(psbt) => psbt,
        Err(error) => {
            checks.push(Check::fail("unsigned_psbt", error.to_string()));
            return report(checks, evidence_sha256, wallet_id);
        }
    };
    checks.push(Check::pass(
        "unsigned_psbt",
        format!(
            "decoded PSBT with txid {}",
            unsigned.unsigned_tx.compute_txid()
        ),
    ));
    checks.push(validate_inputs(&unsigned, &parsed, &adapter_policy));
    checks.push(validate_layout(&unsigned, &evidence.expected, &parsed));
    checks.push(validate_fee(&unsigned, &evidence.expected));
    checks.push(validate_user_signed(
        &unsigned,
        evidence.user_signed_artifact.as_ref(),
        &adapter_policy,
    ));
    checks.push(validate_final_transaction(
        &unsigned,
        evidence.final_transaction_hex.as_deref(),
        &evidence.live.final_transaction_id,
        &adapter_policy,
    ));
    checks.push(validate_live(&evidence.live, &evidence.build_request));
    report(checks, evidence_sha256, wallet_id)
}

fn report(checks: Vec<Check>, evidence_sha256: String, wallet_id: String) -> GateReport {
    let overall = if checks
        .iter()
        .any(|check| check.required && check.status == GateStatus::Fail)
    {
        GateStatus::Fail
    } else if checks
        .iter()
        .any(|check| check.required && check.status == GateStatus::Blocked)
    {
        GateStatus::Blocked
    } else {
        GateStatus::Pass
    };
    GateReport {
        schema_version: REPORT_SCHEMA_VERSION,
        provider: PROVIDER,
        environment: ENVIRONMENT,
        coin: COIN,
        wallet_id,
        generated_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
        scope: "development compatibility only; never production approval",
        evidence_sha256,
        overall,
        checks,
    }
}

fn run(args: &Args) -> Result<(GateReport, Vec<u8>)> {
    let bytes = fs::read(&args.evidence)
        .with_context(|| format!("read evidence {}", args.evidence.display()))?;
    let evidence: Evidence =
        serde_json::from_slice(&bytes).context("decode BitGo evidence JSON")?;
    let report = evaluate(&evidence, format!("{:x}", sha2::Sha256::digest(&bytes)));
    let encoded = serde_json::to_vec_pretty(&report).context("encode gate report")?;
    if let Some(path) = &args.output {
        fs::write(path, &encoded).with_context(|| format!("write report {}", path.display()))?;
    }
    Ok((report, encoded))
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok((report, encoded)) => {
            let _ = io::stdout().lock().write_all(&encoded);
            let _ = io::stdout().lock().write_all(b"\n");
            match report.overall {
                GateStatus::Pass => ExitCode::SUCCESS,
                GateStatus::Fail => ExitCode::FAILURE,
                GateStatus::Blocked => ExitCode::from(2),
            }
        }
        Err(error) => {
            let _ = io::stderr()
                .lock()
                .write_all(format!("xindex-bitgo-dev-gate: {error:#}\n").as_bytes());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::serialize;
    use bitcoin::ecdsa::Signature as BitcoinSignature;
    use bitcoin::hashes::Hash;
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, Sequence, TxIn, TxOut, Witness,
    };
    use xindex_bitgo_adapter::verify_signature_for_key;

    const USER_PUBKEY: &str = "03c10ac628c880629ed0fd2a0563a898f4882baca45e15668a4d3064cf1ea37988";
    const BACKUP_PUBKEY: &str =
        "03e56f84be4460080618ef869bb7b07096880760f748ba23efab533c2359f923bd";
    const BITGO_PUBKEY: &str = "020ae81372264b5eac5c9dc7fe0b9a32bad00771c3a2c71f6e2c971823c3182ed6";

    fn evaluate_fixture(evidence: &Evidence) -> GateReport {
        evaluate(evidence, "11".repeat(32))
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn fixture_wallet() -> ParsedWallet {
        ParsedWallet {
            user: PublicKey::from_str(USER_PUBKEY).expect("user public key"),
            backup: PublicKey::from_str(BACKUP_PUBKEY).expect("backup public key"),
            bitgo: PublicKey::from_str(BITGO_PUBKEY).expect("BitGo public key"),
        }
    }

    fn p2wsh() -> (ScriptBuf, ScriptBuf) {
        let wallet = fixture_wallet();
        let witness_script = multisig_witness_script(&[wallet.user, wallet.backup, wallet.bitgo]);
        (
            ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
            witness_script,
        )
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn fixture_psbt(old_order: bool) -> (Psbt, ScriptBuf, ScriptBuf, Vec<u8>) {
        let (vin0, witness_script) = p2wsh();
        let payout = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xaa; 20]));
        let memo = b"=:ETH.USDT:0xrecipient:990000".to_vec();
        let memo_out = TxOut {
            value: Amount::ZERO,
            script_pubkey: canonical_op_return_script(&memo).expect("canonical memo"),
        };
        let change_out = TxOut {
            value: Amount::from_sat(89_000),
            script_pubkey: vin0.clone(),
        };
        let outputs = if old_order {
            vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: payout.clone(),
                },
                memo_out,
                change_out,
            ]
        } else {
            vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: payout.clone(),
                },
                change_out,
                memo_out,
            ]
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x22; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(200_000),
            script_pubkey: vin0.clone(),
        });
        psbt.inputs[0].witness_script = Some(witness_script);
        (psbt, payout, vin0, memo)
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn fixture(old_order: bool) -> Evidence {
        let (psbt, payout, vin0, memo) = fixture_psbt(old_order);
        let payout_address = expected_address(&payout).expect("payout address");
        let change_address = expected_address(&vin0).expect("change address");
        let memo_spk = canonical_op_return_script(&memo).expect("canonical memo");
        Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            provider: PROVIDER.to_string(),
            environment: ENVIRONMENT.to_string(),
            coin: COIN.to_string(),
            wallet: WalletEvidence {
                wallet_id: "test-wallet".to_string(),
                wallet_type: "hot".to_string(),
                multisig_type: "onchain".to_string(),
                custody_model: "self-custody".to_string(),
                address_type: "p2wsh".to_string(),
                address_chain_code: 20,
                m: 2,
                n: 3,
                user_pubkey_hex: USER_PUBKEY.to_string(),
                backup_pubkey_hex: BACKUP_PUBKEY.to_string(),
                bitgo_pubkey_hex: BITGO_PUBKEY.to_string(),
            },
            build_request: BuildRequestEvidence {
                tx_format: "psbt".to_string(),
                no_split_change: true,
                change_address_type: "p2wsh".to_string(),
                is_replaceable_by_fee: false,
                sequence_id: "xindex-bitgo-fixture-1".to_string(),
                change_address,
                unspents: vec![format!("{}:0", Txid::from_byte_array([0x22; 32]))],
                recipients: vec![
                    RecipientEvidence {
                        address: payout_address,
                        amount_sats: 100_000,
                    },
                    RecipientEvidence {
                        address: format!(
                            "scriptPubKey:{}",
                            alloy_primitives::hex::encode(memo_spk.as_bytes())
                        ),
                        amount_sats: 0,
                    },
                ],
            },
            expected: ExpectedTransaction {
                inputs: vec![ExpectedInput {
                    outpoint: format!("{}:0", Txid::from_byte_array([0x22; 32])),
                    value_sats: 200_000,
                    script_pubkey_hex: alloy_primitives::hex::encode(vin0.as_bytes()),
                    witness_script_hex: alloy_primitives::hex::encode(
                        psbt.inputs[0]
                            .witness_script
                            .as_ref()
                            .expect("witness script")
                            .as_bytes(),
                    ),
                }],
                payout_script_pubkey_hex: alloy_primitives::hex::encode(payout.as_bytes()),
                payout_sats: 100_000,
                vin0_script_pubkey_hex: alloy_primitives::hex::encode(vin0.as_bytes()),
                memo_hex: alloy_primitives::hex::encode(memo),
                max_fee_sats: 20_000,
                require_change: true,
            },
            unsigned_psbt: EncodedArtifact {
                encoding: "base64".to_string(),
                data: B64.encode(psbt.serialize()),
            },
            user_signed_artifact: None,
            final_transaction_hex: None,
            live: LiveEvidence {
                wallet_lookup_corroborated: false,
                build_correlation_id: String::new(),
                build_response_captured: false,
                bitgo_cosign_completed: false,
                transfer_id: String::new(),
                final_transaction_id: String::new(),
            },
        }
    }

    fn status(report: &GateReport, id: &str) -> GateStatus {
        report
            .checks
            .iter()
            .find(|check| check.id == id)
            .map_or(GateStatus::Fail, |check| check.status)
    }

    #[test]
    fn correct_unsigned_capture_passes_shape_but_remains_blocked() {
        let report = evaluate_fixture(&fixture(false));
        assert_eq!(report.evidence_sha256, "11".repeat(32));
        assert_eq!(report.wallet_id, "test-wallet");
        assert_eq!(status(&report, "inputs"), GateStatus::Pass);
        assert_eq!(status(&report, "thorchain_layout"), GateStatus::Pass);
        assert_eq!(status(&report, "fee"), GateStatus::Pass);
        assert_eq!(report.overall, GateStatus::Blocked);
    }

    #[test]
    fn self_asserted_live_claims_cannot_pass() {
        let mut evidence = fixture(false);
        evidence.live.wallet_lookup_corroborated = true;
        evidence.live.build_correlation_id = evidence.build_request.sequence_id.clone();
        evidence.live.build_response_captured = true;
        evidence.live.bitgo_cosign_completed = true;
        evidence.live.transfer_id = "caller-supplied-transfer".to_string();
        evidence.live.final_transaction_id =
            "1111111111111111111111111111111111111111111111111111111111111111".to_string();

        let check = validate_live(&evidence.live, &evidence.build_request);

        assert_eq!(check.status, GateStatus::Blocked);
        assert!(check.detail.contains("authenticated provider provenance"));
    }

    #[test]
    fn memo_before_change_fails_the_gate() {
        let report = evaluate_fixture(&fixture(true));
        assert_eq!(status(&report, "thorchain_layout"), GateStatus::Fail);
        assert_eq!(report.overall, GateStatus::Fail);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn noncanonical_memo_fails_both_adapter_and_gate_boundaries() {
        let mut evidence = fixture(false);
        let (mut candidate, _, _, memo) = fixture_psbt(false);
        let mut script = vec![
            0x6a,
            0x61,
            u8::try_from(memo.len()).expect("fixture memo length"),
        ];
        script.extend_from_slice(&memo);
        candidate.unsigned_tx.output[2].script_pubkey = ScriptBuf::from_bytes(script);
        evidence.unsigned_psbt.data = B64.encode(candidate.serialize());

        let report = evaluate_fixture(&evidence);
        assert_eq!(status(&report, "inputs"), GateStatus::Fail);
        assert_eq!(status(&report, "thorchain_layout"), GateStatus::Fail);
        assert_eq!(report.overall, GateStatus::Fail);
    }

    #[test]
    fn signing_stage_transaction_mutation_fails() {
        let mut evidence = fixture(false);
        let (mut changed, _, _, _) = fixture_psbt(false);
        changed.unsigned_tx.output[0].value = Amount::from_sat(99_999);
        evidence.user_signed_artifact = Some(SignedArtifact {
            format: "psbt".to_string(),
            encoding: "hex".to_string(),
            data: alloy_primitives::hex::encode(changed.serialize()),
        });
        let report = evaluate_fixture(&evidence);
        assert_eq!(
            status(&report, "user_signature_preservation"),
            GateStatus::Fail
        );
    }

    #[test]
    fn witness_script_must_commit_to_the_input_script() {
        let mut evidence = fixture(false);
        let (mut changed, _, _, _) = fixture_psbt(false);
        changed.inputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x51, 0xff]));
        evidence.unsigned_psbt.data = B64.encode(changed.serialize());
        let report = evaluate_fixture(&evidence);
        assert_eq!(status(&report, "inputs"), GateStatus::Fail);
    }

    #[test]
    fn synthetic_half_signed_witness_is_rejected() {
        let mut evidence = fixture(false);
        let (psbt, _, _, _) = fixture_psbt(false);
        let mut half_signed = psbt.unsigned_tx;
        half_signed.input[0].witness = Witness::from_slice(&[b"synthetic-public-witness"]);
        evidence.user_signed_artifact = Some(SignedArtifact {
            format: "transaction".to_string(),
            encoding: "hex".to_string(),
            data: alloy_primitives::hex::encode(serialize(&half_signed)),
        });
        let report = evaluate_fixture(&evidence);
        assert_eq!(
            status(&report, "user_signature_preservation"),
            GateStatus::Fail
        );
        assert_eq!(report.overall, GateStatus::Fail);
    }

    #[test]
    fn rbf_input_fails_the_gate() {
        let mut evidence = fixture(false);
        let (mut psbt, _, _, _) = fixture_psbt(false);
        psbt.unsigned_tx.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        evidence.unsigned_psbt.data = B64.encode(psbt.serialize());
        let report = evaluate_fixture(&evidence);
        assert_eq!(status(&report, "inputs"), GateStatus::Fail);
        assert_eq!(report.overall, GateStatus::Fail);
    }

    #[test]
    fn build_request_must_pin_native_change_and_disable_rbf() {
        let mut evidence = fixture(false);
        evidence.build_request.change_address_type = "p2shP2wsh".to_string();
        evidence.build_request.is_replaceable_by_fee = true;
        let report = evaluate_fixture(&evidence);
        assert_eq!(status(&report, "build_request"), GateStatus::Fail);
        assert_eq!(report.overall, GateStatus::Fail);
    }

    #[test]
    fn witness_script_must_use_the_captured_role_keys() {
        let mut evidence = fixture(false);
        evidence.wallet.bitgo_pubkey_hex =
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string();
        let report = evaluate_fixture(&evidence);
        assert_eq!(status(&report, "expected_transaction"), GateStatus::Fail);
        assert_eq!(report.overall, GateStatus::Fail);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn official_bitgo_half_signed_vector_verifies_the_user_signature() {
        // Static public example from BitGo's manual multisig withdrawal guide.
        // This test verifies an existing signature and never creates or uses a key.
        let unsigned_hex = "01000000010e4d3af014f9efe311062965d561b67f78a1759e7016605cd506ddd7041762d50000000000ffffffff02102700000000000017a9145a581567fd2a630e61e34a696ab3bb887972886d87ad0f010000000000225120850d0ab466d15cb1565dd528d4d9709f3e46f41d41fe6d94aa01378e6269839900000000";
        let half_signed_hex = "010000000001010e4d3af014f9efe311062965d561b67f78a1759e7016605cd506ddd7041762d50000000023220020510ded26d712922bbb61bc68ef6766f836a03527820cbdc8b1551914eb467dafffffffff02102700000000000017a9145a581567fd2a630e61e34a696ab3bb887972886d87ad0f010000000000225120850d0ab466d15cb1565dd528d4d9709f3e46f41d41fe6d94aa01378e626983990500483045022100db45a8d94ee2144f7e29baa855d94a2bf0120707a7ab2fc93734ed94af972c460220558d00b91275aafc7805dfaaf9ab796adbe9f4e66dc467f7eb93b790671a323201000069522103c10ac628c880629ed0fd2a0563a898f4882baca45e15668a4d3064cf1ea379882103e56f84be4460080618ef869bb7b07096880760f748ba23efab533c2359f923bd21020ae81372264b5eac5c9dc7fe0b9a32bad00771c3a2c71f6e2c971823c3182ed653ae00000000";
        let unsigned_tx: Transaction =
            deserialize(&decode_hex("unsigned vector", unsigned_hex).expect("hex"))
                .expect("unsigned transaction");
        let half_signed: Transaction =
            deserialize(&decode_hex("half-signed vector", half_signed_hex).expect("hex"))
                .expect("half-signed transaction");
        let wallet = fixture_wallet();
        let witness_script = multisig_witness_script(&[wallet.user, wallet.backup, wallet.bitgo]);
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("PSBT");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        });
        psbt.inputs[0].witness_script = Some(witness_script);
        let encoded_signature = half_signed.input[0]
            .witness
            .iter()
            .nth(1)
            .expect("user signature");
        let signature =
            BitcoinSignature::from_slice(encoded_signature).expect("DER+sighash signature");
        verify_signature_for_key(&psbt, 0, &wallet.user, &signature)
            .expect("signature verifies for the captured user key");
    }

    #[test]
    fn final_transaction_without_witness_fails() {
        let mut evidence = fixture(false);
        let (psbt, _, _, _) = fixture_psbt(false);
        evidence.final_transaction_hex =
            Some(alloy_primitives::hex::encode(serialize(&psbt.unsigned_tx)));
        evidence.live.final_transaction_id = psbt.unsigned_tx.compute_txid().to_string();
        let report = evaluate_fixture(&evidence);
        assert_eq!(
            status(&report, "bitgo_cosign_preservation"),
            GateStatus::Fail
        );
    }
}
