//! Key-free cross-crate fixtures. Never compiled into production artifacts.

#![expect(clippy::expect_used, reason = "deterministic test-only fixture")]

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::Hash as _;
use bitcoin::psbt::Psbt;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, BlockHash, CompressedPublicKey, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use sha2::{Digest as _, Sha256};
use xindex_chain_utxo::finalized_inventory::{
    FinalizedBitcoinBlock, FinalizedBitcoinInventoryTestHarness, FinalizedBitcoinOutput,
    MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
};
use xindex_custody_core::btc_authorize::BtcSpendAuthorization;
use xindex_custody_core::prepare::{BindContext, PreparedSpend};
use xindex_shared::chain_registry::ChainId;

use crate::request::{attach_bitcoin_authorization, build_from_parts, VultisigSigningPayload};
use crate::{
    validate_and_derive_signing_hashes, AuthorizedBitcoinSpend, AuthorizedVultisigBitcoinKeysign,
    VultisigBitcoinEvidenceConfig, VultisigBitcoinPolicyRuntime, VultisigPublicKey,
    VultisigVaultConfig,
};

const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

/// Strict request/finalizer pair plus its source-pinned policy runtime.
#[expect(
    missing_debug_implementations,
    reason = "the fixture owns non-cloneable authorization capabilities"
)]
pub struct KeyFreeBitcoinRuntimeFixture {
    /// Source-pinned runtime needed to construct the integrated executor.
    pub policy_runtime: VultisigBitcoinPolicyRuntime,
    /// Strict pre-authorized request/finalizer pair.
    pub authorized: AuthorizedVultisigBitcoinKeysign,
}

/// Build a fixed Testnet4 lifecycle fixture using only public data and copied
/// upstream signature-test message bytes.
///
/// No private key, share, signature generation, network, or broadcast action
/// occurs. The custody receipt is explicitly a feature-gated test fixture.
///
/// # Panics
/// Panics only when the checked-in deterministic fixture is internally
/// inconsistent.
#[expect(
    clippy::too_many_lines,
    reason = "one fixture keeps its exact policy/request/finalizer transcript together"
)]
pub async fn key_free_bitcoin_runtime_fixture() -> KeyFreeBitcoinRuntimeFixture {
    let aggregate_key = CompressedPublicKey::from_slice(&GENERATOR).expect("generator key");
    let custody_script = ScriptBuf::new_p2wpkh(&aggregate_key.wpubkey_hash());
    let outpoint = OutPoint::new(Txid::from_byte_array([0x71; 32]), 0);
    let inventory = FinalizedBitcoinInventoryTestHarness::in_memory(
        "vultisig-integrated-runtime-test",
        custody_script.clone(),
        MIN_FINALIZED_BITCOIN_CONFIRMATIONS,
    )
    .await
    .expect("test inventory");
    let source = inventory.policy_source();
    let block_100 = FinalizedBitcoinBlock::new(
        100,
        BlockHash::from_byte_array([100; 32]),
        BlockHash::from_byte_array([99; 32]),
        vec![
            FinalizedBitcoinOutput::new(outpoint, 200_000, custody_script.clone())
                .expect("funding output"),
        ],
        Vec::new(),
    )
    .expect("funding block");
    inventory
        .commit_block(block_100.clone())
        .await
        .expect("funding block commit");
    let mut parent = block_100.block_hash();
    for height in 101u64..=105 {
        let tag = u8::try_from(height).expect("test block tag");
        let hash = BlockHash::from_byte_array([tag; 32]);
        inventory
            .commit_block(
                FinalizedBitcoinBlock::new(height, hash, parent, Vec::new(), Vec::new())
                    .expect("confirmation block"),
            )
            .await
            .expect("confirmation block commit");
        parent = hash;
    }
    let policy_runtime = VultisigBitcoinPolicyRuntime::from_test_source(source.clone());
    let policy = policy_runtime
        .issue_policy(&[outpoint], 10_000)
        .await
        .expect("strict policy");
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(199_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                [0x72; 20],
            )),
        }],
    })
    .expect("fixture PSBT");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(200_000),
        script_pubkey: custody_script,
    });
    psbt.inputs[0].bip32_derivation.insert(
        PublicKey::from_slice(&GENERATOR)
            .expect("generator public key")
            .inner,
        (Fingerprint::default(), DerivationPath::default()),
    );
    psbt.inputs[0].sighash_type = Some(EcdsaSighashType::All.into());

    let context = BindContext {
        chain: ChainId::Btc,
        psbt: psbt.clone(),
        ric: None,
        acc: None,
    };
    let mut approval = validate_and_derive_signing_hashes(&psbt, &policy).expect("policy approval");
    let mut fixed_message = [0u8; 32];
    fixed_message[31] = 1;
    approval.signing_hashes.fill(fixed_message);
    let custody = BtcSpendAuthorization::key_free_test_fixture(approval.unsigned_txid());
    let finalizer = AuthorizedBitcoinSpend {
        policy: approval,
        custody,
        policy_source: source,
    };

    let vault = VultisigVaultConfig::new(
        ChainId::Btc,
        GENERATOR,
        VultisigPublicKey::Secp256k1(GENERATOR),
        "123e4567-e89b-12d3-a456-426614174000",
        "123e4567-e89b-12d3-a456-426614174001",
    )
    .expect("vault config");
    let actual_hash = xindex_chain_utxo::single_key::derive_single_key_psbt_sighashes(
        ChainId::Btc,
        &psbt,
        &GENERATOR,
    )
    .expect("direct Bitcoin hash")[0];
    let mut request = build_from_parts(
        format!("0x{}", alloy_primitives::hex::encode(actual_hash)),
        PreparedSpend::DirectUtxo(Box::new(context)),
        vault,
    )
    .expect("sealed request");
    request.prepare_key = format!("0x{}", alloy_primitives::hex::encode(fixed_message));
    request.payloads = vec![VultisigSigningPayload {
        message: fixed_message.to_vec(),
        lookup_hash: Sha256::digest(fixed_message).into(),
    }];
    attach_bitcoin_authorization(
        &mut request,
        policy.max_fee_sats(),
        finalizer.policy.policy_id(),
        finalizer.policy.provenance_id(),
        VultisigBitcoinEvidenceConfig::new([0x73; 32], "vault-testnet4-runtime", 2, 1)
            .expect("evidence config"),
    )
    .expect("strict request binding");
    let operation_id = request
        .bitcoin_operation_id()
        .expect("strict operation identity");

    KeyFreeBitcoinRuntimeFixture {
        policy_runtime,
        authorized: AuthorizedVultisigBitcoinKeysign {
            request,
            finalizer,
            operation_id,
        },
    }
}
