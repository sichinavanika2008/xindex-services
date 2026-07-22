#![expect(
    clippy::expect_used,
    reason = "fixed transaction fixtures should fail loudly in tests"
)]

use alloy_primitives::hex;
use xindex_zcash_tx::{SaplingV4Transaction, TransparentInput, TransparentOutput};

const AGGREGATE_KEY: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];
const PREVIOUS_TXID: &str = "9b1a2f3e4d5c6b7a8f9e1f0b4b4d5b2b4b8d3e0c8050b5b0e3f7650145cdabcd";
const P2PKH_SCRIPT: &str = "76a914abcdefabcdefabcdefabcdefabcdefabcdefabcd88ac";

fn fixture() -> SaplingV4Transaction {
    SaplingV4Transaction::new(
        AGGREGATE_KEY,
        vec![TransparentInput::new(
            hex::decode(PREVIOUS_TXID)
                .expect("txid hex")
                .try_into()
                .expect("32-byte txid"),
            0,
            100_000_000,
        )],
        vec![TransparentOutput::new(
            99_990_000,
            hex::decode(P2PKH_SCRIPT).expect("script hex"),
        )],
    )
    .expect("reviewed transparent transaction")
}

#[test]
fn matches_the_pinned_recipes_sapling_v4_fixture() {
    let transaction = fixture();
    assert_eq!(
        hex::encode(transaction.unsigned_bytes().expect("unsigned bytes")),
        "0400008085202f8901cdabcd450165f7e3b0b550800c3e8d4b2b5b4d4b0b1f9e8f7a6b5c4d3e2f1a9b0000000000ffffffff01f0b9f505000000001976a914abcdefabcdefabcdefabcdefabcdefabcdefabcd88ac00000000000000000000000000000000000000"
    );
    assert_eq!(
        hex::encode(transaction.signing_hashes().expect("signing hash")[0]),
        // Independently reproduced with Python's personalized BLAKE2b. Unlike
        // the upstream mock, the scriptCode is the aggregate key's real P2PKH
        // script rather than an unrelated placeholder script.
        "4fbfe95688f588e941ea3e552d2c4cdca56f2aa17ab96afc8dd14b186acfd848"
    );
    assert_eq!(transaction.fee_zatoshis().expect("fee"), 10_000);
}

#[test]
fn verifier_metadata_contains_only_recomputed_hashes_and_the_exact_key() {
    let transaction = fixture();
    let raw = transaction.unsigned_bytes().expect("unsigned bytes");
    let metadata = transaction
        .serialize_with_metadata()
        .expect("verifier transaction bytes");

    assert_eq!(&metadata[..raw.len()], raw);
    assert_eq!(&metadata[raw.len()..raw.len() + 3], b"ZSH");
    assert_eq!(&metadata[raw.len() + 3..raw.len() + 36], &AGGREGATE_KEY);
    assert_eq!(metadata[raw.len() + 36], 1);
    assert_eq!(
        &metadata[raw.len() + 37..],
        &transaction.signing_hashes().expect("signing hashes")[0]
    );
}

#[test]
fn invalid_aggregate_keys_and_output_inflation_fail_closed() {
    assert!(SaplingV4Transaction::new(
        [0; 33],
        vec![TransparentInput::new([1; 32], 0, 10)],
        vec![TransparentOutput::new(9, vec![0x51])],
    )
    .is_err());
    assert!(SaplingV4Transaction::new(
        AGGREGATE_KEY,
        vec![TransparentInput::new([1; 32], 0, 10)],
        vec![TransparentOutput::new(11, vec![0x51])],
    )
    .is_err());
}

#[test]
fn duplicate_transparent_outpoints_fail_closed() {
    let duplicate = TransparentInput::new([1; 32], 7, 10);
    assert!(SaplingV4Transaction::new(
        AGGREGATE_KEY,
        vec![duplicate.clone(), duplicate],
        vec![TransparentOutput::new(19, vec![0x51])],
    )
    .is_err());
}

#[test]
fn signed_bytes_insert_one_p2pkh_script_sig_per_input() {
    let transaction = fixture();
    let der = hex::decode(
        "304402206673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e889802204c1a971652e0ada880120ef8025e709fff2080c4a39aae068d12eed009b68c89",
    )
    .expect("fixed strict-DER signature");
    let signed = transaction
        .signed_bytes(std::slice::from_ref(&der))
        .expect("signed transaction bytes");
    let unsigned = transaction.unsigned_bytes().expect("unsigned bytes");

    assert!(signed.len() > unsigned.len());
    let signature_offset = 8 + 1 + 32 + 4 + 1;
    assert_eq!(
        signed[signature_offset],
        u8::try_from(der.len() + 1).unwrap_or(0)
    );
    assert_eq!(
        &signed[signature_offset + 1..signature_offset + 1 + der.len()],
        der
    );
    assert_eq!(signed[signature_offset + 1 + der.len()], 1);
    assert!(transaction.signed_bytes(&[]).is_err());
}
