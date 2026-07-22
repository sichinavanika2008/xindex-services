#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "fixed protobuf fixtures should fail loudly in tests"
)]

use sha2::{Digest, Sha256};
use xindex_cosmos_tx::tx::{build_direct_signing_package, CosmosTxParams};

fn params<'a>() -> CosmosTxParams<'a> {
    CosmosTxParams {
        from_address: "cosmos1custody",
        to_address: "cosmos1asgardvault",
        denom: "uatom",
        send_amount: "5000000",
        fee_amount: "5000",
        gas_limit: 200_000,
        memo: "=:ETH.USDT:0xrecipient:990000",
        sequence: 7,
    }
}

fn read_varint(bytes: &[u8], mut offset: usize) -> (u64, usize) {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = bytes[offset];
        offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return (value, offset);
        }
        shift += 7;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Field<'a> {
    Bytes(u64, &'a [u8]),
    Varint(u64, u64),
}

fn fields(bytes: &[u8]) -> Vec<Field<'_>> {
    let mut fields = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, next) = read_varint(bytes, offset);
        match tag & 7 {
            0 => {
                let (value, end) = read_varint(bytes, next);
                fields.push(Field::Varint(tag >> 3, value));
                offset = end;
            }
            2 => {
                let (len, body_start) = read_varint(bytes, next);
                let body_end =
                    body_start + usize::try_from(len).expect("fixture length fits usize");
                fields.push(Field::Bytes(tag >> 3, &bytes[body_start..body_end]));
                offset = body_end;
            }
            wire => panic!("fixture does not decode protobuf wire type {wire}"),
        }
    }
    fields
}

#[test]
fn direct_sign_doc_and_unsigned_tx_bind_identical_body_and_auth_info() {
    let pubkey = [0x02; 33];
    let package = build_direct_signing_package(&pubkey, &params(), "cosmoshub-4", 42);

    let tx_fields = fields(package.unsigned_tx_bytes());
    let sign_doc_fields = fields(package.sign_doc_bytes());

    assert_eq!(tx_fields.len(), 2, "unsigned TxRaw must omit signatures");
    assert!(matches!(tx_fields[0], Field::Bytes(1, _)));
    assert!(matches!(tx_fields[1], Field::Bytes(2, _)));
    assert_eq!(sign_doc_fields[0], tx_fields[0]);
    assert_eq!(sign_doc_fields[1], tx_fields[1]);
    assert_eq!(
        sign_doc_fields[2],
        Field::Bytes(3, b"cosmoshub-4".as_slice())
    );
    assert_eq!(sign_doc_fields[3], Field::Varint(4, 42));

    let expected_hash: [u8; 32] = Sha256::digest(package.sign_doc_bytes()).into();
    assert_eq!(package.signing_hash(), expected_hash);
}

#[test]
fn direct_chain_identity_changes_only_the_sign_doc_and_hash() {
    let pubkey = [0x03; 33];
    let gaia = build_direct_signing_package(&pubkey, &params(), "cosmoshub-4", 42);
    let noble = build_direct_signing_package(&pubkey, &params(), "noble-1", 42);

    assert_eq!(gaia.unsigned_tx_bytes(), noble.unsigned_tx_bytes());
    assert_ne!(gaia.sign_doc_bytes(), noble.sign_doc_bytes());
    assert_ne!(gaia.signing_hash(), noble.signing_hash());
}

#[test]
fn direct_signature_changes_only_txraw_signature_field() {
    let pubkey = [0x02; 33];
    let package = build_direct_signing_package(&pubkey, &params(), "cosmoshub-4", 42);
    let signed = package.signed_tx_raw(&[0x5a; 64]);

    let unsigned_fields = fields(package.unsigned_tx_bytes());
    let signed_fields = fields(&signed);
    assert_eq!(&signed_fields[..2], unsigned_fields);
    assert_eq!(signed_fields[2], Field::Bytes(3, [0x5a; 64].as_slice()));
}
