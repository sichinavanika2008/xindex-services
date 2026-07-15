#![expect(
    clippy::print_stdout,
    reason = "rehearsal helper: emits the collected signatures on stdout for cast"
)]
//! Collect a k-of-n MINT attestation from the LIVE daemon fleet for the
//! one-box D1 rehearsal. For each of the first 3 daemons it calls the
//! production coordinator client `RemoteHsmBackend::sign_attestation_msg`
//! (POST `/api/v1/sign/eip712-attestation`) — the daemon recomputes the
//! EIP-712 digest on its own pinned domain and signs — and prints the
//! 65-byte signatures (hex, one per line) for `cast` to post to
//! `oracle.attest(intentId, slotIndex, attestedAmount, context, [sigs])`.
//!
//! ```text
//! cargo run -p xindex-signer-daemon --example attest_mint -- \
//!     <chain_id> <oracle_addr> <intent_id> <slot_index> <attested_amount> \
//!     <evidence_hash> <observed_at> <valid_until> <source_block> \
//!     <source_block_hash> <observation_epoch> \
//!     <url0> <addr0> <url1> <addr1> <url2> <addr2>
//! ```

use std::error::Error;

use alloy_primitives::{Address, B256, U256};
use xindex_shared::eip712::{attestation, attestation_oracle_domain, settlement_context};
use xindex_signer::remote::RemoteHsmBackend;
use xindex_signer::HsmBackend;

fn main() -> Result<(), Box<dyn Error>> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 17 {
        return Err(
            "usage: attest_mint <chain_id> <oracle> <intent_id> <slot> <amount> \
                    <evidence_hash> <observed_at> <valid_until> <source_block> \
                    <source_block_hash> <observation_epoch> \
                    <url0> <addr0> <url1> <addr1> <url2> <addr2>"
                .into(),
        );
    }
    let chain_id: u64 = a[0].parse()?;
    let oracle: Address = a[1].parse()?;
    let intent_id: B256 = a[2].parse()?;
    let slot = U256::from_str_radix(&a[3], 10)?;
    let amount = U256::from_str_radix(&a[4], 10)?;
    let evidence_hash: B256 = a[5].parse()?;
    let observed_at: u64 = a[6].parse()?;
    let valid_until: u64 = a[7].parse()?;
    let source_block: u64 = a[8].parse()?;
    let source_block_hash: B256 = a[9].parse()?;
    let observation_epoch: u64 = a[10].parse()?;

    // The remote daemon recomputes the digest on its OWN pinned domain;
    // this domain is constructed only to satisfy the typed API.
    let domain = attestation_oracle_domain(chain_id, oracle);
    let att = attestation(
        intent_id,
        slot,
        amount,
        settlement_context(
            evidence_hash,
            observed_at,
            valid_until,
            U256::from(chain_id),
            source_block,
            source_block_hash,
            observation_epoch,
        ),
    );

    for pair in a[11..].chunks_exact(2).take(3) {
        let backend = RemoteHsmBackend::new(pair[0].clone(), pair[1].parse::<Address>()?);
        let sig = backend.sign_attestation_msg(&domain, &att)?;
        println!("0x{}", alloy_primitives::hex::encode(sig));
    }
    Ok(())
}
