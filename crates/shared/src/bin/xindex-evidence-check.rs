//! Verify an append-only Gate-3 evidence directory without contacting a signer.

use std::io::Write;

use xindex_shared::evidence::EvidenceStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let directory = args.next().ok_or_else(|| {
        std::io::Error::other(
            "usage: xindex-evidence-check <owner-only-evidence-directory> [expected-inventory-keccak256]",
        )
    })?;
    let store = EvidenceStore::open(&directory)?;
    let report = store.verify_records()?;
    if report.record_count == 0 {
        return Err(std::io::Error::other("evidence directory is empty").into());
    }
    if let Some(expected) = args.next() {
        let expected = expected.strip_prefix("0x").unwrap_or(&expected);
        if !report
            .inventory_hash_keccak256
            .eq_ignore_ascii_case(expected)
        {
            return Err(std::io::Error::other("evidence inventory hash mismatch").into());
        }
    }
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::to_string_pretty(&report)?
    )?;
    Ok(())
}
