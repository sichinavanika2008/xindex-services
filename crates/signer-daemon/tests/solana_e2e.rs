//! S7 e2e — drive `SolanaRedeemExecutor` through the REAL daemon
//! `validate_and_sign` (S6), proving the executor's per-step requests pass
//! the never-blind-sign rebuild + byte-match, get ed25519-signed, and
//! reassemble into a confirmed redemption.
//!
//! This is the integration counterpart to the in-crate orchestration test:
//! the cosigners here are backed by the daemon's actual validation, so it
//! catches any divergence between how the executor builds a message and how
//! the daemon rebuilds it.

use std::future::{ready, Future};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::B256;
use xindex_chain_solana::{
    MultisigAccount, ProposalState, SignatureStatus, SolanaChainClient, SolanaChainError,
    SolanaTransfer,
};
use xindex_executor::solana_redeem::{
    SignSolanaFuture, SolanaCosigner, SolanaLockTable, SolanaMemberSig, SolanaRedeemConfig,
    SolanaRedeemError, SolanaRedeemExecutor, SolanaRedeemTask,
};
use xindex_executor::solana_redeem_store::InMemorySolanaRedeemStore;
use xindex_shared::chain_registry::ChainId;
use xindex_shared::signer_wire::SolanaTxSignRequest;
use xindex_signer_daemon::solana_tx::{validate_and_sign, SolSignerConfig};
use xindex_solana_tx::{base58, sigs, squads, Pubkey};

const MULTISIG: [u8; 32] = [0x42; 32];

fn member(seed: u8) -> ([u8; 32], Pubkey) {
    let s = [seed; 32];
    (s, sigs::pubkey_from_seed(&s))
}

/// Stateful stub chain client (mirrors the executor's): the proposal
/// advances as txs are sent, driven by the Squads discriminator + the
/// fee-payer (`account_keys[0]`) of each broadcast.
struct StubChain {
    threshold: u16,
    last_index: u64,
    state: Mutex<ProposalState>,
}

fn fee_payer_of(tx: &[u8]) -> Pubkey {
    let off = 1 + 64 + 3 + 1;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&tx[off..off + 32]);
    Pubkey::new(arr)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

impl SolanaChainClient for StubChain {
    fn chain(&self) -> ChainId {
        ChainId::Sol
    }
    fn recent_blockhash(&self) -> impl Future<Output = Result<[u8; 32], SolanaChainError>> + Send {
        ready(Ok([7u8; 32]))
    }
    fn get_multisig_account(
        &self,
        _multisig: &Pubkey,
    ) -> impl Future<Output = Result<MultisigAccount, SolanaChainError>> + Send {
        ready(Ok(MultisigAccount {
            threshold: self.threshold,
            time_lock: 0,
            transaction_index: self.last_index,
            stale_transaction_index: 0,
        }))
    }
    fn get_proposal_state(
        &self,
        _proposal: &Pubkey,
    ) -> impl Future<Output = Result<ProposalState, SolanaChainError>> + Send {
        let state = self.state.lock().map_or(ProposalState::None, |g| g.clone());
        ready(Ok(state))
    }
    fn send_transaction(
        &self,
        signed_tx: &[u8],
    ) -> impl Future<Output = Result<String, SolanaChainError>> + Send {
        if let Ok(mut g) = self.state.lock() {
            if contains(
                signed_tx,
                &squads::discriminator("vault_transaction_create"),
            ) {
                *g = ProposalState::Active { approved: vec![] };
            } else if contains(signed_tx, &squads::discriminator("proposal_approve")) {
                let approver = fee_payer_of(signed_tx);
                if let ProposalState::Active { approved } = &mut *g {
                    if !approved.contains(&approver) {
                        approved.push(approver);
                    }
                    if u16::try_from(approved.len()).unwrap_or(u16::MAX) >= self.threshold {
                        *g = ProposalState::Approved;
                    }
                }
            } else if contains(
                signed_tx,
                &squads::discriminator("vault_transaction_execute"),
            ) {
                *g = ProposalState::Executed;
            }
        }
        ready(Ok(base58::encode(&signed_tx[1..65])))
    }
    fn get_signature_status(
        &self,
        _signature: &str,
    ) -> impl Future<Output = Result<Option<SignatureStatus>, SolanaChainError>> + Send {
        ready(Ok(Some(SignatureStatus {
            slot: 1,
            confirmations: None,
            confirmation_status: Some("finalized".to_string()),
            err: false,
        })))
    }
    fn get_balance(
        &self,
        _address: &Pubkey,
    ) -> impl Future<Output = Result<u64, SolanaChainError>> + Send {
        ready(Ok(1_000_000_000_000))
    }
    fn transfers_to(
        &self,
        _vault: &str,
        _min_slot: u64,
    ) -> impl Future<Output = Result<Vec<SolanaTransfer>, SolanaChainError>> + Send {
        ready(Ok(Vec::new()))
    }
}

/// A cosigner backed by the daemon's real `validate_and_sign`.
struct DaemonBackedCosigner {
    config: SolSignerConfig,
}

fn cerr(member: Pubkey, message: String) -> SolanaRedeemError {
    SolanaRedeemError::Cosigner {
        pubkey: member.to_base58(),
        message,
    }
}

impl SolanaCosigner for DaemonBackedCosigner {
    fn member_pubkey(&self) -> Pubkey {
        self.config.member_pubkey
    }
    fn sign_solana_tx<'a>(&'a self, req: &'a SolanaTxSignRequest) -> SignSolanaFuture<'a> {
        let config = self.config.clone();
        let req = req.clone();
        Box::pin(async move {
            let member = config.member_pubkey;
            match validate_and_sign(&req, &config) {
                Ok(resp) => {
                    let pubkey = Pubkey::from_base58(&resp.pubkey)
                        .map_err(|e| cerr(member, format!("resp pubkey: {e}")))?;
                    let sig_hex = resp.signature.strip_prefix("0x").unwrap_or(&resp.signature);
                    let bytes = alloy_primitives::hex::decode(sig_hex)
                        .map_err(|e| cerr(member, format!("sig hex: {e}")))?;
                    let signature: [u8; 64] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| cerr(member, "sig len".to_string()))?;
                    Ok(SolanaMemberSig {
                        member_pubkey: pubkey,
                        signature,
                    })
                }
                Err((status, body)) => {
                    Err(cerr(member, format!("daemon {status}: {}", body.0.code)))
                }
            }
        })
    }
}

#[tokio::test]
#[expect(clippy::expect_used, reason = "test code")]
async fn executor_drives_redemption_through_real_daemon_validation() {
    let multisig = Pubkey::new(MULTISIG);
    let seeds: [u8; 5] = [1, 2, 3, 4, 5];
    let members: Vec<Pubkey> = seeds.iter().map(|&s| member(s).1).collect();

    let cosigners: Vec<Box<dyn SolanaCosigner>> = seeds
        .iter()
        .map(|&s| {
            let (seed, pubkey) = member(s);
            let config = SolSignerConfig {
                chain: ChainId::Sol,
                multisig_pda: multisig,
                vault_index: 0,
                members: members.clone(),
                member_pubkey: pubkey,
                member_seed: seed,
            };
            Box::new(DaemonBackedCosigner { config }) as Box<dyn SolanaCosigner>
        })
        .collect();

    let cfg = SolanaRedeemConfig {
        chain: ChainId::Sol,
        multisig_pda: multisig,
        vault_index: 0,
        members,
        threshold: 3,
        confirm_poll: Duration::from_millis(0),
        confirm_timeout: Duration::from_millis(50),
    };
    let chain = Arc::new(StubChain {
        threshold: 3,
        last_index: 10,
        state: Mutex::new(ProposalState::None),
    });
    let store = Arc::new(InMemorySolanaRedeemStore::new());
    let exec = SolanaRedeemExecutor::new(
        cfg,
        chain,
        cosigners,
        store,
        Arc::new(SolanaLockTable::new()),
    )
    .expect("executor");

    let task = SolanaRedeemTask {
        dispatch_id: B256::repeat_byte(0xd1),
        redemption_id: B256::repeat_byte(0xd2),
        chain: ChainId::Sol,
        memo: "=:ETH.USDT:0xabc:1".to_string(),
        send_amount: 2_000_000_000,
        // A user address that is NOT a member / vault / program.
        destination: Pubkey::new([0x99; 32]).to_base58(),
    };

    let outcome = exec
        .execute_redeem(&task)
        .await
        .expect("redemption drives end-to-end through real daemon validation");
    assert_eq!(outcome.transaction_index, 11);
    assert!(!outcome.execute_signature.is_empty());
}
