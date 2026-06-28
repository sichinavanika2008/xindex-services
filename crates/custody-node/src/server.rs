//! axum HTTP shell for the Cobo TSS-Node callback.
//!
//! Thin transport over the pure [`crate::dispatch::decide_callback`]: verify
//! the request JWT, run the decision, sign the response JWT. Every path returns
//! an our-key-signed response — on ANY error (bad JWT, no context, decision
//! reject) it returns a signed REJECT, so the TSS Node always gets an
//! unambiguous fail-closed verdict.

use std::sync::Arc;

use alloy_primitives::Address;
use axum::{extract::State, http::StatusCode, routing::post, Router};
use bitcoin::ScriptBuf;
use xindex_custody_core::gates::CustodyConfig;
use xindex_custody_core::replay::ReplayStore;
use xindex_shared::intent::IntentPolicy;

use crate::cobo_types::CallbackResponse;
use crate::dispatch::decide_callback;
use crate::jwt::JwtKeys;
use crate::prepare::PrepareStore;

/// Shared callback config + keys + stores. Cheap to clone (Arcs + a small
/// owned policy), as axum requires per request.
pub struct CallbackState<P, R> {
    /// Mutual-RS256 JWT keys.
    pub jwt: Arc<JwtKeys>,
    /// Prepare store (correlate Cobo `request_id` → our unsigned spend).
    pub prepare: Arc<P>,
    /// One-shot / replay store backing the CTD-1 decision cores.
    pub replay: Arc<R>,
    /// Ethereum chain id pinning the RIC EIP-712 domain.
    pub chain_id: u64,
    /// `AttestationOracle` address pinning the EIP-712 domain.
    pub verifying_contract: Address,
    /// Static Set-B whitelist + quorum + recency window.
    pub intent_policy: IntentPolicy,
    /// This callback's own BTC custody `scriptPubKey` (for the BTC output
    /// bind); `None` rejects any BTC spend.
    pub btc_custody_spk: Option<ScriptBuf>,
}

impl<P, R> Clone for CallbackState<P, R> {
    fn clone(&self) -> Self {
        Self {
            jwt: Arc::clone(&self.jwt),
            prepare: Arc::clone(&self.prepare),
            replay: Arc::clone(&self.replay),
            chain_id: self.chain_id,
            verifying_contract: self.verifying_contract,
            intent_policy: self.intent_policy.clone(),
            btc_custody_spk: self.btc_custody_spk.clone(),
        }
    }
}

impl<P, R> std::fmt::Debug for CallbackState<P, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackState")
            .field("chain_id", &self.chain_id)
            .field("verifying_contract", &self.verifying_contract)
            .field("btc_custody_enabled", &self.btc_custody_spk.is_some())
            .finish_non_exhaustive()
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// Extract the JWT from the POST body. Cobo's exact body envelope is
/// non-public — try a JSON object carrying the token under a few likely keys,
/// else treat the whole trimmed body as the raw JWT. RECONCILE AT DEV-ENV.
fn extract_jwt(body: &str) -> String {
    let trimmed = body.trim();
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(trimmed) {
        for key in [
            "TSS_JWT_MSG",
            "tss_jwt_msg",
            "jwt",
            "token",
            "data",
            "callback",
        ] {
            if let Some(serde_json::Value::String(s)) = map.get(key) {
                return s.trim().to_string();
            }
        }
    }
    trimmed.to_string()
}

/// Verify → decide → sign, returning the response JWT. Always fail-closed: any
/// failure yields a signed REJECT; if even signing fails (broken key), a bare
/// non-JWT body the TSS Node cannot parse (⇒ it treats the op as REJECT).
pub async fn process_callback<P, R>(
    state: &CallbackState<P, R>,
    body: &str,
    now_unix: i64,
) -> String
where
    P: PrepareStore,
    R: ReplayStore,
{
    let token = extract_jwt(body);
    let response = match state.jwt.verify_request(&token) {
        Ok(req) => {
            let config = CustodyConfig {
                chain_id: state.chain_id,
                verifying_contract: state.verifying_contract,
                intent_policy: &state.intent_policy,
            };
            decide_callback(
                &req,
                state.prepare.as_ref(),
                state.replay.as_ref(),
                config,
                state.btc_custody_spk.as_ref(),
                now_unix,
            )
            .await
        }
        Err(e) => CallbackResponse::reject("jwt_verify_failed", e.to_string()),
    };
    state
        .jwt
        .sign_response(&response)
        .unwrap_or_else(|_| "REJECT".to_string())
}

/// axum handler for `POST /v1/check`. Always HTTP 200 with the signed response
/// JWT body (the verdict is carried inside the JWT, fail-closed).
pub async fn handle_callback<P, R>(
    State(state): State<CallbackState<P, R>>,
    body: String,
) -> (StatusCode, String)
where
    P: PrepareStore + 'static,
    R: ReplayStore + 'static,
{
    (
        StatusCode::OK,
        process_callback(&state, &body, now_unix()).await,
    )
}

/// The callback router. Cobo's TSS Node posts to `service_address` =
/// `…/v1/check`.
pub fn router<P, R>(state: CallbackState<P, R>) -> Router
where
    P: PrepareStore + 'static,
    R: ReplayStore + 'static,
{
    Router::new()
        .route("/v1/check", post(handle_callback::<P, R>))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, U256};
    use alloy_sol_types::SolCall;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use xindex_custody_core::replay::InMemoryReplayStore;
    use xindex_shared::chain_registry::ChainId;
    use xindex_shared::thorchain_router::depositWithExpiryCall;

    use crate::prepare::{EvmPrepared, InMemoryPrepareStore, PreparedSpend};
    use crate::test_support::{oracle, policy, signed_ric, CHAIN_ID, NOW};

    const NODE_PRIV: &str = include_str!("../testdata/test_node_priv.pem");
    const NODE_PUB: &str = include_str!("../testdata/test_node_pub.pem");
    const AMOUNT: u128 = 1_000_000_000_000_000_000;
    const MEMO: &str = "=:ETH.USDT:0xrecipient:990000";

    fn vault() -> Address {
        Address::repeat_byte(0x11)
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn router_addr() -> Address {
        ChainId::Eth.thorchain_router_address().expect("router")
    }

    fn evm_prepared() -> PreparedSpend {
        let amount = U256::from(AMOUNT);
        let data = depositWithExpiryCall {
            vault: vault(),
            asset: Address::ZERO,
            amount,
            memo: MEMO.to_string(),
            expiry: U256::from(1_750_007_200u64),
        }
        .abi_encode();
        let ric = signed_ric(
            ChainId::Eth,
            keccak256(vault().as_slice()),
            MEMO,
            amount,
            &[1, 2, 3],
        );
        PreparedSpend::Evm(EvmPrepared {
            chain: ChainId::Eth,
            to: router_addr(),
            value: amount,
            data,
            ric: Some(ric),
            spend_identity: b"0".to_vec(),
        })
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn build_state() -> CallbackState<InMemoryPrepareStore, InMemoryReplayStore> {
        CallbackState {
            jwt: Arc::new(
                JwtKeys::from_pems(NODE_PUB.as_bytes(), NODE_PRIV.as_bytes()).expect("keys"),
            ),
            prepare: Arc::new(InMemoryPrepareStore::new()),
            replay: Arc::new(InMemoryReplayStore::new()),
            chain_id: CHAIN_ID,
            verifying_contract: oracle(),
            intent_policy: policy(),
            btc_custody_spk: None,
        }
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn node_signed_request(request_id: &str) -> String {
        let claims = serde_json::json!({
            "request_id": request_id, "request_type": 2,
            "request_detail": "{}", "extra_info": "{}"
        });
        let key = EncodingKey::from_rsa_pem(NODE_PRIV.as_bytes()).expect("priv");
        encode(&Header::new(Algorithm::RS256), &claims, &key).expect("sign")
    }

    #[expect(clippy::expect_used, reason = "test code")]
    fn response_action(jwt: &str) -> String {
        use jsonwebtoken::{decode, DecodingKey, Validation};
        let mut v = Validation::new(Algorithm::RS256);
        v.required_spec_claims = std::collections::HashSet::new();
        v.validate_exp = false;
        let d = decode::<serde_json::Value>(
            jwt,
            &DecodingKey::from_rsa_pem(NODE_PUB.as_bytes()).expect("pub"),
            &v,
        )
        .expect("decode response");
        d.claims
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string()
    }

    #[tokio::test]
    async fn honest_signed_request_approves() {
        let state = build_state();
        let _ = state.prepare.put("req-1".to_string(), evm_prepared()).await;
        let resp = process_callback(&state, &node_signed_request("req-1"), NOW).await;
        assert_eq!(response_action(&resp), "APPROVE");
    }

    #[tokio::test]
    async fn missing_context_signed_request_rejects() {
        let state = build_state();
        let resp = process_callback(&state, &node_signed_request("absent"), NOW).await;
        assert_eq!(response_action(&resp), "REJECT");
    }

    #[tokio::test]
    async fn unverifiable_body_rejects() {
        let state = build_state();
        let _ = state.prepare.put("req-1".to_string(), evm_prepared()).await;
        // Not a valid JWT at all → jwt_verify_failed → signed REJECT.
        let resp = process_callback(&state, "this-is-not-a-jwt", NOW).await;
        assert_eq!(response_action(&resp), "REJECT");
    }

    #[tokio::test]
    async fn extract_jwt_pulls_from_json_envelope() {
        let state = build_state();
        let _ = state.prepare.put("req-1".to_string(), evm_prepared()).await;
        let inner = node_signed_request("req-1");
        let body = serde_json::json!({ "TSS_JWT_MSG": inner }).to_string();
        let resp = process_callback(&state, &body, NOW).await;
        assert_eq!(response_action(&resp), "APPROVE");
    }
}
