//! The Turnkey REST client.

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::TurnkeyStamper;
use crate::types::{Activity, SignRawPayloadParams};
use crate::TurnkeyError;

/// Turnkey API host. Turnkey has no separate dev host — the dev-env is a
/// sub-organization + test wallet on the same API.
pub const TURNKEY_API_BASE: &str = "https://api.turnkey.com";

const SUBMIT_SIGN_RAW_PAYLOAD: &str = "/public/v1/submit/sign_raw_payload";
const SUBMIT_APPROVE_ACTIVITY: &str = "/public/v1/submit/approve_activity";
const SUBMIT_REJECT_ACTIVITY: &str = "/public/v1/submit/reject_activity";
const QUERY_GET_ACTIVITY: &str = "/public/v1/query/get_activity";

const TYPE_SIGN_RAW_PAYLOAD: &str = "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2";
const TYPE_APPROVE_ACTIVITY: &str = "ACTIVITY_TYPE_APPROVE_ACTIVITY";
const TYPE_REJECT_ACTIVITY: &str = "ACTIVITY_TYPE_REJECT_ACTIVITY";

/// The Turnkey calls the custody flow uses, as a trait so the executor and the
/// approver-watcher can be tested against a stub without live HTTP. Implemented
/// by [`TurnkeyClient`]. AFIT + `Send`, static dispatch.
pub trait TurnkeyApi: Send + Sync {
    /// Submit a `SIGN_RAW_PAYLOAD` activity (sign our caller-computed sighash).
    /// Returns the activity — `CONSENSUS_NEEDED` if a consensus policy applies,
    /// or `COMPLETED` with the signature if not.
    fn sign_raw_payload(
        &self,
        params: &SignRawPayloadParams,
    ) -> impl Future<Output = Result<Activity, TurnkeyError>> + Send;

    /// Fetch an activity by id (poll a `CONSENSUS_NEEDED` activity to
    /// completion).
    fn get_activity(
        &self,
        activity_id: &str,
    ) -> impl Future<Output = Result<Activity, TurnkeyError>> + Send;

    /// Cast an APPROVE vote on the activity identified by `fingerprint`.
    fn approve_activity(
        &self,
        fingerprint: &str,
    ) -> impl Future<Output = Result<Activity, TurnkeyError>> + Send;

    /// Cast a REJECT vote on the activity identified by `fingerprint`.
    fn reject_activity(
        &self,
        fingerprint: &str,
    ) -> impl Future<Output = Result<Activity, TurnkeyError>> + Send;
}

/// A minimal Turnkey client. Every request is P-256 stamped via
/// [`TurnkeyStamper`] and scoped to `organization_id` (the custody sub-org).
#[derive(Debug)]
pub struct TurnkeyClient {
    http: reqwest::Client,
    base_url: String,
    organization_id: String,
    stamper: TurnkeyStamper,
}

fn now_ms() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
        .to_string()
}

/// The activity-request envelope shared by every `submit/*` endpoint.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivityRequest<'a, P: Serialize> {
    #[serde(rename = "type")]
    activity_type: &'a str,
    timestamp_ms: String,
    organization_id: &'a str,
    parameters: P,
}

/// The `query/get_activity` request body.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetActivityRequest<'a> {
    organization_id: &'a str,
    activity_id: &'a str,
}

/// `approveActivity` / `rejectActivity` parameters.
#[derive(Serialize)]
struct VoteParams<'a> {
    fingerprint: &'a str,
}

/// Every endpoint returns the activity wrapped in an `activity` field.
#[derive(serde::Deserialize)]
struct ActivityResponse {
    activity: Activity,
}

impl TurnkeyClient {
    /// Build a client for `base_url` (host only, e.g. [`TURNKEY_API_BASE`]),
    /// the custody `organization_id`, and the P-256 stamper.
    ///
    /// # Errors
    /// [`TurnkeyError::Http`] if the HTTP client cannot be constructed.
    pub fn new(
        base_url: impl Into<String>,
        organization_id: impl Into<String>,
        stamper: TurnkeyStamper,
    ) -> Result<Self, TurnkeyError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| TurnkeyError::Http(e.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.into(),
            organization_id: organization_id.into(),
            stamper,
        })
    }

    /// Stamp + POST `body` to `path`, deserializing the 2xx response into `T`.
    async fn post_stamped<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, TurnkeyError> {
        let body_str =
            serde_json::to_string(body).map_err(|e| TurnkeyError::Decode(e.to_string()))?;
        let stamp = self.stamper.stamp(&body_str)?;
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("X-Stamp", stamp)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body_str)
            .send()
            .await
            .map_err(|e| TurnkeyError::Http(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| TurnkeyError::Http(e.to_string()))?;
        if status.is_success() {
            serde_json::from_str(&text)
                .map_err(|e| TurnkeyError::Decode(format!("{path} response: {e}")))
        } else {
            Err(TurnkeyError::Api {
                status: status.as_u16(),
                body: text,
            })
        }
    }

    /// Submit an activity with the standard envelope, returning the activity.
    async fn submit_activity<P: Serialize>(
        &self,
        path: &str,
        activity_type: &str,
        parameters: P,
    ) -> Result<Activity, TurnkeyError> {
        let req = ActivityRequest {
            activity_type,
            timestamp_ms: now_ms(),
            organization_id: &self.organization_id,
            parameters,
        };
        let resp: ActivityResponse = self.post_stamped(path, &req).await?;
        Ok(resp.activity)
    }
}

impl TurnkeyApi for TurnkeyClient {
    async fn sign_raw_payload(
        &self,
        params: &SignRawPayloadParams,
    ) -> Result<Activity, TurnkeyError> {
        self.submit_activity(SUBMIT_SIGN_RAW_PAYLOAD, TYPE_SIGN_RAW_PAYLOAD, params)
            .await
    }

    async fn get_activity(&self, activity_id: &str) -> Result<Activity, TurnkeyError> {
        let req = GetActivityRequest {
            organization_id: &self.organization_id,
            activity_id,
        };
        let resp: ActivityResponse = self.post_stamped(QUERY_GET_ACTIVITY, &req).await?;
        Ok(resp.activity)
    }

    async fn approve_activity(&self, fingerprint: &str) -> Result<Activity, TurnkeyError> {
        self.submit_activity(
            SUBMIT_APPROVE_ACTIVITY,
            TYPE_APPROVE_ACTIVITY,
            VoteParams { fingerprint },
        )
        .await
    }

    async fn reject_activity(&self, fingerprint: &str) -> Result<Activity, TurnkeyError> {
        self.submit_activity(
            SUBMIT_REJECT_ACTIVITY,
            TYPE_REJECT_ACTIVITY,
            VoteParams { fingerprint },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ActivityStatus;
    use wiremock::matchers::{body_string_contains, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Throwaway 32-byte P-256 private key (test-only).
    const TEST_KEY: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    #[expect(clippy::expect_used, reason = "test code")]
    fn client_for(server: &MockServer) -> TurnkeyClient {
        TurnkeyClient::new(
            server.uri(),
            "org-1",
            TurnkeyStamper::from_hex(TEST_KEY).expect("stamper"),
        )
        .expect("client")
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn sign_raw_payload_stamps_and_parses_consensus_needed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(SUBMIT_SIGN_RAW_PAYLOAD))
            .and(header_exists("X-Stamp"))
            .and(body_string_contains("ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"))
            .and(body_string_contains("HASH_FUNCTION_NO_OP"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "id": "act-1", "organizationId": "org-1",
                    "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                    "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fp-1"
                }
            })))
            .mount(&server)
            .await;

        let params = SignRawPayloadParams::hex_no_op("0xkey", "0xabcdef");
        let act = client_for(&server)
            .sign_raw_payload(&params)
            .await
            .expect("sign");
        assert_eq!(act.id, "act-1");
        assert_eq!(act.status, ActivityStatus::ConsensusNeeded);
        assert_eq!(act.fingerprint, "fp-1");
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn get_activity_returns_completed_signature() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(QUERY_GET_ACTIVITY))
            .and(header_exists("X-Stamp"))
            .and(body_string_contains("\"activityId\":\"act-1\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "id": "act-1", "status": "ACTIVITY_STATUS_COMPLETED",
                    "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fp-1",
                    "result": { "signRawPayloadResult": {
                        "r": &"11".repeat(32), "s": &"22".repeat(32), "v": "00"
                    }}
                }
            })))
            .mount(&server)
            .await;

        let act = client_for(&server)
            .get_activity("act-1")
            .await
            .expect("get");
        assert!(act.status.is_completed());
        let (r, _s, v) = act.sign_result().expect("sig").rsv().expect("rsv");
        assert_eq!(r[0], 0x11);
        assert_eq!(v, 0);
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn approve_activity_posts_fingerprint_to_approve_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(SUBMIT_APPROVE_ACTIVITY))
            .and(header_exists("X-Stamp"))
            .and(body_string_contains("ACTIVITY_TYPE_APPROVE_ACTIVITY"))
            .and(body_string_contains("\"fingerprint\":\"fp-1\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "id": "act-1", "status": "ACTIVITY_STATUS_COMPLETED",
                    "type": "ACTIVITY_TYPE_APPROVE_ACTIVITY", "fingerprint": "fp-1"
                }
            })))
            .mount(&server)
            .await;

        let act = client_for(&server)
            .approve_activity("fp-1")
            .await
            .expect("approve");
        assert!(act.status.is_completed());
    }

    #[tokio::test]
    #[expect(clippy::expect_used, reason = "test code")]
    async fn non_2xx_is_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(QUERY_GET_ACTIVITY))
            .respond_with(ResponseTemplate::new(401).set_body_string("{\"message\":\"bad stamp\"}"))
            .mount(&server)
            .await;

        let err = client_for(&server)
            .get_activity("act-x")
            .await
            .expect_err("should 401");
        assert!(matches!(err, TurnkeyError::Api { status: 401, .. }));
    }
}
