//! Turnkey activity request/response types.
//!
//! Hand-rolled from Turnkey's public API docs + SDK. Turnkey models every
//! mutation as an *activity*: a stamped request returns an [`Activity`] whose
//! [`ActivityStatus`] is `COMPLETED` (result ready), `CONSENSUS_NEEDED`
//! (awaiting k-of-n `approveActivity`), or terminal `FAILED` / `REJECTED`.
//! PROVISIONAL — reconcile field-by-field against the Turnkey dev-env.

use serde::{Deserialize, Serialize};

use crate::TurnkeyError;

/// `parameters.encoding` for a pre-built hex payload (our sighash hex).
pub const PAYLOAD_ENCODING_HEXADECIMAL: &str = "PAYLOAD_ENCODING_HEXADECIMAL";
/// `parameters.hashFunction` for an already-hashed payload — Turnkey signs the
/// raw bytes as given (we compute the sighash ourselves). RECONCILE AT DEV-ENV:
/// `HASH_FUNCTION_NO_OP` vs `HASH_FUNCTION_NOT_APPLICABLE` for a pre-hash.
pub const HASH_FUNCTION_NO_OP: &str = "HASH_FUNCTION_NO_OP";

/// `SIGN_RAW_PAYLOAD` activity parameters: sign a caller-computed payload
/// (our exact sighash) with the chosen private key / wallet account.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRawPayloadParams {
    /// The signing key selector — a Turnkey private-key id or wallet-account
    /// address (the custody key).
    pub sign_with: String,
    /// The payload to sign, hex-encoded (our sighash).
    pub payload: String,
    /// Payload encoding ([`PAYLOAD_ENCODING_HEXADECIMAL`]).
    pub encoding: String,
    /// Hash function ([`HASH_FUNCTION_NO_OP`] — Turnkey signs the bytes as-is).
    pub hash_function: String,
}

impl SignRawPayloadParams {
    /// Sign a pre-computed sighash (hex, already hashed) with `sign_with`.
    /// `payload_hex` may carry a `0x` prefix or not — Turnkey accepts hex.
    #[must_use]
    pub fn hex_no_op(sign_with: impl Into<String>, payload_hex: impl Into<String>) -> Self {
        Self {
            sign_with: sign_with.into(),
            payload: payload_hex.into(),
            encoding: PAYLOAD_ENCODING_HEXADECIMAL.to_string(),
            hash_function: HASH_FUNCTION_NO_OP.to_string(),
        }
    }
}

/// A Turnkey activity (the response envelope's `activity` object).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    /// The activity id (used to poll [`crate::TurnkeyApi::get_activity`]).
    pub id: String,
    /// The sub-org this activity belongs to.
    #[serde(default)]
    pub organization_id: String,
    /// Current status.
    pub status: ActivityStatus,
    /// The activity type tag (e.g. `ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2`).
    #[serde(rename = "type", default)]
    pub activity_type: String,
    /// The activity fingerprint — the value `approveActivity` / `rejectActivity`
    /// reference to vote on THIS activity.
    #[serde(default)]
    pub fingerprint: String,
    /// The result, present once `COMPLETED`.
    #[serde(default)]
    pub result: Option<ActivityResult>,
}

impl Activity {
    /// The raw-payload signature result, if this activity completed a
    /// `SIGN_RAW_PAYLOAD`.
    #[must_use]
    pub fn sign_result(&self) -> Option<&SignRawPayloadResult> {
        self.result.as_ref()?.sign_raw_payload_result.as_ref()
    }
}

/// The `activity.result` union (only the variants we consume are modelled).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ActivityResult {
    /// Present for a completed `SIGN_RAW_PAYLOAD`.
    #[serde(default)]
    pub sign_raw_payload_result: Option<SignRawPayloadResult>,
}

/// A `SIGN_RAW_PAYLOAD` result: the ECDSA signature components, hex-encoded.
#[derive(Debug, Clone, Deserialize)]
pub struct SignRawPayloadResult {
    /// Signature `r`, hex (32 bytes).
    pub r: String,
    /// Signature `s`, hex (32 bytes).
    pub s: String,
    /// Recovery id `v`, hex (`"00"` / `"01"`).
    pub v: String,
}

impl SignRawPayloadResult {
    /// Decode to `(r, s, v)` — `r`/`s` as 32-byte arrays, `v` as the recovery
    /// id byte (0/1). The executor assembles the family-specific signature
    /// (DER for the BTC witness, `r‖s‖v+27` for EVM).
    ///
    /// # Errors
    /// [`TurnkeyError::Result`] if any component is not the expected length.
    pub fn rsv(&self) -> Result<([u8; 32], [u8; 32], u8), TurnkeyError> {
        let r = decode32(&self.r, "r")?;
        let s = decode32(&self.s, "s")?;
        let v_bytes = alloy_primitives::hex::decode(self.v.trim_start_matches("0x"))
            .map_err(|e| TurnkeyError::Result(format!("bad v hex: {e}")))?;
        let v = match v_bytes.as_slice() {
            [b] => *b,
            _ => {
                return Err(TurnkeyError::Result(format!(
                    "v must be 1 byte, got {}",
                    v_bytes.len()
                )))
            }
        };
        Ok((r, s, v))
    }
}

fn decode32(hex: &str, field: &str) -> Result<[u8; 32], TurnkeyError> {
    let bytes = alloy_primitives::hex::decode(hex.trim_start_matches("0x"))
        .map_err(|e| TurnkeyError::Result(format!("bad {field} hex: {e}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| TurnkeyError::Result(format!("{field} must be 32 bytes, got {}", bytes.len())))
}

/// Turnkey activity status. Unknown values map to [`ActivityStatus::Unknown`]
/// so a new server-side status never breaks deserialization (and is treated as
/// non-terminal / non-approved — fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
pub enum ActivityStatus {
    /// Created, not yet processed.
    #[serde(rename = "ACTIVITY_STATUS_CREATED")]
    Created,
    /// In progress.
    #[serde(rename = "ACTIVITY_STATUS_PENDING")]
    Pending,
    /// Awaiting k-of-n `approveActivity` (the approver-watcher's gate point).
    #[serde(rename = "ACTIVITY_STATUS_CONSENSUS_NEEDED")]
    ConsensusNeeded,
    /// Completed — the result (signature) is available.
    #[serde(rename = "ACTIVITY_STATUS_COMPLETED")]
    Completed,
    /// Terminally failed.
    #[serde(rename = "ACTIVITY_STATUS_FAILED")]
    Failed,
    /// Rejected (a `rejectActivity`, or a policy denial).
    #[serde(rename = "ACTIVITY_STATUS_REJECTED")]
    Rejected,
    /// Any status this client does not model.
    #[serde(other)]
    #[default]
    Unknown,
}

impl ActivityStatus {
    /// The result (signature) is ready.
    #[must_use]
    pub fn is_completed(self) -> bool {
        matches!(self, ActivityStatus::Completed)
    }

    /// Awaiting consensus — the approver must vote.
    #[must_use]
    pub fn is_consensus_needed(self) -> bool {
        matches!(self, ActivityStatus::ConsensusNeeded)
    }

    /// No further progress will happen (poll loops should stop).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ActivityStatus::Completed | ActivityStatus::Failed | ActivityStatus::Rejected
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn status_deserializes_known_and_unknown() {
        let c: ActivityStatus =
            serde_json::from_str("\"ACTIVITY_STATUS_COMPLETED\"").expect("known");
        assert_eq!(c, ActivityStatus::Completed);
        assert!(c.is_completed() && c.is_terminal());

        let n: ActivityStatus =
            serde_json::from_str("\"ACTIVITY_STATUS_CONSENSUS_NEEDED\"").expect("known");
        assert!(n.is_consensus_needed() && !n.is_terminal());

        let u: ActivityStatus =
            serde_json::from_str("\"ACTIVITY_STATUS_FUTURE\"").expect("unknown");
        assert_eq!(u, ActivityStatus::Unknown);
        assert!(!u.is_terminal());
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn sign_params_serialize_camel_case() {
        let p = SignRawPayloadParams::hex_no_op("0xkey", "0xdeadbeef");
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(json.contains("\"signWith\":\"0xkey\""));
        assert!(json.contains("\"hashFunction\":\"HASH_FUNCTION_NO_OP\""));
        assert!(json.contains("\"encoding\":\"PAYLOAD_ENCODING_HEXADECIMAL\""));
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test code")]
    fn activity_parses_and_exposes_signature() {
        let body = serde_json::json!({
            "id": "act-1",
            "organizationId": "org-1",
            "status": "ACTIVITY_STATUS_COMPLETED",
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
            "fingerprint": "fp-1",
            "result": { "signRawPayloadResult": {
                "r": &"11".repeat(32), "s": &"22".repeat(32), "v": "01"
            }}
        });
        let a: Activity = serde_json::from_value(body).expect("activity");
        assert!(a.status.is_completed());
        assert_eq!(a.fingerprint, "fp-1");
        let (r, s, v) = a.sign_result().expect("sig").rsv().expect("rsv");
        assert_eq!(r[0], 0x11);
        assert_eq!(s[0], 0x22);
        assert_eq!(v, 1);
    }

    #[test]
    fn rsv_rejects_wrong_length() {
        let bad = SignRawPayloadResult {
            r: "11".to_string(),
            s: "22".repeat(32),
            v: "00".to_string(),
        };
        assert!(bad.rsv().is_err());
    }
}
