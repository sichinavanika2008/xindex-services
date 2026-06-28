//! Cobo TSS-Node callback wire types.
//!
//! The TSS Node POSTs a JWT (RS256) whose claims are a `CallbackRequest`. The
//! exact field names + the per-type `request_detail` / `extra_info` schema are
//! NOT in Cobo's public docs — every field here is parsed leniently and the
//! exact shape is **reconciled at the `api.dev.cobo.com` dev-env**
//! (`docs/runbooks/cobo-btc-gate.md`). This is safe by construction: the
//! callback only APPROVEs a `KeySign` that (a) we recognize AND (b) has a
//! prepare-context we stored AND (c) passes the k-of-n RIC decision — so a
//! mis-parsed field can only cause a fail-closed REJECT, never a false APPROVE.

use serde::{Deserialize, Serialize};

/// A Cobo TSS-Node callback request (the JWT claims). Fields are aliased
/// across the casings Cobo might use; unknown fields are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct CallbackRequest {
    /// The unique request id Cobo echoes from our transfer submission — our
    /// correlation key into the [`crate::prepare::PrepareStore`].
    #[serde(alias = "requestId", alias = "id", alias = "request_id")]
    pub request_id: String,
    /// The request kind (`KeyGen` / `KeySign` / `KeyReshare`). Encoding (int vs
    /// string) is non-public → kept as a raw value, interpreted by
    /// [`Self::is_key_sign`]. RECONCILE AT DEV-ENV.
    #[serde(alias = "requestType", alias = "type", alias = "request_type", default)]
    pub request_type: serde_json::Value,
    /// Per-type details as a serialized-JSON string (Cobo's documented shape).
    /// Used at dev-env for the message↔prepare cross-check. RECONCILE AT DEV-ENV.
    #[serde(alias = "requestDetail", alias = "request_detail", default)]
    pub request_detail: String,
    /// Per-type extra info as a serialized-JSON string. RECONCILE AT DEV-ENV.
    #[serde(alias = "extraInfo", alias = "extra_info", default)]
    pub extra_info: String,
}

impl CallbackRequest {
    /// True iff this is a transaction/message-signing (`KeySign`) request — the
    /// only kind this callback gates. Matches the documented integer (`2`) and
    /// the string spellings; anything else returns `false` so an unrecognized
    /// type fails closed (REJECT). RECONCILE the exact encoding AT DEV-ENV.
    #[must_use]
    pub fn is_key_sign(&self) -> bool {
        match &self.request_type {
            serde_json::Value::Number(n) => n.as_i64() == Some(2),
            serde_json::Value::String(s) => {
                let s = s.to_ascii_lowercase();
                s == "keysign" || s == "typekeysign" || s == "2" || s == "sign"
            }
            _ => false,
        }
    }
}

/// The callback response. `status` + `action` are Cobo's documented shape
/// ("status 0 + action REJECT indicates the reason"); exact casing/codes are
/// reconciled at dev-env. Built only via the constructors so the action string
/// is never free-typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallbackResponse {
    /// Cobo response status (0 = handled). RECONCILE AT DEV-ENV.
    pub status: i64,
    /// `"APPROVE"` or `"REJECT"`. RECONCILE exact casing AT DEV-ENV.
    pub action: String,
    /// Rejection reason (`code: message`); absent on APPROVE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CallbackResponse {
    /// APPROVE — Cobo's MPC may produce the signature.
    #[must_use]
    pub fn approve() -> Self {
        Self {
            status: 0,
            action: "APPROVE".to_string(),
            error: None,
        }
    }

    /// REJECT (fail-closed) carrying the stable `code` + operator-facing detail.
    #[must_use]
    pub fn reject(code: &str, message: impl Into<String>) -> Self {
        Self {
            status: 0,
            action: "REJECT".to_string(),
            error: Some(format!("{code}: {}", message.into())),
        }
    }

    /// True iff this response approves the signature.
    #[must_use]
    pub fn is_approve(&self) -> bool {
        self.action == "APPROVE"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_sign_recognized_int_and_string() {
        let mk = |v: serde_json::Value| CallbackRequest {
            request_id: "r".into(),
            request_type: v,
            request_detail: String::new(),
            extra_info: String::new(),
        };
        assert!(mk(serde_json::json!(2)).is_key_sign());
        assert!(mk(serde_json::json!("KeySign")).is_key_sign());
        assert!(mk(serde_json::json!("TypeKeySign")).is_key_sign());
        assert!(!mk(serde_json::json!(1)).is_key_sign());
        assert!(!mk(serde_json::json!("KeyGen")).is_key_sign());
        assert!(!mk(serde_json::Value::Null).is_key_sign());
    }

    #[test]
    fn deserializes_aliased_fields() {
        let body = serde_json::json!({
            "request_id": "abc-123",
            "request_type": 2,
            "request_detail": "{\"k\":\"v\"}",
            "extra_info": "{}"
        });
        #[expect(clippy::expect_used, reason = "test code")]
        let req: CallbackRequest = serde_json::from_value(body).expect("parse");
        assert_eq!(req.request_id, "abc-123");
        assert!(req.is_key_sign());
    }

    #[test]
    fn camelcase_request_id_alias_parses() {
        let body = serde_json::json!({ "requestId": "x", "type": "KeySign" });
        #[expect(clippy::expect_used, reason = "test code")]
        let req: CallbackRequest = serde_json::from_value(body).expect("parse");
        assert_eq!(req.request_id, "x");
        assert!(req.is_key_sign());
    }

    #[test]
    fn response_serializes_approve_without_error() {
        #[expect(clippy::expect_used, reason = "test code")]
        let s = serde_json::to_string(&CallbackResponse::approve()).expect("serialize");
        assert!(s.contains("APPROVE"));
        assert!(!s.contains("error"));
    }
}
