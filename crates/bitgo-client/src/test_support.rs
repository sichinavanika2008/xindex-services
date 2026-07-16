#![expect(clippy::expect_used, reason = "test-only response fixtures")]

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use wiremock::{Request, ResponseTemplate};

const TEST_TOKEN: &str = "test-token";

pub(crate) fn test_authorization() -> String {
    format!(
        "Bearer {}",
        alloy_primitives::hex::encode(Sha256::digest(TEST_TOKEN.as_bytes()))
    )
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the returned responder must own its JSON fixture"
)]
pub(crate) fn signed_json_response(
    status: u16,
    body: Value,
) -> impl Fn(&Request) -> ResponseTemplate {
    signed_response(
        status,
        serde_json::to_vec(&body).expect("test response JSON"),
        "application/json",
    )
}

pub(crate) fn signed_response(
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
) -> impl Fn(&Request) -> ResponseTemplate {
    move |request| {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_millis()
            .to_string();
        let path = match request.url.query() {
            Some(query) => format!("{}?{query}", request.url.path()),
            None => request.url.path().to_owned(),
        };
        let subject = format!("{timestamp}|{path}|{status}|");
        let mut mac = Hmac::<Sha256>::new_from_slice(TEST_TOKEN.as_bytes()).expect("HMAC key");
        mac.update(subject.as_bytes());
        mac.update(&body);
        let hmac = alloy_primitives::hex::encode(mac.finalize().into_bytes());
        ResponseTemplate::new(status)
            .insert_header("timestamp", timestamp)
            .insert_header("hmac", hmac)
            .set_body_raw(body.clone(), content_type)
    }
}
