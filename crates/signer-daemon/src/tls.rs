//! Exact-peer mutual TLS for the signer daemon (`DL-M5-5`, closes `M-R3`).
//!
//! The shared `xindex-ops` verifier performs normal `WebPKI` validation and then
//! requires the presented end-entity certificate's SHA-256 fingerprint to
//! match an explicitly configured leaf. A sibling issued by the same CA is
//! therefore rejected before the request reaches the router.

use std::sync::Arc;

use rustls::ServerConfig;
use tokio::net::TcpListener;
pub use xindex_ops::tls::{
    client_config, exact_pinned_async_client_builder, exact_pinned_blocking_client_builder,
    load_cert_chain, load_private_key, pinned_cert_store, server_config, PinnedCertStore, TlsError,
};

/// Serve `app` over mutual TLS on `listener` — the production bind for the
/// daemon router (`server.rs` returns the router; this wraps it in the TLS
/// acceptor). Each accepted connection completes the mTLS handshake (an
/// unpinned client is dropped here, before any request is dispatched) and is
/// then served on its own task.
///
/// # Errors
/// Returns the listener's I/O error if `accept` fails. Per-connection TLS /
/// HTTP errors are logged and isolated to that connection.
pub async fn serve_mtls(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: axum::Router,
) -> std::io::Result<()> {
    xindex_ops::tls::serve_mtls(listener, config, app).await
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]
    use super::*;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::pki_types::ServerName;
    use rustls::ClientConfig;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    /// One self-signed identity: PEM cert + PEM key, as an operator would hold.
    struct Identity {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    }

    fn self_signed(cn: &str) -> Identity {
        let ck = rcgen::generate_simple_self_signed(vec![cn.to_string()]).expect("gen cert");
        Identity {
            cert_pem: ck.cert.pem().into_bytes(),
            key_pem: ck.key_pair.serialize_pem().into_bytes(),
        }
    }

    fn client_ca() -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().expect("CA key");
        let cert = params.self_signed(&key).expect("CA cert");
        (cert, key)
    }

    fn ca_signed_client(name: &str, ca: &Certificate, ca_key: &KeyPair) -> Identity {
        ca_signed_identity(
            name,
            ExtendedKeyUsagePurpose::ClientAuth,
            ca,
            ca_key,
            &ca.pem(),
            None,
        )
    }

    fn ca_signed_server(name: &str, ca: &Certificate, ca_key: &KeyPair) -> Identity {
        ca_signed_identity(
            name,
            ExtendedKeyUsagePurpose::ServerAuth,
            ca,
            ca_key,
            &ca.pem(),
            None,
        )
    }

    fn ca_signed_identity(
        name: &str,
        purpose: ExtendedKeyUsagePurpose,
        issuer: &Certificate,
        issuer_key: &KeyPair,
        chain_tail_pem: &str,
        validity_years: Option<(i32, i32)>,
    ) -> Identity {
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("leaf params");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![purpose];
        if let Some((not_before, not_after)) = validity_years {
            params.not_before = rcgen::date_time_ymd(not_before, 1, 1);
            params.not_after = rcgen::date_time_ymd(not_after, 1, 1);
        }
        let key = KeyPair::generate().expect("leaf key");
        let cert = params
            .signed_by(&key, issuer, issuer_key)
            .expect("signed leaf");
        Identity {
            cert_pem: format!("{}{chain_tail_pem}", cert.pem()).into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
        }
    }

    fn subordinate_ca(issuer: &Certificate, issuer_key: &KeyPair) -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::new()).expect("intermediate params");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().expect("intermediate key");
        let cert = params
            .signed_by(&key, issuer, issuer_key)
            .expect("intermediate cert");
        (cert, key)
    }

    fn server_cfg(server: &Identity, pinned_client: &Identity) -> ServerConfig {
        server_config(
            load_cert_chain(&server.cert_pem).expect("chain"),
            load_private_key(&server.key_pem).expect("key"),
            pinned_cert_store(std::slice::from_ref(&pinned_client.cert_pem)).expect("pins"),
        )
        .expect("server config")
    }

    fn client_cfg(client: &Identity, server: &Identity) -> ClientConfig {
        client_config(
            load_cert_chain(&client.cert_pem).expect("chain"),
            load_private_key(&client.key_pem).expect("key"),
            pinned_cert_store(std::slice::from_ref(&server.cert_pem)).expect("server pin"),
        )
        .expect("client config")
    }

    /// Drive a full mTLS handshake over an in-memory duplex. The pin is enforced
    /// server-side, so `Ok` here means the client certificate was accepted.
    async fn handshake(server: ServerConfig, client: ClientConfig) -> Result<(), String> {
        let (client_io, server_io) = tokio::io::duplex(16_384);
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let connector = TlsConnector::from(Arc::new(client));
        let server_task = tokio::spawn(async move {
            acceptor
                .accept(server_io)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
        let name = ServerName::try_from("daemon").expect("server name");
        let client_res = connector.connect(name, client_io).await;
        let server_res = server_task.await.map_err(|e| e.to_string())?;
        server_res?;
        client_res.map(|_| ()).map_err(|e| e.to_string())
    }

    #[tokio::test]
    async fn pinned_coordinator_accepted_rogue_rejected() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = self_signed("daemon");
        let coordinator = self_signed("coordinator");
        let rogue = self_signed("rogue");

        // The daemon pins ONLY the coordinator's cert as a client root.
        let pinned = server_cfg(&server, &coordinator);

        // The pinned coordinator handshakes successfully.
        let ok = handshake(pinned.clone(), client_cfg(&coordinator, &server)).await;
        assert!(ok.is_ok(), "pinned coordinator must be accepted: {ok:?}");

        // A rogue client (valid cert, NOT pinned) is rejected at the handshake.
        let rejected = handshake(pinned, client_cfg(&rogue, &server)).await;
        assert!(rejected.is_err(), "unpinned client must be rejected");
    }

    #[tokio::test]
    async fn sibling_client_signed_by_same_ca_is_rejected_by_exact_leaf_pin() {
        let server = self_signed("daemon");
        let (ca, ca_key) = client_ca();
        let coordinator_a = ca_signed_client("coordinator-a", &ca, &ca_key);
        let sibling_b = ca_signed_client("coordinator-b", &ca, &ca_key);

        let pinned = server_cfg(&server, &coordinator_a);
        let accepted = handshake(pinned.clone(), client_cfg(&coordinator_a, &server)).await;
        assert!(
            accepted.is_ok(),
            "configured leaf A must pass: {accepted:?}"
        );

        let sibling = handshake(pinned, client_cfg(&sibling_b, &server)).await;
        assert!(
            sibling.is_err(),
            "sibling leaf B must fail even though it chains to A's root"
        );
    }

    #[tokio::test]
    async fn ca_only_entry_does_not_authorize_any_issued_leaf() {
        let server = self_signed("daemon");
        let (ca, ca_key) = client_ca();
        let issued_client = ca_signed_client("coordinator", &ca, &ca_key);
        let ca_only = pinned_cert_store(&[ca.pem().into_bytes()]).expect("CA-only pin entry");
        let server_tls = server_config(
            load_cert_chain(&server.cert_pem).expect("server chain"),
            load_private_key(&server.key_pem).expect("server key"),
            ca_only,
        )
        .expect("server config");

        assert!(
            handshake(server_tls, client_cfg(&issued_client, &server))
                .await
                .is_err(),
            "a configured CA certificate pins the CA leaf itself, not every issued identity"
        );
    }

    #[tokio::test]
    async fn sibling_server_signed_by_same_ca_is_rejected_by_exact_leaf_pin() {
        let coordinator = self_signed("coordinator");
        let (ca, ca_key) = client_ca();
        let daemon_a = ca_signed_server("daemon", &ca, &ca_key);
        let sibling_b = ca_signed_server("daemon", &ca, &ca_key);

        let accepted = handshake(
            server_cfg(&daemon_a, &coordinator),
            client_cfg(&coordinator, &daemon_a),
        )
        .await;
        assert!(accepted.is_ok(), "configured server leaf A must pass");

        let sibling = handshake(
            server_cfg(&sibling_b, &coordinator),
            client_cfg(&coordinator, &daemon_a),
        )
        .await;
        assert!(
            sibling.is_err(),
            "sibling server leaf B must fail even with the same name and root"
        );
    }

    #[tokio::test]
    async fn exact_pin_does_not_bypass_server_hostname_validation() {
        let coordinator = self_signed("coordinator");
        let wrong_name = self_signed("not-daemon");

        assert!(
            handshake(
                server_cfg(&wrong_name, &coordinator),
                client_cfg(&coordinator, &wrong_name),
            )
            .await
            .is_err(),
            "the exact certificate must still fail normal hostname validation"
        );
    }

    #[tokio::test]
    async fn explicit_rotation_overlap_accepts_only_the_two_configured_leaves() {
        let server = self_signed("daemon");
        let (ca, ca_key) = client_ca();
        let old = ca_signed_client("coordinator-old", &ca, &ca_key);
        let renewed = ca_signed_client("coordinator-new", &ca, &ca_key);
        let sibling = ca_signed_client("coordinator-sibling", &ca, &ca_key);
        let pins = pinned_cert_store(&[old.cert_pem.clone(), renewed.cert_pem.clone()])
            .expect("rotation pins");
        let server_tls = server_config(
            load_cert_chain(&server.cert_pem).expect("server chain"),
            load_private_key(&server.key_pem).expect("server key"),
            pins,
        )
        .expect("server config");

        assert!(
            handshake(server_tls.clone(), client_cfg(&old, &server))
                .await
                .is_ok(),
            "old leaf remains valid during explicit overlap"
        );
        assert!(
            handshake(server_tls.clone(), client_cfg(&renewed, &server))
                .await
                .is_ok(),
            "renewed leaf is explicitly allowed"
        );
        assert!(
            handshake(server_tls, client_cfg(&sibling, &server))
                .await
                .is_err(),
            "an unlisted sibling remains rejected"
        );
    }

    #[tokio::test]
    async fn intermediate_chain_and_exact_leaf_both_validate() {
        let server = self_signed("daemon");
        let (root, root_key) = client_ca();
        let (intermediate, intermediate_key) = subordinate_ca(&root, &root_key);
        let chain_tail = format!("{}{}", intermediate.pem(), root.pem());
        let client = ca_signed_identity(
            "coordinator",
            ExtendedKeyUsagePurpose::ClientAuth,
            &intermediate,
            &intermediate_key,
            &chain_tail,
            None,
        );
        let result = handshake(server_cfg(&server, &client), client_cfg(&client, &server)).await;
        assert!(
            result.is_ok(),
            "valid leaf/intermediate/root chain must pass: {result:?}"
        );
    }

    #[tokio::test]
    async fn exact_pin_does_not_bypass_expiry_or_not_yet_valid_checks() {
        let server = self_signed("daemon");
        let (ca, ca_key) = client_ca();
        let expired = ca_signed_identity(
            "expired-client",
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
            &ca.pem(),
            Some((2020, 2021)),
        );
        let future = ca_signed_identity(
            "future-client",
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
            &ca.pem(),
            Some((2090, 2091)),
        );

        assert!(
            handshake(server_cfg(&server, &expired), client_cfg(&expired, &server))
                .await
                .is_err(),
            "an exactly pinned expired leaf must fail WebPKI"
        );
        assert!(
            handshake(server_cfg(&server, &future), client_cfg(&future, &server))
                .await
                .is_err(),
            "an exactly pinned future leaf must fail WebPKI"
        );
    }

    #[test]
    fn empty_allowlist_fails_closed() {
        assert!(matches!(
            pinned_cert_store(&[]),
            Err(TlsError::NoPinnedCerts)
        ));
    }

    #[test]
    fn malformed_pem_errors_not_panics() {
        assert!(load_private_key(b"not a pem").is_err() || load_private_key(b"").is_err());
        // Non-PEM input yields no certs (empty), never a usable chain or a panic.
        assert!(load_cert_chain(b"garbage").unwrap_or_default().is_empty());
    }

    /// 2-B/red-team: a server cert paired with a NON-matching private key must
    /// fail closed at config build (rustls `with_single_cert` rejects it),
    /// never produce a serving config with a broken identity.
    #[test]
    fn server_config_rejects_mismatched_key() {
        let server = self_signed("daemon");
        let other = self_signed("other");
        let coord = self_signed("coordinator");
        let pinned = pinned_cert_store(std::slice::from_ref(&coord.cert_pem)).expect("pins");
        let r = server_config(
            load_cert_chain(&server.cert_pem).expect("chain"),
            load_private_key(&other.key_pem).expect("key"), // WRONG key for this cert
            pinned,
        );
        assert!(r.is_err(), "cert/key mismatch must be rejected");
    }

    /// 2-B/red-team: a PEM with no CERTIFICATE section (e.g. a key-only blob)
    /// yields zero pinned roots → `NoPinnedCerts`, not a silently-empty
    /// allowlist that would trust no one (or, worse, anyone).
    #[test]
    fn pinned_cert_store_no_cert_section_fails_closed() {
        let key_only = self_signed("x").key_pem; // valid PEM, but a KEY not a CERT
        assert!(matches!(
            pinned_cert_store(std::slice::from_ref(&key_only)),
            Err(TlsError::NoPinnedCerts)
        ));
    }
}
