//! Mutual TLS for the signer daemon (`DL-M5-5`, closes `M-R3`).
//!
//! Production runs each operator's daemon behind mutual TLS. The daemon
//! presents its own server certificate AND requires the connecting coordinator
//! to present a client certificate that is **pinned** in this daemon's
//! allowlist. The pin is expressed as a [`RootCertStore`] holding only the
//! coordinator's (self-signed) certificate(s); rustls's vetted
//! [`WebPkiClientVerifier`] then rejects — at the TLS handshake, before the
//! request ever reaches the router — any client whose certificate does not
//! chain to a pinned root. Coordinators hold zero key material, so this
//! authenticates *which* coordinator host may submit signing requests, in depth
//! with the on-chain attestation quorum (`DL-M5-1`).
//!
//! The crypto backend is `ring` (the provider already used across the
//! workspace), selected explicitly so no process-default provider needs to be
//! installed and no second backend is pulled in.

use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Errors building the mTLS configuration or loading key material.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A PEM blob could not be parsed (malformed, or no key section).
    #[error("PEM parse: {0}")]
    Pem(String),
    /// The pinned-client allowlist was empty (fail closed — an empty allowlist
    /// would either trust everyone or no one; both are configuration errors).
    #[error("no pinned client certificates")]
    NoPinnedCerts,
    /// rustls rejected the assembled configuration.
    #[error("rustls: {0}")]
    Rustls(String),
}

/// The `ring` crypto provider, used explicitly everywhere so the daemon never
/// depends on a process-default provider being installed.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Parse a PEM certificate chain (leaf first).
///
/// # Errors
/// [`TlsError::Pem`] if the PEM is malformed.
pub fn load_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Pem(e.to_string()))
}

/// Parse a single PEM private key (PKCS#8, SEC1, or RSA).
///
/// # Errors
/// [`TlsError::Pem`] if the PEM is malformed or contains no private key.
pub fn load_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| TlsError::Pem(e.to_string()))
}

/// Build a [`RootCertStore`] from the pinned coordinator certificate PEM(s) —
/// the daemon's client-auth allowlist.
///
/// # Errors
/// [`TlsError::Pem`] on a malformed PEM, [`TlsError::Rustls`] if a certificate
/// is rejected, [`TlsError::NoPinnedCerts`] if the result is empty.
pub fn pinned_root_store(client_cert_pems: &[Vec<u8>]) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    for pem in client_cert_pems {
        for cert in load_cert_chain(pem)? {
            roots
                .add(cert)
                .map_err(|e| TlsError::Rustls(e.to_string()))?;
        }
    }
    if roots.is_empty() {
        return Err(TlsError::NoPinnedCerts);
    }
    Ok(roots)
}

/// Build the daemon's mTLS [`ServerConfig`]: present `server_chain`/`server_key`
/// and require a client certificate chaining to one of `pinned_clients`.
///
/// # Errors
/// [`TlsError::Rustls`] if the verifier or server certificate is rejected.
pub fn server_config(
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    pinned_clients: RootCertStore,
) -> Result<ServerConfig, TlsError> {
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(pinned_clients), provider())
            .build()
            .map_err(|e| TlsError::Rustls(e.to_string()))?;
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain, server_key)
        .map_err(|e| TlsError::Rustls(e.to_string()))
}

/// Build the coordinator-side mTLS [`ClientConfig`]: present
/// `client_chain`/`client_key` and pin the daemon's server certificate as the
/// only trusted root (`pinned_server`).
///
/// # Errors
/// [`TlsError::Rustls`] if the client certificate is rejected.
pub fn client_config(
    client_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    pinned_server: RootCertStore,
) -> Result<ClientConfig, TlsError> {
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .with_root_certificates(pinned_server)
        .with_client_auth_cert(client_chain, client_key)
        .map_err(|e| TlsError::Rustls(e.to_string()))
}

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
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (tcp, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(err) => {
                    tracing::debug!(error = %err, "mTLS handshake rejected (unpinned/invalid client)");
                    return;
                }
            };
            let io = TokioIo::new(stream);
            let service = TowerToHyperService::new(app);
            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                tracing::debug!(error = %err, "mTLS connection ended with error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test code")]
    use super::*;
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

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

    fn single_root(cert_pem: &[u8]) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        for cert in load_cert_chain(cert_pem).expect("certs") {
            roots.add(cert).expect("add root");
        }
        roots
    }

    fn server_cfg(server: &Identity, pinned_client: &Identity) -> ServerConfig {
        server_config(
            load_cert_chain(&server.cert_pem).expect("chain"),
            load_private_key(&server.key_pem).expect("key"),
            pinned_root_store(std::slice::from_ref(&pinned_client.cert_pem)).expect("pins"),
        )
        .expect("server config")
    }

    fn client_cfg(client: &Identity, server: &Identity) -> ClientConfig {
        client_config(
            load_cert_chain(&client.cert_pem).expect("chain"),
            load_private_key(&client.key_pem).expect("key"),
            single_root(&server.cert_pem),
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

    #[test]
    fn empty_allowlist_fails_closed() {
        assert!(matches!(
            pinned_root_store(&[]),
            Err(TlsError::NoPinnedCerts)
        ));
    }

    #[test]
    fn malformed_pem_errors_not_panics() {
        assert!(load_private_key(b"not a pem").is_err() || load_private_key(b"").is_err());
        // Non-PEM input yields no certs (empty), never a usable chain or a panic.
        assert!(load_cert_chain(b"garbage").unwrap_or_default().is_empty());
    }
}
