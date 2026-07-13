//! Shared pinned mutual-TLS transport for production HTTP roles.
//!
//! A service presents one certificate and requires every client certificate to
//! chain to an explicitly configured root set. An empty client allowlist is a
//! configuration error. The helper deliberately does not read files itself:
//! callers control owner/mode checks before supplying PEM bytes.

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

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("PEM parse: {0}")]
    Pem(String),
    #[error("no pinned certificates")]
    NoPinnedCerts,
    #[error("rustls: {0}")]
    Rustls(String),
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Parse a PEM certificate chain (leaf first).
///
/// # Errors
/// Malformed PEM or an empty chain.
pub fn load_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let chain = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TlsError::Pem(error.to_string()))?;
    if chain.is_empty() {
        return Err(TlsError::Pem("certificate chain is empty".to_string()));
    }
    Ok(chain)
}

/// Parse a PKCS#8, SEC1, or RSA PEM private key.
///
/// # Errors
/// Malformed PEM or no private key.
pub fn load_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|error| TlsError::Pem(error.to_string()))
}

/// Build a root store containing only explicitly pinned certificate PEMs.
///
/// # Errors
/// Malformed/rejected certificate or an empty allowlist.
pub fn pinned_root_store(cert_pems: &[Vec<u8>]) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    for pem in cert_pems {
        for cert in load_cert_chain(pem)? {
            roots
                .add(cert)
                .map_err(|error| TlsError::Rustls(error.to_string()))?;
        }
    }
    if roots.is_empty() {
        return Err(TlsError::NoPinnedCerts);
    }
    Ok(roots)
}

/// Build a server configuration requiring a pinned client certificate.
///
/// # Errors
/// Invalid trust roots, protocol versions, key, or certificate chain.
pub fn server_config(
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    pinned_clients: RootCertStore,
) -> Result<ServerConfig, TlsError> {
    if pinned_clients.is_empty() {
        return Err(TlsError::NoPinnedCerts);
    }
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(pinned_clients), provider())
            .build()
            .map_err(|error| TlsError::Rustls(error.to_string()))?;
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| TlsError::Rustls(error.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain, server_key)
        .map_err(|error| TlsError::Rustls(error.to_string()))
}

/// Build a client configuration presenting its identity and trusting only the
/// pinned server roots.
///
/// # Errors
/// Empty roots, invalid protocols, key, or certificate chain.
pub fn client_config(
    client_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    pinned_server: RootCertStore,
) -> Result<ClientConfig, TlsError> {
    if pinned_server.is_empty() {
        return Err(TlsError::NoPinnedCerts);
    }
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| TlsError::Rustls(error.to_string()))?
        .with_root_certificates(pinned_server)
        .with_client_auth_cert(client_chain, client_key)
        .map_err(|error| TlsError::Rustls(error.to_string()))
}

/// Serve an Axum router over pinned mutual TLS. A failed handshake or HTTP
/// connection is isolated to that peer; listener failure terminates the
/// service so its supervisor can restart/alert.
///
/// # Errors
/// Listener accept failure.
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
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!(%error, "mTLS handshake rejected");
                    return;
                }
            };
            let io = TokioIo::new(stream);
            let service = TowerToHyperService::new(app);
            if let Err(error) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                tracing::debug!(%error, "mTLS connection ended");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_allowlist_fails_closed() {
        assert!(matches!(
            pinned_root_store(&[]),
            Err(TlsError::NoPinnedCerts)
        ));
    }
}
