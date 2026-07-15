//! Shared exact-peer mutual-TLS transport for production HTTP roles.
//!
//! Every peer first passes normal rustls `WebPKI` chain, time, purpose,
//! signature, and (for servers) hostname validation. The presented end-entity
//! certificate must then match an explicitly configured SHA-256 leaf pin. A
//! configured PEM entry is leaf-first; its first certificate is pinned and its
//! last certificate is the explicit trust anchor. The peer must present any
//! intermediates during the handshake. Separate entries allow an intentional
//! rotation overlap. The helper deliberately does not read files itself:
//! callers control owner/mode checks before supplying PEM.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use hyper::server::conn::http1::Builder;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    RootCertStore, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::network::{async_client_builder, blocking_client_builder, HttpClientPolicy};

/// Systemic resource policy for production mTLS HTTP listeners.
///
/// The connection gate is acquired before a TLS task is spawned, so silent
/// unauthenticated peers cannot grow the task set. The request gate applies
/// after authentication and fails fast with HTTP 503 rather than queueing an
/// unbounded number of handlers on one or many keep-alive connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsServerPolicy {
    pub max_pre_auth_connections: usize,
    pub max_in_flight_requests: usize,
    pub handshake_timeout: Duration,
    pub header_timeout: Duration,
    pub request_timeout: Duration,
    pub connection_lifetime: Duration,
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for TlsServerPolicy {
    fn default() -> Self {
        Self {
            max_pre_auth_connections: 64,
            max_in_flight_requests: 64,
            handshake_timeout: Duration::from_secs(5),
            header_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            connection_lifetime: Duration::from_secs(30),
            max_header_bytes: 32 * 1024,
            max_body_bytes: 4 * 1024 * 1024,
        }
    }
}

impl TlsServerPolicy {
    fn validate(self) -> std::io::Result<Self> {
        if self.max_pre_auth_connections == 0
            || self.max_in_flight_requests == 0
            || self.handshake_timeout.is_zero()
            || self.header_timeout.is_zero()
            || self.request_timeout.is_zero()
            || self.connection_lifetime.is_zero()
            || self.max_header_bytes < 8 * 1024
            || self.max_body_bytes == 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mTLS resource policy contains a zero/undersized bound",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("PEM parse: {0}")]
    Pem(String),
    #[error("no pinned certificates")]
    NoPinnedCerts,
    #[error("rustls: {0}")]
    Rustls(String),
    #[error("HTTP client policy: {0}")]
    HttpClient(String),
}

/// Explicit trust anchors plus exact SHA-256 end-entity certificate pins.
///
/// Each configured PEM entry must be leaf-first. The first certificate is an
/// allowed peer identity and the last certificate is its explicit `WebPKI` trust
/// anchor. The peer must present any intermediate certificates. To overlap an
/// intentional renewal, configure each allowed leaf as its own entry.
#[derive(Clone)]
pub struct PinnedCertStore {
    roots: RootCertStore,
    leaf_sha256: Vec<[u8; 32]>,
}

impl std::fmt::Debug for PinnedCertStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedCertStore")
            .field("trust_anchors", &self.roots.len())
            .field("exact_leaf_pins", &self.leaf_sha256.len())
            .finish()
    }
}

#[derive(Debug)]
struct ExactClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    leaf_sha256: Vec<[u8; 32]>,
}

#[derive(Debug)]
struct ExactServerCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    leaf_sha256: Vec<[u8; 32]>,
}

fn exact_leaf_matches(cert: &CertificateDer<'_>, pins: &[[u8; 32]]) -> bool {
    let digest: [u8; 32] = Sha256::digest(cert.as_ref()).into();
    pins.iter().any(|pin| pin == &digest)
}

fn exact_leaf_error() -> RustlsError {
    RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

impl ClientCertVerifier for ExactClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        if !exact_leaf_matches(end_entity, &self.leaf_sha256) {
            return Err(exact_leaf_error());
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

impl ServerCertVerifier for ExactServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        if !exact_leaf_matches(end_entity, &self.leaf_sha256) {
            return Err(exact_leaf_error());
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
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

/// Build explicit trust anchors plus exact leaf-certificate pins.
///
/// Each `cert_pems` entry is one allowed peer bundle in leaf-first order. The
/// first certificate is pinned and the last certificate is its explicit
/// `WebPKI` trust anchor. A CA-only entry therefore cannot accidentally authorize
/// its issued leaves: the handshake fails the exact-leaf comparison.
///
/// # Errors
/// Malformed/rejected certificate or an empty allowlist.
pub fn pinned_cert_store(cert_pems: &[Vec<u8>]) -> Result<PinnedCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    let mut leaf_sha256 = Vec::new();
    for pem in cert_pems {
        let chain = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| TlsError::Pem(error.to_string()))?;
        let Some(leaf) = chain.first() else {
            continue;
        };
        let fingerprint: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        if !leaf_sha256.contains(&fingerprint) {
            leaf_sha256.push(fingerprint);
        }
        let Some(trust_anchor) = chain.last().cloned() else {
            continue;
        };
        roots
            .add(trust_anchor)
            .map_err(|error| TlsError::Rustls(error.to_string()))?;
    }
    if roots.is_empty() || leaf_sha256.is_empty() {
        return Err(TlsError::NoPinnedCerts);
    }
    Ok(PinnedCertStore { roots, leaf_sha256 })
}

/// Build a server configuration requiring a pinned client certificate.
///
/// # Errors
/// Invalid trust roots, protocol versions, key, or certificate chain.
pub fn server_config(
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    pinned_clients: PinnedCertStore,
) -> Result<ServerConfig, TlsError> {
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(pinned_clients.roots), provider())
            .build()
            .map_err(|error| TlsError::Rustls(error.to_string()))?;
    let verifier = Arc::new(ExactClientCertVerifier {
        inner: verifier,
        leaf_sha256: pinned_clients.leaf_sha256,
    });
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
    pinned_server: PinnedCertStore,
) -> Result<ClientConfig, TlsError> {
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(pinned_server.roots), provider())
            .build()
            .map_err(|error| TlsError::Rustls(error.to_string()))?;
    let verifier = Arc::new(ExactServerCertVerifier {
        inner: verifier,
        leaf_sha256: pinned_server.leaf_sha256,
    });
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| TlsError::Rustls(error.to_string()))?
        .dangerous()
        // This remains normal WebPKI validation: the custom verifier above
        // delegates every chain/time/hostname/purpose/signature decision to
        // WebPkiServerVerifier, then adds the exact end-entity pin check.
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client_chain, client_key)
        .map_err(|error| TlsError::Rustls(error.to_string()))
}

/// Start a bounded async reqwest mTLS client whose server passes normal
/// `WebPKI` checks and an exact leaf pin.
///
/// # Errors
/// Invalid HTTP policy, identity, trust bundle, or TLS configuration.
pub fn exact_pinned_async_client_builder(
    policy: HttpClientPolicy,
    client_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    pinned_server: PinnedCertStore,
) -> Result<reqwest::ClientBuilder, TlsError> {
    let tls = client_config(client_chain, client_key, pinned_server)?;
    Ok(async_client_builder(policy)
        .map_err(|error| TlsError::HttpClient(error.to_string()))?
        .https_only(true)
        .use_preconfigured_tls(tls))
}

/// Blocking counterpart to [`exact_pinned_async_client_builder`].
///
/// # Errors
/// Invalid HTTP policy, identity, trust bundle, or TLS configuration.
pub fn exact_pinned_blocking_client_builder(
    policy: HttpClientPolicy,
    client_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    pinned_server: PinnedCertStore,
) -> Result<reqwest::blocking::ClientBuilder, TlsError> {
    let tls = client_config(client_chain, client_key, pinned_server)?;
    Ok(blocking_client_builder(policy)
        .map_err(|error| TlsError::HttpClient(error.to_string()))?
        .https_only(true)
        .use_preconfigured_tls(tls))
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
    serve_mtls_with_policy(listener, config, app, TlsServerPolicy::default()).await
}

/// Serve an Axum router over pinned mutual TLS under explicit connection,
/// request, time, header, and body bounds.
///
/// # Errors
/// Invalid policy or listener accept failure.
pub async fn serve_mtls_with_policy(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: axum::Router,
    policy: TlsServerPolicy,
) -> std::io::Result<()> {
    let policy = policy.validate()?;
    let acceptor = TlsAcceptor::from(config);
    let connection_gate = Arc::new(Semaphore::new(policy.max_pre_auth_connections));
    let request_gate = Arc::new(Semaphore::new(policy.max_in_flight_requests));
    let request_timeout = policy.request_timeout;
    let bounded_app = app
        .layer(DefaultBodyLimit::max(policy.max_body_bytes))
        .layer(middleware::from_fn(
            move |request: Request<Body>, next: Next| {
                let request_gate = Arc::clone(&request_gate);
                async move {
                    let Ok(permit) = request_gate.try_acquire_owned() else {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    };
                    let response =
                        match tokio::time::timeout(request_timeout, next.run(request)).await {
                            Ok(response) => response,
                            Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
                        };
                    drop(permit);
                    response
                }
            },
        ));
    loop {
        let (tcp, _peer) = listener.accept().await?;
        let Ok(connection_permit) = Arc::clone(&connection_gate).try_acquire_owned() else {
            tracing::warn!(
                max_connections = policy.max_pre_auth_connections,
                "mTLS pre-authentication capacity exhausted; dropping peer"
            );
            drop(tcp);
            continue;
        };
        let acceptor = acceptor.clone();
        let app = bounded_app.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let stream =
                match tokio::time::timeout(policy.handshake_timeout, acceptor.accept(tcp)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        tracing::debug!(%error, "mTLS handshake rejected");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!("mTLS handshake timed out");
                        return;
                    }
                };
            let io = TokioIo::new(stream);
            let service = TowerToHyperService::new(app);
            // These internal JSON APIs deliberately serve HTTP/1 only. The
            // direct HTTP/1 builder starts its header timer immediately;
            // protocol auto-detection would otherwise wait indefinitely for
            // the first plaintext byte after a completed TLS handshake.
            let mut builder = Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(policy.header_timeout)
                .max_buf_size(policy.max_header_bytes);
            let connection = builder.serve_connection(io, service);
            match tokio::time::timeout(policy.connection_lifetime, connection).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::debug!(%error, "mTLS connection ended"),
                Err(_) => tracing::debug!("mTLS connection lifetime expired"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures")]

    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    use axum::body::Bytes;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::Router;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::Notify;
    use tokio_rustls::{client::TlsStream, TlsConnector};

    struct Identity {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    }

    struct TestServer {
        address: SocketAddr,
        connector: TlsConnector,
        server_cert_pem: Vec<u8>,
        client_cert_pem: Vec<u8>,
        client_key_pem: Vec<u8>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn identity(name: &str) -> Identity {
        let generated =
            rcgen::generate_simple_self_signed(vec![name.to_string()]).expect("certificate");
        Identity {
            cert_pem: generated.cert.pem().into_bytes(),
            key_pem: generated.key_pair.serialize_pem().into_bytes(),
        }
    }

    async fn start_server(policy: TlsServerPolicy, app: Router) -> TestServer {
        let server = identity("server");
        let client = identity("client");
        let server_tls = server_config(
            load_cert_chain(&server.cert_pem).expect("server chain"),
            load_private_key(&server.key_pem).expect("server key"),
            pinned_cert_store(std::slice::from_ref(&client.cert_pem)).expect("client pin"),
        )
        .expect("server TLS");
        let client_tls = client_config(
            load_cert_chain(&client.cert_pem).expect("client chain"),
            load_private_key(&client.key_pem).expect("client key"),
            pinned_cert_store(std::slice::from_ref(&server.cert_pem)).expect("server pin"),
        )
        .expect("client TLS");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let task = tokio::spawn(serve_mtls_with_policy(
            listener,
            Arc::new(server_tls),
            app,
            policy,
        ));
        TestServer {
            address,
            connector: TlsConnector::from(Arc::new(client_tls)),
            server_cert_pem: server.cert_pem,
            client_cert_pem: client.cert_pem,
            client_key_pem: client.key_pem,
            task,
        }
    }

    async fn connect_tls(server: &TestServer) -> Result<TlsStream<TcpStream>, String> {
        let tcp = TcpStream::connect(server.address)
            .await
            .map_err(|error| error.to_string())?;
        let name = ServerName::try_from("server").map_err(|error| error.to_string())?;
        server
            .connector
            .connect(name, tcp)
            .await
            .map_err(|error| error.to_string())
    }

    async fn request(server: &TestServer, raw: &str) -> Result<String, String> {
        let mut stream = connect_tls(server).await?;
        stream
            .write_all(raw.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .map_err(|_| "response timeout".to_string())?
            .map_err(|error| error.to_string())?;
        String::from_utf8(response).map_err(|error| error.to_string())
    }

    fn policy() -> TlsServerPolicy {
        TlsServerPolicy {
            max_pre_auth_connections: 2,
            max_in_flight_requests: 2,
            handshake_timeout: Duration::from_millis(80),
            header_timeout: Duration::from_millis(80),
            request_timeout: Duration::from_millis(400),
            connection_lifetime: Duration::from_secs(1),
            max_header_bytes: 8 * 1024,
            max_body_bytes: 64,
        }
    }

    #[test]
    fn empty_root_allowlist_fails_closed() {
        assert!(matches!(
            pinned_cert_store(&[]),
            Err(TlsError::NoPinnedCerts)
        ));
    }

    #[tokio::test]
    async fn reqwest_builder_preserves_webpki_and_exact_leaf_verifier() {
        let server = start_server(
            policy(),
            Router::new().route("/health", get(|| async { "ok" })),
        )
        .await;
        let client = exact_pinned_async_client_builder(
            HttpClientPolicy {
                connect_timeout: Duration::from_millis(250),
                request_timeout: Duration::from_secs(1),
                max_response_bytes: 4 * 1024,
            },
            load_cert_chain(&server.client_cert_pem).expect("client chain"),
            load_private_key(&server.client_key_pem).expect("client key"),
            pinned_cert_store(std::slice::from_ref(&server.server_cert_pem)).expect("server pin"),
        )
        .expect("bounded exact-pin builder")
        .resolve("server", server.address)
        .build()
        .expect("reqwest client");

        let response = client
            .get(format!("https://server:{}/health", server.address.port()))
            .send()
            .await
            .expect("pinned mTLS request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.expect("response body"), "ok");
    }

    #[tokio::test]
    async fn silent_socket_releases_pre_auth_capacity_after_timeout() {
        let mut server_policy = policy();
        server_policy.max_pre_auth_connections = 1;
        let server = start_server(
            server_policy,
            Router::new().route("/health", get(|| async { "ok" })),
        )
        .await;

        let silent = TcpStream::connect(server.address)
            .await
            .expect("silent connection");
        tokio::time::sleep(Duration::from_millis(20)).await;

        let overloaded = tokio::time::timeout(
            Duration::from_millis(120),
            request(
                &server,
                "GET /health HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n",
            ),
        )
        .await;
        assert!(overloaded.is_ok(), "overload must fail fast");
        assert!(
            !overloaded
                .expect("completed")
                .unwrap_or_default()
                .contains(" 200 "),
            "an over-capacity peer must not reach the router"
        );

        drop(silent);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let response = request(
            &server,
            "GET /health HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("honest request after timeout");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn silent_authenticated_peer_is_closed_at_header_deadline() {
        let mut server_policy = policy();
        server_policy.max_pre_auth_connections = 1;
        let server = start_server(
            server_policy,
            Router::new().route("/health", get(|| async { "ok" })),
        )
        .await;

        let mut silent = connect_tls(&server).await.expect("TLS handshake");
        tokio::time::sleep(Duration::from_millis(110)).await;
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_millis(100), silent.read(&mut byte))
            .await
            .expect("header timeout must close the connection");
        assert!(
            matches!(closed, Ok(0))
                || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof),
            "deadline must close the TLS stream"
        );

        let response = request(
            &server,
            "GET /health HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("honest request after header timeout");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn fixed_and_chunked_oversized_json_are_rejected_before_decode() {
        let server = start_server(
            policy(),
            Router::new().route("/json", post(|_body: Bytes| async { StatusCode::OK })),
        )
        .await;
        let body = format!("{{\"padding\":\"{}\"}}", "x".repeat(128));
        let fixed = format!(
            "POST /json HTTP/1.1\r\nHost: server\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let fixed_response = request(&server, &fixed).await.expect("fixed response");
        assert!(
            fixed_response.starts_with("HTTP/1.1 413"),
            "{fixed_response}"
        );

        let chunked = format!(
            "POST /json HTTP/1.1\r\nHost: server\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        );
        let chunked_response = request(&server, &chunked).await.expect("chunked response");
        assert!(
            chunked_response.starts_with("HTTP/1.1 413"),
            "{chunked_response}"
        );
    }

    #[tokio::test]
    async fn authenticated_request_saturation_returns_503_then_recovers() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let entered_handler = Arc::clone(&entered);
        let release_handler = Arc::clone(&release);
        let app = Router::new()
            .route(
                "/slow",
                get(move || {
                    let entered = Arc::clone(&entered_handler);
                    let release = Arc::clone(&release_handler);
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        "slow"
                    }
                }),
            )
            .route("/health", get(|| async { "ok" }));
        let mut server_policy = policy();
        server_policy.max_pre_auth_connections = 3;
        server_policy.max_in_flight_requests = 1;
        let server = Arc::new(start_server(server_policy, app).await);

        let entered_wait = entered.notified();
        let first_server = Arc::clone(&server);
        let first = tokio::spawn(async move {
            request(
                &first_server,
                "GET /slow HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n",
            )
            .await
        });
        entered_wait.await;

        let overloaded = request(
            &server,
            "GET /health HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("overload response");
        assert!(overloaded.starts_with("HTTP/1.1 503"), "{overloaded}");

        release.notify_one();
        let first_response = first.await.expect("first task").expect("first response");
        assert!(
            first_response.starts_with("HTTP/1.1 200"),
            "{first_response}"
        );
        let recovered = request(
            &server,
            "GET /health HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("recovered request");
        assert!(recovered.starts_with("HTTP/1.1 200"), "{recovered}");
    }

    #[tokio::test]
    async fn request_deadline_cancels_slow_handler_and_releases_capacity() {
        let mut server_policy = policy();
        server_policy.max_in_flight_requests = 1;
        server_policy.request_timeout = Duration::from_millis(50);
        let server = start_server(
            server_policy,
            Router::new()
                .route(
                    "/slow",
                    get(|| async {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        "slow"
                    }),
                )
                .route("/health", get(|| async { "ok" })),
        )
        .await;

        let timed_out = request(
            &server,
            "GET /slow HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("timeout response");
        assert!(timed_out.starts_with("HTTP/1.1 408"), "{timed_out}");
        let recovered = request(
            &server,
            "GET /health HTTP/1.1\r\nHost: server\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("request after cancellation");
        assert!(recovered.starts_with("HTTP/1.1 200"), "{recovered}");
    }
}
