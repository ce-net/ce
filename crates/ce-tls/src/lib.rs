//! TLS-from-identity for CE.
//!
//! A CE node serves its HTTP API over TLS using a self-signed certificate whose key **is** the
//! node's Ed25519 identity. A client knows the target's `NodeId` (the Ed25519 public key) in
//! advance — it registered the device before connecting — and **pins** the presented certificate
//! against it: the cert's public key must equal the expected `NodeId`. This gives confidentiality
//! (TLS) plus authenticity with no certificate authority and no trust-on-first-use:
//!
//! - SSH accepts the host key on first connection (could be an impostor).
//! - CE knows the `NodeId` up front, so a MITM presenting any other cert is rejected outright.
//!
//! The handshake signatures are still verified by the underlying crypto provider (ring); the
//! custom verifier *additionally* pins the leaf certificate's identity. The mesh (`/ce/rpc/1`)
//! is separately encrypted by libp2p Noise; this covers the direct HTTP API.

use anyhow::{anyhow, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use std::sync::Arc;

/// A node identity: the 32-byte Ed25519 public key (same as `ce_identity::NodeId`).
pub type NodeId = [u8; 32];

/// PKCS#8 v1 prefix for an Ed25519 private key (RFC 8410), followed by the 32-byte seed.
const ED25519_PKCS8_PREFIX: [u8; 16] =
    [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

/// SubjectPublicKeyInfo prefix for an Ed25519 public key, followed by the 32-byte key.
const ED25519_SPKI_PREFIX: [u8; 12] =
    [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Build a self-signed cert + key from a node's Ed25519 secret seed. The certificate's public key
/// is exactly the node's identity key, so clients can pin to its `NodeId`.
fn cert_and_key(seed: &[u8; 32]) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
    pkcs8.extend_from_slice(seed);

    let key_pair = rcgen::KeyPair::from_der(&pkcs8)
        .map_err(|e| anyhow!("ed25519 key from seed: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec!["ce-node".to_string()]);
    params.alg = &rcgen::PKCS_ED25519;
    params.key_pair = Some(key_pair);
    let cert = rcgen::Certificate::from_params(params).map_err(|e| anyhow!("cert: {e}"))?;
    let cert_der = cert.serialize_der().map_err(|e| anyhow!("serialize cert: {e}"))?;
    let key_der = cert.serialize_private_key_der();

    Ok((
        CertificateDer::from(cert_der),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
    ))
}

/// A rustls `ServerConfig` presenting the node's identity certificate.
pub fn server_config(seed: &[u8; 32]) -> Result<Arc<ServerConfig>> {
    let (cert, key) = cert_and_key(seed)?;
    let cfg = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("tls versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| anyhow!("server cert: {e}"))?;
    Ok(Arc::new(cfg))
}

/// A rustls `ClientConfig` that pins the server certificate to `expected` (its `NodeId`).
pub fn client_config(expected: NodeId) -> Result<Arc<ClientConfig>> {
    let cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("tls versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
            expected,
            provider: Arc::new(default_provider()),
        }))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Extract the Ed25519 public key (`NodeId`) from a certificate's SubjectPublicKeyInfo.
pub fn node_id_from_cert(cert: &CertificateDer) -> Option<NodeId> {
    let der = cert.as_ref();
    der.windows(ED25519_SPKI_PREFIX.len())
        .position(|w| w == ED25519_SPKI_PREFIX)
        .and_then(|pos| {
            let start = pos + ED25519_SPKI_PREFIX.len();
            der.get(start..start + 32).and_then(|s| s.try_into().ok())
        })
}

/// Verifies the handshake signatures (via ring) AND pins the leaf certificate's identity key
/// to the expected `NodeId`. Hostname/CA are intentionally ignored — the `NodeId` pin is the
/// trust anchor.
#[derive(Debug)]
struct PinnedVerifier {
    expected: NodeId,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match node_id_from_cert(end_entity) {
            Some(id) if id == self.expected => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General(
                "server certificate identity does not match the expected NodeId".into(),
            )),
            None => Err(rustls::Error::General(
                "server certificate is not a CE Ed25519 identity cert".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;

    fn identity(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-tls-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    #[test]
    fn cert_public_key_equals_node_id() {
        let id = identity("certkey");
        let (cert, _key) = cert_and_key(&id.secret_bytes()).unwrap();
        assert_eq!(node_id_from_cert(&cert), Some(id.node_id()), "cert key must be the identity key");
    }

    #[test]
    fn server_and_client_configs_build() {
        let id = identity("cfg");
        assert!(server_config(&id.secret_bytes()).is_ok());
        assert!(client_config(id.node_id()).is_ok());
    }

    #[test]
    fn pin_matches_only_the_right_identity() {
        let server = identity("pin-server");
        let other = identity("pin-other");
        let (cert, _) = cert_and_key(&server.secret_bytes()).unwrap();

        // The pinned verifier accepts a cert whose key matches, rejects one that doesn't.
        let now = UnixTime::now();
        let name = ServerName::try_from("ce-node").unwrap();

        let good = PinnedVerifier { expected: server.node_id(), provider: Arc::new(default_provider()) };
        assert!(good.verify_server_cert(&cert, &[], &name, &[], now).is_ok());

        let bad = PinnedVerifier { expected: other.node_id(), provider: Arc::new(default_provider()) };
        assert!(bad.verify_server_cert(&cert, &[], &name, &[], now).is_err());
    }
}
