/// CE device authentication helpers.
///
/// ## Security model
///
/// Every sync/exec request is signed with the sender's Ed25519 identity key.
/// The signature covers:
///
///   `b"ce-auth-v1 " || METHOD || " " || PATH || " " || timestamp_le_u64 || " " || SHA256(body)`
///
/// Properties this provides:
/// - **Authenticity**: only the holder of the private key can produce a valid sig.
/// - **Body integrity**: swapping the request body (MITM) invalidates the sig.
/// - **Freshness**: timestamp must be within ±5 minutes of server time.
/// - **Replay prevention**: server tracks last-accepted timestamp per sender;
///   strictly increasing requirement closes replays within the 5-minute window.
/// - **Explicit trust**: sender's NodeId must appear in the local machines.toml.
///
/// ## What requires TLS on top
///
/// Signatures prove who sent the data and that it wasn't tampered with, but
/// they do NOT hide the content from a passive observer. The connection must be
/// encrypted (TLS) for confidentiality. CE nodes derive a self-signed TLS cert
/// from their Ed25519 identity key; clients pin against the registered NodeId
/// (the cert's embedded public key), eliminating TOFU risk entirely.
///
/// This is strictly stronger than SSH host-key TOFU:
/// - SSH: you accept the host key on first connection (could be an impostor).
/// - CE: you register the device's NodeId before any connection is made.
use ce_identity::{Identity, NodeId};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Canonical bytes the client signs for authenticated sync/exec requests.
///
/// Includes SHA256(body) so that tampering with the request body invalidates
/// the signature even if the attacker leaves method, path, and timestamp intact.
pub fn auth_bytes(method: &str, path: &str, timestamp_ms: u64, body: &[u8]) -> Vec<u8> {
    let body_hash: [u8; 32] = Sha256::digest(body).into();
    let mut buf = Vec::new();
    buf.extend_from_slice(b"ce-auth-v1 ");
    buf.extend_from_slice(method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(path.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.push(b' ');
    buf.extend_from_slice(&body_hash);
    buf
}

/// Build the three CE auth headers for a request.
///
/// `body` must be the exact bytes that will be sent as the request body.
/// For requests with no body (e.g. GET), pass `b""`.
pub fn make_auth_headers(
    identity: &Identity,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<(String, String)> {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let bytes = auth_bytes(method, path, ts_ms, body);
    let sig = identity.sign(&bytes);
    vec![
        ("X-CE-From".to_string(), hex::encode(identity.node_id())),
        ("X-CE-Timestamp".to_string(), ts_ms.to_string()),
        ("X-CE-Sig".to_string(), hex::encode(sig)),
    ]
}

/// Parse the NodeId from an `X-CE-From` header value.
pub fn parse_from_header(hex: &str) -> Option<NodeId> {
    let bytes = hex::decode(hex).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;
    use std::path::PathBuf;

    fn test_identity(tag: &str) -> Identity {
        let dir = std::env::temp_dir()
            .join(format!("ce-auth-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    #[test]
    fn auth_bytes_changes_with_body() {
        let b1 = auth_bytes("PUT", "/sync/foo", 1000, b"hello");
        let b2 = auth_bytes("PUT", "/sync/foo", 1000, b"world");
        assert_ne!(b1, b2, "different bodies must produce different auth bytes");
    }

    #[test]
    fn auth_bytes_changes_with_method() {
        let b1 = auth_bytes("PUT", "/sync/foo", 1000, b"");
        let b2 = auth_bytes("GET", "/sync/foo", 1000, b"");
        assert_ne!(b1, b2);
    }

    #[test]
    fn auth_bytes_changes_with_path() {
        let b1 = auth_bytes("PUT", "/sync/foo", 1000, b"");
        let b2 = auth_bytes("PUT", "/sync/bar", 1000, b"");
        assert_ne!(b1, b2);
    }

    #[test]
    fn auth_bytes_changes_with_timestamp() {
        let b1 = auth_bytes("PUT", "/sync/foo", 1000, b"");
        let b2 = auth_bytes("PUT", "/sync/foo", 1001, b"");
        assert_ne!(b1, b2);
    }

    #[test]
    fn make_auth_headers_roundtrip() {
        let id = test_identity("roundtrip");
        let body = b"test file content";
        let headers = make_auth_headers(&id, "PUT", "/sync/test.txt", body);

        // Extract the three headers.
        let from_hex = headers.iter().find(|(k, _)| k == "X-CE-From").unwrap().1.clone();
        let ts_str = headers.iter().find(|(k, _)| k == "X-CE-Timestamp").unwrap().1.clone();
        let sig_hex = headers.iter().find(|(k, _)| k == "X-CE-Sig").unwrap().1.clone();

        let ts_ms: u64 = ts_str.parse().unwrap();
        let sig_bytes = hex::decode(sig_hex).unwrap();
        let sig: [u8; 64] = sig_bytes.try_into().unwrap();
        let from: NodeId = parse_from_header(&from_hex).unwrap();

        // Verify against the expected bytes.
        let bytes = auth_bytes("PUT", "/sync/test.txt", ts_ms, body);
        ce_identity::verify(&from, &bytes, &sig).expect("signature must verify");
        assert_eq!(from, id.node_id());
    }

    #[test]
    fn signature_fails_with_wrong_body() {
        let id = test_identity("wrongbody");
        let headers = make_auth_headers(&id, "PUT", "/sync/f", b"original");

        let ts_str = headers.iter().find(|(k, _)| k == "X-CE-Timestamp").unwrap().1.clone();
        let sig_hex = headers.iter().find(|(k, _)| k == "X-CE-Sig").unwrap().1.clone();
        let ts_ms: u64 = ts_str.parse().unwrap();
        let sig: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();

        // Build auth bytes with a DIFFERENT (tampered) body.
        let tampered = auth_bytes("PUT", "/sync/f", ts_ms, b"tampered");
        let result = ce_identity::verify(&id.node_id(), &tampered, &sig);
        assert!(result.is_err(), "signature over original body must not verify for tampered body");
    }
}
