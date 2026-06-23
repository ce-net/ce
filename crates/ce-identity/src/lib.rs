use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

pub type NodeId = [u8; 32];

pub struct Identity {
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Identity {
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let key_path = dir.join("node.key");
        let signing_key = if key_path.exists() {
            let bytes = std::fs::read(&key_path)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("corrupt key file — delete {} and restart", key_path.display()))?;
            SigningKey::from_bytes(&bytes)
        } else {
            let key = SigningKey::generate(&mut OsRng);
            std::fs::write(&key_path, key.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }
            key
        };
        let verifying_key = signing_key.verifying_key();
        Ok(Self { signing_key, verifying_key })
    }

    pub fn node_id(&self) -> NodeId {
        self.verifying_key.to_bytes()
    }

    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id())
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }

    /// Raw secret bytes — seed for the libp2p keypair so both share the same identity.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Construct an identity directly from 32 raw secret-key bytes — no filesystem, no RNG.
    /// Deterministic: the same seed always yields the same node id. Used by browser/mobile clients
    /// and by golden-vector generation where the key must be fixed and reproducible.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }
}

pub fn verify(node_id: &NodeId, data: &[u8], sig: &[u8; 64]) -> Result<()> {
    let key = VerifyingKey::from_bytes(node_id)?;
    let signature = Signature::from_bytes(sig);
    key.verify(data, &signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("ce-id-{}-{}", std::process::id(), tag));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn generate_creates_key_file() {
        let dir = tmpdir("gen");
        Identity::load_or_generate(&dir).unwrap();
        assert!(dir.join("node.key").exists());
    }

    #[test]
    fn reload_returns_same_node_id() {
        let dir = tmpdir("reload");
        let id1 = Identity::load_or_generate(&dir).unwrap();
        let id2 = Identity::load_or_generate(&dir).unwrap();
        assert_eq!(id1.node_id(), id2.node_id());
    }

    #[test]
    fn sign_and_verify_succeeds() {
        let dir = tmpdir("sign");
        let id = Identity::load_or_generate(&dir).unwrap();
        let sig = id.sign(b"hello, ce");
        assert!(verify(&id.node_id(), b"hello, ce", &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let dir = tmpdir("tamper");
        let id = Identity::load_or_generate(&dir).unwrap();
        let sig = id.sign(b"original");
        assert!(verify(&id.node_id(), b"tampered", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let dir1 = tmpdir("wk1");
        let dir2 = tmpdir("wk2");
        let id1 = Identity::load_or_generate(&dir1).unwrap();
        let id2 = Identity::load_or_generate(&dir2).unwrap();
        let sig = id1.sign(b"data");
        // id2's key should not verify id1's signature
        assert!(verify(&id2.node_id(), b"data", &sig).is_err());
    }

    #[test]
    fn node_id_hex_is_64_chars() {
        let dir = tmpdir("hex");
        let id = Identity::load_or_generate(&dir).unwrap();
        assert_eq!(id.node_id_hex().len(), 64);
    }

    #[test]
    fn node_id_hex_roundtrips() {
        let dir = tmpdir("rt");
        let id = Identity::load_or_generate(&dir).unwrap();
        let decoded: [u8; 32] = hex::decode(id.node_id_hex())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(decoded, id.node_id());
    }

    #[test]
    fn secret_bytes_len() {
        let dir = tmpdir("secret");
        let id = Identity::load_or_generate(&dir).unwrap();
        assert_eq!(id.secret_bytes().len(), 32);
    }
}
