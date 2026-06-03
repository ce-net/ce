//! ce-protocol-1 — wire format for CE cell signaling.
//!
//! Cells that implement this protocol get first-class status: they can signal
//! other cells, earn/spend credit, and self-replicate. Containers that don't
//! implement it are "foreign" — they run but cannot communicate through CE.
//!
//! Wired into ce-mesh under the `ce-protocol-1` gossip topic. ce-mesh decodes
//! incoming messages, runs `CellSignal::verify()`, and emits
//! `MeshEvent::CellSignal` for valid signals. Burn-proof / chain-side
//! validation lives in ce-node.

use anyhow::{Result, anyhow};
use ce_identity::{NodeId, verify};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u8 = 1;
/// Gossipsub topic name — subscribed by ce-mesh in `Mesh::run`.
pub const GOSSIP_TOPIC: &str = "ce-protocol-1";

// ----- Address -----

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CellAddress {
    /// Signal a specific node.
    Node(NodeId),
    /// Broadcast to all subscribed cells.
    Broadcast,
}

// ----- Capability declaration -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// e.g. "inference", "storage", "relay"
    pub name: String,
    pub version: u32,
}

// ----- Burn proof -----

/// Proof that the sender burned credits before signaling. Required for non-zero-cost operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnProof {
    /// ID of the Meter or Transfer Tx that was burned.
    pub tx_id: [u8; 32],
    /// Burned amount in base units (1 credit = `ce_chain::CREDIT` base units).
    pub amount: u128,
    /// Block that confirmed the burn.
    pub block_height: u64,
    pub block_hash: [u8; 32],
}

// ----- Signal body (unsigned) — what gets signed -----

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignalBody {
    version: u8,
    from: NodeId,
    to: CellAddress,
    capabilities: Vec<Capability>,
    payload: Vec<u8>,
    burn_proof: Option<BurnProof>,
    /// Monotonically increasing per sender — prevents replay attacks.
    nonce: u64,
}

// ----- Full signal (wire format) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellSignal {
    pub version: u8,
    pub from: NodeId,
    pub to: CellAddress,
    pub capabilities: Vec<Capability>,
    pub payload: Vec<u8>,
    pub burn_proof: Option<BurnProof>,
    pub nonce: u64,
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
}

impl CellSignal {
    /// Build and sign a signal. `identity` must match `from`.
    pub fn build(
        from: NodeId,
        to: CellAddress,
        capabilities: Vec<Capability>,
        payload: Vec<u8>,
        burn_proof: Option<BurnProof>,
        nonce: u64,
        identity: &ce_identity::Identity,
    ) -> Self {
        let body = SignalBody {
            version: PROTOCOL_VERSION,
            from,
            to: to.clone(),
            capabilities: capabilities.clone(),
            payload: payload.clone(),
            burn_proof: burn_proof.clone(),
            nonce,
        };
        let data = bincode::serialize(&body).expect("serialize signal body");
        let sig = identity.sign(&data);
        Self {
            version: PROTOCOL_VERSION,
            from,
            to,
            capabilities,
            payload,
            burn_proof,
            nonce,
            sig,
        }
    }

    /// Verify the signature and protocol version.
    pub fn verify(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(anyhow!("unsupported protocol version {}", self.version));
        }
        let body = SignalBody {
            version: self.version,
            from: self.from,
            to: self.to.clone(),
            capabilities: self.capabilities.clone(),
            payload: self.payload.clone(),
            burn_proof: self.burn_proof.clone(),
            nonce: self.nonce,
        };
        let data = bincode::serialize(&body)?;
        verify(&self.from, &data, &self.sig)
    }

    /// Encode to wire bytes (bincode).
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    /// Decode from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// Content-addressed ID — SHA256 of the encoded signal.
    pub fn id(&self) -> [u8; 32] {
        let data = bincode::serialize(self).unwrap_or_default();
        Sha256::digest(data).into()
    }

    /// True if the signal carries a payload but no burn proof.
    /// CE nodes should reject signals where this returns true (free-riding).
    pub fn requires_burn(&self) -> bool {
        !self.payload.is_empty() && self.burn_proof.is_none()
    }
}

// ----- Serde helper for [u8; 64] -----

mod sig_serde {
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(sig)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected 64 bytes for signal signature"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;
    use std::path::Path;

    #[test]
    fn roundtrip_and_verify() {
        let tmp = tempdir();
        let id = Identity::load_or_generate(Path::new(&tmp)).unwrap();
        let node_id = id.node_id();

        let sig = CellSignal::build(
            node_id,
            CellAddress::Broadcast,
            vec![Capability {
                name: "test".into(),
                version: 1,
            }],
            b"hello cell".to_vec(),
            None,
            0,
            &id,
        );

        assert!(sig.verify().is_ok());
        assert!(sig.requires_burn()); // has payload, no burn proof

        let encoded = sig.encode().unwrap();
        let decoded = CellSignal::decode(&encoded).unwrap();
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded.nonce, 0);
    }

    fn tempdir() -> String {
        let dir = std::env::temp_dir().join(format!("ce-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    fn idf(tag: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-proto-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let id = idf("tamper");
        let mut sig = CellSignal::build(id.node_id(), CellAddress::Broadcast, vec![], b"orig".to_vec(), None, 1, &id);
        assert!(sig.verify().is_ok());
        sig.payload = b"tampered".to_vec();
        assert!(sig.verify().is_err(), "payload tamper must break the signature");
    }

    #[test]
    fn wrong_signer_fails_verify() {
        let a = idf("a");
        let b = idf("b");
        // signed by b, but claims to be from a
        let mut sig = CellSignal::build(b.node_id(), CellAddress::Broadcast, vec![], b"x".to_vec(), None, 0, &b);
        sig.from = a.node_id();
        assert!(sig.verify().is_err());
    }

    #[test]
    fn requires_burn_logic() {
        let id = idf("burn");
        // empty payload → no burn needed
        let empty = CellSignal::build(id.node_id(), CellAddress::Broadcast, vec![], vec![], None, 0, &id);
        assert!(!empty.requires_burn());
        // payload + burn proof → satisfied
        let burn = BurnProof { tx_id: [1u8; 32], amount: 1, block_height: 1, block_hash: [2u8; 32] };
        let paid = CellSignal::build(id.node_id(), CellAddress::Broadcast, vec![], b"p".to_vec(), Some(burn), 0, &id);
        assert!(!paid.requires_burn());
    }

    #[test]
    fn id_changes_with_content() {
        let id = idf("idc");
        let s1 = CellSignal::build(id.node_id(), CellAddress::Broadcast, vec![], b"a".to_vec(), None, 0, &id);
        let s2 = CellSignal::build(id.node_id(), CellAddress::Broadcast, vec![], b"b".to_vec(), None, 0, &id);
        assert_ne!(s1.id(), s2.id());
    }
}
