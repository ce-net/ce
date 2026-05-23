use anyhow::{anyhow, Result};
use ce_identity::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A trusted device entry in ~/.local/share/ce/machines.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// Hex-encoded Ed25519 node ID of the trusted device.
    pub node_id: String,
    /// API address in "host:port" form, e.g. "192.168.1.10:8080".
    pub addr: String,
}

/// The full device registry, serialised as TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Devices {
    #[serde(default)]
    pub devices: HashMap<String, DeviceEntry>,
}

impl Devices {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let d: Devices = toml::from_str(&text)?;
        Ok(d)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn load_or_empty(path: &Path) -> Self {
        Self::load(path).unwrap_or_default()
    }

    pub fn add(&mut self, name: &str, node_id: NodeId, addr: &str) {
        self.devices.insert(
            name.to_string(),
            DeviceEntry { node_id: hex::encode(node_id), addr: addr.to_string() },
        );
    }

    /// Remove a device by name. Returns true if it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.devices.remove(name).is_some()
    }

    /// Look up a device by name. Returns (node_id, addr) or an error.
    pub fn get(&self, name: &str) -> Result<(NodeId, String)> {
        let entry = self.devices.get(name).ok_or_else(|| anyhow!("unknown device '{name}'"))?;
        let bytes = hex::decode(&entry.node_id)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("bad node_id for '{name}'"))?;
        Ok((arr, entry.addr.clone()))
    }

    /// Returns true if the given node_id belongs to any registered device.
    pub fn is_trusted(&self, node_id: &NodeId) -> bool {
        let hex = hex::encode(node_id);
        self.devices.values().any(|e| e.node_id == hex)
    }

    pub fn list(&self) -> Vec<(String, NodeId, String)> {
        let mut out: Vec<(String, NodeId, String)> = self
            .devices
            .iter()
            .filter_map(|(name, entry)| {
                let bytes = hex::decode(&entry.node_id).ok()?;
                let arr: [u8; 32] = bytes.try_into().ok()?;
                Some((name.clone(), arr, entry.addr.clone()))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}
