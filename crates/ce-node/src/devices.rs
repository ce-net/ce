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
    /// Owner-assigned organizational tags (e.g. "build", "home", "primary").
    ///
    /// These are subjective labels you attach locally to organize and select
    /// your own devices. They are distinct from the capability-derived self-tags
    /// a node advertises on the mesh (`gpu`, `docker`, `linux`, ...), which describe
    /// what work a node can realistically perform and are read from the atlas.
    #[serde(default)]
    pub tags: Vec<String>,
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
        // Preserve any tags already set for this name (re-adding should not wipe them).
        let tags = self.devices.get(name).map(|e| e.tags.clone()).unwrap_or_default();
        self.devices.insert(
            name.to_string(),
            DeviceEntry { node_id: hex::encode(node_id), addr: addr.to_string(), tags },
        );
    }

    /// Add one or more owner tags to an existing device. Duplicates are ignored.
    pub fn add_tags(&mut self, name: &str, tags: &[String]) -> Result<()> {
        let entry = self.devices.get_mut(name).ok_or_else(|| anyhow!("unknown device '{name}'"))?;
        for t in tags {
            if !entry.tags.iter().any(|e| e == t) {
                entry.tags.push(t.clone());
            }
        }
        entry.tags.sort();
        Ok(())
    }

    /// Remove one or more owner tags from an existing device.
    pub fn remove_tags(&mut self, name: &str, tags: &[String]) -> Result<()> {
        let entry = self.devices.get_mut(name).ok_or_else(|| anyhow!("unknown device '{name}'"))?;
        entry.tags.retain(|e| !tags.iter().any(|t| t == e));
        Ok(())
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

    /// Like `list`, but also returns each device's owner tags. Sorted by name.
    /// Used by the `ce fleet` view, which joins these with mesh self-tags.
    pub fn entries(&self) -> Vec<(String, NodeId, String, Vec<String>)> {
        let mut out: Vec<(String, NodeId, String, Vec<String>)> = self
            .devices
            .iter()
            .filter_map(|(name, entry)| {
                let bytes = hex::decode(&entry.node_id).ok()?;
                let arr: [u8; 32] = bytes.try_into().ok()?;
                Some((name.clone(), arr, entry.addr.clone(), entry.tags.clone()))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir()
            .join(format!("ce-devices-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn make_identity(tag: &str) -> Identity {
        Identity::load_or_generate(&tmpdir(tag)).unwrap()
    }

    #[test]
    fn add_and_get_roundtrip() {
        let id = make_identity("add-get");
        let mut d = Devices::default();
        d.add("server", id.node_id(), "10.0.0.1:8080");

        let (nid, addr) = d.get("server").unwrap();
        assert_eq!(nid, id.node_id());
        assert_eq!(addr, "10.0.0.1:8080");
    }

    #[test]
    fn get_unknown_returns_error() {
        let d = Devices::default();
        assert!(d.get("ghost").is_err());
    }

    #[test]
    fn is_trusted_after_add() {
        let id = make_identity("trust");
        let mut d = Devices::default();
        assert!(!d.is_trusted(&id.node_id()));
        d.add("laptop", id.node_id(), "192.168.1.5:8080");
        assert!(d.is_trusted(&id.node_id()));
    }

    #[test]
    fn is_not_trusted_for_unknown_node() {
        let id = make_identity("untrusted");
        let id2 = make_identity("untrusted2");
        let mut d = Devices::default();
        d.add("server", id.node_id(), "1.2.3.4:8080");
        assert!(!d.is_trusted(&id2.node_id()), "unregistered node must not be trusted");
    }

    #[test]
    fn remove_clears_trust() {
        let id = make_identity("remove");
        let mut d = Devices::default();
        d.add("server", id.node_id(), "1.2.3.4:8080");
        assert!(d.is_trusted(&id.node_id()));
        let removed = d.remove("server");
        assert!(removed);
        assert!(!d.is_trusted(&id.node_id()), "trust must clear after remove");
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let mut d = Devices::default();
        assert!(!d.remove("nope"));
    }

    #[test]
    fn list_sorted_by_name() {
        let a = make_identity("list-a");
        let b = make_identity("list-b");
        let c = make_identity("list-c");
        let mut d = Devices::default();
        d.add("zebra", c.node_id(), "1.1.1.1:1");
        d.add("alpha", a.node_id(), "2.2.2.2:2");
        d.add("middle", b.node_id(), "3.3.3.3:3");

        let list = d.list();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].0, "alpha");
        assert_eq!(list[1].0, "middle");
        assert_eq!(list[2].0, "zebra");
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tmpdir("saveload");
        let path = dir.join("machines.toml");

        let id1 = make_identity("sl-id1");
        let id2 = make_identity("sl-id2");

        let mut d = Devices::default();
        d.add("desktop", id1.node_id(), "192.168.1.10:8080");
        d.add("server", id2.node_id(), "10.0.0.1:9090");
        d.save(&path).unwrap();

        let loaded = Devices::load(&path).unwrap();
        assert_eq!(loaded.devices.len(), 2);
        assert!(loaded.is_trusted(&id1.node_id()));
        assert!(loaded.is_trusted(&id2.node_id()));

        let (nid, addr) = loaded.get("desktop").unwrap();
        assert_eq!(nid, id1.node_id());
        assert_eq!(addr, "192.168.1.10:8080");
    }

    #[test]
    fn tags_add_dedup_remove_and_persist() {
        let dir = tmpdir("tags");
        let path = dir.join("machines.toml");
        let id = make_identity("tags-id");

        let mut d = Devices::default();
        d.add("desktop", id.node_id(), "10.0.0.1:8844");
        d.add_tags("desktop", &["gpu".into(), "build".into(), "gpu".into()]).unwrap();
        // Duplicate "gpu" collapses; tags are sorted.
        assert_eq!(d.entries()[0].3, vec!["build".to_string(), "gpu".to_string()]);

        // Re-adding the same device preserves tags.
        d.add("desktop", id.node_id(), "10.0.0.2:8844");
        assert_eq!(d.entries()[0].3, vec!["build".to_string(), "gpu".to_string()]);

        d.remove_tags("desktop", &["build".into()]).unwrap();
        assert_eq!(d.entries()[0].3, vec!["gpu".to_string()]);

        // Tagging an unknown device errors.
        assert!(d.add_tags("ghost", &["x".into()]).is_err());

        d.save(&path).unwrap();
        let loaded = Devices::load(&path).unwrap();
        assert_eq!(loaded.entries()[0].3, vec!["gpu".to_string()]);
    }

    #[test]
    fn load_or_empty_on_missing_file() {
        let d = Devices::load_or_empty(std::path::Path::new("/nonexistent/machines.toml"));
        assert_eq!(d.devices.len(), 0);
    }

    #[test]
    fn add_overwrites_existing_name() {
        let id1 = make_identity("overwrite1");
        let id2 = make_identity("overwrite2");
        let mut d = Devices::default();
        d.add("mybox", id1.node_id(), "1.1.1.1:1");
        d.add("mybox", id2.node_id(), "2.2.2.2:2"); // overwrite
        assert!(!d.is_trusted(&id1.node_id()), "old entry must be gone");
        assert!(d.is_trusted(&id2.node_id()), "new entry must be present");
        let (_, addr) = d.get("mybox").unwrap();
        assert_eq!(addr, "2.2.2.2:2");
    }
}
