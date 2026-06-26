//! On-disk install store: the single ce-owned home for every installed app.
//!
//! Layout under the CE data dir (`~/.local/share/ce` on Linux,
//! `~/Library/Application Support/ce` on macOS):
//!
//! ```text
//! <data>/apps/<name>/<version>/      fetched artifact tree
//! <data>/apps/<name>/installed.toml  record: manifest + resolved target + digest
//! <data>/bin/<shim>                  the ONLY ce-owned PATH entry; ce-generated shims
//! ```
//!
//! There are no other host-installed binaries and no per-app plists: daemons are
//! registered here and supervised by the single `ce` service.
//!
//! Containing every install under one ce-owned tree is what keeps a donor's machine
//! trustworthy at scale: with no scattered host binaries or per-app service files,
//! onboarding and full teardown are uniform and reversible on each of millions of
//! contributed devices, so people can lend compute to the supercomputer without it
//! leaving residue or fighting their system's own package manager.

use crate::manifest::AppManifest;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Handle to the install store rooted at the CE data dir.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

/// The persisted record of one installed app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub manifest: AppManifest,
    /// Host target the artifact was resolved for (native), else empty.
    #[serde(default)]
    pub target: String,
    /// Content digest of the installed artifact, if content-addressed.
    #[serde(default)]
    pub digest: Option<String>,
}

impl Store {
    /// Open (do not create) a store at the given CE data dir.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Store { root: root.into() }
    }

    pub fn apps_dir(&self) -> PathBuf {
        self.root.join("apps")
    }

    /// The single PATH-injected directory holding ce-generated launcher shims.
    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    fn app_dir(&self, name: &str) -> PathBuf {
        self.apps_dir().join(name)
    }

    fn record_path(&self, name: &str) -> PathBuf {
        self.app_dir(name).join("installed.toml")
    }

    /// Versioned artifact directory for an app.
    pub fn version_dir(&self, name: &str, version: &str) -> PathBuf {
        self.app_dir(name).join(version)
    }

    /// Ensure the store skeleton exists.
    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(self.apps_dir())?;
        std::fs::create_dir_all(self.bin_dir())?;
        Ok(())
    }

    /// Whether `name` is installed.
    pub fn is_installed(&self, name: &str) -> bool {
        self.record_path(name).exists()
    }

    /// Read one install record.
    pub fn get(&self, name: &str) -> Result<Option<InstalledApp>> {
        let p = self.record_path(name);
        if !p.exists() {
            return Ok(None);
        }
        let s = std::fs::read_to_string(&p)
            .with_context(|| format!("reading install record {}", p.display()))?;
        let rec: InstalledApp =
            toml::from_str(&s).with_context(|| format!("parsing install record {}", p.display()))?;
        Ok(Some(rec))
    }

    /// List every installed app, sorted by name.
    pub fn list(&self) -> Result<Vec<InstalledApp>> {
        let dir = self.apps_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(rec) = self.get(&name)? {
                out.push(rec);
            }
        }
        out.sort_by(|a, b| a.manifest.app.name.cmp(&b.manifest.app.name));
        Ok(out)
    }

    /// Write (or overwrite) the install record for an app.
    pub fn record(&self, rec: &InstalledApp) -> Result<()> {
        let dir = self.app_dir(&rec.manifest.app.name);
        std::fs::create_dir_all(&dir)?;
        let s = toml::to_string_pretty(rec)?;
        std::fs::write(self.record_path(&rec.manifest.app.name), s)?;
        Ok(())
    }

    /// Path of the marker that records whether an app's daemon is enabled for the
    /// single ce supervisor to keep running.
    fn daemon_flag_path(&self, name: &str) -> PathBuf {
        self.app_dir(name).join("daemon.enabled")
    }

    /// Enable or disable supervision of an app's daemon. Enabling an app that has no
    /// `[daemon]` is a caller error; the marker is a presence flag (its content is
    /// informational only).
    pub fn set_daemon_enabled(&self, name: &str, on: bool) -> Result<()> {
        let p = self.daemon_flag_path(name);
        if on {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&p, b"enabled\n")?;
        } else if p.exists() {
            std::fs::remove_file(&p)?;
        }
        Ok(())
    }

    /// Whether the app's daemon is enabled for supervision.
    pub fn is_daemon_enabled(&self, name: &str) -> bool {
        self.daemon_flag_path(name).exists()
    }

    /// Remove an app's entire tree (record + artifacts). Shims are removed by the
    /// caller, which knows the shim names. Idempotent.
    pub fn remove(&self, name: &str) -> Result<()> {
        let dir = self.app_dir(name);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    /// Write a launcher shim into the ce-owned bin dir. The shim execs
    /// `ce app run <name> -- "$@"` so the app is always launched sandboxed and
    /// capability-scoped, never as a free-standing host binary. Unix only for now;
    /// Windows shims (`.cmd`) land with the supervisor work.
    #[cfg(unix)]
    pub fn write_shim(&self, shim_name: &str, app_name: &str) -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        self.ensure()?;
        let path = self.bin_dir().join(shim_name);
        let body = format!(
            "#!/bin/sh\n# ce-generated launcher shim — do not edit.\nexec ce app run {app_name} -- \"$@\"\n"
        );
        std::fs::write(&path, body)?;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms)?;
        Ok(path)
    }

    /// Remove a shim by name (idempotent).
    pub fn remove_shim(&self, shim_name: &str) -> Result<()> {
        let path = self.bin_dir().join(shim_name);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

/// Resolve the CE data dir the same way the `ce` binary does, so the store sits
/// beside `identity/` and `chain/`.
pub fn data_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "ce")
        .map(|d| d.data_dir().to_owned())
        .unwrap_or_else(|| PathBuf::from(".ce"))
}

/// Convenience: open the store at the default CE data dir.
pub fn default_store() -> Store {
    Store::new(data_dir())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::AppManifest;

    fn sample() -> AppManifest {
        AppManifest::parse(
            r#"
            [app]
            name = "demo"
            version = "1.2.3"
            runtime = "oci"
            [oci]
            image = "img/demo"
            "#,
        )
        .unwrap()
    }

    fn tmp(name: &str) -> PathBuf {
        // Use the session scratchpad-friendly temp; std temp dir is fine for unit tests.
        let mut p = std::env::temp_dir();
        p.push(format!("ce-appmgr-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn record_list_remove_roundtrip() {
        let root = tmp("store");
        let store = Store::new(&root);
        store.ensure().unwrap();
        assert!(store.list().unwrap().is_empty());

        let rec = InstalledApp {
            manifest: sample(),
            target: "linux-amd64".into(),
            digest: Some("blake3:zzzz".into()),
        };
        store.record(&rec).unwrap();
        assert!(store.is_installed("demo"));

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].manifest.app.name, "demo");
        assert_eq!(listed[0].target, "linux-amd64");

        store.remove("demo").unwrap();
        assert!(!store.is_installed("demo"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn shim_is_executable_and_targets_app() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmp("shim");
        let store = Store::new(&root);
        let path = store.write_shim("rdev", "rdev").unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("ce app run rdev"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "shim must be executable");
        store.remove_shim("rdev").unwrap();
        assert!(!path.exists());
        std::fs::remove_dir_all(&root).ok();
    }
}
