//! `desired.rs` — the declarative "desired apps" set for a SCOPE (a workspace or org) and the PURE
//! reconcile diff the in-process supervisor uses to converge a machine to it. No I/O, no deps, fully
//! unit-tested — so it lives safely inside the node (which must never depend on `ce-rs`).
//!
//! The model (PLAN/ce-appmgr-hardening.md §6/§7): installing an app for a scope adds it to that scope's
//! desired-set; the set replicates across the scope's devices (over the existing per-user mesh that
//! gitsync already uses — a synced file, NOT ce-coord, to keep `ce-rs` out of the node); each device's
//! supervisor diffs installed-vs-desired and installs/updates/removes to converge. A device enrolled in
//! several scopes reconciles the UNION, namespaced per scope, so personal + org apps coexist.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One app a scope wants present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredApp {
    /// Where to install from: a registry name, `./path`, `git:…`, `oci:…`, or `blob:…` (install §4.1).
    pub source: String,
    /// Pinned version (empty = whatever the source currently resolves).
    #[serde(default)]
    pub version: String,
    /// Capability requirements, echoed for audit/placement (informational on the device).
    #[serde(default)]
    pub requires: Vec<String>,
}

/// A scope's desired set (single writer = the scope owner).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredSet {
    /// Scope label (`personal`, `acme`, `acme/backend`) — namespaces ownership so a multi-homed device
    /// runs the union of its scopes without collision.
    #[serde(default)]
    pub scope: String,
    /// app name -> desired spec.
    #[serde(default)]
    pub apps: BTreeMap<String, DesiredApp>,
}

/// What a device must DO to converge to a desired set, given what it has.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reconcile {
    /// Apps to install or update — `(name, spec)`.
    pub install: Vec<(String, DesiredApp)>,
    /// Apps to remove: this scope owned them but no longer wants them. We only ever remove apps this
    /// scope manages — never the user's other apps or another scope's.
    pub remove: Vec<String>,
}

impl DesiredSet {
    /// Diff against the currently-installed `(name -> version)` and the `managed` set (the app names this
    /// scope currently owns on the device). Pure.
    pub fn reconcile(
        &self,
        installed: &BTreeMap<String, String>,
        managed: &BTreeSet<String>,
    ) -> Reconcile {
        let mut r = Reconcile::default();
        for (name, spec) in &self.apps {
            let need = match installed.get(name) {
                None => true, // not installed at all
                Some(v) => !spec.version.is_empty() && v != &spec.version, // pinned-version drift
            };
            if need {
                r.install.push((name.clone(), spec.clone()));
            }
        }
        for name in managed {
            if !self.apps.contains_key(name) {
                r.remove.push(name.clone());
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(v: &str) -> DesiredApp {
        DesiredApp { source: "reg".into(), version: v.into(), requires: vec![] }
    }

    #[test]
    fn installs_missing_and_version_drift_only() {
        let mut set = DesiredSet::default();
        set.apps.insert("a".into(), spec("")); // unpinned -> install if absent, never re-install
        set.apps.insert("b".into(), spec("1.0.0")); // pinned -> reinstall on drift
        let installed: BTreeMap<String, String> =
            [("b".to_string(), "0.9.0".to_string())].into_iter().collect();
        let managed = BTreeSet::new();
        let r = set.reconcile(&installed, &managed);
        // a missing -> install; b drift 0.9 != 1.0 -> install; nothing to remove.
        assert!(r.install.iter().any(|(n, _)| n == "a"));
        assert!(r.install.iter().any(|(n, _)| n == "b"));
        assert!(r.remove.is_empty());
    }

    #[test]
    fn removes_only_managed_not_desired() {
        let set = DesiredSet::default(); // wants nothing
        let installed = BTreeMap::new();
        let managed: BTreeSet<String> = ["old".to_string(), "keep".to_string()].into_iter().collect();
        let r = set.reconcile(&installed, &managed);
        assert_eq!(r.remove.len(), 2); // both managed apps are no longer desired
        assert!(r.install.is_empty());
    }

    #[test]
    fn pinned_match_is_noop() {
        let mut set = DesiredSet::default();
        set.apps.insert("a".into(), spec("1.0.0"));
        let installed: BTreeMap<String, String> =
            [("a".to_string(), "1.0.0".to_string())].into_iter().collect();
        let managed: BTreeSet<String> = ["a".to_string()].into_iter().collect();
        let r = set.reconcile(&installed, &managed);
        assert!(r.install.is_empty() && r.remove.is_empty());
    }
}
