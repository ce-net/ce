//! Supervision policy: which daemons the single `ce` service should keep running,
//! and how. There is exactly one OS service (`com.ce-net.ce`); this replaces the
//! per-app launchd/systemd plists. The policy lives here (pure, testable); the
//! mechanism — spawning, restarting, health probing, ce-hub registration — lives
//! in the `ce` binary which owns the process/runtime deps.

use crate::manifest::AppManifest;
use crate::store::{InstalledApp, Store};
use anyhow::Result;

/// Restart behavior for a supervised daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    /// Restart only after a non-zero exit (the default).
    OnFailure,
    /// Always restart on exit.
    Always,
    /// Never restart (run once).
    Never,
}

impl RestartPolicy {
    pub fn parse(s: &str) -> RestartPolicy {
        match s.trim() {
            "always" => RestartPolicy::Always,
            "never" | "no" => RestartPolicy::Never,
            _ => RestartPolicy::OnFailure,
        }
    }

    /// Given an exit code, should the supervisor restart the instance?
    pub fn should_restart(&self, exit_code: i32) -> bool {
        match self {
            RestartPolicy::Always => true,
            RestartPolicy::Never => false,
            RestartPolicy::OnFailure => exit_code != 0,
        }
    }
}

/// The resolved supervision policy for one app.
#[derive(Debug, Clone)]
pub struct DaemonPolicy {
    pub restart: RestartPolicy,
    /// Liveness probe the supervisor polls (URL or command); informational here.
    pub health: Option<String>,
}

/// Extract the supervision policy from a manifest, or `None` if the app is not a
/// daemon (a one-shot CLI).
pub fn daemon_policy(m: &AppManifest) -> Option<DaemonPolicy> {
    m.daemon.as_ref().map(|d| DaemonPolicy {
        restart: RestartPolicy::parse(&d.restart),
        health: d.health.clone(),
    })
}

/// The installed daemon apps the supervisor should currently keep running:
/// installed, declares a `[daemon]`, and enabled via `ce app daemon enable`.
pub fn enabled_daemons(store: &Store) -> Result<Vec<InstalledApp>> {
    Ok(store
        .list()?
        .into_iter()
        .filter(|a| a.manifest.is_daemon() && store.is_daemon_enabled(&a.manifest.app.name))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::AppManifest;

    #[test]
    fn restart_policy_semantics() {
        assert!(RestartPolicy::Always.should_restart(0));
        assert!(RestartPolicy::Always.should_restart(1));
        assert!(!RestartPolicy::Never.should_restart(1));
        assert!(RestartPolicy::OnFailure.should_restart(1));
        assert!(!RestartPolicy::OnFailure.should_restart(0));
        assert_eq!(RestartPolicy::parse("always"), RestartPolicy::Always);
        assert_eq!(RestartPolicy::parse("on-failure"), RestartPolicy::OnFailure);
        assert_eq!(RestartPolicy::parse("never"), RestartPolicy::Never);
    }

    #[test]
    fn policy_only_for_daemons() {
        let cli = AppManifest::parse(
            r#"
            [app]
            name = "tool"
            version = "1.0.0"
            runtime = "native"
            [native]
            bin = "tool"
            artifacts."linux-amd64" = "sha256:aa"
            "#,
        )
        .unwrap();
        assert!(daemon_policy(&cli).is_none());

        let dmn = AppManifest::parse(
            r#"
            [app]
            name = "pg"
            version = "16.0.0"
            runtime = "oci"
            [oci]
            image = "postgres:16"
            [daemon]
            enabled = false
            restart = "always"
            health = "tcp://127.0.0.1:5432"
            "#,
        )
        .unwrap();
        let p = daemon_policy(&dmn).unwrap();
        assert_eq!(p.restart, RestartPolicy::Always);
        assert_eq!(p.health.as_deref(), Some("tcp://127.0.0.1:5432"));
    }
}
