//! Dependency resolution across all runtime tiers.
//!
//! An app's `[deps].apps` entries are `"name <semver-req>"` strings. The resolver
//! walks that graph from a [`Registry`], checks each fetched manifest satisfies the
//! requirement, detects cycles, and returns a topologically-ordered install plan
//! (dependencies before dependents). Service/capability/system deps are surfaced
//! on the plan so the caller can provision or prompt for them.

use crate::manifest::AppManifest;
use anyhow::{Result, anyhow, bail};
use semver::VersionReq;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Source of manifests. `ce` backs this with the ce-hub HTTP registry; tests back
/// it with an in-memory map. `async fn` in trait (stable, edition 2024).
#[allow(async_fn_in_trait)]
pub trait Registry {
    /// Fetch the published manifest for `name`. (Single-version registry for now;
    /// a multi-version solver replaces this when ce-hub stores version history.)
    async fn manifest(&self, name: &str) -> Result<AppManifest>;
}

/// A parsed `"name <req>"` dependency specifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepSpec {
    pub name: String,
    pub req: VersionReq,
}

impl DepSpec {
    /// Parse `"ce-storage >= 0.2"`, `"ce-storage>=0.2"`, or a bare `"ce-storage"`
    /// (which means any version).
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            bail!("empty dependency spec");
        }
        // Split the leading package token from the version requirement. The name
        // runs until the first whitespace or comparison operator.
        let split = s
            .find(|c: char| c.is_whitespace() || matches!(c, '>' | '<' | '=' | '^' | '~'))
            .unwrap_or(s.len());
        let (name, rest) = s.split_at(split);
        let name = name.trim();
        if name.is_empty() {
            bail!("dependency spec '{s}' has no package name");
        }
        let rest = rest.trim();
        let req = if rest.is_empty() {
            VersionReq::STAR
        } else {
            rest.parse()
                .map_err(|e| anyhow!("bad version requirement in '{s}': {e}"))?
        };
        Ok(DepSpec { name: name.to_string(), req })
    }
}

/// One node of a resolved install plan.
#[derive(Debug, Clone)]
pub struct PlanItem {
    pub manifest: AppManifest,
}

/// The full resolution result: apps to install in order, plus the union of
/// non-app requirements the caller must satisfy.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// Apps in install order — dependencies precede dependents.
    pub items: Vec<PlanItem>,
    /// System services the graph depends on (e.g. `postgres`).
    pub services: BTreeSet<String>,
    /// ce-cap abilities the graph requires.
    pub capabilities: BTreeSet<String>,
    /// Required host features -> requirement value (e.g. `docker = "optional"`).
    pub system: HashMap<String, String>,
}

impl Plan {
    /// Names in install order — handy for display/tests.
    pub fn order(&self) -> Vec<String> {
        self.items.iter().map(|i| i.manifest.app.name.clone()).collect()
    }
}

/// Resolve `root`'s full dependency closure into an ordered [`Plan`].
pub async fn resolve<R: Registry>(registry: &R, root: &str) -> Result<Plan> {
    let mut visiting: HashSet<String> = HashSet::new(); // on the current DFS path (cycle guard)
    let mut done: HashSet<String> = HashSet::new();
    let mut plan = Plan::default();
    visit(registry, root, None, &mut visiting, &mut done, &mut plan).await?;
    Ok(plan)
}

/// Post-order DFS: append a node only after all its deps, yielding install order.
/// Iterative with an explicit stack to avoid boxing recursive async futures.
async fn visit<R: Registry>(
    registry: &R,
    name: &str,
    req: Option<&VersionReq>,
    visiting: &mut HashSet<String>,
    done: &mut HashSet<String>,
    plan: &mut Plan,
) -> Result<()> {
    // Explicit work stack of (name, req, children_expanded?).
    let mut stack: Vec<Frame> = vec![Frame {
        name: name.to_string(),
        req: req.cloned(),
        expanded: false,
        manifest: None,
    }];

    while let Some(frame) = stack.last_mut() {
        let fname = frame.name.clone();

        if done.contains(&fname) {
            stack.pop();
            continue;
        }

        if !frame.expanded {
            if visiting.contains(&fname) {
                bail!("dependency cycle detected at '{fname}'");
            }
            let manifest = registry.manifest(&fname).await?;
            if let Some(req) = &frame.req {
                if !req.matches(&manifest.app.version) {
                    bail!(
                        "'{fname}' resolved to {} which does not satisfy '{req}'",
                        manifest.app.version
                    );
                }
            }
            // Collect non-app requirements as we go.
            for svc in &manifest.deps.services {
                plan.services.insert(svc.clone());
            }
            for cap in &manifest.deps.capabilities {
                plan.capabilities.insert(cap.clone());
            }
            for (k, v) in &manifest.deps.system {
                plan.system.insert(k.clone(), v.clone());
            }

            visiting.insert(fname.clone());
            frame.expanded = true;
            frame.manifest = Some(manifest.clone());

            // Push children (app deps) to be processed before we finalize this node.
            let mut children = Vec::new();
            for dep in &manifest.deps.apps {
                let spec = DepSpec::parse(dep)?;
                if !done.contains(&spec.name) {
                    children.push(Frame {
                        name: spec.name,
                        req: Some(spec.req),
                        expanded: false,
                        manifest: None,
                    });
                }
            }
            // Reverse so the stack processes them in declared order.
            for c in children.into_iter().rev() {
                stack.push(c);
            }
            continue;
        }

        // Children done — finalize this node.
        let manifest = frame.manifest.take().expect("expanded frame has manifest");
        visiting.remove(&fname);
        done.insert(fname.clone());
        plan.items.push(PlanItem { manifest });
        stack.pop();
    }

    Ok(())
}

struct Frame {
    name: String,
    req: Option<VersionReq>,
    expanded: bool,
    manifest: Option<AppManifest>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::AppManifest;
    use std::collections::HashMap;

    struct MockRegistry {
        manifests: HashMap<String, AppManifest>,
    }

    impl Registry for MockRegistry {
        async fn manifest(&self, name: &str) -> Result<AppManifest> {
            self.manifests
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("no such app '{name}'"))
        }
    }

    fn oci(name: &str, version: &str, dep_apps: &[&str], services: &[&str]) -> AppManifest {
        let apps = dep_apps
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let svcs = services
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let toml = format!(
            r#"
            [app]
            name = "{name}"
            version = "{version}"
            runtime = "oci"
            [oci]
            image = "img/{name}"
            [deps]
            apps = [{apps}]
            services = [{svcs}]
            "#
        );
        AppManifest::parse(&toml).unwrap()
    }

    fn registry(ms: Vec<AppManifest>) -> MockRegistry {
        MockRegistry {
            manifests: ms.into_iter().map(|m| (m.app.name.clone(), m)).collect(),
        }
    }

    #[test]
    fn dep_spec_parses_forms() {
        let a = DepSpec::parse("ce-storage >= 0.2").unwrap();
        assert_eq!(a.name, "ce-storage");
        assert!(a.req.matches(&"0.3.0".parse().unwrap()));
        assert!(!a.req.matches(&"0.1.0".parse().unwrap()));

        let b = DepSpec::parse("ce-storage>=0.2").unwrap();
        assert_eq!(b.name, "ce-storage");

        let c = DepSpec::parse("rdev").unwrap();
        assert_eq!(c.name, "rdev");
        assert!(c.req.matches(&"9.9.9".parse().unwrap()));
    }

    #[tokio::test]
    async fn resolves_linear_chain_in_order() {
        // app -> mid -> leaf
        let reg = registry(vec![
            oci("app", "1.0.0", &["mid >= 1"], &[]),
            oci("mid", "1.2.0", &["leaf"], &[]),
            oci("leaf", "0.1.0", &[], &["postgres"]),
        ]);
        let plan = resolve(&reg, "app").await.unwrap();
        assert_eq!(plan.order(), vec!["leaf", "mid", "app"]);
        assert!(plan.services.contains("postgres"));
    }

    #[tokio::test]
    async fn diamond_installs_shared_dep_once() {
        // top -> {left, right} -> base
        let reg = registry(vec![
            oci("top", "1.0.0", &["left", "right"], &[]),
            oci("left", "1.0.0", &["base"], &[]),
            oci("right", "1.0.0", &["base"], &[]),
            oci("base", "1.0.0", &[], &[]),
        ]);
        let plan = resolve(&reg, "top").await.unwrap();
        let order = plan.order();
        assert_eq!(order.iter().filter(|n| *n == "base").count(), 1);
        // base before left/right; left/right before top.
        let pos = |n: &str| order.iter().position(|x| x == n).unwrap();
        assert!(pos("base") < pos("left"));
        assert!(pos("base") < pos("right"));
        assert!(pos("left") < pos("top"));
    }

    #[tokio::test]
    async fn rejects_cycle() {
        let reg = registry(vec![
            oci("a", "1.0.0", &["b"], &[]),
            oci("b", "1.0.0", &["a"], &[]),
        ]);
        assert!(resolve(&reg, "a").await.is_err());
    }

    #[tokio::test]
    async fn rejects_unsatisfied_version() {
        let reg = registry(vec![
            oci("app", "1.0.0", &["dep >= 2"], &[]),
            oci("dep", "1.0.0", &[], &[]),
        ]);
        let err = resolve(&reg, "app").await.unwrap_err().to_string();
        assert!(err.contains("does not satisfy"), "{err}");
    }
}
