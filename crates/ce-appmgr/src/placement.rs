//! Where an app/system runs. `ce-appmgr` is global, not just local: install and
//! run target the mesh via `--on <placement>`. Local (`self`) is the default; all
//! other placements ship the install to the target node's agent over the existing
//! mesh-deploy / mesh-kill primitives (capability-authed, mesh-first).
//!
//! This is the addressing scheme that turns scattered donated machines into one pool:
//! `tag`, `fleet`, and `nearest` are designed so a single command targets the right
//! slice of millions of nodes — every GPU box, an entire edge fleet, or the
//! lowest-latency capable host — without anyone naming or tracking individual
//! machines. It is how work is aimed at the supercomputer rather than at a server.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// A placement target for an app instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind", content = "value")]
pub enum Placement {
    /// This host (the default).
    Local,
    /// A specific node by id (64 hex chars).
    Node(String),
    /// Any node carrying all of these tags (e.g. `gpu`, `linux`).
    Tag(Vec<String>),
    /// Every node in a named fleet.
    Fleet(String),
    /// Atlas/latency-guided: the nearest capable node.
    Nearest,
}

impl Default for Placement {
    fn default() -> Self {
        Placement::Local
    }
}

impl Placement {
    /// Parse the `--on` value:
    /// `self` | `node=<id>` | `tag=a,b` | `fleet=<name>` | `nearest`.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        match s {
            "" | "self" | "local" => Ok(Placement::Local),
            "nearest" => Ok(Placement::Nearest),
            _ => {
                let Some((key, val)) = s.split_once('=') else {
                    bail!("bad placement '{s}' (use self|node=<id>|tag=a,b|fleet=<name>|nearest)");
                };
                let val = val.trim();
                match key.trim() {
                    "node" => {
                        if val.is_empty() {
                            bail!("placement 'node=' needs a node id");
                        }
                        Ok(Placement::Node(val.to_string()))
                    }
                    "tag" => {
                        let tags: Vec<String> = val
                            .split(',')
                            .map(str::trim)
                            .filter(|t| !t.is_empty())
                            .map(String::from)
                            .collect();
                        if tags.is_empty() {
                            bail!("placement 'tag=' needs at least one tag");
                        }
                        Ok(Placement::Tag(tags))
                    }
                    "fleet" => {
                        if val.is_empty() {
                            bail!("placement 'fleet=' needs a fleet name");
                        }
                        Ok(Placement::Fleet(val.to_string()))
                    }
                    other => bail!("unknown placement kind '{other}'"),
                }
            }
        }
    }

    /// Whether this placement runs on the local host.
    pub fn is_local(&self) -> bool {
        matches!(self, Placement::Local)
    }
}

impl std::fmt::Display for Placement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Placement::Local => write!(f, "self"),
            Placement::Node(id) => write!(f, "node={id}"),
            Placement::Tag(tags) => write!(f, "tag={}", tags.join(",")),
            Placement::Fleet(name) => write!(f, "fleet={name}"),
            Placement::Nearest => write!(f, "nearest"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_forms() {
        assert_eq!(Placement::parse("self").unwrap(), Placement::Local);
        assert_eq!(Placement::parse("").unwrap(), Placement::Local);
        assert_eq!(Placement::parse("nearest").unwrap(), Placement::Nearest);
        assert_eq!(Placement::parse("node=abc").unwrap(), Placement::Node("abc".into()));
        assert_eq!(
            Placement::parse("tag=gpu, linux").unwrap(),
            Placement::Tag(vec!["gpu".into(), "linux".into()])
        );
        assert_eq!(Placement::parse("fleet=edge").unwrap(), Placement::Fleet("edge".into()));
    }

    #[test]
    fn rejects_garbage() {
        assert!(Placement::parse("node=").is_err());
        assert!(Placement::parse("tag=").is_err());
        assert!(Placement::parse("bogus=1").is_err());
        assert!(Placement::parse("whatever").is_err());
    }

    #[test]
    fn display_roundtrips() {
        for s in ["self", "nearest", "node=abc", "tag=gpu,linux", "fleet=edge"] {
            let p = Placement::parse(s).unwrap();
            assert_eq!(Placement::parse(&p.to_string()).unwrap(), p);
        }
    }
}
