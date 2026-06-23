//! Capability-based authorization — CE's single trust primitive.
//!
//! This module replaces the old device-allowlist (`machines.toml`) **and** the single-level
//! grant. There is exactly one idea:
//!
//! > **A node trusts a small set of root keys. Authority is a signed, attenuating capability
//! > chain from one of those roots to the requester.**
//!
//! There is no notion of "device", "company", "team", or "person" here — only keys, abilities,
//! resource matchers, caveats, and signatures. Products that model organizations are built on
//! top by *issuing* capabilities; they do not live in CE. The node is the enforcement point: it
//! must decide whether to run an incoming exec/sync/tunnel *before* doing the work, so
//! verification lives here while issuance and human-facing policy live in apps.
//!
//! ## The token
//!
//! A [`Capability`] is a signed statement: *"issuer `I` authorizes audience `A` to perform
//! `{abilities}` on resources matching `{resource}`, subject to `{caveats}`."* A [`SignedCapability`]
//! is that statement plus `I`'s Ed25519 signature. Capabilities link into a **chain** via
//! [`Capability::parent`] (the [`CapId`] hash of the parent), so `A` can sub-delegate a subset of
//! what it holds to a third party `B`, who can delegate further — without bound.
//!
//! ## The trust root
//!
//! A node honors a chain only if its **root** (the first link's issuer) is an *accepted root* for
//! that node: either the node's **own identity** (self-delegation — the zero-config personal case),
//! or a **configured root key** (the org/CA anchor — the SSH `TrustedUserCAKeys` analog). The
//! anchor is a list of *keys*, not devices: one key covers unlimited principals via issued caps.
//!
//! ## Attenuation (the security backbone)
//!
//! Every link in a chain must be **no broader than its parent**: abilities a subset, resource a
//! subset, caveats at least as restrictive. Verified at every link, this makes delegation safe —
//! no link can ever amplify authority. See [`authorize`] for the full algorithm and the exact
//! security properties enforced.
//!
//! ## Revocation
//!
//! Three layers, cheapest first: short [`Caveats::not_after`] expiries (offline); an on-chain
//! `RevokeCapability` anchor keyed by `(issuer, nonce)` consulted via the `is_revoked` callback
//! (revoking any link revokes its whole subtree); and root-key rotation (the nuclear option).

use anyhow::{Result, anyhow};
use ce_identity::{Identity, NodeId, verify};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation tag mixed into every capability signature, so a capability signature can
/// never be mistaken for any other CE signature (auth requests, settlements, blocks, grants v1).
const CAP_DOMAIN: &[u8] = b"ce-cap-v1";

/// The content-address of a capability: `sha256(cap_bytes)`. Used to link a child to its parent
/// and to name a capability for revocation.
pub type CapId = [u8; 32];

// Abilities are **opaque action strings** (e.g. "exec", "sync", "tunnel"). CE assigns them no
// meaning — the enforcer (the node, or an app) defines its own action vocabulary. The verifier only
// checks that the requested action string is present in the capability's `abilities` set and is
// preserved by attenuation. This keeps the primitive free of application semantics: adding a new
// app action never touches this crate.

/// Which nodes a capability applies to, matched against a node's id and capability self-tags
/// (the same `gpu`/`docker`/`linux`/... set advertised in the atlas).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resource {
    /// Every node under the root's authority.
    Any,
    /// One specific node.
    Node(NodeId),
    /// Nodes advertising this single self-tag.
    Tag(String),
    /// Nodes advertising all of these self-tags.
    AllOf(Vec<String>),
}

impl Resource {
    /// Does the node identified by (`id`, `tags`) fall within this resource set?
    pub fn matches(&self, id: &NodeId, tags: &[String]) -> bool {
        match self {
            Resource::Any => true,
            Resource::Node(n) => n == id,
            Resource::Tag(t) => tags.iter().any(|x| x == t),
            Resource::AllOf(ts) => ts.iter().all(|t| tags.iter().any(|x| x == t)),
        }
    }

    /// Is `self` no broader than `parent` — i.e. is the node-set selected by `self` a subset of
    /// the node-set selected by `parent`? Used to enforce attenuation during delegation.
    ///
    /// Conservative by design: when a relationship cannot be guaranteed structurally (e.g. a
    /// specific `Node` under a `Tag`, whose tags are not known here), it returns `false` and the
    /// delegation is rejected. A false negative only refuses a (possibly valid) narrowing; it can
    /// never wrongly *grant* authority.
    pub fn is_subset_of(&self, parent: &Resource) -> bool {
        match parent {
            // Everything is a subset of "any".
            Resource::Any => true,
            // Only the same single node is a subset of a single node.
            Resource::Node(p) => matches!(self, Resource::Node(s) if s == p),
            // A subset of `Tag(t)` must guarantee every selected node carries `t`.
            Resource::Tag(t) => match self {
                Resource::Tag(s) => s == t,
                Resource::AllOf(s) => s.contains(t),
                _ => false,
            },
            // A subset of `AllOf(ps)` must guarantee every selected node carries all of `ps`.
            Resource::AllOf(ps) => match self {
                Resource::AllOf(s) => ps.iter().all(|p| s.contains(p)),
                Resource::Tag(s) => ps.iter().all(|p| p == s),
                _ => false,
            },
        }
    }
}

/// Constraints attached to a capability. Temporal caveats are enforced by [`authorize`]; resource
/// ceilings (`max_*`) and action caveats (`allowed_ports`, `path_prefix`) are enforced by whichever
/// action consumes them — an action that cannot honor a caveat must reject rather than exceed it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caveats {
    /// Unix seconds before which the capability is not yet valid. `0` = no lower bound.
    pub not_before: u64,
    /// Unix seconds after which the capability is invalid. `0` = never expires.
    pub not_after: u64,
    /// Max CPU cores a deploy under this capability may request.
    pub max_cpu: Option<u32>,
    /// Max memory (MB) a deploy under this capability may request.
    pub max_mem_mb: Option<u32>,
    /// Max credits the audience may spend under this capability.
    pub max_credits: Option<u64>,
    /// Tunnel: the only remote ports a tunnel under this capability may reach. `None` = unrestricted.
    pub allowed_ports: Option<Vec<u16>>,
    /// Sync/Delete: confine writes to paths under this prefix (relative to the target's home).
    /// `None` = unrestricted.
    pub path_prefix: Option<String>,
}

impl Caveats {
    /// Are the temporal caveats satisfied at `now` (unix seconds)?
    pub fn valid_at(&self, now: u64) -> Result<(), String> {
        if self.not_before != 0 && now < self.not_before {
            return Err("capability not yet valid".into());
        }
        if self.not_after != 0 && now > self.not_after {
            return Err("capability has expired".into());
        }
        Ok(())
    }

    /// Is `self` at least as restrictive as `parent`? A child capability may only narrow.
    pub fn is_narrower_or_equal(&self, parent: &Caveats) -> bool {
        // Expiry: a child may not outlive its parent (0 = infinity).
        if parent.not_after != 0 && (self.not_after == 0 || self.not_after > parent.not_after) {
            return false;
        }
        // Start: a child may not become valid earlier than its parent.
        if self.not_before < parent.not_before {
            return false;
        }
        // Resource ceilings: a child may not raise a parent's cap.
        if !le_opt(self.max_cpu, parent.max_cpu)
            || !le_opt(self.max_mem_mb, parent.max_mem_mb)
            || !le_opt(self.max_credits, parent.max_credits)
        {
            return false;
        }
        // Allowed ports: if the parent restricts, the child's set must be a subset.
        if let Some(pp) = &parent.allowed_ports {
            match &self.allowed_ports {
                Some(sp) => {
                    if !sp.iter().all(|p| pp.contains(p)) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        // Path prefix: if the parent confines, the child must be confined within it.
        if let Some(pp) = &parent.path_prefix {
            match &self.path_prefix {
                Some(sp) => {
                    if !path_within(sp, pp) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

/// Is path `child` contained within path `parent`, on a `/` boundary? A raw `starts_with` is
/// wrong: `/home/userdata` is *not* within `/home/user`, even though it shares the textual prefix.
/// Containment holds iff the parent is empty (unconfined), the paths are equal, or `child` lies
/// strictly under `parent` as a path component. Trailing slashes are normalized first.
fn path_within(child: &str, parent: &str) -> bool {
    let child = child.trim_end_matches('/');
    let parent = parent.trim_end_matches('/');
    parent.is_empty() || child == parent || child.starts_with(&format!("{parent}/"))
}

/// `child <= parent` where `None` means "no limit". A parent with no limit accepts any child; a
/// parent with a limit rejects an unlimited (`None`) child.
fn le_opt<T: Ord + Copy>(child: Option<T>, parent: Option<T>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(c), Some(p)) => c <= p,
    }
}

/// The unsigned capability statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Who is delegating (the signer).
    pub issuer: NodeId,
    /// Who receives this authority (the holder).
    pub audience: NodeId,
    /// The operations granted.
    pub abilities: Vec<String>,
    /// Which nodes this applies to.
    pub resource: Resource,
    /// Constraints.
    pub caveats: Caveats,
    /// Issuer-chosen identifier, unique per issuer. Names this capability for revocation.
    pub nonce: u64,
    /// The [`CapId`] of the parent capability in the delegation chain. `None` = a root delegation
    /// (its issuer must be an accepted root for the enforcing node).
    pub parent: Option<CapId>,
}

/// Canonical bytes the issuer signs. Domain-separated.
pub fn cap_bytes(c: &Capability) -> Vec<u8> {
    bincode::serialize(&(
        CAP_DOMAIN,
        &c.issuer,
        &c.audience,
        &c.abilities,
        &c.resource,
        &c.caveats,
        c.nonce,
        &c.parent,
    ))
    .unwrap_or_default()
}

/// The content-address of a capability — `sha256(cap_bytes)`.
pub fn cap_id(c: &Capability) -> CapId {
    let mut h = Sha256::new();
    h.update(cap_bytes(c));
    h.finalize().into()
}

mod sig_serde {
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(sig)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        bytes.try_into().map_err(|_| D::Error::custom("expected 64 bytes for signature"))
    }
}

/// A [`Capability`] plus the issuer's Ed25519 signature over [`cap_bytes`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCapability {
    pub cap: Capability,
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
}

impl SignedCapability {
    /// Issue (sign) a capability with `issuer`'s key.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        issuer: &Identity,
        audience: NodeId,
        abilities: Vec<String>,
        resource: Resource,
        caveats: Caveats,
        nonce: u64,
        parent: Option<CapId>,
    ) -> Self {
        let cap = Capability {
            issuer: issuer.node_id(),
            audience,
            abilities,
            resource,
            caveats,
            nonce,
            parent,
        };
        let sig = issuer.sign(&cap_bytes(&cap));
        SignedCapability { cap, sig }
    }

    /// Verify the issuer's signature over the capability body.
    pub fn verify_sig(&self) -> Result<()> {
        verify(&self.cap.issuer, &cap_bytes(&self.cap), &self.sig)
    }

    /// This capability's [`CapId`].
    pub fn id(&self) -> CapId {
        cap_id(&self.cap)
    }
}

/// Encode a capability chain (root-first) to bincode bytes — the form carried on the wire (the mesh
/// `grant` field) and inside a token.
pub fn encode_chain_bytes(chain: &[SignedCapability]) -> Vec<u8> {
    bincode::serialize(chain).unwrap_or_default()
}

/// Decode a chain from bincode bytes (the wire form).
pub fn decode_chain_bytes(b: &[u8]) -> Result<Vec<SignedCapability>> {
    bincode::deserialize(b).map_err(|e| anyhow!("malformed capability chain: {e}"))
}

/// Encode a capability chain (root-first) to a portable hex token for CLI flags and wallets.
pub fn encode_chain(chain: &[SignedCapability]) -> String {
    hex::encode(encode_chain_bytes(chain))
}

/// Decode a token produced by [`encode_chain`].
pub fn decode_chain(s: &str) -> Result<Vec<SignedCapability>> {
    let bytes = hex::decode(s.trim()).map_err(|_| anyhow!("capability token is not valid hex"))?;
    decode_chain_bytes(&bytes)
}

/// Decide whether `requester` may perform `action` on the node identified by (`self_id`,
/// `self_tags`), given a presented capability `chain` (**root-first**: `chain[0]` is the root
/// delegation, the last link is held by `requester`).
///
/// `accepted_roots` are the root keys this node honors. The node's **own** id is always an implicit
/// accepted root, so a node can always delegate its own resources without configuration.
///
/// `is_revoked(issuer, nonce)` consults the on-chain revocation set; revoking any link's
/// `(issuer, nonce)` invalidates that link and therefore the whole chain (and any subtree).
///
/// Returns `Ok(())` if allowed, or `Err(reason)` (safe to log / return to the caller). The exact
/// properties enforced, in order:
/// 1. the chain is non-empty and roots at an accepted root (`chain[0].issuer ∈ accepted_roots ∪ {self}`);
/// 2. every link's signature verifies (its `issuer` signed it);
/// 3. every link is temporally valid at `now` and not revoked;
/// 4. every link's `resource` matches this node;
/// 5. **continuity**: each non-root link is issued by its parent's `audience` and names the parent
///    by `CapId`; the root link has no parent;
/// 6. **attenuation**: each non-root link is no broader than its parent (abilities ⊆, resource ⊆,
///    caveats ⊇);
/// 7. the leaf's `audience` is `requester` and its `abilities` include `action`.
#[allow(clippy::too_many_arguments)]
pub fn authorize(
    self_id: &NodeId,
    accepted_roots: &[NodeId],
    self_tags: &[String],
    now: u64,
    requester: &NodeId,
    action: &str,
    chain: &[SignedCapability],
    is_revoked: &dyn Fn(&NodeId, u64) -> bool,
) -> Result<(), String> {
    if chain.is_empty() {
        return Err("no capability presented".into());
    }

    // 1. Root must be an accepted authority for this node.
    let root_issuer = &chain[0].cap.issuer;
    if root_issuer != self_id && !accepted_roots.contains(root_issuer) {
        return Err("capability chain does not root at an accepted authority".into());
    }

    for (i, link) in chain.iter().enumerate() {
        let c = &link.cap;

        // 2. Signature.
        link.verify_sig().map_err(|_| format!("link {i}: invalid signature"))?;
        // 3a. Temporal.
        c.caveats.valid_at(now).map_err(|e| format!("link {i}: {e}"))?;
        // 3b. Revocation.
        if is_revoked(&c.issuer, c.nonce) {
            return Err(format!("link {i}: capability revoked"));
        }
        // 4. Resource must apply to this node.
        if !c.resource.matches(self_id, self_tags) {
            return Err(format!("link {i}: resource does not match this node"));
        }

        if i == 0 {
            // Root link carries no parent.
            if c.parent.is_some() {
                return Err("root capability must not name a parent".into());
            }
        } else {
            let parent = &chain[i - 1].cap;
            // 5. Continuity: issued by the parent's audience, and names the parent by hash.
            if c.issuer != parent.audience {
                return Err(format!("link {i}: issuer is not the parent's audience"));
            }
            match c.parent {
                Some(pid) if pid == cap_id(parent) => {}
                _ => return Err(format!("link {i}: parent hash does not match the chain")),
            }
            // 6. Attenuation: never broaden.
            if !abilities_subset(&c.abilities, &parent.abilities) {
                return Err(format!("link {i}: abilities exceed the parent"));
            }
            if !c.resource.is_subset_of(&parent.resource) {
                return Err(format!("link {i}: resource is broader than the parent"));
            }
            if !c.caveats.is_narrower_or_equal(&parent.caveats) {
                return Err(format!("link {i}: caveats are broader than the parent"));
            }
        }
    }

    // 7. The leaf must be held by the requester and grant the action.
    let leaf = &chain[chain.len() - 1].cap;
    if &leaf.audience != requester {
        return Err("leaf capability is not held by the request sender".into());
    }
    if !leaf.abilities.iter().any(|a| a == action) {
        return Err(format!("capability does not grant '{action}'"));
    }
    Ok(())
}

fn abilities_subset(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|a| parent.contains(a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fresh identity in a unique temp dir (tests run in parallel within one process).
    fn id(tag: &str) -> Identity {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ce-cap-test-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn never_revoked(_: &NodeId, _: u64) -> bool {
        false
    }

    /// Caveats with a not_after expiry and nothing else.
    fn expires(at: u64) -> Caveats {
        Caveats { not_after: at, ..Default::default() }
    }

    // ---- single self-issued capability (replaces machines.toml full-admin) ----

    #[test]
    fn self_issued_cap_authorizes_its_ability() {
        let node = id("node");
        let laptop = id("laptop");
        let c = SignedCapability::issue(
            &node,
            laptop.node_id(),
            vec!["exec".to_string(), "sync".to_string()],
            Resource::Any,
            Caveats::default(),
            1,
            None,
        );
        // Authorized by the resource owner (issuer == self) for a granted ability.
        assert!(
            authorize(&node.node_id(), &[], &[], 1000, &laptop.node_id(), "exec", &[c.clone()], &never_revoked)
                .is_ok()
        );
        // ...but not for an ability it doesn't grant.
        assert!(
            authorize(&node.node_id(), &[], &[], 1000, &laptop.node_id(), "tunnel", &[c], &never_revoked)
                .is_err()
        );
    }

    #[test]
    fn empty_chain_is_denied() {
        let node = id("node");
        let who = id("who");
        assert!(
            authorize(&node.node_id(), &[], &[], 1000, &who.node_id(), "exec", &[], &never_revoked).is_err()
        );
    }

    #[test]
    fn unaccepted_root_is_denied() {
        let node = id("node");
        let stranger = id("stranger"); // not self, not in accepted_roots
        let laptop = id("laptop");
        let c = SignedCapability::issue(
            &stranger,
            laptop.node_id(),
            vec!["exec".to_string()],
            Resource::Any,
            Caveats::default(),
            1,
            None,
        );
        let r = authorize(&node.node_id(), &[], &[], 1000, &laptop.node_id(), "exec", &[c], &never_revoked);
        assert!(r.unwrap_err().contains("accepted authority"));
    }

    #[test]
    fn configured_org_root_is_accepted() {
        let node = id("node");
        let org = id("org"); // org root, configured as accepted (node is governed by it)
        let employee = id("employee");
        let c = SignedCapability::issue(
            &org,
            employee.node_id(),
            vec!["exec".to_string()],
            Resource::Any,
            Caveats::default(),
            7,
            None,
        );
        assert!(
            authorize(&node.node_id(), &[org.node_id()], &[], 1000, &employee.node_id(), "exec", &[c], &never_revoked)
                .is_ok()
        );
    }

    #[test]
    fn wrong_audience_is_denied() {
        let node = id("node");
        let laptop = id("laptop");
        let stranger = id("stranger");
        let c = SignedCapability::issue(&node, laptop.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 1, None);
        // stranger presents laptop's capability
        let r = authorize(&node.node_id(), &[], &[], 1000, &stranger.node_id(), "exec", &[c], &never_revoked);
        assert!(r.unwrap_err().contains("not held by"));
    }

    #[test]
    fn tampered_signature_is_denied() {
        let node = id("node");
        let laptop = id("laptop");
        let mut c = SignedCapability::issue(&node, laptop.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 1, None);
        // escalate abilities after signing
        c.cap.abilities.push("tunnel".to_string());
        let r = authorize(&node.node_id(), &[], &[], 1000, &laptop.node_id(), "tunnel", &[c], &never_revoked);
        assert!(r.unwrap_err().contains("signature"));
    }

    #[test]
    fn expiry_is_enforced() {
        let node = id("node");
        let laptop = id("laptop");
        let c = SignedCapability::issue(&node, laptop.node_id(), vec!["exec".to_string()], Resource::Any, expires(500), 1, None);
        // expired at now=1000
        assert!(
            authorize(&node.node_id(), &[], &[], 1000, &laptop.node_id(), "exec", &[c.clone()], &never_revoked)
                .unwrap_err()
                .contains("expired")
        );
        // valid before expiry
        assert!(
            authorize(&node.node_id(), &[], &[], 499, &laptop.node_id(), "exec", &[c], &never_revoked).is_ok()
        );
    }

    #[test]
    fn not_before_is_enforced() {
        let node = id("node");
        let laptop = id("laptop");
        let c = SignedCapability::issue(
            &node,
            laptop.node_id(),
            vec!["exec".to_string()],
            Resource::Any,
            Caveats { not_before: 1000, ..Default::default() },
            1,
            None,
        );
        assert!(
            authorize(&node.node_id(), &[], &[], 999, &laptop.node_id(), "exec", &[c.clone()], &never_revoked)
                .unwrap_err()
                .contains("not yet valid")
        );
        assert!(authorize(&node.node_id(), &[], &[], 1000, &laptop.node_id(), "exec", &[c], &never_revoked).is_ok());
    }

    #[test]
    fn revocation_is_enforced() {
        let node = id("node");
        let laptop = id("laptop");
        let c = SignedCapability::issue(&node, laptop.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 42, None);
        let revoke_42 = |_issuer: &NodeId, nonce: u64| nonce == 42;
        assert!(
            authorize(&node.node_id(), &[], &[], 1000, &laptop.node_id(), "exec", &[c], &revoke_42)
                .unwrap_err()
                .contains("revoked")
        );
    }

    #[test]
    fn resource_node_mismatch_is_denied() {
        let node = id("node");
        let other = id("other");
        let laptop = id("laptop");
        // capability targets `other`, not `node`
        let c = SignedCapability::issue(
            &node,
            laptop.node_id(),
            vec!["exec".to_string()],
            Resource::Node(other.node_id()),
            Caveats::default(),
            1,
            None,
        );
        let r = authorize(&node.node_id(), &[], &[], 1000, &laptop.node_id(), "exec", &[c], &never_revoked);
        assert!(r.unwrap_err().contains("does not match"));
    }

    #[test]
    fn resource_tag_matches_node_tags() {
        let node = id("node");
        let laptop = id("laptop");
        let c = SignedCapability::issue(
            &node,
            laptop.node_id(),
            vec!["exec".to_string()],
            Resource::Tag("gpu".into()),
            Caveats::default(),
            1,
            None,
        );
        let tags = vec!["gpu".to_string(), "linux".to_string()];
        assert!(authorize(&node.node_id(), &[], &tags, 1000, &laptop.node_id(), "exec", &[c.clone()], &never_revoked).is_ok());
        // a node without the tag is not covered
        assert!(authorize(&node.node_id(), &[], &["linux".to_string()], 1000, &laptop.node_id(), "exec", &[c], &never_revoked).is_err());
    }

    // ---- multi-level delegation chains ----

    /// Build a valid root→mid→leaf chain: `root` (self) → `mid` → `leaf`, all Exec/Any.
    fn three_level(root: &Identity, mid: &Identity, leaf: &Identity) -> Vec<SignedCapability> {
        let c0 = SignedCapability::issue(root, mid.node_id(), vec!["exec".to_string(), "sync".to_string()], Resource::Any, Caveats::default(), 1, None);
        let c1 = SignedCapability::issue(mid, leaf.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 2, Some(c0.id()));
        vec![c0, c1]
    }

    #[test]
    fn valid_two_link_chain_authorizes() {
        let root = id("root");
        let mid = id("mid");
        let leaf = id("leaf");
        let chain = three_level(&root, &mid, &leaf);
        assert!(
            authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), "exec", &chain, &never_revoked).is_ok()
        );
    }

    #[test]
    fn three_link_chain_authorizes() {
        let root = id("root");
        let a = id("a");
        let b = id("b");
        let c0 = SignedCapability::issue(&root, a.node_id(), vec!["exec".to_string(), "sync".to_string(), "tunnel".to_string()], Resource::Any, Caveats::default(), 1, None);
        let c1 = SignedCapability::issue(&a, b.node_id(), vec!["exec".to_string(), "sync".to_string()], Resource::Any, Caveats::default(), 2, Some(c0.id()));
        let leaf = id("leaf");
        let c2 = SignedCapability::issue(&b, leaf.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 3, Some(c1.id()));
        let chain = vec![c0, c1, c2];
        assert!(authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), "exec", &chain, &never_revoked).is_ok());
        // leaf cannot use an ability it wasn't delegated, even though the root had it
        assert!(authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), "tunnel", &chain, &never_revoked).is_err());
    }

    #[test]
    fn chain_denies_ability_amplification() {
        let root = id("root");
        let mid = id("mid");
        let leaf = id("leaf");
        let c0 = SignedCapability::issue(&root, mid.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 1, None);
        // mid tries to grant Tunnel, which it was never given
        let c1 = SignedCapability::issue(&mid, leaf.node_id(), vec!["exec".to_string(), "tunnel".to_string()], Resource::Any, Caveats::default(), 2, Some(c0.id()));
        let r = authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), "tunnel", &[c0, c1], &never_revoked);
        assert!(r.unwrap_err().contains("exceed the parent"));
    }

    #[test]
    fn chain_denies_expiry_extension() {
        let root = id("root");
        let mid = id("mid");
        let leaf = id("leaf");
        let c0 = SignedCapability::issue(&root, mid.node_id(), vec!["exec".to_string()], Resource::Any, expires(500), 1, None);
        // child tries to outlive parent
        let c1 = SignedCapability::issue(&mid, leaf.node_id(), vec!["exec".to_string()], Resource::Any, expires(9999), 2, Some(c0.id()));
        let r = authorize(&root.node_id(), &[], &[], 100, &leaf.node_id(), "exec", &[c0, c1], &never_revoked);
        assert!(r.unwrap_err().contains("caveats are broader"));
    }

    #[test]
    fn chain_denies_resource_broadening() {
        let root = id("root");
        let mid = id("mid");
        let leaf = id("leaf");
        let c0 = SignedCapability::issue(&root, mid.node_id(), vec!["exec".to_string()], Resource::Tag("gpu".into()), Caveats::default(), 1, None);
        // child tries to broaden from tag=gpu to any
        let c1 = SignedCapability::issue(&mid, leaf.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 2, Some(c0.id()));
        let tags = vec!["gpu".to_string()];
        let r = authorize(&root.node_id(), &[], &tags, 1000, &leaf.node_id(), "exec", &[c0, c1], &never_revoked);
        assert!(r.unwrap_err().contains("broader than the parent"));
    }

    #[test]
    fn chain_denies_broken_continuity() {
        let root = id("root");
        let mid = id("mid");
        let other = id("other");
        let leaf = id("leaf");
        let c0 = SignedCapability::issue(&root, mid.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 1, None);
        // c1 issued by `other`, not by the parent's audience `mid`
        let c1 = SignedCapability::issue(&other, leaf.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 2, Some(c0.id()));
        let r = authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), "exec", &[c0, c1], &never_revoked);
        assert!(r.unwrap_err().contains("not the parent's audience"));
    }

    #[test]
    fn chain_denies_wrong_parent_hash() {
        let root = id("root");
        let mid = id("mid");
        let leaf = id("leaf");
        let c0 = SignedCapability::issue(&root, mid.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 1, None);
        // c1 names a bogus parent hash
        let c1 = SignedCapability::issue(&mid, leaf.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 2, Some([9u8; 32]));
        let r = authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), "exec", &[c0, c1], &never_revoked);
        assert!(r.unwrap_err().contains("parent hash"));
    }

    #[test]
    fn chain_root_with_parent_is_denied() {
        let root = id("root");
        let leaf = id("leaf");
        // a root link must have parent == None
        let c0 = SignedCapability::issue(&root, leaf.node_id(), vec!["exec".to_string()], Resource::Any, Caveats::default(), 1, Some([1u8; 32]));
        let r = authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), "exec", &[c0], &never_revoked);
        assert!(r.unwrap_err().contains("must not name a parent"));
    }

    #[test]
    fn revoking_a_middle_link_kills_the_chain() {
        let root = id("root");
        let mid = id("mid");
        let leaf = id("leaf");
        let chain = three_level(&root, &mid, &leaf);
        // revoke the root link's nonce (1) — the whole subtree dies
        let revoke_root = |_i: &NodeId, nonce: u64| nonce == 1;
        let r = authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), "exec", &chain, &revoke_root);
        assert!(r.unwrap_err().contains("revoked"));
    }

    #[test]
    fn chain_denies_port_widening() {
        let root = id("root");
        let mid = id("mid");
        let leaf = id("leaf");
        let restricted = Caveats { allowed_ports: Some(vec![22]), ..Default::default() };
        let c0 = SignedCapability::issue(&root, mid.node_id(), vec!["tunnel".to_string()], Resource::Any, restricted, 1, None);
        // child tries to allow an extra port
        let widened = Caveats { allowed_ports: Some(vec![22, 8080]), ..Default::default() };
        let c1 = SignedCapability::issue(&mid, leaf.node_id(), vec!["tunnel".to_string()], Resource::Any, widened, 2, Some(c0.id()));
        let r = authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), "tunnel", &[c0, c1], &never_revoked);
        assert!(r.unwrap_err().contains("caveats are broader"));
    }

    // ---- unit tests for the helper predicates ----

    #[test]
    fn resource_subset_rules() {
        let a = [1u8; 32];
        assert!(Resource::Tag("gpu".into()).is_subset_of(&Resource::Any));
        assert!(Resource::Node(a).is_subset_of(&Resource::Any));
        assert!(Resource::Node(a).is_subset_of(&Resource::Node(a)));
        assert!(!Resource::Any.is_subset_of(&Resource::Tag("gpu".into())));
        assert!(!Resource::Node(a).is_subset_of(&Resource::Tag("gpu".into())));
        assert!(Resource::Tag("gpu".into()).is_subset_of(&Resource::Tag("gpu".into())));
        assert!(!Resource::Tag("cpu".into()).is_subset_of(&Resource::Tag("gpu".into())));
        assert!(Resource::AllOf(vec!["gpu".into(), "linux".into()]).is_subset_of(&Resource::Tag("gpu".into())));
        assert!(Resource::AllOf(vec!["gpu".into(), "linux".into()]).is_subset_of(&Resource::AllOf(vec!["gpu".into()])));
        assert!(!Resource::AllOf(vec!["gpu".into()]).is_subset_of(&Resource::AllOf(vec!["gpu".into(), "linux".into()])));
    }

    #[test]
    fn caveats_narrower_rules() {
        let parent = Caveats { not_after: 1000, max_cpu: Some(8), ..Default::default() };
        // equal is allowed
        assert!(parent.is_narrower_or_equal(&parent));
        // tighter expiry + lower cpu = narrower
        assert!(Caveats { not_after: 500, max_cpu: Some(4), ..Default::default() }.is_narrower_or_equal(&parent));
        // no expiry under a finite parent = broader
        assert!(!Caveats { not_after: 0, max_cpu: Some(4), ..Default::default() }.is_narrower_or_equal(&parent));
        // higher cpu = broader
        assert!(!Caveats { not_after: 500, max_cpu: Some(16), ..Default::default() }.is_narrower_or_equal(&parent));
        // unlimited cpu under a capped parent = broader
        assert!(!Caveats { not_after: 500, max_cpu: None, ..Default::default() }.is_narrower_or_equal(&parent));
    }

    #[test]
    fn path_prefix_attenuation_is_boundary_aware() {
        let parent = Caveats { path_prefix: Some("/home/user".into()), ..Default::default() };
        // A sibling that merely shares the textual prefix is NOT within the parent.
        let sibling = Caveats { path_prefix: Some("/home/userdata".into()), ..Default::default() };
        assert!(!sibling.is_narrower_or_equal(&parent));
        // A true sub-path IS within the parent.
        let child = Caveats { path_prefix: Some("/home/user/docs".into()), ..Default::default() };
        assert!(child.is_narrower_or_equal(&parent));
        // Equal (modulo trailing slash) is within.
        let equal = Caveats { path_prefix: Some("/home/user/".into()), ..Default::default() };
        assert!(equal.is_narrower_or_equal(&parent));
        // An unconfined child under a confined parent is broader.
        let unconfined = Caveats { path_prefix: None, ..Default::default() };
        assert!(!unconfined.is_narrower_or_equal(&parent));
    }

    #[test]
    fn chain_token_roundtrips() {
        let root = id("root");
        let mid = id("mid");
        let leaf = id("leaf");
        let chain = three_level(&root, &mid, &leaf);
        let token = encode_chain(&chain);
        let back = decode_chain(&token).unwrap();
        assert_eq!(back.len(), chain.len());
        assert_eq!(back[0].cap, chain[0].cap);
        assert!(back[1].verify_sig().is_ok());
    }
}
