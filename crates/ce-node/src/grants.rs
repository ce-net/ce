//! Scoped capability grants — CE's generic delegation primitive.
//!
//! ## What this is (and is not)
//!
//! A **grant** is a signed statement by which a *trusted admin* (any node already in
//! the enforcing device's `machines.toml`) delegates a *subset* of its authority to
//! another principal. It is the mechanism that replaces all-or-nothing trust:
//!
//!   "I, issuer `O`, authorize subject `P` to perform `{permissions}` on any workspace
//!    whose capability self-tags satisfy `selector`, subject to `constraints`."
//!
//! This is **generic mechanism, not policy**. There is no notion of company, team, or
//! person here — only keys, permissions, tag-selectors, and limits. Products that model
//! organizations (a "company workspace") are built *on top* by minting grants; they do
//! not live in `ce-node`. The node is the enforcement point — it must decide whether to
//! run an incoming exec/sync *before* doing the work — so verification lives in CE while
//! issuance and human-facing policy live in the app.
//!
//! ## Trust root
//!
//! A device accepts a grant only if its `issuer` is already a trusted admin in the local
//! `machines.toml`. Your own devices (in each other's registries) are full-scope admins
//! and need no grant; they can in turn delegate scoped grants to coworkers. Enforcement
//! is identical on both transports:
//! - mesh RPC (`/ce/rpc/1`): the sender's NodeId is libp2p-noise-authenticated (the
//!   PeerId↔`from_node` cross-check), so the grant simply rides along as opaque bytes.
//! - HTTP (`/exec`, `/sync`): the request is Ed25519-signed (`ce-auth-v1`); the grant is
//!   presented in the `X-CE-Grant` header.
//!
//! ## Revocation
//!
//! v1 relies on short `not_after` expiries plus the nuclear option of un-trusting the
//! issuer (which invalidates every grant it signed). An on-chain `RevokeGrant` anchor
//! keyed by `(issuer, nonce)` is the planned global mechanism.

use anyhow::{anyhow, Result};
use ce_identity::{Identity, NodeId, verify};
use serde::{Deserialize, Serialize};

use crate::devices::Devices;

/// A generic action a grant can authorize. No product semantics — just the operations a
/// node can perform on behalf of a caller. `Exec` and `Sync` are enforced today; `Deploy`
/// and `Kill` are defined for the remote-job path and reserved until it is mesh-routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// Run a sandboxed command (mesh RPC `Exec`, HTTP `/exec`).
    Exec,
    /// Write a file (mesh RPC `SyncFile`, HTTP `/sync`).
    Sync,
    /// Submit a job bid / deploy a cell. Reserved (no mesh-routed deploy path yet).
    Deploy,
    /// Force-stop a job. Reserved (no mesh-routed kill path yet).
    Kill,
    /// Read status / list jobs.
    Status,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Exec => "exec",
            Permission::Sync => "sync",
            Permission::Deploy => "deploy",
            Permission::Kill => "kill",
            Permission::Status => "status",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "exec" => Ok(Permission::Exec),
            "sync" => Ok(Permission::Sync),
            "deploy" => Ok(Permission::Deploy),
            "kill" => Ok(Permission::Kill),
            "status" => Ok(Permission::Status),
            other => Err(anyhow!("unknown permission '{other}' (expected exec|sync|deploy|kill|status)")),
        }
    }
}

/// Which workspaces a grant applies to, matched against a device's capability self-tags
/// (the same `gpu`/`docker`/`linux`/... set advertised in the atlas). Targeting by tag
/// rather than by node id means a grant covers workspaces that don't exist yet but later
/// advertise the tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Selector {
    /// Every workspace under the issuer's authority.
    Any,
    /// Workspaces advertising this single self-tag.
    Tag(String),
    /// Workspaces advertising all of these self-tags.
    AllOf(Vec<String>),
}

impl Selector {
    /// True if a device with the given capability self-tags falls within this selector.
    pub fn matches(&self, self_tags: &[String]) -> bool {
        match self {
            Selector::Any => true,
            Selector::Tag(t) => self_tags.iter().any(|x| x == t),
            Selector::AllOf(ts) => ts.iter().all(|t| self_tags.iter().any(|x| x == t)),
        }
    }

    /// Parse a CLI selector string: `*` / `any` → Any; `tag=foo` or `foo` → Tag; a
    /// comma-separated `tag=a,b,c` → AllOf.
    pub fn parse(s: &str) -> Self {
        let body = s.strip_prefix("tag=").unwrap_or(s);
        if body == "*" || body.eq_ignore_ascii_case("any") {
            return Selector::Any;
        }
        let parts: Vec<String> = body.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
        match parts.len() {
            0 => Selector::Any,
            1 => Selector::Tag(parts.into_iter().next().unwrap()),
            _ => Selector::AllOf(parts),
        }
    }
}

/// Limits attached to a grant. `not_after` is enforced now; the resource ceilings are
/// carried by the mechanism and enforced by whichever action consumes resources (the
/// mesh-routed deploy path, once built). They are not silently ignored — actions that
/// cannot honor a cap must reject the grant rather than exceed it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraints {
    /// Unix seconds after which the grant is invalid. `0` means no expiry.
    pub not_after: u64,
    /// Max CPU cores a deploy under this grant may request.
    pub max_cpu: Option<u32>,
    /// Max memory (MB) a deploy under this grant may request.
    pub max_mem_mb: Option<u32>,
    /// Max credits the subject may spend under this grant.
    pub max_credits: Option<u64>,
}

/// The unsigned capability statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub issuer: NodeId,
    pub subject: NodeId,
    pub permissions: Vec<Permission>,
    pub selector: Selector,
    pub constraints: Constraints,
    /// Issuer-chosen identifier, unique per issuer. Names the grant for revocation.
    pub nonce: u64,
}

/// Canonical bytes the issuer signs. Domain-separated so a grant signature can never be
/// mistaken for any other CE signature (auth requests, settlements, blocks).
pub fn grant_bytes(g: &Grant) -> Vec<u8> {
    bincode::serialize(&(
        b"ce-grant-v1",
        &g.issuer,
        &g.subject,
        &g.permissions,
        &g.selector,
        &g.constraints,
        g.nonce,
    ))
    .unwrap_or_default()
}

mod sig_serde {
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(sig)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        bytes.try_into().map_err(|_| D::Error::custom("expected 64 bytes for signature"))
    }
}

/// A `Grant` plus the issuer's Ed25519 signature over `grant_bytes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGrant {
    pub grant: Grant,
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
}

impl SignedGrant {
    /// Issue a grant signed by `issuer`.
    pub fn issue(
        issuer: &Identity,
        subject: NodeId,
        permissions: Vec<Permission>,
        selector: Selector,
        constraints: Constraints,
        nonce: u64,
    ) -> Self {
        let grant = Grant {
            issuer: issuer.node_id(),
            subject,
            permissions,
            selector,
            constraints,
            nonce,
        };
        let sig = issuer.sign(&grant_bytes(&grant));
        SignedGrant { grant, sig }
    }

    /// Verify the issuer's signature over the grant body.
    pub fn verify(&self) -> Result<()> {
        verify(&self.grant.issuer, &grant_bytes(&self.grant), &self.sig)
    }

    /// Encode to a portable token string (hex of bincode) for CLI flags / headers.
    pub fn encode(&self) -> String {
        hex::encode(bincode::serialize(self).unwrap_or_default())
    }

    /// Decode a token produced by [`encode`](Self::encode).
    pub fn decode(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim()).map_err(|_| anyhow!("grant token is not valid hex"))?;
        bincode::deserialize(&bytes).map_err(|e| anyhow!("malformed grant token: {e}"))
    }
}

/// Decide whether `sender` may perform `action` on this device.
///
/// Returns `Ok(())` if allowed, or `Err(reason)` describing why not (suitable for logging
/// and returning to the caller). The rules, in order:
/// 1. A `sender` already trusted in `machines.toml` is a full-scope admin — always allowed.
/// 2. Otherwise a grant must be presented whose `subject` is the sender, whose `issuer` is
///    a trusted admin on this device, whose signature verifies, which has not expired,
///    whose `permissions` include `action`, and whose `selector` matches this device's
///    capability `self_tags`.
pub fn authorize(
    devices: &Devices,
    self_tags: &[String],
    now_secs: u64,
    sender: &NodeId,
    action: Permission,
    grant: Option<&SignedGrant>,
) -> Result<(), String> {
    if devices.is_trusted(sender) {
        return Ok(());
    }
    let sg = grant.ok_or_else(|| "sender is not a trusted device and presented no grant".to_string())?;
    let g = &sg.grant;
    if &g.subject != sender {
        return Err("grant subject does not match the request sender".into());
    }
    if !devices.is_trusted(&g.issuer) {
        return Err("grant issuer is not a trusted admin on this device".into());
    }
    sg.verify().map_err(|_| "grant signature is invalid".to_string())?;
    if g.constraints.not_after != 0 && g.constraints.not_after < now_secs {
        return Err("grant has expired".into());
    }
    if !g.permissions.contains(&action) {
        return Err(format!("grant does not permit '{}'", action.as_str()));
    }
    if !g.selector.matches(self_tags) {
        return Err("grant selector does not match this workspace's capabilities".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;

    fn id(tag: &str) -> Identity {
        // Unique dir per identity: tests run in parallel within one process, so a dir keyed only
        // by (pid, tag) lets two tests calling fixture() race on the same `node.key`.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("ce-grant-test-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    /// admin in machines.toml, subject holding a grant from that admin, and a stranger.
    fn fixture() -> (Devices, Identity, Identity, Identity) {
        let admin = id("admin");
        let subject = id("subject");
        let stranger = id("stranger");
        let mut devices = Devices::default();
        devices.add("admin", admin.node_id(), "10.0.0.1:8844");
        (devices, admin, subject, stranger)
    }

    fn grant_for(
        admin: &Identity,
        subject: &Identity,
        perms: Vec<Permission>,
        selector: Selector,
        not_after: u64,
    ) -> SignedGrant {
        SignedGrant::issue(
            admin,
            subject.node_id(),
            perms,
            selector,
            Constraints { not_after, ..Default::default() },
            1,
        )
    }

    #[test]
    fn admin_has_full_scope_without_grant() {
        let (devices, admin, _subject, _stranger) = fixture();
        assert!(authorize(&devices, &[], 1000, &admin.node_id(), Permission::Exec, None).is_ok());
        assert!(authorize(&devices, &[], 1000, &admin.node_id(), Permission::Sync, None).is_ok());
    }

    #[test]
    fn stranger_without_grant_is_denied() {
        let (devices, _admin, _subject, stranger) = fixture();
        assert!(authorize(&devices, &[], 1000, &stranger.node_id(), Permission::Exec, None).is_err());
    }

    #[test]
    fn valid_grant_authorizes_named_permission_and_selector() {
        let (devices, admin, subject, _stranger) = fixture();
        let g = grant_for(&admin, &subject, vec![Permission::Exec], Selector::Tag("gpu".into()), 0);
        let tags = vec!["gpu".to_string(), "linux".to_string()];
        assert!(authorize(&devices, &tags, 1000, &subject.node_id(), Permission::Exec, Some(&g)).is_ok());
    }

    #[test]
    fn grant_denies_unlisted_permission() {
        let (devices, admin, subject, _stranger) = fixture();
        let g = grant_for(&admin, &subject, vec![Permission::Exec], Selector::Any, 0);
        let r = authorize(&devices, &[], 1000, &subject.node_id(), Permission::Sync, Some(&g));
        assert!(r.unwrap_err().contains("does not permit"));
    }

    #[test]
    fn grant_denies_selector_mismatch() {
        let (devices, admin, subject, _stranger) = fixture();
        let g = grant_for(&admin, &subject, vec![Permission::Exec], Selector::Tag("gpu".into()), 0);
        let tags = vec!["linux".to_string()]; // no gpu
        let r = authorize(&devices, &tags, 1000, &subject.node_id(), Permission::Exec, Some(&g));
        assert!(r.unwrap_err().contains("selector"));
    }

    #[test]
    fn grant_denies_when_subject_is_not_the_sender() {
        let (devices, admin, subject, stranger) = fixture();
        let g = grant_for(&admin, &subject, vec![Permission::Exec], Selector::Any, 0);
        // stranger replays subject's grant
        let r = authorize(&devices, &[], 1000, &stranger.node_id(), Permission::Exec, Some(&g));
        assert!(r.unwrap_err().contains("subject"));
    }

    #[test]
    fn grant_denies_untrusted_issuer() {
        let (devices, _admin, subject, stranger) = fixture();
        // grant signed by a stranger who is NOT a trusted admin
        let g = grant_for(&stranger, &subject, vec![Permission::Exec], Selector::Any, 0);
        let r = authorize(&devices, &[], 1000, &subject.node_id(), Permission::Exec, Some(&g));
        assert!(r.unwrap_err().contains("issuer"));
    }

    #[test]
    fn grant_denies_tampered_signature() {
        let (devices, admin, subject, _stranger) = fixture();
        let mut g = grant_for(&admin, &subject, vec![Permission::Exec], Selector::Any, 0);
        // Escalate the permission set after signing.
        g.grant.permissions.push(Permission::Sync);
        let r = authorize(&devices, &[], 1000, &subject.node_id(), Permission::Sync, Some(&g));
        assert!(r.unwrap_err().contains("signature"));
    }

    #[test]
    fn authorizes_deploy_and_kill_and_isolates_permissions() {
        let (devices, admin, subject, _stranger) = fixture();
        // A grant covering Deploy+Kill authorizes both.
        let g = grant_for(&admin, &subject, vec![Permission::Deploy, Permission::Kill], Selector::Any, 0);
        assert!(authorize(&devices, &[], 1000, &subject.node_id(), Permission::Deploy, Some(&g)).is_ok());
        assert!(authorize(&devices, &[], 1000, &subject.node_id(), Permission::Kill, Some(&g)).is_ok());
        // A Deploy-only grant must not authorize Kill or Exec.
        let gd = grant_for(&admin, &subject, vec![Permission::Deploy], Selector::Any, 0);
        assert!(authorize(&devices, &[], 1000, &subject.node_id(), Permission::Kill, Some(&gd)).is_err());
        assert!(authorize(&devices, &[], 1000, &subject.node_id(), Permission::Exec, Some(&gd)).is_err());
        // Permission strings round-trip.
        assert_eq!(Permission::parse("deploy").unwrap(), Permission::Deploy);
        assert_eq!(Permission::parse("kill").unwrap(), Permission::Kill);
    }

    #[test]
    fn grant_denies_after_expiry() {
        let (devices, admin, subject, _stranger) = fixture();
        let g = grant_for(&admin, &subject, vec![Permission::Exec], Selector::Any, 500);
        let r = authorize(&devices, &[], 1000, &subject.node_id(), Permission::Exec, Some(&g));
        assert!(r.unwrap_err().contains("expired"));
        // Still valid before expiry.
        assert!(authorize(&devices, &[], 499, &subject.node_id(), Permission::Exec, Some(&g)).is_ok());
    }

    #[test]
    fn token_encode_decode_roundtrips() {
        let (_devices, admin, subject, _stranger) = fixture();
        let g = grant_for(&admin, &subject, vec![Permission::Exec, Permission::Sync], Selector::AllOf(vec!["gpu".into(), "linux".into()]), 12345);
        let token = g.encode();
        let back = SignedGrant::decode(&token).unwrap();
        assert_eq!(back.grant, g.grant);
        assert!(back.verify().is_ok());
    }

    #[test]
    fn selector_parse_and_match() {
        assert_eq!(Selector::parse("*"), Selector::Any);
        assert_eq!(Selector::parse("any"), Selector::Any);
        assert_eq!(Selector::parse("tag=gpu"), Selector::Tag("gpu".into()));
        assert_eq!(Selector::parse("gpu"), Selector::Tag("gpu".into()));
        assert_eq!(Selector::parse("tag=gpu,linux"), Selector::AllOf(vec!["gpu".into(), "linux".into()]));

        assert!(Selector::Any.matches(&[]));
        assert!(Selector::Tag("gpu".into()).matches(&["gpu".to_string()]));
        assert!(!Selector::Tag("gpu".into()).matches(&["linux".to_string()]));
        assert!(Selector::AllOf(vec!["gpu".into(), "linux".into()]).matches(&["gpu".to_string(), "linux".to_string(), "docker".to_string()]));
        assert!(!Selector::AllOf(vec!["gpu".into(), "cuda".into()]).matches(&["gpu".to_string()]));
    }
}
