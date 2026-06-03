# CE Capabilities — the authorization primitive

> Status: canonical spec. The verification core lives in `crates/ce-node/src/capability.rs`; the
> on-chain revocation anchor in `crates/ce-chain`. This document is the source of truth — code is
> built to match it.

CE has **one** trust primitive. It replaces both the old device allowlist (`machines.toml`) and
the old single-level grant.

> **A node trusts a small set of root keys. Authority is a signed, attenuating capability chain
> from one of those roots to the requester.**

There is no concept of "device", "company", "team", or "person" in CE — only keys, abilities,
resource matchers, caveats, and signatures. Organizations are modeled by *apps* that issue
capabilities; that policy never enters the node. The node is the enforcement point: it decides
whether to perform an incoming exec/sync/tunnel **before** doing the work, so verification lives in
CE while issuance and human-facing policy live on top.

## Why not a device list

A per-device allowlist is `O(devices)` config that every node must maintain by hand. It does not
scale to a fleet, let alone an org or a global mesh — an office is not going to hand-register every
laptop on every machine. A **root-key anchor** is `O(1) per trust domain` (usually a single key)
and covers unlimited principals through issued capabilities. This is the same split SSH makes
between `authorized_keys` (a list that doesn't scale) and certificate authorities
(`TrustedUserCAKeys`, one key governing many). CE keeps only the scalable half.

## The three rungs of the trust gradient

| Relationship | Mechanism | Who sets policy |
|---|---|---|
| My own fleet | self-issued capabilities (root = my key) | me |
| Org / delegated | capability chains rooted at a configured org key | the org's **app** |
| True strangers | **payment + verification** — no capability at all | the market |

Capabilities cover the first two rungs. Strangers present no capability; access is granted by the
*economy* (pay-to-use) with correctness from *verification* (redundancy/proofs) — an orthogonal
axis, out of scope for this document.

## The token

```text
Capability {
  issuer:    NodeId          // who delegates (the signer)
  audience:  NodeId          // who receives this authority (the holder)
  abilities: [Ability]       // exec | sync | delete | tunnel | deploy | kill | status
  resource:  Resource        // Any | Node(id) | Tag(t) | AllOf([t..])
  caveats:   Caveats         // not_before, not_after, max_cpu/mem/credits,
                             //   allowed_ports (tunnel), path_prefix (sync/delete)
  nonce:     u64             // unique per issuer — names this capability for revocation
  parent:    Option<CapId>   // sha256 of the parent capability; None = a root delegation
}
SignedCapability = Capability + issuer's Ed25519 signature over cap_bytes(Capability)
CapId            = sha256(cap_bytes(Capability))
```

`cap_bytes` is domain-separated with the tag `ce-cap-v1`, so a capability signature can never be
confused with any other CE signature (auth requests, settlements, blocks).

A **chain** is `[SignedCapability]` ordered **root-first**: `chain[0]` is the root delegation, and
the last link is held by the requester.

## The trust root

A node accepts a chain only if its root (`chain[0].issuer`) is an **accepted root** for that node:

1. the node's **own identity** — self-delegation. The zero-config personal/fleet case: the resource
   owner issues capabilities for its own resources. *(Always implicitly accepted.)*
2. a **configured root key** — the org/CA anchor (a list of public keys in node config, normally
   length 1). A node opts in to a domain by listing its root key here; it can then honor chains
   that domain issues.

Self-issued (own-key) needs no configuration at all and fully replaces `machines.toml`.

## Attenuation — the security backbone

Each non-root link must be **no broader than its parent**. Verified at every link:

- **abilities** ⊆ parent's abilities,
- **resource** ⊆ parent's resource (`Resource::is_subset_of`, conservative: ambiguous narrowings
  are rejected, never silently granted),
- **caveats** at least as restrictive (`Caveats::is_narrower_or_equal`): a child may not outlive its
  parent's `not_after`, start before its `not_before`, raise any `max_*` ceiling, widen
  `allowed_ports`, or escape `path_prefix`.

Because narrowing is monotonic and checked per link, **no chain can ever amplify authority**. A
holder can safely hand a third party a strict subset of what it holds, recursively, without bound.

## The authorization algorithm

`authorize(self_id, accepted_roots, self_tags, now, requester, action, chain, is_revoked)` returns
`Ok(())` or `Err(reason)`. In order:

1. the chain is non-empty and `chain[0].issuer ∈ accepted_roots ∪ {self_id}`;
2. every link's signature verifies (its `issuer` signed it);
3. every link is temporally valid at `now` (`not_before`/`not_after`) and **not revoked**;
4. every link's `resource` matches this node `(self_id, self_tags)`;
5. **continuity**: every non-root link is issued by its parent's `audience` and names the parent by
   `CapId`; the root link has no parent;
6. **attenuation**: every non-root link is no broader than its parent;
7. the leaf's `audience == requester` and its `abilities` include `action`.

The decision is fully **local and offline** — no network lookup on the hot path. The only external
input is the revocation set, which the node already has from the synced chain.

## Revocation

Three layers, cheapest first:

1. **Expiry** — `Caveats.not_after`. Short-lived by default, renewed often. Free and offline.
   Covers most cases.
2. **On-chain `RevokeCapability { issuer, nonce }`** — signed by the issuer (the tx origin), it adds
   `(issuer, nonce)` to a chain-tracked revocation set. `authorize`'s `is_revoked(issuer, nonce)`
   consults it. Revoking **any** link revokes that link and therefore its whole subtree. This is the
   global, eventually-consistent kill switch, riding the blockchain CE already syncs.
3. **Root rotation** — drop or rotate a configured root key. The org/account nuclear option.

## Caveat enforcement responsibility

Temporal caveats (`not_before`/`not_after`) are enforced by `authorize`. Resource ceilings and
action caveats are enforced by the action that consumes them — `allowed_ports` by the tunnel,
`path_prefix` by sync/delete, `max_cpu/mem/credits` by deploy. **An action that cannot honor a
caveat must reject the request rather than exceed it** (fail-closed).

## Bootstrapping (your fleet, no device list)

The resource owner issues a capability to each device. On the **desktop** (the owner of its own
resources):

```bash
ce grant <laptop-node-id> --can exec,sync,tunnel --ports 22 --expires 90d
# → a SignedCapability token, signed by the desktop's own key
```

The laptop stores the token in its **capability wallet** and presents it (the CLI auto-attaches the
chain over the mesh proxy). The desktop accepts it because the chain roots at the desktop's own key.
No `ce devices add`, no `machines.toml`. For an org, nodes are provisioned with the org root key
(accepted root #2) and the org's app mints chained, attenuated capabilities to employees/devices —
the identical mechanism at scale.

## What this replaces / removes

- **Removed:** `machines.toml`, `crates/ce-node/src/devices.rs`, `ce devices add/ls/revoke`,
  the single-level grant rooted in the device list.
- **Added:** the capability chain above, an `accepted_roots` node config (public keys),
  `Ability::Tunnel`/`Delete`, the `RevokeCapability` chain tx, and a client-side capability wallet.
- **Mandatory:** the full capability chain is forwarded through the mesh proxy (`/mesh-exec`,
  `/mesh-sync`, …), not stubbed out.

## Security properties (summary)

- No ambient authority: every action requires an explicit capability chain.
- No amplification: monotonic attenuation, checked per link.
- No confused deputy: the leaf must be held by the authenticated request sender
  (`audience == requester`, where `requester` is the libp2p-noise-authenticated `from_node`).
- No replay across signatures: domain separation (`ce-cap-v1`).
- Tamper-evident: each link is individually signed; `parent` binds links by content hash.
- Revocable: expiry + on-chain anchor (subtree-killing) + root rotation.
- Offline-verifiable: no central authority on the hot path.
