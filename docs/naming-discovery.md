# Naming & discovery — design

**Status: done (v0).** Two primitives that turn "address nodes by 64-hex and a capacity snapshot"
into "name and find anything on the mesh by role" — the substrate a control plane needs.

## Naming (`NameClaim`)

A consensus-enforced binding from a human-readable name to a NodeId.

- `TxKind::NameClaim { name, node }` — signed by the claimer; the chain requires `origin == node`
  (you name only yourself) and `is_valid_name(name)` (3–32 chars, lowercase `a-z` / `0-9` / hyphen,
  no leading/trailing hyphen — DNS-label-shaped, case-safe).
- **First claim wins.** Uniqueness is enforced in `append()` (the name must be unclaimed both
  on-chain and earlier in the same block), exactly like channel-id uniqueness. A `names: name →
  NodeId` cache gives O(1) `resolve_name`.
- API: `POST /names/claim { name }` (takes effect once mined), `GET /names/:name` → owner NodeId.
  `ce-rs`: `claim_name` / `resolve_name`. CLI: `ce name claim <name>` / `ce name resolve <name>`.
- **v0 scope:** permanent, free, first-come. Transfer, release, expiry, and an anti-squatting
  claim fee/stake are refinements (a name fee is the natural anti-squatting lever).

## Discovery (service registry over the DHT)

"Who offers service S?" — generalised from the data layer's content routing.

- Reuses the **Kademlia provider records** built for chunk fetch (Stage 2 of the data layer): a
  service advertises under `service_key(s) = sha256("ce-svc/" + s)`, domain-separated from chunk
  cids so the two never collide in the shared keyspace. `advertise_service` → `start_providing`;
  `find_service` → `get_providers`.
- **Returns NodeIds, not PeerIds.** `node_id_from_peer_id` recovers the NodeId from a PeerId
  (ed25519 PeerIds inline the public key via an identity multihash), so a discovered provider can
  immediately be messaged (app messaging) or deployed to (mesh deploy) — all of which address by
  NodeId. This is the inverse of `peer_id_from_node_id`.
- API: `POST /discovery/advertise { service }`, `GET /discovery/find/:service` → provider NodeIds.
  `ce-rs`: `advertise_service` / `find_service`. CLI: `ce discover advertise|find <service>`.
- **v0 scope:** advertise is one-shot — provider records expire, so re-advertise periodically
  (app responsibility for now; a node-side refresh loop is a refinement). Service metadata (price,
  capabilities) isn't carried in the record; pair discovery with the atlas / `history` for that.

## CE vs app

CE provides the *mechanisms*: a unique on-chain name binding, and an authenticated advertise/find
over the DHT. Policy stays with the app — what a name means, which services to trust, pricing,
selection among providers (combine with the trust gradient / `history`). No global directory
authority: naming is consensus, discovery is the DHT.

## Why these, now

With app messaging done, an app can talk to any node it can *name*. Naming makes references stable
and human; discovery makes them findable by role instead of pre-shared NodeId. Together they're
the addressing layer a control plane builds on. Relay incentives (paid, discoverable relays) are
the next readiness gate for a permissionless mesh.
