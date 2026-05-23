# ce-protocol-1 (CEP-1)

Wire format for CE cell signaling. Cells that implement this protocol get first-class status in the mesh: they can signal other cells, earn/spend credit, and self-replicate. Containers that don't implement it are "foreign" — they run but cannot communicate through CE.

Implemented in the `ce-protocol` crate.

---

## Signal structure

```rust
pub struct CellSignal {
    pub version: u8,                    // always 1
    pub from: NodeId,                   // sender's Ed25519 public key (32 bytes)
    pub to: CellAddress,                // Node(NodeId) or Broadcast
    pub capabilities: Vec<Capability>, // what this cell can do
    pub payload: Vec<u8>,              // application data (opaque bytes)
    pub burn_proof: Option<BurnProof>, // required for non-empty payloads
    pub nonce: u64,                    // monotone per sender — replay prevention
    pub sig: [u8; 64],                 // Ed25519 signature over all fields above
}
```

### CellAddress

```rust
pub enum CellAddress {
    Node(NodeId),   // unicast to a specific node
    Broadcast,      // all subscribed cells on the mesh
}
```

### Capability

```rust
pub struct Capability {
    pub name: String,    // e.g. "inference", "storage", "relay", "compute"
    pub version: u32,    // semver major
}
```

### BurnProof

Proof that credits were spent before transmitting a non-trivial payload. Prevents free-riding.

```rust
pub struct BurnProof {
    pub tx_id: [u8; 32],      // ID of the Meter or Transfer tx that was burned
    pub amount: u64,           // credits burned
    pub block_height: u64,     // block that confirmed the burn
    pub block_hash: [u8; 32], // hash of that block
}
```

---

## Serialization

Wire format: **bincode** (little-endian, length-prefixed).

The signature covers a `SignalBody` struct (all fields except `sig`) serialized with bincode. This ensures the signature is deterministic regardless of the outer envelope's serialization.

Gossipsub topic: `ce-protocol-1`

---

## Building a signal

```rust
use ce_protocol::{CellAddress, CellSignal, Capability};

let signal = CellSignal::build(
    identity.node_id(),
    CellAddress::Broadcast,
    vec![Capability { name: "compute".into(), version: 1 }],
    payload_bytes,
    burn_proof,       // None for capability-only announcements
    nonce,            // increment per signal sent
    &identity,
);

// Encode for wire
let bytes = signal.encode()?;

// Decode on receive
let received = CellSignal::decode(&bytes)?;
received.verify()?;   // check sig + version
```

---

## Protocol rules

1. **Version check:** Nodes reject signals where `version != 1`.
2. **Signature check:** `verify()` must pass before processing any signal.
3. **Burn requirement:** Signals with non-empty `payload` and no `burn_proof` are rejected by compliant nodes. `requires_burn()` returns `true` for these.
4. **Nonce monotonicity:** Nodes SHOULD track the last seen nonce per sender and reject signals where `nonce ≤ last_seen`. This prevents replay.
5. **Capability announcement:** Cells MAY send capability-only signals (empty payload, no burn proof) to announce what services they provide. These are free.

---

## Integration with ce-mesh

`ce-mesh` subscribes to the `ce-protocol-1` gossipsub topic in `Mesh::run`. Inbound:

1. Decode message bytes as `CellSignal`; drop on decode error.
2. Call `signal.verify()`; drop on bad signature or wrong version.
3. Emit `MeshEvent::CellSignal(signal)` to the node.

Outbound: `MeshHandle::broadcast_signal(&signal)` serializes (bincode) and publishes to the topic.

Chain-side validation (burn-proof tx lookup, amount match) happens in `ce-node`'s
mesh event loop before the signal is exposed via `GET /signals`.

---

## CEP-1 version history

| Version | Status | Notes |
|---|---|---|
| 1 | Current | Initial wire format |
