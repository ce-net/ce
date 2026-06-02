# App messaging — design

**Status: Stage 1 (directed messages) done.** The keystone primitive for building control
systems on CE: an app can send a **signed, directed message to a specific node** over the
relay-traversed mesh, and receive messages addressed to it. Control is "send a command to node X,
get telemetry back" — without an app-facing message primitive, every app has to smuggle its
protocol through CEP-1 broadcast or fork the node.

Stage 1 ✅: `RpcRequest::AppMessage { from_node, topic, payload }` → `AppAck` over `/ce/rpc/1`
(the receiving node verifies `from_node` against the Noise PeerId, then enqueues + fans out);
`POST /mesh/send`, `GET /mesh/messages` (snapshot ring), `GET /mesh/messages/stream` (SSE, mirrors
`/signals/stream`); `ce-rs` `send_message` / `messages` + an `AppMessage` type. Authentication is
CE (the sender NodeId is verified); authorization is the app (it inspects `from`). Tested across
two in-process nodes (`app_message_delivered_across_mesh`). Next: Stage 2 app pub/sub, Stage 3 a
sync request/response helper.

## What CE already has (and the gap)

- **Broadcast:** CEP-1 cell signals (`POST /signals/send`) — signed, gossiped, burn-gated. App-usable, but *broadcast* and shaped for capability/signal semantics.
- **Directed transport:** `/ce/rpc/1` request-response (relay-routed, Noise-authenticated) — but it carries only **CE-internal** RPCs (`Exec`, `Deploy`, `FetchChunk`, …). Apps can't put their own messages on it.

The gap is **directed app-to-app messaging**. This adds it as a thin, app-namespaced layer over the
exact `/ce/rpc/1` plumbing that already carries `FetchChunk`.

## Model

- A message is `{ from, topic, payload }`: `from` is the sender NodeId (Noise-authenticated — the
  node verifies `from` owns the connecting PeerId, so the receiver can *trust who sent it*),
  `topic` is an app-chosen string namespace, `payload` is opaque bytes (CE never parses it).
- **Delivery, not RPC.** Sending returns an ack that the receiving node *enqueued* the message;
  request/response is an app convention (include a reply topic, send a message back). This is the
  simplest primitive that composes — like NATS/libp2p, one-way messaging with RPC layered on top.
- **Authentication is CE; authorization is the app.** CE guarantees `from` is genuine; *who may
  command what* is app policy — the app inspects `from` and decides. (Mechanism, not policy.)

## Wire + API

- `RpcRequest::AppMessage { from_node, topic, payload }` → `RpcResponse::AppAck` on `/ce/rpc/1`.
  The receiving node verifies `from_node` against the Noise PeerId, then enqueues + fans out.
- `POST /mesh/send { to, topic, payload_hex }` — send to a node.
- `GET /mesh/messages` — snapshot of the recent inbox ring (best-effort, capped).
- `GET /mesh/messages/stream` — SSE push of every incoming message (the reliable path; mirrors
  `/signals/stream`).
- `ce-rs`: `send_message(to, topic, &[u8])`, `messages()` (snapshot).

Inbox is a bounded ring + a broadcast channel, exactly like the CEP-1 signal ring — apps consume
the SSE stream to avoid missing messages; the snapshot is for polling/debugging.

## Staged plan

- **Stage 1 — directed messages (this).** `AppMessage` RPC, inbox ring + SSE, `/mesh/send` +
  `/mesh/messages[/stream]`, `ce-rs` send/receive. Authenticated, relay-routed, app-namespaced.
- **Stage 2 — app pub/sub.** App-defined gossip topics (publish/subscribe), distinct from CEP-1;
  for telemetry fan-out and discovery beacons.
- **Stage 3 — sync request/response helper.** A node-side convenience that correlates a reply to a
  request across the inbox (true RPC), so apps don't hand-roll reply matching.

## CE vs app

CE provides authenticated, relay-routed delivery + a namespaced inbox. Apps own the message
schema, the authorization policy (which `from` may do what), retries, and any request/response or
state-machine semantics on top. No app logic runs in the node — messages surface to the app via
the HTTP API, exactly as signals do.
