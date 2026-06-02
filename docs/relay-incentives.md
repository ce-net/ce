# Relay incentives — design

**Status: economic substrate done (v0); libp2p enforcement is the follow-on.** A relay forwards
circuit traffic for NAT'd peers and should be paid for it, so a permissionless mesh can have many
relays instead of one altruistic project-run node.

## Why this is the hard one (and how we sidestep it)

Paying relays normally needs **metering or proof-of-relay**, both nasty: a relay can claim bytes it
didn't forward, and endpoints can collude to mint fake relay receipts. Tor never solved it.

We sidestep proof-of-relay with an incentive realignment: **the relay's customer is the NAT'd node
that needs reachability, and that node pays to keep itself reachable.** You're buying *your own*
connectivity, so you pay voluntarily; the relay simply stops forwarding if you stop paying. Loss is
bounded to one billing interval — the same pay-as-you-go / trust-gradient pattern as data serving.
No minting, no collusion surface.

## It's just another metered service

A relay is paid exactly like a data provider (data-layer Stage 3): over a **payment channel**, with
signed receipts. There is **no new chain type** — relay payment rides `ChannelOpen`/`ChannelClose`
and the existing `ChunkReceipt` / `channel_receipt_bytes`. The relay is the channel `host`, the
client the `payer`. And everything is **mesh-routed** — receipts travel over `/ce/rpc/1`, never
direct HTTP to the relay's `ip:port`.

- **Advertise (discovery):** a node started with `--relay-price-per-min <p>` advertises the `relay`
  service via the DHT (the discovery primitive), so clients `find_service("relay")` to locate
  relays. `p = 0` is a free, discoverable relay.
- **Pay:** `RpcRequest::RelayReceipt { channel_id, cumulative, payer_sig }` over the mesh. The
  client node signs `channel_receipt_bytes(channel_id, relay, cumulative)` and sends it; `POST
  /relay/pay { relay, channel_id, cumulative }` / `ce-rs` `pay_relay` drive it.
- **Verify + account:** `relay_authorize` (pure, unit-tested with real signatures) checks the
  receipt's signature, that the relay is the channel host, capacity, and that `cumulative` covers
  `price_per_min × minutes_elapsed`. A per-channel `RelayMeter` tracks the high-water mark; the
  relay closes the channel (`ChannelClose`) to collect.

## The honest boundary

libp2p circuit-relay v2 grants reservations from its own config limits and exposes **no payment
hook** — there's no clean callback to accept/drop a reservation based on external (paid/unpaid)
state. So v0 ships the **economic substrate + the paid/unpaid decision** (the relay knows, per
channel, whether a client is paid-up). Wiring that decision into the relay behaviour to actually
drop unpaid circuits is the integration follow-on — likely a thin custom wrapper over
`relay::Behaviour`, or a libp2p version exposing a reservation gate. Until then a relay can run
priced + accounted, and apps can pay; enforcement is advisory.

## v0 scope & refinements

- **Done:** priced `relay` advertisement, mesh-routed `RelayReceipt`, channel-backed verification +
  per-channel accounting, `relay_authorize` (pure), `ce relay`-less but `ce-rs` `pay_relay` + `ce
  start --relay-price-per-min`.
- **Refinements:** drop unpaid circuits at the libp2p layer (the boundary above); a relay-side
  auto-close/expiry sweep; per-byte (not just per-minute) metering; client auto-pay loop (open
  channel on first use, keep receipts flowing); reachability-gated advertisement (only advertise
  `relay` when AutoNAT says we're publicly reachable).

## CE vs app

CE provides the mechanism: a discoverable priced relay, channel-backed receipts, and verification.
Which relays to use, when to open channels, and the pay cadence are app/client policy.
