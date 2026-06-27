read docs/standards.md when writing code
read docs/design.md when writing terminal and user facing interfaces
read README.md when you need to update / overview of what the assignment was and an overview of the project.
read docs/testing.md when you need to run and write tests.

Dont take credit for commits - give all credits to me Leif Rydenfalk - ledamecrydenfalk@gmail.com. No claude co author. Always use git properly.

Always document everything for future ai and human dev reference. But dont overdocument to save tokens.

Always pull latest before you start working so we dont get merge issues! Always commit everything and keep all docs up to date!

No emojis ever in the repo unless told so by a human. This is NOT a playground for llms this is a serious project with serious code quality requirements.

---

## CE Project Overview

Rust workspace: Byzantine-fault-tolerant compute marketplace on a VRF-leader-elected blockchain.

**Crates:** `ce-identity` / `ce-cap` / `ce-tls` / `ce-runtime` / `ce-guard` / `ce-wasm` / `ce-appmgr` / `ce-chain` / `ce-mesh` / `ce-container` / `ce-node` / `ce-protocol` / `ce-deploy` (see README.md for what each does).

**Credit model:** Produce blocks (when elected leader) → earn credits. Run jobs → spend credits (payer debited, host credited; 80% of each settlement is burned). No credits → 402.

**Consensus:** VRF leader election (CE-TWLE), not PoW. Each ~10s slot, the node with a valid VRF ticket below its weight-proportional threshold produces the block; fork choice is the heaviest-weight suffix. Consensus weight `W = min(bond, earned-work-score)`. The `difficulty`/`nonce` block fields are vestigial (kept at 0). See docs/consensus.md.

**Key constraints:**
- `Mesh` (`Swarm` inside) is `!Sync` → event handlers are free fns (not async methods)
- `[u8; 64]` sigs use local `sig_serde` module — serde only handles arrays ≤ 32
- Block production is one VRF eval + one signature — no PoW mining loop
- Docker metering is optional (silently disabled if socket is missing)

**Gossipsub topics:** `ce-transactions`, `ce-blocks`, `ce-heights`, `ce-syncreq`, `ce-syncresp`, `ce-protocol-1` (planned)

**Data dir:** `~/.local/share/ce/` → `identity/node.key` (chmod 600) + `chain/chain.json`

**E2E tests:** `cargo test -p ce-deploy -- --ignored` (needs HETZNER_API_TOKEN, CE_SSH_KEY_NAME, CE_SSH_KEY_PATH) 