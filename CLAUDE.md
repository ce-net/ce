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

Rust workspace: Byzantine-fault-tolerant compute marketplace on a PoW blockchain.

**Crates:** `ce-identity` / `ce-chain` / `ce-mesh` / `ce-container` / `ce-node` / `ce-protocol` / `ce-deploy`

**Credit model:** Mine blocks → earn credits. Run jobs → spend credits (payer debited, host credited). No credits → 402.

**Consensus:** honest-majority PoW. Difficulty self-adjusts every 2016 blocks targeting 10 min/block.

**Key constraints:**
- `Mesh` (`Swarm` inside) is `!Sync` → event handlers are free fns (not async methods)
- `[u8; 64]` sigs use local `sig_serde` module — serde only handles arrays ≤ 32
- Mining runs in `spawn_blocking` — never block the async executor
- Docker metering is optional (silently disabled if socket is missing)

**Gossipsub topics:** `ce-transactions`, `ce-blocks`, `ce-heights`, `ce-syncreq`, `ce-syncresp`, `ce-protocol-1` (planned)

**Data dir:** `~/.local/share/ce/` → `identity/node.key` (chmod 600) + `chain/chain.json`

**E2E tests:** `cargo test -p ce-deploy -- --ignored` (needs HETZNER_API_TOKEN, CE_SSH_KEY_NAME, CE_SSH_KEY_PATH) 