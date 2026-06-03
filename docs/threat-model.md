# CE threat model

CE is not a currency where a break costs money — it is a **compute fabric where a break costs
control of machines**. An attacker who defeats CE doesn't get "fake credits"; they get the ability
to run code on participating devices, amplified by self-replication. Security is therefore about the
whole path **mint → pay → authorize → execute → contain**, designed fail-closed and least-privilege.

## The three paths to running an attacker's code on a victim

### Path 0 — reach the node's control API directly
**Risk:** the HTTP API exposes value-moving endpoints (`/transfer`, `/capabilities/revoke`,
`/mesh-deploy`, `/mesh-kill`, `/jobs/*`, `/channels/*`, `/tunnel`, `/signals/send`).
**Defense (implemented):**
- API binds **`127.0.0.1`** by default (`--api-bind` to override; a non-loopback bind logs a warning).
- Every **mutating (non-GET) request requires a Bearer token** (`<data_dir>/api.token`, chmod 600,
  derived from the node identity; `$CE_API_TOKEN` overrides). Read-only GETs stay open.
- On the public relay: UFW denies `:8844`; nginx proxies only `/health`, `/bootstrap`, and the
  read-only SSE streams from localhost.

### Path A — forge the economy (free credits → free compute)
**Risk:** if blocks are free to produce, an attacker mints unlimited credits and buys unlimited jobs.
**Defense (implemented):** real Nakamoto PoW —
- every block must satisfy its declared **difficulty** (`has_leading_zeros`), enforced in
  `Chain::append` (the single chokepoint `try_reorg` also routes through);
- difficulty is fixed by a deterministic **retarget** (a miner can't understate it);
- **fork choice is by cumulative work**, not block count, so the heaviest chain wins and honest
  miners converge instead of each forking their own;
- **timestamp** median-time-past + future-drift bounds resist timewarp;
- **sync-before-mine** stops a fresh node forking its own chain;
- clean-break on-disk format (version-prefixed) so incompatible chains are rejected, not misread.

Residual: absolute security scales with honest hashrate (inherent to PoW). `MIN_DIFFICULTY` is a
floor; the retarget raises the effective difficulty under real mining.

### Path B — forge or steal authority (capabilities → exec/spawn)
**Risk:** a forged/stolen capability or a too-loose `spawn` grant runs code on a host; with
self-replication, one compromise propagates down the tree.
**Defense:**
- **Capabilities** (`ce-cap`) are signed, attenuating chains rooted at an accepted key; `authorize`
  enforces subset-attenuation, expiry, audience, and root at every link. Privilege can only shrink.
- **Mesh transport** is libp2p-Noise: the sender's NodeId is authenticated end-to-end; inbound
  Deploy/Kill RPCs require a capability **and consult on-chain revocation**.
- **Revocation** is on-chain (`RevokeCapability`) + expiry; `rdev serve` now consults the node's
  `/capabilities/revoked` set (refreshed periodically) and denies revoked chains.
- **`rdev/spawn`** (the unsandboxed host-exec edge) is default-deny: it requires the `spawn`
  ability **and** a program on `$RDEV_SPAWN_ALLOW`, runs with a **scrubbed environment**, and
  confines `cwd` to the target's home.
- **`rdev/exec`** runs in a gVisor container with no network.

## Known residual risk / follow-ups
- **Signed-binary attestation** for replication is not yet enforced: a `sync` cap can overwrite an
  allow-listed binary's bytes, so a compromised seed could push a trojan over an allow-listed name.
  The spawn allowlist limits *which names* run; signing the bytes (org-root-signed sha256 verified
  before spawn) would close the overwrite path. Planned.
- **Per-request replay envelope** (signed nonce + freshness) is not yet added. Mitigated today by
  Noise sender-authentication and capability expiry; planned for defense-in-depth.
- **Privilege drop / rlimits** on spawned host processes (run as a non-root user, cap CPU/mem) —
  planned; run `rdev serve` as a non-root user meanwhile.
- No external audit / fuzzing yet; consensus security scales with participation.

## Test coverage
Adversarial unit + integration tests exist for: PoW rejection, understated-difficulty rejection,
timestamp rejection, work-based reorg, two-miner convergence, API token gating, capability
attenuation/expiry/audience/escalation, delegation rooted at an org key, and spawn allowlist/auth.
