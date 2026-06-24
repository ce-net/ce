# AGENTS.md — branch sybil-p4-p9

Agent "aegis" is implementing CE compute-donation Sybil-security phases P4-P9 on branch
`sybil-p4-p9` (worktree `.worktrees/sybil-p4-p9`, off `main`). This is CONSENSUS-CRITICAL work.

Tracking design doc: `PLAN/compute-donation-sybil-security.md` (sections 2(a)-(f), 6 phased
rollout, 5 open problems, 7 red-team). Extends `ce/docs/sybil-resistance.md` and
`ce/docs/consensus.md`. CE-TWLE consensus phases 0-3 are already on main (VRF leader election,
slot-spacing in `append()`, `W=min(bond,earned)`, HostBond/HostUnbond, SlashEquivocation,
80% settlement burn, `/beacon`).

## Scope of this branch

- `ce-chain`: new TxKind variants + per-phase modules (bond_gate, capacity_audit, verification,
  held_escrow, lineage) wired into the apply/append dispatch.
- `ce-mesh`: network hardening (net_hardening) + placement beacon (placement_beacon).
- `ce-node`: drivers wiring the new chain/mesh primitives into the HTTP API + job manager.
- `ce-identity`: ECVRF (RFC 9381) hardening.

## Module ownership is DISJOINT (six implementers, never the same file)

See the MODULE CONTRACT in the scaffold commit / the task output. Each phase P4-P9 owns its own
file(s); the shared `ce-chain/src/lib.rs` only carries thin dispatch arms that call into the
per-phase modules, so implementers fill in their own module without colliding.

## Requests to other agents

- Please do NOT rebase or force-push this branch — multiple implementers hold local work against
  these files.
- Do NOT touch `ce/` or `ce-fabric/` working trees from this branch; this is the shared consensus
  repo, cooperate.
- Coordinate via this file before editing `ce-chain/src/lib.rs` dispatch arms (the one shared file).

## Build note

The Mac has ~2GB free disk: do NOT `cargo build` the full ce workspace locally. Use
`cargo check -p ce-chain` per crate, or rsync this worktree to `root@178.105.145.170:/opt/build/ce-sybil`
and build there (56GB free, rust installed). The integrator owns the full build.

No emojis anywhere in the repo. Author all commits as Leif Rydenfalk
<ledamecrydenfalk@gmail.com>, no co-author lines.
