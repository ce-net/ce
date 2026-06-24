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

## Status — ALL PHASES P4-P9 INTEGRATED, FULL WORKSPACE GREEN (2026-06-24)

The six disjoint phase implementations (P4 bond gate, P5 net_hardening, P6 capacity_audit,
P7 placement_beacon + verification, P8 held_escrow + ce-meritrank, P9 lineage + ECVRF) are
integrated and the WHOLE `ce` workspace builds and tests clean on the relay
(`root@178.105.145.170:/opt/build/ce-sybil`, `CARGO_TARGET_DIR=/opt/build/target-sybil`):

- `cargo build --workspace` — clean, **0 warnings**.
- `cargo test --workspace` — **all pass, 0 failed** (ce-chain 193 unit + 14 prop incl. the
  pre-existing consensus/append/economy tests, unchanged; ce-meritrank 14; ce-node 12 unit +
  adversarial/chain_actor/local_cluster integration; ce-mesh 31; ce-identity 13 + prop).
- `cargo build/test -p ce-identity --features ecvrf` — clean (real schnorrkel RFC-9381 VRF).
- `cargo build -p ce-mesh --features real-vdf` — lib compiles (real POA Wesolowski VDF). The
  optional-feature **test binary** needs the system lib `libgmp` (`-lgmp`) installed to link;
  the default build (PlaceholderVdf) needs nothing. This is an environment dep of the
  unmaintained `vdf 0.1` crate, not a code defect — `real-vdf` is OFF by default for exactly
  this reason. The default workspace (what CI/integrator build) is fully green.

Integration wiring done this pass: the five new `TxKind` variants (`CapacityAd`,
`ChallengeResponse`, `SlashCapacityChallenge`, `JobResult`, `SlashVerificationFault`) are now
handled in every `ce-node` match site (`tx_value`/`tx_burn_amount` x3 -> None;
`tx_stream_view` -> labelled, amount 0; `classify_tx` -> labelled, slash classes carry
offender/reporter direction). No consensus value/amount semantics attached to the new variants
(they move no credits directly) so chain economy math is unchanged.

CRYPTO (per task rule — never hand-rolled): both heavy primitives are a clean trait + a vetted
crate behind an OFF-by-default feature + a `#[doc(hidden)]` consensus-INSECURE placeholder for the
default build. VDF: `ce-mesh::placement_beacon::Vdf` trait, `RealVdf` (POA `vdf 0.1` Wesolowski,
feature `real-vdf`), `PlaceholderVdf` default. VRF: `ce-identity::vrf::Vrf` trait, `Ecvrf`
(schnorrkel sr25519, feature `ecvrf`), `Ed25519AsVrf` default (the currently-wired
signature-as-VRF). Both carry `needs-review (crypto)` doc markers; the integrator owns the
parameter pinning + the consensus-format migration before any swap.

REMAINING before this secures real consensus (integrator + security review):
1. Swap the additive observational hooks into live consensus (lineage `earned_work_score`,
   the per-job slice-lock admission gate, the placement-beacon seed into committee/auditor
   selection) — deliberately left un-flipped so no existing append/consensus test changed.
2. Enable `real-vdf` + `ecvrf` and migrate the on-chain `Block.vrf_proof`/beacon format
   (consensus-format change); pin VDF discriminant + `delay->difficulty` for `T_vdf >> slot`.
3. Empirical calibration (design 5.9): bond floor `T_floor`, FaultFee fraction, correlation
   window + circuit-breaker, MeritRank alpha/beta/gamma, held-escrow schedule, committee N/K,
   burn-vs-reporter split.
4. Expert security review of the committee-selection / multi-winner-forced-error / lineage and
   MeritRank circularity-break logic against the red-team findings (design 7).
5. Phase 5 network hardening must ship WITH/BEFORE Phase 8 held-escrow (disappearance-vs-eclipse).

## Status — P9 (lineage earned-accounting + ECVRF) DONE

`ce-chain/src/lineage.rs` filled (design 2(f)/2(b2)/2(d)): `LineageGraph` (bond-funding/fund-flow
graph from on-chain `Transfer` edges, deterministic K-hop BFS), `common_funding_origin`,
`distinct_origin_count` (union-find, collapses sock-puppets by ORIGIN not PeerId — H6/H14),
`lineage_earned_work_score` (drops self-dealing, collapses same-origin payers, recursive-MeritRank
weakest-hop weighting, per-origin cap). Additive observational hooks in `lib.rs`:
`Chain::lineage_graph()` + `Chain::lineage_earned_work_score(node, merit_of)` — NOT yet swapped into
the consensus `earned_work_score`/`consensus_weight` (left for the integrator to flip after review,
so no existing consensus/append test changes). `ce-identity/src/vrf.rs`: clean `Vrf` trait +
`Ed25519AsVrf` (the currently-wired 64-byte signature-as-VRF, behavior-identical to
`ce-chain::vrf_verify`) + real RFC-9381-class `Ecvrf` via the VETTED `schnorrkel` crate behind the
optional `ecvrf` feature (OFF by default — adopting it widens `Block.vrf_proof`, a consensus-format
migration the integrator owns); a `#[doc(hidden)]` consensus-INSECURE placeholder keeps the surface
compiling when the feature is off. Relay-verified: ce-chain 193+14 tests pass (incl. 12 new P9
tests), ce-identity passes in both default and `--features ecvrf`, 0 warnings.

## Build note

The Mac has ~2GB free disk: do NOT `cargo build` the full ce workspace locally. Use
`cargo check -p ce-chain` per crate, or rsync this worktree to `root@178.105.145.170:/opt/build/ce-sybil`
and build there (56GB free, rust installed). The integrator owns the full build.

No emojis anywhere in the repo. Author all commits as Leif Rydenfalk
<ledamecrydenfalk@gmail.com>, no co-author lines.
