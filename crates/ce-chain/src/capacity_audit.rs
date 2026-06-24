//! Phase 6 (P6) — capacity audits: continuous, unpredictable, all-capacity, job-bound.
//!
//! Governs: design `2(c)` "Capacity audit (catches V3)" + `6` Phase 6. Closes V3 (fake capacity)
//! as a DETERRENT (heuristic, never proof — `5` problem 7). Replaces the defeatable periodic
//! benchmark (red-team H7/H16) with inline-probe + parallel-full-capacity + job-session-bound
//! challenges. A miss is provable by on-chain ABSENCE of a `ChallengeResponse` => self-healing
//! `FaultFee = 1/32 bond` (NOT confiscation — flaky-hardware safety valve), and disappearance must
//! be confirmed across >=3 independent relays over a multi-epoch window before any forfeiture
//! (design `2(d)` H18 — this depends on Phase 5 net hardening shipping with/before this).
//!
//! Wires the `CapacityAd`, `ChallengeResponse`, and `SlashCapacityChallenge` TxKinds (see lib.rs).
//! Pure chain-side validation + the FaultFee accounting; the actual benchmark *execution* + probe
//! issuance is a node/mesh driver (ce-node, ce-mesh placement_beacon), not consensus.
//!
//! ## The three failure modes this defeats (design `2(c)`), and HOW
//!
//! - **Rent-burst** (advertise 100xH100, rent one only for a predictable benchmark window): defeated
//!   by [`host_is_challenged`] — challenge times are derived from the P7 *placement beacon*, so they
//!   are UNPREDICTABLE (a rent-burster cannot rent-just-in-time for a beacon-random instant), and by
//!   binding probes to in-flight jobs ([`validate_inline_probe`]) so silicon must stay attached
//!   continuously — which is just owning it.
//! - **Proxy / relay** (one fast box answers for N advertised Sybils): defeated by session-binding
//!   ([`response_binding`]) — the response must commit to the SAME execution context (container /
//!   session key) as the host's paid jobs, so an outsourced answer for a different session is
//!   rejected ([`validate_challenge_response`] replay/outsourcing check); and by demanding N parallel
//!   beacon-seeded benchmarks sized to the FULL advertised `C` ([`parallel_challenge_count`]) so one
//!   rented GPU cannot answer 100 parallel full-capacity benchmarks inside the deadline.
//! - **Honest-only-during-audits** (pass audits, junk on real jobs): defeated by the cheap inline
//!   throughput probe run on EVERY job's first seconds, byte-identical to audits
//!   ([`validate_inline_probe`]) — a mismatch is slashable on the spot, not a post-hoc signal.
//!
//! ## Integer-only, deterministic, consensus-reachable
//! Everything here is `u128`/`u64`, saturating, no floats, no iteration-order dependence — the
//! `append()` `SlashCapacityChallenge`/`ChallengeResponse` arms call into it, so it must never panic.
//! Probabilities/tolerances are integer basis points against [`BPS_DENOM`] (`10_000 == 100%`), the
//! same convention as `bond_gate` and the chain's settlement burn.

use ce_identity::NodeId;

/// Basis-point denominator (`10_000 bps == 100%`), matching `bond_gate::PDETECT_BPS_DENOM` and the
/// chain's `BPS_DENOM`. Local copy so this module is self-contained and consensus-pure.
pub const BPS_DENOM: u128 = 10_000;

/// FaultFee denominator: a missed capacity challenge costs `1/FAULT_FEE_DIVISOR` of the bond,
/// self-healing (design `2(d)` slash class 2; Filecoin 3.51-day fault-fee shape). Slash class 2 is
/// deliberately MILD (recover and stop paying), unlike `SlashEquivocation`'s 100% burn — a missed
/// challenge can be an honest flaky-hardware/eclipse event, so it must never confiscate the bond.
pub const FAULT_FEE_DIVISOR: u128 = 32;

/// Share of a charged FaultFee paid to the reporter who submitted the provable miss, in basis points;
/// the remainder is BURNED. Design `2(c)(5)`/`2(d)` H10: the reporter cut must be SMALL (burn >= 90%)
/// so a cluster cannot slash its own H1 and route the fee to its own auditor H2 at a net profit —
/// "no in-cluster slash recycling". Set to 1000 bps (10%) — the design's ceiling — strictly below the
/// chain's legacy `SLASH_REPORTER_BPS = 2500` for equivocation. With FaultFee already only `bond/32`,
/// the reporter nets at most `bond/320`, far below any value a fake-capacity host could steal.
pub const CAPACITY_REPORTER_BPS: u128 = 1_000;

/// Number of independent relays across which a host must be confirmed unreachable before a missed
/// challenge becomes a chargeable fault (design `2(c)`/`2(d)` H18 eclipse safety valve). A censored
/// (eclipsed) host looks identical to a faulty one, so a single missed challenge is NEVER chargeable —
/// only multi-relay, multi-epoch disappearance is. The relay-reachability evidence is produced by the
/// Phase 5 net-hardening layer ([`crate`] does not observe the network); P6 only *validates* that the
/// evidence meets this bar via [`disappearance_confirmed`].
pub const MIN_DISTINCT_RELAYS_FOR_FAULT: u32 = 3;

/// Minimum number of distinct consensus epochs the unreachability must span before forfeiture
/// (design `2(d)` "multi-epoch window"). One bad epoch is noise; sustained absence across several is
/// signal. Conservative default; calibrate on live data (design `5` problem 9).
pub const UNREACHABILITY_EPOCHS: u64 = 3;

/// Deadline, in blocks after the challenge-issuing block, by which a `ChallengeResponse` must be
/// confirmed on-chain. Past this, the challenge is provably missed (ABSENCE is the proof). Short
/// enough that a rent-burster cannot spin up real silicon on demand, long enough to tolerate normal
/// gossip/mining latency. Conservative default; calibrate.
pub const CHALLENGE_RESPONSE_DEADLINE_BLOCKS: u64 = 6;

/// Maximum advertised-capacity growth per epoch, in basis points of the previous claim
/// (design `2(c)`: "Cap advertised `C` growth rate" + "vest bond with sustained delivered
/// throughput"). A host cannot 100x its advertised capacity in one epoch; it must grow it gradually
/// and back each step with bond + delivered throughput. `5000 bps == +50%/epoch`. Conservative.
pub const MAX_CAPACITY_GROWTH_BPS: u128 = 5_000;

/// Tolerance band, in basis points, for the inline delivered-throughput probe: a measured throughput
/// below `claimed * (1 - PROBE_TOLERANCE_BPS/BPS_DENOM)` is a slashable mismatch (design `2(c)`:
/// "cheap inline probe on EVERY job's first seconds (slash on mismatch)"). The band absorbs honest
/// measurement jitter (thermal, scheduling) without licensing a meaningful capacity lie. `2000 bps`
/// (delivering < 80% of claimed throughput is a fault). Conservative; calibrate.
pub const PROBE_TOLERANCE_BPS: u128 = 2_000;

/// The FaultFee charged for a single provable missed capacity challenge: `bond / FAULT_FEE_DIVISOR`.
/// Integer floor division; self-healing (recover and stop paying), NOT confiscation. A bond below the
/// divisor rounds to a zero fee (harmless — such a host has no role under the P4 bond gate anyway).
pub fn fault_fee(active_bond: u128) -> u128 {
    active_bond / FAULT_FEE_DIVISOR
}

/// How a charged FaultFee is split (design `2(c)(5)`/`2(d)` H10): a SMALL reporter reward and a
/// DOMINANT burn (>= 90%). Never routed to a counterparty/other host (which would incentivise
/// fraudulent disputes) — exactly the chain's existing slash-routing discipline, with a lower
/// reporter share for this self-healing class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultFeeRouting {
    /// Credits paid to the reporter who submitted the provable miss.
    pub reporter_reward: u128,
    /// Credits destroyed (burned). `reporter_reward + burned == fee`.
    pub burned: u128,
}

/// Split a charged `fee` into the reporter reward and the burned remainder per [`CAPACITY_REPORTER_BPS`].
/// `reporter_reward = floor(fee * CAPACITY_REPORTER_BPS / BPS_DENOM)`, `burned = fee - reporter_reward`,
/// so the two always sum exactly to `fee` (no base unit created or lost). Floor on the reward keeps the
/// burn the dominant party even on rounding (design intent: burn >= 90%).
pub fn route_fault_fee(fee: u128) -> FaultFeeRouting {
    let reporter_reward = fee.saturating_mul(CAPACITY_REPORTER_BPS) / BPS_DENOM;
    let burned = fee.saturating_sub(reporter_reward);
    FaultFeeRouting { reporter_reward, burned }
}

/// A capacity advertisement's on-chain payload (the `CapacityAd` TxKind body, mirrored here for
/// validation helpers — kept field-identical to `lib.rs` `TxKind::CapacityAd`). The host claims
/// `capacity_units` for `epoch` and signs it; two conflicting ads for one epoch are slashable via
/// `SlashEquivocation` over the `ce-capacity-ad` domain (the chain's existing equivocation primitive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityClaim {
    pub host: NodeId,
    pub capacity_units: u64,
    pub epoch: u64,
}

/// Whether a new capacity claim's growth over the host's previous claim is within
/// [`MAX_CAPACITY_GROWTH_BPS`] (design `2(c)` growth-rate cap). `previous_capacity == 0` (a host's
/// first ad) is unconstrained by growth (the bond gate still sizes it). Integer, cross-multiplied to
/// avoid float/division-bias: `new <= prev + prev * MAX_GROWTH_BPS / BPS_DENOM`, computed as
/// `new * BPS_DENOM <= prev * (BPS_DENOM + MAX_GROWTH_BPS)` with saturation.
pub fn capacity_growth_ok(previous_capacity: u64, new_capacity: u64) -> bool {
    if previous_capacity == 0 {
        return true; // first ad: growth-cap N/A (bond gate sizes it); shrinking is always fine.
    }
    if new_capacity <= previous_capacity {
        return true; // never penalise shrinking advertised capacity.
    }
    let lhs = (new_capacity as u128).saturating_mul(BPS_DENOM);
    let rhs = (previous_capacity as u128).saturating_mul(BPS_DENOM.saturating_add(MAX_CAPACITY_GROWTH_BPS));
    lhs <= rhs
}

/// Validate a `CapacityAd` (design `2(c)` + P4 bond gate). An ad is admissible iff the host already
/// holds `active_bond >= bond_gate::required_bond(capacity_units)` (the V3 cost floor — faking 100x
/// capacity costs ~100x bond) AND the claim's per-epoch growth is within the cap. Origin == host is
/// checked by the caller (`append()` arm) since it is an envelope property. Pure, deterministic.
pub fn validate_capacity_ad(claim: &CapacityClaim, active_bond: u128, previous_capacity: u64) -> bool {
    crate::bond_gate::bond_gates_role(active_bond, claim.capacity_units)
        && capacity_growth_ok(previous_capacity, claim.capacity_units)
}

/// The placement-beacon-derived challenge nonce for a `(host, epoch)` pair (design `2(c)` anti-
/// collusion (1): challenge selection MUST use the VDF-delayed, windowed, producer-unbiasable
/// PLACEMENT BEACON of P7 — NOT the raw `/beacon` tip, which the about-to-be-audited slot leader can
/// withhold/re-roll). `placement_seed` is that beacon's output for the epoch (a `[u8; 32]`), supplied
/// by `ce-mesh::placement_beacon` (P7); P6 does not — and must not — produce it. The nonce binds the
/// challenge to the specific host + epoch + beacon so it cannot be precomputed or transplanted.
///
/// Deterministic domain-separated hash, integer-only. Every honest node derives the same nonce from
/// the same beacon, so "did this host owe a response this epoch?" is an objective, non-grindable fact.
pub fn challenge_nonce(placement_seed: &[u8; 32], host: &NodeId, epoch: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ce-capacity-challenge\0");
    h.update(placement_seed);
    h.update(host);
    h.update(epoch.to_le_bytes());
    h.finalize().into()
}

/// Whether `host` is selected for a capacity challenge in this epoch, given the P7 placement-beacon
/// seed and the audit sampling rate `challenge_rate_bps` (design `2(c)`: continuous, UNPREDICTABLE
/// challenges; the rate is the audit dial `p = ν(1−t)` set by the scheduler from the host's tier). The
/// selection is a beacon-keyed threshold on [`challenge_nonce`], so the host CANNOT predict whether
/// (or when) it will be challenged — defeating rent-burst's "rent silicon only for the known window".
///
/// `selected iff (first 8 bytes of nonce as u64) < challenge_rate_bps * (u64::MAX / BPS_DENOM)`.
/// `challenge_rate_bps == 0` never selects; `>= BPS_DENOM` always selects. Integer, deterministic.
pub fn host_is_challenged(placement_seed: &[u8; 32], host: &NodeId, epoch: u64, challenge_rate_bps: u128) -> bool {
    if challenge_rate_bps == 0 {
        return false;
    }
    if challenge_rate_bps >= BPS_DENOM {
        return true;
    }
    let nonce = challenge_nonce(placement_seed, host, epoch);
    let draw = u64::from_le_bytes([
        nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
    ]);
    // threshold = challenge_rate_bps / BPS_DENOM of the u64 space, integer-only (no float).
    let threshold = (u64::MAX as u128).saturating_mul(challenge_rate_bps) / BPS_DENOM;
    (draw as u128) < threshold
}

/// How many parallel full-capacity benchmarks a host advertising `capacity_units` must answer within
/// the deadline (design `2(c)` proxy fix: "demand N independent beacon-seeded benchmarks IN PARALLEL
/// sized to the FULL advertised `C`" — one rented GPU cannot answer 100 parallel full-capacity
/// benchmarks). One benchmark instance per unit of advertised capacity (each sized to saturate one
/// unit), so a host claiming `C` units must run `C` of them at once. Saturates at `u64::MAX`.
pub fn parallel_challenge_count(capacity_units: u64) -> u64 {
    capacity_units.max(1)
}

/// The session-binding a `ChallengeResponse` must commit to (design `2(c)` proxy fix: "bind the
/// challenge to the SAME execution context as paid jobs — same container / attestation / session
/// key"). A valid response hashes the beacon challenge nonce TOGETHER WITH the host's live job-session
/// key, so the box that answers must be the box holding the host's paid-job session — an outsourced
/// answer computed by a different proxy box (different session key) produces a different binding and is
/// rejected by [`validate_challenge_response`]. `session_key` is the per-session secret-derived public
/// commitment the job manager (ce-node) already tracks; P6 only checks the binding.
///
/// Deterministic, domain-separated, integer-only.
pub fn response_binding(challenge_nonce: &[u8; 32], session_key: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ce-capacity-response\0");
    h.update(challenge_nonce);
    h.update(session_key);
    h.finalize().into()
}

/// Validate a `ChallengeResponse` (design `2(c)`): it (a) answers an OUTSTANDING beacon-seeded
/// challenge the host actually owed this epoch, (b) is confirmed within
/// [`CHALLENGE_RESPONSE_DEADLINE_BLOCKS`] of the issuing block, and (c) is bound to the host's job
/// SESSION (not a transplantable/replayable answer). Returns whether the response clears the challenge.
///
/// - `was_challenged`: did [`host_is_challenged`] hold for this host+epoch under the P7 beacon? (A
///   response to a non-existent challenge is meaningless and rejected — closes "spam responses to look
///   alive without ever being audited".)
/// - `expected_binding`: [`response_binding`] over this epoch's [`challenge_nonce`] and the host's
///   live session key, recomputed by the verifier; `submitted_response` MUST equal it (the
///   replay/outsourcing check — a response for a different session/epoch/beacon won't match).
/// - `challenge_block` / `response_block`: the deadline window check.
///
/// Pure, deterministic. The driver (ce-node) supplies `was_challenged`/`expected_binding` from beacon
/// + session state; P6 enforces the relation.
pub fn validate_challenge_response(
    was_challenged: bool,
    expected_binding: &[u8; 32],
    submitted_response: &[u8; 32],
    challenge_block: u64,
    response_block: u64,
) -> bool {
    if !was_challenged {
        return false; // no outstanding challenge => nothing to answer.
    }
    if response_block < challenge_block {
        return false; // a response cannot precede its challenge.
    }
    if response_block.saturating_sub(challenge_block) > CHALLENGE_RESPONSE_DEADLINE_BLOCKS {
        return false; // past the deadline: this is a (late) miss, not a clear.
    }
    // Session-bound, beacon-bound equality: rejects replayed/outsourced/transplanted answers.
    submitted_response == expected_binding
}

/// Validate the cheap inline delivered-throughput probe run on every job's first seconds (design
/// `2(c)` honest-only-during-audits fix). Returns whether the measured throughput clears the
/// tolerance band: `measured >= claimed * (1 - PROBE_TOLERANCE_BPS/BPS_DENOM)`. A result below the
/// band is a slashable capacity mismatch (the host advertised more than it delivers). Integer,
/// cross-multiplied: `measured * BPS_DENOM >= claimed * (BPS_DENOM - PROBE_TOLERANCE_BPS)`.
///
/// `claimed_throughput == 0` trivially passes (nothing claimed, nothing to fail).
pub fn inline_probe_ok(claimed_throughput: u128, measured_throughput: u128) -> bool {
    if claimed_throughput == 0 {
        return true;
    }
    let need = claimed_throughput.saturating_mul(BPS_DENOM.saturating_sub(PROBE_TOLERANCE_BPS));
    let have = measured_throughput.saturating_mul(BPS_DENOM);
    have >= need
}

/// Network-layer evidence that a host has disappeared (design `2(c)`/`2(d)` H18). Produced by the
/// Phase 5 net-hardening layer (`ce-mesh::net_hardening`), which observes relay reachability — the
/// CHAIN cannot observe the network, so disappearance is asserted via this evidence and only ever
/// turned into a chargeable fault by [`disappearance_confirmed`]. This keeps slashing-by-absence
/// eclipse-safe: a censored host (reachable via some relays but eclipsed from others) does NOT meet
/// the bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisappearanceEvidence {
    /// Distinct independent relays that confirmed the host unreachable.
    pub distinct_relays_unreachable: u32,
    /// Number of consensus epochs the unreachability has spanned.
    pub epochs_spanned: u64,
}

/// Whether disappearance evidence clears the eclipse safety valve (design `2(c)`/`2(d)` H18): the host
/// must be unreachable across `>= MIN_DISTINCT_RELAYS_FOR_FAULT` independent relays for
/// `>= UNREACHABILITY_EPOCHS` epochs. Below either bar, the miss is treated as possible
/// censorship/eclipse and is NOT chargeable. This is load-bearing on the Phase-5-with/before-Phase-6
/// ordering (the contract's flagged dependency).
pub fn disappearance_confirmed(ev: &DisappearanceEvidence) -> bool {
    ev.distinct_relays_unreachable >= MIN_DISTINCT_RELAYS_FOR_FAULT
        && ev.epochs_spanned >= UNREACHABILITY_EPOCHS
}

/// Validate a `SlashCapacityChallenge` and size the FaultFee (design `2(c)`/`2(d)` slash class 2 — the
/// consensus-critical accounting the `append()` arm calls). A provable missed challenge charges
/// `fault_fee(bond) = bond/32`, self-healing, NOT confiscation, and ONLY when:
///
///  1. the host actually owed a response this epoch (`was_challenged` under the P7 beacon),
///  2. NO valid `ChallengeResponse` was confirmed within the deadline (`response_present == false` —
///     the on-chain ABSENCE that is the proof), and
///  3. disappearance is confirmed across `>= 3` relays over a multi-epoch window (eclipse safety
///     valve, [`disappearance_confirmed`]).
///
/// Returns `Some(fault_fee)` when all hold (and the fee is non-zero), else `None` (inadmissible:
/// host responded, was never challenged, or disappearance not yet confirmed — the append() arm then
/// rejects the slash tx so it cannot grief a flaky/eclipsed honest host). Pure, deterministic, never
/// panics. Idempotency (one fee per `(offender, epoch)`) is enforced in the `append()` arm with the
/// chain's existing in-block/confirmed slash-set pattern, exactly like `SlashEquivocation`.
pub fn validate_capacity_slash(
    _offender: &NodeId,
    active_bond: u128,
    was_challenged: bool,
    response_present: bool,
    disappearance: &DisappearanceEvidence,
) -> Option<u128> {
    if active_bond == 0 {
        return None; // nothing to slash (and no role under the bond gate).
    }
    if !was_challenged {
        return None; // no outstanding challenge => no miss to prove.
    }
    if response_present {
        return None; // the host answered: not a miss.
    }
    if !disappearance_confirmed(disappearance) {
        return None; // could be eclipse/censorship — not yet chargeable (H18).
    }
    let fee = fault_fee(active_bond);
    if fee == 0 {
        return None; // sub-divisor bond: no chargeable fee, avoid a no-op slash tx.
    }
    Some(fee)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bond_gate::{required_bond, PER_UNIT_BOND};

    const C: u128 = PER_UNIT_BOND; // one credit, for readability.
    const HOST: NodeId = [7u8; 32];

    // ---- FaultFee: 1/32 of bond, self-healing not confiscation ----

    #[test]
    fn fault_fee_is_one_thirtysecond() {
        assert_eq!(fault_fee(32_000), 1_000);
        assert_eq!(fault_fee(31), 0); // floor division: sub-divisor bonds round to 0.
        assert_eq!(fault_fee(32 * C), C);
    }

    #[test]
    fn fault_fee_never_confiscates_the_bond() {
        // The whole point of slash class 2: a miss costs a small fraction, never the bond.
        let bond = 1_000 * C;
        let fee = fault_fee(bond);
        assert!(fee < bond / 10, "fault fee must be a small fraction, not confiscation");
        assert_eq!(fee, bond / 32);
    }

    // ---- FaultFee routing: small reporter cut, dominant burn (>= 90%, H10) ----

    #[test]
    fn fault_fee_routing_burns_at_least_ninety_percent() {
        let fee = 1_000_000u128;
        let r = route_fault_fee(fee);
        assert_eq!(r.reporter_reward + r.burned, fee, "no base unit created or lost");
        assert_eq!(r.reporter_reward, 100_000); // 10%.
        assert_eq!(r.burned, 900_000); // 90%.
        // Burn dominates: an in-cluster slash-and-self-audit loses >= 90% of the fee (H10).
        assert!(r.burned >= fee * 9 / 10);
    }

    #[test]
    fn fault_fee_routing_tiny_fee_burns_everything() {
        // A fee smaller than BPS_DENOM/CAPACITY_REPORTER_BPS rounds the reporter reward to 0 — all
        // burned. The burn is always the dominant (here, sole) party.
        let r = route_fault_fee(9);
        assert_eq!(r.reporter_reward, 0);
        assert_eq!(r.burned, 9);
    }

    // ---- CapacityAd: bond gate + growth-rate cap ----

    #[test]
    fn capacity_ad_requires_proportional_bond() {
        let claim = CapacityClaim { host: HOST, capacity_units: 5_000, epoch: 1 };
        // First ad (no previous), bond exactly sized: admissible.
        assert!(validate_capacity_ad(&claim, required_bond(5_000), 0));
        // One base unit short of the required bond: rejected (V3 cost floor).
        assert!(!validate_capacity_ad(&claim, required_bond(5_000) - 1, 0));
        // Zero bond: rejected.
        assert!(!validate_capacity_ad(&claim, 0, 0));
    }

    #[test]
    fn capacity_growth_is_rate_capped() {
        // +50%/epoch is the cap. From 1000 units: 1500 is OK, 1501 is not.
        assert!(capacity_growth_ok(1_000, 1_500));
        assert!(!capacity_growth_ok(1_000, 1_501));
        // First ad and shrinking are always fine.
        assert!(capacity_growth_ok(0, 1_000_000));
        assert!(capacity_growth_ok(1_000, 1_000));
        assert!(capacity_growth_ok(1_000, 500));
    }

    #[test]
    fn rent_burst_cannot_100x_capacity_in_one_epoch() {
        // The headline V3 move (advertise 100x) is blocked by the growth cap even with the bond: a
        // host that bonded for 100x cannot JUMP its advertised C 100x in one epoch.
        let claim = CapacityClaim { host: HOST, capacity_units: 100_000, epoch: 2 };
        // Even with bond for 100k units, growth from 1k -> 100k (100x) exceeds the +50% cap.
        assert!(!validate_capacity_ad(&claim, required_bond(100_000), 1_000));
    }

    // ---- Beacon-seeded challenge selection: unpredictable, beacon-bound (not raw /beacon) ----

    #[test]
    fn challenge_selection_is_deterministic_per_beacon() {
        let seed = [9u8; 32];
        // Same (seed, host, epoch) => same decision on every honest node.
        let a = host_is_challenged(&seed, &HOST, 5, 5_000);
        let b = host_is_challenged(&seed, &HOST, 5, 5_000);
        assert_eq!(a, b);
        // Different beacon seed => generally different challenge nonce (anti-grind: the host can't
        // pin the outcome to a value it can withhold/re-roll).
        assert_ne!(challenge_nonce(&[1u8; 32], &HOST, 5), challenge_nonce(&[2u8; 32], &HOST, 5));
    }

    #[test]
    fn challenge_rate_zero_and_full() {
        let seed = [3u8; 32];
        // rate 0 => never challenged; rate >= 100% => always challenged.
        assert!(!host_is_challenged(&seed, &HOST, 1, 0));
        assert!(host_is_challenged(&seed, &HOST, 1, BPS_DENOM));
        assert!(host_is_challenged(&seed, &HOST, 1, BPS_DENOM + 5_000));
    }

    #[test]
    fn challenge_rate_selects_roughly_proportional_fraction() {
        // Over many epochs at a 50% rate, ~half are selected — the sampling dial works. Integer,
        // deterministic, but well-spread across the beacon-keyed nonce. Loose bound (this is a hash
        // distribution sanity check, not a statistical test).
        let seed = [42u8; 32];
        let n = 2_000u64;
        let selected = (0..n).filter(|e| host_is_challenged(&seed, &HOST, *e, 5_000)).count() as u64;
        assert!(selected > n * 35 / 100 && selected < n * 65 / 100, "got {selected}/{n} at 50% rate");
    }

    // ---- Parallel full-capacity sizing (proxy defeat) ----

    #[test]
    fn parallel_challenge_count_scales_with_capacity() {
        // One rented GPU cannot answer 100 parallel full-capacity benchmarks: claiming 100 units
        // demands 100 parallel benchmarks.
        assert_eq!(parallel_challenge_count(100), 100);
        assert_eq!(parallel_challenge_count(1), 1);
        assert_eq!(parallel_challenge_count(0), 1); // at least one.
    }

    // ---- ChallengeResponse: session-bound, deadline-bound, replay-rejecting ----

    fn binding_for(seed: &[u8; 32], host: &NodeId, epoch: u64, session: &[u8; 32]) -> [u8; 32] {
        response_binding(&challenge_nonce(seed, host, epoch), session)
    }

    #[test]
    fn valid_response_clears_the_challenge() {
        let seed = [11u8; 32];
        let session = [22u8; 32];
        let expected = binding_for(&seed, &HOST, 7, &session);
        // Within deadline, correctly session-bound: clears.
        assert!(validate_challenge_response(true, &expected, &expected, 100, 103));
        // Exactly at the deadline boundary still clears.
        assert!(validate_challenge_response(
            true,
            &expected,
            &expected,
            100,
            100 + CHALLENGE_RESPONSE_DEADLINE_BLOCKS
        ));
    }

    #[test]
    fn outsourced_or_replayed_response_is_rejected() {
        let seed = [11u8; 32];
        let session = [22u8; 32];
        let expected = binding_for(&seed, &HOST, 7, &session);

        // A proxy box answering with a DIFFERENT session key produces a different binding: rejected.
        let proxy_session = [99u8; 32];
        let outsourced = binding_for(&seed, &HOST, 7, &proxy_session);
        assert!(!validate_challenge_response(true, &expected, &outsourced, 100, 101));

        // A response REPLAYED from a different epoch (different beacon nonce) is rejected.
        let other_epoch = binding_for(&seed, &HOST, 8, &session);
        assert!(!validate_challenge_response(true, &expected, &other_epoch, 100, 101));

        // A response to a challenge the host never owed is rejected.
        assert!(!validate_challenge_response(false, &expected, &expected, 100, 101));
    }

    #[test]
    fn late_or_pre_dated_response_is_rejected() {
        let seed = [11u8; 32];
        let session = [22u8; 32];
        let expected = binding_for(&seed, &HOST, 7, &session);
        // Past the deadline: a (late) miss, not a clear.
        assert!(!validate_challenge_response(
            true,
            &expected,
            &expected,
            100,
            100 + CHALLENGE_RESPONSE_DEADLINE_BLOCKS + 1
        ));
        // Response before its challenge: rejected.
        assert!(!validate_challenge_response(true, &expected, &expected, 100, 99));
    }

    // ---- Inline throughput probe (honest-only-during-audits defeat) ----

    #[test]
    fn inline_probe_slashes_under_delivery() {
        // Claimed 1000 units/s, tolerance 20% => need >= 800 measured.
        assert!(inline_probe_ok(1_000, 1_000)); // full delivery.
        assert!(inline_probe_ok(1_000, 800)); // exactly at the band edge.
        assert!(!inline_probe_ok(1_000, 799)); // below band: slashable mismatch.
        assert!(!inline_probe_ok(1_000, 100)); // gross under-delivery (advertised 10x reality).
        assert!(inline_probe_ok(0, 0)); // nothing claimed, nothing to fail.
    }

    // ---- Disappearance: eclipse-safe (>= 3 relays, multi-epoch) ----

    #[test]
    fn disappearance_needs_three_relays_and_multi_epoch() {
        // Full bar: chargeable.
        assert!(disappearance_confirmed(&DisappearanceEvidence {
            distinct_relays_unreachable: 3,
            epochs_spanned: 3
        }));
        // Too few relays (looks like eclipse): not chargeable.
        assert!(!disappearance_confirmed(&DisappearanceEvidence {
            distinct_relays_unreachable: 2,
            epochs_spanned: 10
        }));
        // Too few epochs (single bad window): not chargeable.
        assert!(!disappearance_confirmed(&DisappearanceEvidence {
            distinct_relays_unreachable: 9,
            epochs_spanned: 1
        }));
    }

    // ---- validate_capacity_slash: the consensus-critical FaultFee accounting ----

    fn confirmed_disappearance() -> DisappearanceEvidence {
        DisappearanceEvidence { distinct_relays_unreachable: 3, epochs_spanned: 3 }
    }

    #[test]
    fn fake_capacity_node_failing_a_full_capacity_challenge_is_slashable() {
        // THE headline P6 test: a fake-capacity host was beacon-challenged, returned NO response
        // within the deadline (on-chain absence), and is confirmed gone across >= 3 relays =>
        // slashable for FaultFee = bond/32.
        let bond = 320 * C;
        let fee = validate_capacity_slash(&HOST, bond, true, false, &confirmed_disappearance());
        assert_eq!(fee, Some(bond / 32));
        assert_eq!(fee, Some(10 * C));
    }

    #[test]
    fn host_that_responded_is_not_slashable() {
        // response_present == true: the challenge was cleared, no fault.
        let bond = 320 * C;
        assert_eq!(
            validate_capacity_slash(&HOST, bond, true, true, &confirmed_disappearance()),
            None
        );
    }

    #[test]
    fn never_challenged_host_is_not_slashable() {
        // No outstanding challenge this epoch => no miss to prove (can't grief an un-audited host).
        let bond = 320 * C;
        assert_eq!(
            validate_capacity_slash(&HOST, bond, false, false, &confirmed_disappearance()),
            None
        );
    }

    #[test]
    fn eclipsed_host_is_not_slashable_until_disappearance_confirmed() {
        // A missed challenge with only 1 relay reporting unreachable looks like eclipse/censorship:
        // NOT chargeable (H18 safety valve). This protects an honest-but-eclipsed host.
        let bond = 320 * C;
        let eclipse = DisappearanceEvidence { distinct_relays_unreachable: 1, epochs_spanned: 5 };
        assert_eq!(validate_capacity_slash(&HOST, bond, true, false, &eclipse), None);
    }

    #[test]
    fn unbonded_host_has_nothing_to_slash() {
        assert_eq!(
            validate_capacity_slash(&HOST, 0, true, false, &confirmed_disappearance()),
            None
        );
    }

    #[test]
    fn sub_divisor_bond_yields_no_chargeable_fee() {
        // A bond below the divisor rounds the fee to 0; validate returns None so no no-op slash tx
        // can be confirmed (and such a host has no role under the P4 bond gate anyway).
        assert_eq!(
            validate_capacity_slash(&HOST, 16, true, false, &confirmed_disappearance()),
            None
        );
    }
}
