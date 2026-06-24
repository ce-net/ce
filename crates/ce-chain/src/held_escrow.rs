//! Phase 8 (P8) — held escrow (farm-then-defect / V7 reducer) + MeritRank substrate.
//!
//! Governs: design `2(d)` "Held escrow" + `2(e)` MeritRank + `6` Phase 8. Closes V7, bounds V6.
//! PREREQUISITE: the lineage-based distinct-counterparty earned-accounting (`lineage.rs`, P9/`2(f)`)
//! must land first. PREREQUISITE: Phase 5 net hardening (`ce-mesh/net_hardening.rs`) must ship
//! WITH or BEFORE this phase, because forfeit-on-disappearance depends on >=3-relay multi-epoch
//! unreachability confirmation (H18).
//!
//! Held escrow is DETERRENT-ONLY with NO restitution anchor — compute has no persistent artifact
//! and no repair cost (`1` thesis, H13). Size it against max-gain-from-defection (the `2(a)`
//! inequality), not a repair cost. Four corrections over Storj (H13/H18):
//!  - a host may NEVER accept a job whose value exceeds its currently-forfeitable held balance +
//!    standing-bond headroom (the `2(a)` admission gate — this is what makes "wait for escrow to
//!    release then take one big job" impossible);
//!  - the release schedule depends on cumulative DISTINCT-COUNTERPARTY VERIFIED value (lineage.rs),
//!    NOT wall-clock tenure (so a farm cannot run down the clock with self-dealt work);
//!  - release LAGS the longest open audit/dispute window:
//!    `release = max(unbond_window, longest_in_flight_job_dispute_window)`;
//!  - forfeiture on disappearance fires ONLY when net_hardening reports the host unreachable across
//!    >=3 independent relays for a multi-epoch window (`ExitKind::AbruptConfirmed`) — never on a
//!    single missed challenge (H18 eclipse safety valve), and the forfeited amount is BURNED (no
//!    restitution target).
//!
//! This module owns ONLY the on-chain held-balance ledger arithmetic + the graceful-vs-abrupt-exit
//! forfeiture decision. The actual `Chain`-state wiring (a `held` map hooked into the
//! `JobSettle`/`Heartbeat` apply-arms and released/forfeited on exit) is wired in `lib.rs` against
//! these pure functions, and is INERT until `HELD_FRACTION_BPS > 0` (default 0 — no withholding, so
//! the existing consensus tests and ledger balances are byte-for-byte unchanged until the integrator
//! calibrates and turns it on, design `9` "ship with conservative defaults").
//!
//! MeritRank itself (the decayed personalized random walk) is an APP-LAYER scorer, NOT a node
//! primitive (design `2(e)`); it lives in the separate `ce-meritrank` crate, never here.
//! Integer-only, deterministic — no floats in any consensus path.

use ce_identity::NodeId;

/// Basis-point denominator shared with the rest of the chain (`10_000 bps == 100%`).
pub const BPS_DENOM: u128 = 10_000;

/// Basis points of each `UptimeReward`/`JobSettle`/`Heartbeat` net earning back-loaded into the
/// host's held balance (design `2(d)` Storj-style back-load).
///
/// **DEFAULT 0 (flag default-off).** The held-escrow ledger is a no-op until this is set, because
/// (per design `2(f)`/`6` and the P8 task note) earned-weight / held-escrow MUST NOT relax any
/// high-value verification tier until the P9 lineage distinct-counterparty accounting lands. Shipping
/// at 0 keeps every existing ledger balance and consensus test unchanged; the integrator raises it
/// (Storj uses 75% held early, tapering) once lineage + net-hardening are both live. Calibration is
/// empirical (design `9`).
pub const HELD_FRACTION_BPS: u128 = 0;

/// The portion of a single net earning that is withheld into the host's held balance.
/// Integer floor division — an earning smaller than `BPS_DENOM / HELD_FRACTION_BPS` base units
/// withholds 0 (consistent with `settlement_burn`'s rounding). Saturating, deterministic.
///
/// `net` is the POST-settlement-burn amount actually credited to the host (so held escrow is taken
/// out of what the host really earns, never out of the burn). With `HELD_FRACTION_BPS == 0` this is
/// always 0.
pub fn withheld_portion(net: u128) -> u128 {
    net.saturating_mul(HELD_FRACTION_BPS) / BPS_DENOM
}

/// The amount actually paid out to the host's free balance after the held-escrow back-load:
/// `net - withheld_portion(net)`. The withheld remainder accrues to the held balance instead.
/// With `HELD_FRACTION_BPS == 0` this is `net` unchanged (the ledger is byte-identical to today).
pub fn payout_after_hold(net: u128) -> u128 {
    net.saturating_sub(withheld_portion(net))
}

/// Block height at which a held balance may be released: lags the longest in-flight dispute window
/// (design `2(d)` correction (3)). `unbond_release` is the standing-bond release height
/// (`block_index + UNBOND_BLOCKS` set on `HostUnbond`); `longest_dispute_end` is the end height of
/// the longest open audit/dispute the host is exposed to (the latest verification/capacity-challenge
/// deadline among the host's open jobs). A defector cannot reclaim before fraud on the scam job can
/// be proven, because release is the MAX of the two.
pub fn release_height(unbond_release: u64, longest_dispute_end: u64) -> u64 {
    unbond_release.max(longest_dispute_end)
}

/// Whether a host may accept a job of `job_value`: its `forfeitable_held + bond_headroom` must
/// cover it (design `2(d)` correction (1) / the `2(a)` admission gate). This is the rule that makes
/// farm-then-defect loss-making: taking a big job REQUIRES the escrow still be held (it is part of
/// the coverage), so "wait until escrow releases, then take one big job" is impossible — once the
/// escrow releases it no longer covers a job, so no big job can be accepted against it.
///
/// `bond_headroom` is the UNLOCKED standing-bond slice headroom (`bond_gate::admit_job` owns the
/// per-job slice accounting; this gate composes ON TOP — both must pass). Saturating add so a
/// pathological overflow never silently wraps to admit.
pub fn can_accept_job(forfeitable_held: u128, bond_headroom: u128, job_value: u128) -> bool {
    forfeitable_held.saturating_add(bond_headroom) >= job_value
}

/// Outcome of a host's exit, deciding whether the held balance is released or forfeited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// Graceful exit (explicit `HostUnbond`, served out the dispute window past `release_height`):
    /// the held balance is RELEASED to the host's free balance. Nothing is forfeited.
    Graceful,
    /// Confirmed abrupt disappearance: unreachable across >=`MIN_INDEPENDENT_RELAYS` independent
    /// relays for a multi-epoch window, as reported by `net_hardening::disappearance_confirmed`
    /// (H18). The held balance is FORFEITED — burned (deterrent-only, no restitution target, design
    /// `2(d)`: compute has no repair anchor).
    AbruptConfirmed,
    /// Not yet confirmed (could be censorship / eclipse, or simply still within the dispute window):
    /// NO action — neither release nor forfeit (H18 safety valve). The conservative default.
    Unconfirmed,
}

impl ExitKind {
    /// Classify an exit from the raw evidence, keeping the eclipse safety valve front-and-centre.
    ///
    ///  - `unbonded_and_window_elapsed`: the host issued `HostUnbond` AND the current height is at or
    ///    past its `release_height` (unbond window + longest dispute window both served) — a clean,
    ///    provable graceful exit.
    ///  - `disappearance_confirmed`: `net_hardening::disappearance_confirmed(...)` returned true
    ///    (>=3 independent relays unreachable over the multi-epoch window).
    ///
    /// A graceful exit takes precedence: a host that properly unbonded and served its window is
    /// released even if it then goes offline (going offline AFTER a clean exit is not a defection).
    /// Only an UNANNOUNCED disappearance with no served window forfeits. Anything else is
    /// `Unconfirmed` (no action) — the safe default that never confiscates a merely-censored host.
    pub fn classify(unbonded_and_window_elapsed: bool, disappearance_confirmed: bool) -> ExitKind {
        if unbonded_and_window_elapsed {
            ExitKind::Graceful
        } else if disappearance_confirmed {
            ExitKind::AbruptConfirmed
        } else {
            ExitKind::Unconfirmed
        }
    }
}

/// Validate forfeiture of a host's held balance: forfeit (burn) ONLY on `ExitKind::AbruptConfirmed`,
/// never on a single missed challenge or a still-`Unconfirmed` exit (H18). Returns the amount to
/// forfeit (the WHOLE currently-held balance, deterrent-only, no restitution split) or `None` when
/// nothing is forfeited.
///
/// `held_balance == 0` yields `None` even on a confirmed abrupt exit (nothing to forfeit), so the
/// caller never emits a zero-value burn. Pure, deterministic; consensus-reachable.
pub fn validate_forfeiture(_host: &NodeId, held_balance: u128, exit: ExitKind) -> Option<u128> {
    match exit {
        ExitKind::AbruptConfirmed if held_balance > 0 => Some(held_balance),
        _ => None,
    }
}

/// The amount of a host's held balance that is RELEASED to free balance on a graceful exit at/after
/// `release_height` (design `2(d)`). Returns the whole held balance on `Graceful`, else 0 — the
/// mirror of `validate_forfeiture` (a held balance is either fully released or fully forfeited, never
/// partially, since the exit is a single classified event). Pure, deterministic.
pub fn releasable_on_exit(held_balance: u128, exit: ExitKind) -> u128 {
    match exit {
        ExitKind::Graceful => held_balance,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: NodeId = [7u8; 32];

    // ---- back-load arithmetic (design 2(d) Storj back-load) ----

    #[test]
    fn withhold_is_zero_by_default_flag_off() {
        // HELD_FRACTION_BPS defaults to 0 (flag-off until P9 lineage lands) — the ledger is a no-op
        // and payout equals net exactly, so existing consensus balances are unchanged.
        assert_eq!(HELD_FRACTION_BPS, 0, "must ship default-off until lineage (design 2f/6)");
        assert_eq!(withheld_portion(1_000_000), 0);
        assert_eq!(payout_after_hold(1_000_000), 1_000_000);
    }

    #[test]
    fn withhold_arithmetic_is_integer_floor_and_conserving() {
        // Simulate a calibrated fraction WITHOUT mutating the const: prove the bps math itself is a
        // conserving integer floor split (the property the const will satisfy once turned on).
        let net: u128 = 1_000_003;
        let frac_bps: u128 = 7_500; // 75% Storj-style early hold.
        let withheld = net.saturating_mul(frac_bps) / BPS_DENOM;
        let payout = net.saturating_sub(withheld);
        assert_eq!(withheld, 750_002); // floor
        assert_eq!(withheld + payout, net, "no credits created or destroyed by the split");
        assert!(payout >= net / 4); // host keeps at least the un-held remainder
    }

    #[test]
    fn withhold_saturates_and_never_panics() {
        // Even at the extreme, saturating math means no overflow panic in a consensus path.
        let _ = withheld_portion(u128::MAX);
        let _ = payout_after_hold(u128::MAX);
    }

    // ---- release schedule lags the longest dispute window (design 2(d) correction (3)) ----

    #[test]
    fn release_lags_longest_window() {
        // Dispute window outlasts the unbond window => release waits for the dispute window.
        assert_eq!(release_height(2016, 3000), 3000);
        // Unbond window outlasts the dispute window => release waits for the unbond window.
        assert_eq!(release_height(5000, 3000), 5000);
        // Equal => that height.
        assert_eq!(release_height(4000, 4000), 4000);
    }

    #[test]
    fn defector_cannot_reclaim_before_fraud_provable() {
        // A host with an open high-value job whose dispute window ends at 9000 cannot reclaim at the
        // bare unbond height 2016 — release is pinned to 9000 so the scam can still be proven.
        let unbond = 2016;
        let open_dispute_end = 9000;
        assert_eq!(release_height(unbond, open_dispute_end), 9000);
    }

    // ---- admission gate (design 2(d) correction (1) / 2(a)) ----

    #[test]
    fn admission_requires_coverage() {
        assert!(can_accept_job(100, 50, 150)); // exactly covered
        assert!(!can_accept_job(100, 50, 151)); // 1 over => refused
        assert!(can_accept_job(0, 0, 0)); // trivial job, no coverage needed
    }

    #[test]
    fn farm_then_defect_is_loss_making_by_construction() {
        // The whole point (V7): to take a big job you must STILL hold enough escrow to cover it.
        let big_job = 1_000_000u128;
        // Case A: escrow already released (held=0) and no bond headroom => the big job is REFUSED,
        // so "wait for release then take one big job" cannot happen.
        assert!(!can_accept_job(0, 0, big_job));
        // Case B: escrow still held and covers the job => the job CAN be taken, but then defecting
        // forfeits that very escrow (validate_forfeiture below), so the defection is loss-making.
        assert!(can_accept_job(big_job, 0, big_job));
        let forfeited = validate_forfeiture(&A, big_job, ExitKind::AbruptConfirmed);
        assert_eq!(forfeited, Some(big_job), "defecting burns the escrow that admitted the job");
    }

    #[test]
    fn admission_saturating_add_does_not_wrap_to_admit() {
        // forfeitable_held + bond_headroom must saturate (not wrap) so a crafted huge pair never
        // wraps below job_value and wrongly admits. With saturation, MAX+MAX >= any job_value.
        assert!(can_accept_job(u128::MAX, u128::MAX, u128::MAX));
        assert!(can_accept_job(u128::MAX, 1, u128::MAX));
    }

    // ---- exit classification + forfeiture conditions (design 2(d)/2(e), H18) ----

    #[test]
    fn classify_graceful_takes_precedence() {
        // A host that unbonded and served its window is Graceful even if later unreachable: going
        // offline after a clean exit is not a defection.
        assert_eq!(ExitKind::classify(true, true), ExitKind::Graceful);
        assert_eq!(ExitKind::classify(true, false), ExitKind::Graceful);
    }

    #[test]
    fn classify_abrupt_only_on_confirmed_disappearance() {
        // Unannounced + confirmed-disappeared => abrupt (forfeit).
        assert_eq!(ExitKind::classify(false, true), ExitKind::AbruptConfirmed);
    }

    #[test]
    fn classify_unconfirmed_is_the_safe_default() {
        // No clean exit AND no confirmed disappearance (e.g. a single missed challenge, or an
        // eclipse/censorship blip) => no action. This is the H18 eclipse safety valve.
        assert_eq!(ExitKind::classify(false, false), ExitKind::Unconfirmed);
    }

    #[test]
    fn forfeit_only_on_abrupt_confirmed() {
        let held = 500u128;
        assert_eq!(validate_forfeiture(&A, held, ExitKind::AbruptConfirmed), Some(500));
        // Graceful exit => released, never forfeited.
        assert_eq!(validate_forfeiture(&A, held, ExitKind::Graceful), None);
        // Unconfirmed (single missed challenge / eclipse) => NEVER forfeited (H18).
        assert_eq!(validate_forfeiture(&A, held, ExitKind::Unconfirmed), None);
    }

    #[test]
    fn forfeit_zero_balance_yields_none() {
        // Nothing to forfeit => None even on a confirmed abrupt exit (no zero-value burn emitted).
        assert_eq!(validate_forfeiture(&A, 0, ExitKind::AbruptConfirmed), None);
    }

    #[test]
    fn release_on_graceful_exit_only() {
        let held = 777u128;
        assert_eq!(releasable_on_exit(held, ExitKind::Graceful), 777);
        assert_eq!(releasable_on_exit(held, ExitKind::AbruptConfirmed), 0);
        assert_eq!(releasable_on_exit(held, ExitKind::Unconfirmed), 0);
    }

    #[test]
    fn release_and_forfeit_are_mutually_exclusive() {
        // A held balance is either fully released or fully forfeited or untouched — never both, and
        // never partially. Across every exit kind, released + forfeited <= held_balance.
        let held = 12_345u128;
        for exit in [ExitKind::Graceful, ExitKind::AbruptConfirmed, ExitKind::Unconfirmed] {
            let released = releasable_on_exit(held, exit);
            let forfeited = validate_forfeiture(&A, held, exit).unwrap_or(0);
            assert!(released == 0 || forfeited == 0, "release and forfeit cannot both fire");
            assert!(released.saturating_add(forfeited) <= held, "cannot move more than is held");
        }
    }

    #[test]
    fn single_missed_challenge_never_forfeits() {
        // Mirror of the self-healing FaultFee: one missed beacon challenge looks like censorship, so
        // it classifies Unconfirmed and forfeits nothing — only the multi-epoch >=3-relay confirmed
        // disappearance (H18) does.
        let one_missed_challenge = ExitKind::classify(false, false);
        assert_eq!(validate_forfeiture(&A, 1_000_000, one_missed_challenge), None);
    }
}
