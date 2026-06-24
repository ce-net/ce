//! Phase 5 (P5) — libp2p network hardening.
//!
//! Governs: design §3 net row + §6 Phase 5 + sybil-resistance.md §4.3. Closes V8 (eclipse /
//! routing / beacon-grind) and the N1/N4/N5/N8 / D2/D5 network findings. MUST ship WITH or BEFORE
//! Phase 8 (held_escrow), because forfeit-on-disappearance depends on >=3-relay multi-epoch
//! unreachability confirmation being real (design §2(d)/§2(c) H18).
//!
//! Scope (all in ce-mesh, no consensus change):
//!  - gossipsub P4 (invalid-message) then P5 (application) peer scoring; slashed/revoked peers
//!    driven below the graylist threshold so they are dropped from the mesh — design §2(e).
//!  - per-/24 (IPv4) and per-/48 (IPv6) IP-diversity caps on the DHT / peer table to bound an
//!    eclipse attacker's share of a victim's peer set (the go-ipfs 0.7 pregenerated-PeerID fix).
//!  - >=3 independent relays / multiple bootstrap domains so a host reachable only via one relay is
//!    a structural BRIDGE (feeds MeritRank connectivity-decay, design §2(e)).
//!  - relay-reachability evidence the chain's disappearance detection reads (held_escrow H18).
//!
//! The pure logic here (subnet bucketing, relay-quorum gating, app-score mapping) is unit-tested
//! without a live swarm — the `Mesh` builder simply applies the configs these free functions
//! produce. `Mesh` is `!Sync` (the libp2p `Swarm` is inside it), so everything in this module is a
//! free function operating on plain values, never a method holding the swarm across an await
//! (CLAUDE.md key constraint).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use libp2p::gossipsub::{PeerScoreParams, PeerScoreThresholds};

// ---------------------------------------------------------------------------
// Constants (sybil-resistance.md §4.3, CE-tuned small-mesh values)
// ---------------------------------------------------------------------------

/// Gossipsub peer-score floor a slashed/revoked peer is driven to (design §2(e)): strictly below
/// the graylist threshold (`GRAYLIST_THRESHOLD = -400`) so the peer is graylisted — ignored
/// mesh-wide without a hard disconnect.
///
/// NOTE on the design doc: sybil-resistance.md §4.3 step 3 says "drive slashed/revoked peers to
/// `-300`", but step 2 sets `graylist = -400`. `-300 > -400`, so the step-3 figure (written before
/// the step-2 thresholds were fixed) would NOT graylist. We implement the *intent* ("instantly
/// below graylist") and set the floor to `-500`, comfortably under `-400`. This is the secure
/// variant, not the naive literal.
pub const SLASHED_PEER_SCORE: f64 = -500.0;

/// `app_specific_weight` (P5). 1.0 so application scores map 1:1 into peer score (the bridge that
/// imports economic Sybil resistance into the transport layer — §4.3 step 3).
pub const APP_SPECIFIC_WEIGHT: f64 = 1.0;

/// Application score assigned to a slashed/revoked peer so that
/// `app_score * APP_SPECIFIC_WEIGHT == SLASHED_PEER_SCORE`.
pub const SLASHED_APP_SCORE: f64 = SLASHED_PEER_SCORE / APP_SPECIFIC_WEIGHT;

/// Maximum peers admitted from a single /24 IPv4 block (and /48 IPv6 block) **table-wide**, to
/// bound an eclipse attacker's share of a victim's peer set. On a small mesh, >2 peers per /24 is
/// presumptively one operator's Sybils (sybil-resistance.md §4.3 step 5: "~3 per /24 table-wide";
/// we take the tighter value 2 to match the P6 colocation threshold).
pub const MAX_PEERS_PER_24: usize = 2;

/// Maximum peers per /24 (or /48) admitted into a **single Kademlia k-bucket** (go-ipfs 0.7 fix:
/// "max 1 peer per /24 per k-bucket"). Stricter than the table-wide cap because a single bucket is
/// the unit an Erebus router tries to monopolize.
pub const MAX_PEERS_PER_24_PER_BUCKET: usize = 1;

/// P6 IP-colocation threshold (sybil-resistance.md §4.3 step 2): not Ethereum's 10 — on a small
/// mesh >2 peers per /24 is presumptively one operator's Sybils.
pub const IP_COLOCATION_THRESHOLD: f64 = 2.0;

/// P6 IP-colocation weight (negative; penalty grows as the square over the threshold).
pub const IP_COLOCATION_WEIGHT: f64 = -35.0;

/// P4 invalid-message-delivery weight (negative). A few provably-invalid messages (bad PoW / bad
/// Ed25519 sig / malformed bincode) drive a peer below graylist.
pub const INVALID_MESSAGE_WEIGHT: f64 = -100.0;

/// P7 behaviour-pattern penalty weight (re-graft before backoff, ignored IWANT, etc.).
pub const BEHAVIOUR_PENALTY_WEIGHT: f64 = -15.0;
/// P7 behaviour-penalty threshold below which the counter contributes 0.
pub const BEHAVIOUR_PENALTY_THRESHOLD: f64 = 6.0;

/// Decay interval for parameter counters (§4.3 step 2).
pub const DECAY_INTERVAL: Duration = Duration::from_secs(12);

/// Aggregate positive-topic score cap (§4.3 step 2).
pub const TOPIC_SCORE_CAP: f64 = 100.0;

// Score thresholds (§4.3 step 2). gossip < publish < graylist, all negative.
/// Below this, the peer is not used for gossip emission/promotion.
pub const GOSSIP_THRESHOLD: f64 = -100.0;
/// Below this, we will not publish messages to (or accept PX from) the peer.
pub const PUBLISH_THRESHOLD: f64 = -200.0;
/// Below this, the peer is graylisted: its RPCs are ignored mesh-wide.
pub const GRAYLIST_THRESHOLD: f64 = -400.0;

/// Minimum number of INDEPENDENT relays a node should maintain reservations with, so no single
/// relay can censor it and disappearance can be confirmed across a quorum (design §2(d) H18,
/// sybil-resistance.md §4.3 step 7).
pub const MIN_INDEPENDENT_RELAYS: usize = 3;

/// Multi-epoch window over which a peer must be unreachable across `MIN_INDEPENDENT_RELAYS` before
/// its disappearance is reported as confirmed to the chain (design §2(c)/§2(d) H18). One epoch is a
/// `Heartbeat` interval (30s); we require unreachability sustained over a multi-epoch span so a
/// transient censorship/eclipse blip is never mistaken for a graceful/abrupt exit. Set to 30 min
/// (60 epochs) — far longer than any single missed challenge, mirroring the self-healing FaultFee.
pub const UNREACHABILITY_WINDOW: Duration = Duration::from_secs(30 * 60);

/// IPv4 diversity-bucket prefix length (/24).
const V4_PREFIX_BITS: u32 = 24;
/// IPv6 diversity-bucket prefix length (/48 — the smallest allocation handed to an end site, so it
/// is the IPv6 analogue of a /24 for diversity purposes).
const V6_PREFIX_BITS: u32 = 48;

// ---------------------------------------------------------------------------
// Gossipsub peer scoring (P4 + P5)
// ---------------------------------------------------------------------------

/// Build the gossipsub peer-scoring parameters (P4 invalid-message + P5 application weights) and
/// the matching thresholds the `Mesh` builder applies via `with_peer_score`.
///
/// Decisions baked in (sybil-resistance.md §4.3):
///  - P4 invalid-message weight `-100`, P6 IP-colocation `-35` @ threshold 2, P7 behaviour `-15`.
///  - P3/P3b mesh-delivery scoring ships OFF (`weight = 0`, set per-topic by the caller) until the
///    mesh is warm (>=8 stable peers/topic) — statistical scoring on a cold mesh penalizes honest
///    peers for the network's own quietness and causes partition.
///  - `app_specific_weight = 1.0` so on-chain bond/reputation maps straight into the peer score and
///    slashed/revoked peers can be driven to `SLASHED_PEER_SCORE` via `set_application_score`.
///  - thresholds: gossip `-100`, publish `-200`, graylist `-400`.
///
/// `whitelisted_ips` are capability-rooted own-peers (e.g. Leif's laptop + desktop behind the same
/// home NAT) and the relay IPs that colocation must NOT penalize — relayed `/p2p-circuit` peers all
/// present the relay's IP, so colocation there is meaningless (the §4.3 "Critical pitfall"). The
/// caller is also responsible for skipping colocation scoring on `/p2p-circuit` addresses entirely.
pub fn peer_score_config(whitelisted_ips: impl IntoIterator<Item = IpAddr>) -> (PeerScoreParams, PeerScoreThresholds) {
    let params = PeerScoreParams {
        // Per-topic params are added by the caller (it owns the TopicHash values). Mesh-delivery
        // (P3/P3b) weights stay 0 until the mesh is warm.
        topics: HashMap::new(),
        topic_score_cap: TOPIC_SCORE_CAP,
        app_specific_weight: APP_SPECIFIC_WEIGHT,
        ip_colocation_factor_weight: IP_COLOCATION_WEIGHT,
        ip_colocation_factor_threshold: IP_COLOCATION_THRESHOLD,
        ip_colocation_factor_whitelist: whitelisted_ips.into_iter().collect::<HashSet<IpAddr>>(),
        behaviour_penalty_weight: BEHAVIOUR_PENALTY_WEIGHT,
        behaviour_penalty_threshold: BEHAVIOUR_PENALTY_THRESHOLD,
        behaviour_penalty_decay: 0.5,
        decay_interval: DECAY_INTERVAL,
        decay_to_zero: 0.01,
        retain_score: Duration::from_secs(3600),
    };

    let thresholds = PeerScoreThresholds {
        gossip_threshold: GOSSIP_THRESHOLD,
        publish_threshold: PUBLISH_THRESHOLD,
        graylist_threshold: GRAYLIST_THRESHOLD,
        // Only accept peer-exchange (PX) from peers above the publish threshold (well-behaved).
        accept_px_threshold: 0.0,
        // Opportunistic grafting kicks in only for clearly positive-scoring peers.
        opportunistic_graft_threshold: 5.0,
    };

    (params, thresholds)
}

/// Map a peer's on-chain economic standing to a gossipsub P5 application score
/// (`set_application_score`). This is the bridge that imports economic Sybil resistance into the
/// transport layer (§4.3 step 3): minting N PeerIds is free, but earning a positive P5 score
/// requires N real bonds + verified histories.
///
///  - `slashed_or_revoked` peers are driven to `SLASHED_APP_SCORE` (below graylist) regardless of
///    any other standing — a slash dominates.
///  - otherwise the score is `bond_term + reputation_term`, capped at `+TOPIC_SCORE_CAP` so a
///    whale cannot buy unbounded mesh influence, and floored at 0 for an unbonded-but-clean peer
///    (no positive reward, but not penalized at the app layer — P4/P6/P7 still apply).
///
/// `bond_units` and `reputation_points` are caller-supplied non-negative integers (base-unit bond
/// scaled to a small score, and `/history` reputation). Kept as `u32` so the mapping is
/// deterministic and overflow-free; the cap makes the exact scaling non-load-bearing.
pub fn application_score(slashed_or_revoked: bool, bond_units: u32, reputation_points: u32) -> f64 {
    if slashed_or_revoked {
        return SLASHED_APP_SCORE;
    }
    // Each bond unit and reputation point is worth 1 score point; capped.
    let raw = (bond_units as u64).saturating_add(reputation_points as u64);
    (raw.min(TOPIC_SCORE_CAP as u64)) as f64
}

// ---------------------------------------------------------------------------
// IP diversity caps (/24 IPv4, /48 IPv6)
// ---------------------------------------------------------------------------

/// Diversity bucket key for an IP: the /24 (IPv4) or /48 (IPv6) the address falls in, returned as a
/// `u128` for cheap hashing/equality. IPv4 buckets are tagged in the high bits so a v4 /24 and a v6
/// /48 never collide.
pub fn diversity_bucket(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from_be_bytes(v4.octets());
            let masked = bits & (u32::MAX << (32 - V4_PREFIX_BITS));
            // Tag with the v4 marker in bit 64 so it cannot alias a v6 /48 prefix.
            (1u128 << 64) | (masked as u128)
        }
        IpAddr::V6(v6) => {
            let bits = u128::from_be_bytes(v6.octets());
            bits & (u128::MAX << (128 - V6_PREFIX_BITS))
        }
    }
}

/// Whether admitting one more peer in `bucket` would stay within the table-wide cap
/// `MAX_PEERS_PER_24`, given how many peers are already counted per bucket.
///
/// NOTE: the contract's original stub took a bare `current_same_24: usize`. We keep that
/// thin-predicate spelling as [`admit_within_subnet_cap`] for call sites that already track the
/// per-/24 count, and provide [`admit_into_table`] for call sites that hold the full bucket map.
pub fn admit_within_subnet_cap(current_same_24: usize) -> bool {
    current_same_24 < MAX_PEERS_PER_24
}

/// Table-wide admission: would adding `candidate_ip` exceed `MAX_PEERS_PER_24` for its /24 (or /48)
/// given the current `bucket_counts`? Whitelisted (capability-rooted own / relay) IPs always admit.
pub fn admit_into_table(
    candidate_ip: IpAddr,
    bucket_counts: &HashMap<u128, usize>,
    whitelisted: &HashSet<IpAddr>,
) -> bool {
    if whitelisted.contains(&candidate_ip) {
        return true;
    }
    let bucket = diversity_bucket(candidate_ip);
    let current = bucket_counts.get(&bucket).copied().unwrap_or(0);
    admit_within_subnet_cap(current)
}

/// Single-k-bucket admission (the go-ipfs 0.7 Kademlia fix): at most
/// `MAX_PEERS_PER_24_PER_BUCKET` peers from the same /24 (or /48) in one k-bucket. The caller passes
/// `same_bucket_in_kbucket` (how many peers already in this k-bucket share the candidate's
/// diversity bucket) and whether the candidate is a whitelisted (capability-rooted own/relay) IP,
/// which always admits.
pub fn admit_into_kbucket(same_bucket_in_kbucket: usize, candidate_whitelisted: bool) -> bool {
    candidate_whitelisted || same_bucket_in_kbucket < MAX_PEERS_PER_24_PER_BUCKET
}

// ---------------------------------------------------------------------------
// Relay quorum / bridge detection / disappearance confirmation
// ---------------------------------------------------------------------------

/// Whether the local node holds reservations with at least `MIN_INDEPENDENT_RELAYS` *independent*
/// relays. "Independent" means distinct relays in distinct diversity buckets — two relays sharing a
/// /24 do not count as independent (a single operator running three relays in one rack is one point
/// of censorship, not three). Pass each relay's reachable IP.
pub fn has_relay_quorum(relay_ips: &[IpAddr]) -> bool {
    let distinct: HashSet<u128> = relay_ips.iter().map(|ip| diversity_bucket(*ip)).collect();
    distinct.len() >= MIN_INDEPENDENT_RELAYS
}

/// Whether `peer` is a structural BRIDGE: reachable through fewer than `MIN_INDEPENDENT_RELAYS`
/// distinct relay paths (the signature of every sock-puppet farm, design §2(e) connectivity-decay).
/// A bridge is NOT slashed — it is discounted by the app-layer MeritRank scorer and feeds the
/// verify-dial. `distinct_relay_paths` is the number of *independent* relay circuits the peer is
/// reachable on (caller should already have de-duplicated by diversity bucket).
pub fn is_bridge_peer(distinct_relay_paths: usize) -> bool {
    distinct_relay_paths < MIN_INDEPENDENT_RELAYS
}

/// Whether a peer's disappearance is CONFIRMED for the chain's held-escrow / capacity-audit
/// forfeiture (design §2(d) H18). Confirmation requires BOTH:
///  - unreachability observed across at least `MIN_INDEPENDENT_RELAYS` *independent* relays (a
///    quorum — so a single eclipsing/censoring relay cannot fabricate a disappearance), AND
///  - that unreachability sustained for at least `UNREACHABILITY_WINDOW` (multi-epoch — so a
///    transient blip is never mistaken for an exit; mirrors the self-healing FaultFee).
///
/// This is deliberately conservative: it returns `false` whenever there is any doubt, because a
/// false positive forfeits an honest (merely censored/eclipsed) host's escrow. Phase 8 reads this;
/// Phase 5 must therefore ship with/before Phase 8.
pub fn disappearance_confirmed(distinct_unreachable_relays: usize, window_elapsed: Duration) -> bool {
    distinct_unreachable_relays >= MIN_INDEPENDENT_RELAYS && window_elapsed >= UNREACHABILITY_WINDOW
}

// ---------------------------------------------------------------------------
// Tests (pure logic — no live swarm needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // --- peer score config / thresholds ---

    #[test]
    fn score_thresholds_are_ordered_and_negative() {
        let (params, th) = peer_score_config(std::iter::empty());
        assert!(GOSSIP_THRESHOLD > PUBLISH_THRESHOLD);
        assert!(PUBLISH_THRESHOLD > GRAYLIST_THRESHOLD);
        assert_eq!(th.gossip_threshold, GOSSIP_THRESHOLD);
        assert_eq!(th.publish_threshold, PUBLISH_THRESHOLD);
        assert_eq!(th.graylist_threshold, GRAYLIST_THRESHOLD);
        assert_eq!(params.app_specific_weight, APP_SPECIFIC_WEIGHT);
        assert_eq!(params.ip_colocation_factor_weight, IP_COLOCATION_WEIGHT);
        assert_eq!(params.ip_colocation_factor_threshold, IP_COLOCATION_THRESHOLD);
        assert!(params.ip_colocation_factor_weight < 0.0, "P6 weight must be negative");
        assert!(params.behaviour_penalty_weight < 0.0, "P7 weight must be negative");
    }

    #[test]
    fn whitelisted_ips_flow_into_colocation_whitelist() {
        let ip = v4(10, 0, 0, 1);
        let (params, _) = peer_score_config([ip]);
        assert!(params.ip_colocation_factor_whitelist.contains(&ip));
    }

    #[test]
    fn slashed_peer_app_score_is_below_graylist() {
        let s = application_score(true, 999_999, 999_999);
        // slash dominates everything
        assert_eq!(s, SLASHED_APP_SCORE);
        // and once weighted, sits below the graylist threshold so the peer is dropped.
        let peer_score = s * APP_SPECIFIC_WEIGHT;
        assert!(peer_score <= SLASHED_PEER_SCORE);
        assert!(peer_score < GRAYLIST_THRESHOLD);
    }

    #[test]
    fn application_score_is_capped_and_floored() {
        assert_eq!(application_score(false, 0, 0), 0.0);
        // Capped at the topic score cap — no unbounded influence from a whale.
        assert_eq!(application_score(false, u32::MAX, u32::MAX), TOPIC_SCORE_CAP);
        assert_eq!(application_score(false, 10, 5), 15.0);
    }

    // --- diversity buckets ---

    #[test]
    fn same_24_collapses_to_one_bucket() {
        assert_eq!(diversity_bucket(v4(203, 0, 113, 1)), diversity_bucket(v4(203, 0, 113, 254)));
        assert_ne!(diversity_bucket(v4(203, 0, 113, 1)), diversity_bucket(v4(203, 0, 114, 1)));
    }

    #[test]
    fn v4_and_v6_buckets_never_collide() {
        let v4b = diversity_bucket(v4(0, 0, 0, 0));
        let v6b = diversity_bucket(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_ne!(v4b, v6b);
        // The v4 marker bit is set on v4 buckets and clear on v6 buckets.
        assert_ne!(v4b & (1u128 << 64), 0);
    }

    #[test]
    fn same_48_collapses_to_one_bucket() {
        let a = IpAddr::V6("2001:db8:abcd:0001::1".parse::<Ipv6Addr>().unwrap());
        let b = IpAddr::V6("2001:db8:abcd:ffff::9".parse::<Ipv6Addr>().unwrap());
        let c = IpAddr::V6("2001:db8:abce:0001::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(diversity_bucket(a), diversity_bucket(b)); // same /48
        assert_ne!(diversity_bucket(a), diversity_bucket(c)); // different /48
    }

    // --- subnet caps ---

    #[test]
    fn subnet_cap_predicate() {
        assert!(admit_within_subnet_cap(0));
        assert!(admit_within_subnet_cap(MAX_PEERS_PER_24 - 1));
        assert!(!admit_within_subnet_cap(MAX_PEERS_PER_24));
        assert!(!admit_within_subnet_cap(MAX_PEERS_PER_24 + 5));
    }

    #[test]
    fn table_admission_enforces_per_24_cap() {
        let mut counts: HashMap<u128, usize> = HashMap::new();
        let wl: HashSet<IpAddr> = HashSet::new();
        // Three Sybils in the same /24: first two admit, third is rejected.
        let ips = [v4(198, 51, 100, 1), v4(198, 51, 100, 2), v4(198, 51, 100, 3)];
        assert!(admit_into_table(ips[0], &counts, &wl));
        *counts.entry(diversity_bucket(ips[0])).or_default() += 1;
        assert!(admit_into_table(ips[1], &counts, &wl));
        *counts.entry(diversity_bucket(ips[1])).or_default() += 1;
        assert!(!admit_into_table(ips[2], &counts, &wl), "3rd peer in /24 must be rejected");
        // A peer in a different /24 still admits.
        assert!(admit_into_table(v4(198, 51, 101, 1), &counts, &wl));
    }

    #[test]
    fn whitelisted_own_peers_bypass_cap() {
        // Leif's laptop + desktop behind the same home NAT must not be capped out.
        let mut counts: HashMap<u128, usize> = HashMap::new();
        let home = v4(192, 168, 1, 50);
        let wl: HashSet<IpAddr> = [home].into_iter().collect();
        counts.insert(diversity_bucket(home), MAX_PEERS_PER_24 + 10);
        assert!(admit_into_table(home, &counts, &wl), "whitelisted IP always admits");
    }

    #[test]
    fn kbucket_admission_is_stricter() {
        // At most 1 per /24 per k-bucket.
        assert!(admit_into_kbucket(0, false));
        assert!(!admit_into_kbucket(MAX_PEERS_PER_24_PER_BUCKET, false));
        // Whitelisted bypasses.
        assert!(admit_into_kbucket(99, true));
    }

    // --- relay quorum / bridge / disappearance ---

    #[test]
    fn relay_quorum_requires_distinct_subnets() {
        // Three relays in three distinct /24s => quorum.
        let relays = [v4(1, 1, 1, 1), v4(2, 2, 2, 2), v4(3, 3, 3, 3)];
        assert!(has_relay_quorum(&relays));
        // Three "relays" all in one /24 => NOT independent, no quorum.
        let same = [v4(1, 1, 1, 1), v4(1, 1, 1, 2), v4(1, 1, 1, 3)];
        assert!(!has_relay_quorum(&same));
        // Two distinct subnets is below the minimum.
        assert!(!has_relay_quorum(&[v4(1, 1, 1, 1), v4(2, 2, 2, 2)]));
    }

    #[test]
    fn bridge_detection() {
        assert!(is_bridge_peer(0));
        assert!(is_bridge_peer(MIN_INDEPENDENT_RELAYS - 1));
        assert!(!is_bridge_peer(MIN_INDEPENDENT_RELAYS));
        assert!(!is_bridge_peer(MIN_INDEPENDENT_RELAYS + 2));
    }

    #[test]
    fn disappearance_needs_quorum_and_full_window() {
        let win = UNREACHABILITY_WINDOW;
        let short = win / 2;
        // Quorum but window not elapsed => not confirmed (eclipse/censorship safety valve).
        assert!(!disappearance_confirmed(MIN_INDEPENDENT_RELAYS, short));
        // Window elapsed but only one relay saw it => not confirmed (single relay cannot fabricate).
        assert!(!disappearance_confirmed(1, win));
        // Both conditions => confirmed.
        assert!(disappearance_confirmed(MIN_INDEPENDENT_RELAYS, win));
        assert!(disappearance_confirmed(MIN_INDEPENDENT_RELAYS + 1, win + Duration::from_secs(1)));
    }

    #[test]
    fn unreachability_window_is_multi_epoch() {
        // Must be far longer than a single 30s heartbeat epoch so one missed challenge never
        // triggers forfeiture (mirrors the self-healing FaultFee).
        assert!(UNREACHABILITY_WINDOW >= Duration::from_secs(30 * 10));
    }
}
