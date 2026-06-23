//! Vivaldi network coordinates — predicted RTT between any two nodes without an O(n^2) probe
//! matrix. Each node holds one low-dimensional coordinate, nudged toward its measured RTTs; the
//! predicted RTT between two nodes is the distance between their coordinates. Pure and
//! transport-free (see `docs/compute-fabric.md` §2.2). The node updates the local coordinate from
//! measured ping RTTs and carries it in the atlas so the `ce-graph` SDK can assemble global topology.
//!
//! Algorithm: Dabek et al., "Vivaldi: A Decentralized Network Coordinate System" (SIGCOMM 2004),
//! with the additive *height* term modelling per-node last-mile access latency. The update follows
//! the well-tested HashiCorp Serf formulation.

use serde::{Deserialize, Serialize};

/// Euclidean dimensionality of the coordinate space. Three dimensions plus a height term predict
/// internet RTT well in practice without overfitting.
const DIMS: usize = 3;

/// Fraction of the corrective force applied to the coordinate per sample (Vivaldi `c_c`).
const C_C: f64 = 0.25;
/// Fraction by which a sample adjusts the local error estimate (Vivaldi `c_e`).
const C_E: f64 = 0.25;
/// Height is a latency and can never be negative.
const MIN_HEIGHT: f64 = 0.0;
/// Below this magnitude two coordinates are treated as coincident.
const ZERO_THRESHOLD: f64 = 1.0e-9;

/// A point in the coordinate space: a Euclidean vector plus a non-negative height. The height models
/// the access-link latency added on every connection to or from this node, regardless of direction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Coordinate {
    pub vec: [f64; DIMS],
    pub height: f64,
}

impl Default for Coordinate {
    fn default() -> Self {
        Self::origin()
    }
}

impl Coordinate {
    /// The origin coordinate (vector at 0, zero height) — a node that has made no observations.
    pub fn origin() -> Self {
        Coordinate { vec: [0.0; DIMS], height: MIN_HEIGHT }
    }

    /// Predicted RTT (ms) to `other`: Euclidean distance between the vectors plus both heights.
    pub fn distance(&self, other: &Coordinate) -> f64 {
        self.planar_distance(other) + self.height + other.height
    }

    /// Euclidean magnitude of `self.vec - other.vec` (excludes the height terms).
    fn planar_distance(&self, other: &Coordinate) -> f64 {
        let mut sum = 0.0;
        for i in 0..DIMS {
            let d = self.vec[i] - other.vec[i];
            sum += d * d;
        }
        sum.sqrt()
    }

    /// True if all components are finite (a malformed peer coordinate must never poison the model).
    pub fn is_valid(&self) -> bool {
        self.height.is_finite() && self.vec.iter().all(|c| c.is_finite())
    }
}

/// The local node's Vivaldi state: its coordinate and a running estimate of how wrong that
/// coordinate currently is (0 = perfect, 1 = no confidence). Feed it measured RTTs via
/// [`Model::observe`] and read predictions with [`Model::predict_rtt`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Model {
    coord: Coordinate,
    error: f64,
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl Model {
    /// A fresh model at the origin with full uncertainty.
    pub fn new() -> Self {
        Model { coord: Coordinate::origin(), error: 1.0 }
    }

    /// This node's current coordinate (publish it in the atlas).
    pub fn coordinate(&self) -> &Coordinate {
        &self.coord
    }

    /// The current local error estimate, in [0, 1].
    pub fn error(&self) -> f64 {
        self.error
    }

    /// Predicted RTT (ms) from this node to a peer with coordinate `remote`.
    pub fn predict_rtt(&self, remote: &Coordinate) -> f64 {
        self.coord.distance(remote)
    }

    /// Fold one measured RTT sample to a peer (with the peer's coordinate and error) into the local
    /// coordinate. Ignores non-positive or non-finite RTTs and invalid remote coordinates, so a
    /// hostile or buggy peer cannot corrupt the model.
    pub fn observe(&mut self, rtt_ms: f64, remote: &Coordinate, remote_error: f64) {
        if !rtt_ms.is_finite() || rtt_ms <= 0.0 || !remote.is_valid() {
            return;
        }
        let remote_error = if remote_error.is_finite() { remote_error.clamp(0.0, 1.0) } else { 1.0 };

        let dist = self.coord.distance(remote);
        let wrongness = (dist - rtt_ms).abs() / rtt_ms;

        // Confidence weighting: samples from lower-error peers move us more.
        let total = self.error + remote_error;
        let weight = if total > 0.0 { self.error / total } else { 0.5 };

        // Exponentially-weighted update of the local error estimate.
        self.error = (C_E * weight * wrongness + self.error * (1.0 - C_E * weight)).clamp(0.0, 1.0);

        // Move `force` of the way toward the correct distance, away from the peer.
        let force = C_C * weight * (rtt_ms - dist);
        self.coord = apply_force(&self.coord, force, remote);
    }
}

/// Move `c` a distance of `force` along the unit vector pointing from `other` toward `c` (away from
/// `other` when `force` is positive), updating the height proportionally. Mirrors Serf's `applyForce`.
fn apply_force(c: &Coordinate, force: f64, other: &Coordinate) -> Coordinate {
    let (unit, mag) = unit_vector_at(&c.vec, &other.vec);
    let mut vec = c.vec;
    for i in 0..DIMS {
        vec[i] += unit[i] * force;
    }
    let mut height = c.height;
    if mag > ZERO_THRESHOLD {
        height = ((c.height + other.height) * force / mag + c.height).max(MIN_HEIGHT);
    }
    Coordinate { vec, height }
}

/// Unit vector pointing from `b` to `a`, with its pre-normalisation magnitude. When `a` and `b`
/// coincide, returns a deterministic axis so repeated samples can still separate the two points.
fn unit_vector_at(a: &[f64; DIMS], b: &[f64; DIMS]) -> ([f64; DIMS], f64) {
    let mut dir = [0.0; DIMS];
    let mut mag = 0.0;
    for i in 0..DIMS {
        dir[i] = a[i] - b[i];
        mag += dir[i] * dir[i];
    }
    mag = mag.sqrt();
    if mag > ZERO_THRESHOLD {
        for d in dir.iter_mut() {
            *d /= mag;
        }
        (dir, mag)
    } else {
        let mut fallback = [0.0; DIMS];
        fallback[0] = 1.0;
        (fallback, 0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_is_symmetric_and_includes_height() {
        let a = Coordinate { vec: [1.0, 0.0, 0.0], height: 2.0 };
        let b = Coordinate { vec: [4.0, 0.0, 0.0], height: 3.0 };
        // planar 3.0 + heights 2.0 + 3.0 = 8.0
        assert!((a.distance(&b) - 8.0).abs() < 1e-9);
        assert!((a.distance(&b) - b.distance(&a)).abs() < 1e-9);
    }

    #[test]
    fn converges_toward_a_fixed_anchor() {
        // Peer B is a perfectly-confident anchor at the origin; the true RTT to it is 80ms.
        let anchor = Coordinate::origin();
        let mut a = Model::new();
        for _ in 0..2000 {
            a.observe(80.0, &anchor, 0.0);
        }
        let predicted = a.predict_rtt(&anchor);
        assert!((predicted - 80.0).abs() < 5.0, "predicted {predicted} not near 80");
        assert!(a.error() < 0.1, "error {} should shrink with consistent samples", a.error());
    }

    #[test]
    fn height_never_goes_negative() {
        let anchor = Coordinate::origin();
        let mut a = Model::new();
        for _ in 0..500 {
            a.observe(5.0, &anchor, 0.0);
            assert!(a.coordinate().height >= 0.0);
        }
    }

    #[test]
    fn three_nodes_recover_pairwise_rtts() {
        // A valid metric triangle (triangle inequality holds): AB=40, AC=50, BC=30.
        let (ab, ac, bc) = (40.0, 50.0, 30.0);
        let mut a = Model::new();
        let mut b = Model::new();
        let mut c = Model::new();
        for _ in 0..4000 {
            let (ca, cb, cc) = (a.coordinate().clone(), b.coordinate().clone(), c.coordinate().clone());
            let (ea, eb, ec) = (a.error(), b.error(), c.error());
            a.observe(ab, &cb, eb);
            a.observe(ac, &cc, ec);
            b.observe(ab, &ca, ea);
            b.observe(bc, &cc, ec);
            c.observe(ac, &ca, ea);
            c.observe(bc, &cb, eb);
        }
        let pab = a.predict_rtt(b.coordinate());
        let pac = a.predict_rtt(c.coordinate());
        let pbc = b.predict_rtt(c.coordinate());
        // Vivaldi is approximate; require each prediction within 25% of truth.
        assert!((pab - ab).abs() / ab < 0.25, "AB predicted {pab}");
        assert!((pac - ac).abs() / ac < 0.25, "AC predicted {pac}");
        assert!((pbc - bc).abs() / bc < 0.25, "BC predicted {pbc}");
    }

    #[test]
    fn rejects_bad_samples() {
        let mut a = Model::new();
        let before = a.coordinate().clone();
        a.observe(-1.0, &Coordinate::origin(), 0.0);
        a.observe(f64::NAN, &Coordinate::origin(), 0.0);
        a.observe(10.0, &Coordinate { vec: [f64::INFINITY, 0.0, 0.0], height: 0.0 }, 0.0);
        assert_eq!(&before, a.coordinate(), "bad samples must not move the coordinate");
    }
}
