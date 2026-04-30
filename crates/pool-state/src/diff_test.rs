//! End-state model-vs-chain reconciliation (Tier 3.1).
//!
//! After [`compute_loss_with_trace`](crate::compute_loss_with_trace) emits an
//! [`AmmReplayTrace`], `reserves_post_back` records the pool reserves our
//! replay believes the backrun left behind. This module compares those
//! reserves against the *actual* post-backrun vault balances — taken straight
//! from the backrun tx's `post_token_balances` — and quantifies the gap in
//! basis points. A small gap is the strongest single piece of evidence that
//! every step of the replay (frontrun, victim, backrun) lined up with chain
//! reality, which is what `victim_loss` and `attacker_profit_real` rely on.

/// Maximum side-wise relative gap between predicted and observed reserves
/// before [`Signal::ReservesMatchPostState`](swap_events::types::Signal)
/// flips from Informational to Fail. Calibrated to tolerate routing /
/// multi-hop CPIs that touch the vault outside the recognised swap, while
/// still flagging meaningful model bugs. 100 bps matches the threshold the
/// per-step `InvariantResidual` uses, keeping the two replay-fidelity signals
/// on the same scale.
pub const PASS_THRESHOLD_BPS: u32 = 100;

/// Larger of the two side-wise relative divergences between predicted and
/// observed `(base, quote)` reserves, in basis points. Reports the max
/// rather than the mean so a model bug on one side can't hide behind an
/// accurate other side.
///
/// `observed == 0` on a side is treated specially: if we also predicted
/// zero the side is a perfect match, otherwise the result saturates to
/// `u32::MAX` so the consumer can't accidentally read a huge gap as small.
pub fn reserves_divergence_bps(predicted: (u64, u64), observed: (u64, u64)) -> u32 {
    let base = side_divergence_bps(predicted.0, observed.0);
    let quote = side_divergence_bps(predicted.1, observed.1);
    base.max(quote)
}

fn side_divergence_bps(predicted: u64, observed: u64) -> u32 {
    if observed == 0 {
        return if predicted == 0 { 0 } else { u32::MAX };
    }
    let delta = (predicted as i128 - observed as i128).unsigned_abs();
    let scaled = delta.saturating_mul(10_000) / observed as u128;
    scaled.min(u32::MAX as u128) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_when_predicted_matches_observed() {
        assert_eq!(reserves_divergence_bps((1_000, 2_000), (1_000, 2_000)), 0);
        assert_eq!(reserves_divergence_bps((0, 0), (0, 0)), 0);
    }

    #[test]
    fn five_percent_off_returns_500_bps() {
        // Predicted 5% higher than observed on the base side; quote matches.
        assert_eq!(reserves_divergence_bps((1_050, 2_000), (1_000, 2_000)), 500);
        // Predicted 5% lower — same magnitude.
        assert_eq!(reserves_divergence_bps((950, 2_000), (1_000, 2_000)), 500);
    }

    #[test]
    fn returns_max_of_the_two_sides() {
        // Base off by 100 bps, quote off by 250 bps. Max wins.
        let pred = (1_010, 2_050);
        let obs = (1_000, 2_000);
        assert_eq!(reserves_divergence_bps(pred, obs), 250);
    }

    #[test]
    fn saturates_when_observed_zero_and_predicted_nonzero() {
        assert_eq!(reserves_divergence_bps((1, 0), (0, 0)), u32::MAX);
        assert_eq!(reserves_divergence_bps((0, 1), (0, 0)), u32::MAX);
    }

    #[test]
    fn no_overflow_on_max_reserves() {
        // u64::MAX vs (u64::MAX - 1) — single-unit gap on a colossal pool
        // should round to 0 bps without overflowing the i128 / u128 path.
        let huge = u64::MAX;
        assert_eq!(reserves_divergence_bps((huge, huge), (huge - 1, huge)), 0);
    }

    #[test]
    fn pass_threshold_is_within_signed_i32_range() {
        // Sanity: the const fits comfortably in i32 too, in case a downstream
        // consumer does signed math on the bps value.
        assert!(PASS_THRESHOLD_BPS < i32::MAX as u32);
    }
}
