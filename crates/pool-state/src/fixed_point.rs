//! Overflow-safe Q64.64 / 256-bit arithmetic helpers used by concentrated-
//! liquidity replay (Whirlpool, eventually Meteora DLMM).
//!
//! Whirlpool's swap formulas multiply quantities like `liquidity * sqrt_price`
//! where each factor can saturate u128 — the intermediate product is a u256
//! that we then divide back into u128. Standard fare for any Uniswap V3
//! port, but Rust has no native `u256`, so this module wraps
//! [`primitive_types::U256`] in a minimal API that the swap math layer can
//! depend on without leaking the U256 type around.

use primitive_types::U256;

/// Compute `floor((a * b) / denom)` with full 256-bit intermediate precision.
///
/// Returns `None` when:
///   * `denom == 0`, or
///   * the quotient overflows `u128` (i.e. `a * b / denom >= 2^128`).
///
/// Use cases (from Uniswap V3 / Whirlpool sqrt-price math):
///   * `liquidity * sqrt_price >> 64` → input/output amount conversions.
///   * `numerator * Q64 / denominator` → next sqrt_price after a swap.
///   * Any `mul_div` pattern where the intermediate doesn't fit in `u128`.
///
/// The full-precision multiply is what makes this safe even when both
/// operands are at `u128::MAX`; the `try_into` step at the end is the only
/// place we narrow back down, so a saturating quotient is *detected* rather
/// than silently wrapped.
pub fn mul_div_floor(a: u128, b: u128, denom: u128) -> Option<u128> {
    if denom == 0 {
        return None;
    }
    let prod = U256::from(a).checked_mul(U256::from(b))?;
    let quotient = prod / U256::from(denom);
    if quotient.bits() > 128 {
        None
    } else {
        Some(quotient.low_u128())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn zero_inputs_are_zero() {
        assert_eq!(mul_div_floor(0, 12_345, 7), Some(0));
        assert_eq!(mul_div_floor(12_345, 0, 7), Some(0));
    }

    #[test]
    fn zero_denominator_returns_none() {
        assert_eq!(mul_div_floor(1, 1, 0), None);
        assert_eq!(mul_div_floor(0, 0, 0), None);
        assert_eq!(mul_div_floor(u128::MAX, u128::MAX, 0), None);
    }

    #[test]
    fn identity_division_returns_product_when_it_fits() {
        // a * b fits in u128, denom = 1 → quotient is just a*b.
        assert_eq!(mul_div_floor(7, 11, 1), Some(77));
        assert_eq!(
            mul_div_floor(1u128 << 60, 1u128 << 60, 1),
            Some(1u128 << 120),
        );
    }

    #[test]
    fn overflow_quotient_returns_none() {
        // a*b = u128::MAX^2 ≈ 2^256, divided by 1 → far past u128 — must
        // detect rather than truncate.
        assert_eq!(mul_div_floor(u128::MAX, u128::MAX, 1), None);
        // Slightly less obvious: divide by 2 still overflows.
        assert_eq!(mul_div_floor(u128::MAX, u128::MAX, 2), None);
    }

    #[test]
    fn saturating_self_division_returns_max() {
        // MAX^2 / MAX = MAX exactly. The corner case where overflow
        // detection must not incorrectly trip.
        assert_eq!(
            mul_div_floor(u128::MAX, u128::MAX, u128::MAX),
            Some(u128::MAX),
        );
    }

    #[test]
    fn agrees_with_naive_path_when_intermediate_fits() {
        // Hand-picked: a*b fits in u128, so the naive (a*b)/denom is
        // exact and authoritative.
        let cases = [
            (1_000_000u128, 1_000_000u128, 1u128),
            (1_000_000u128, 1_000_000u128, 7u128),
            (u64::MAX as u128, u64::MAX as u128, 12_345u128),
        ];
        for (a, b, d) in cases {
            let naive = (a * b) / d;
            assert_eq!(mul_div_floor(a, b, d), Some(naive));
        }
    }

    proptest! {
        /// Commutative in `a` ↔ `b`: the multiply is the only place a/b
        /// matter, so swapping arguments must produce the same quotient.
        #[test]
        fn prop_commutative_in_a_b(
            a in any::<u128>(),
            b in any::<u128>(),
            d in 1u128..=u128::MAX,
        ) {
            prop_assert_eq!(mul_div_floor(a, b, d), mul_div_floor(b, a, d));
        }

        /// When the intermediate product fits in `u128`, the full-precision
        /// path must agree with the naive `(a*b)/d` path. This is the
        /// fast-path correctness pin: the real value of `mul_div_floor` is
        /// the *non-fitting* case, but if it disagrees here something is
        /// wrong with U256 conversion.
        #[test]
        fn prop_agrees_with_naive_when_intermediate_fits(
            // Cap inputs so a*b never overflows u128.
            a in 0u128..=(1u128 << 63),
            b in 0u128..=(1u128 << 63),
            d in 1u128..=u128::MAX,
        ) {
            // (1<<63) * (1<<63) = 1<<126, comfortably within u128.
            let naive = (a * b) / d;
            prop_assert_eq!(mul_div_floor(a, b, d), Some(naive));
        }

        /// Floor semantics: `mul_div_floor(a, b, d) * d <= a * b`. The
        /// quotient never overshoots the true product. Skip cases where
        /// the result overflowed (None) — those are the divisor-too-small
        /// cases the API explicitly rejects.
        #[test]
        fn prop_quotient_never_overshoots(
            a in any::<u128>(),
            b in any::<u128>(),
            d in 1u128..=u128::MAX,
        ) {
            if let Some(q) = mul_div_floor(a, b, d) {
                // q * d <= a * b. Compare in U256 to avoid u128 overflow on
                // either side.
                let lhs = U256::from(q) * U256::from(d);
                let rhs = U256::from(a) * U256::from(b);
                prop_assert!(lhs <= rhs);
                // And the next quotient up exceeds it (proves we returned
                // the *floor*, not something smaller).
                let next = U256::from(q) * U256::from(d) + U256::from(d);
                prop_assert!(next > rhs);
            }
        }
    }
}
