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

/// Compute `ceil((a * b) / denom)` with full 256-bit intermediate precision.
///
/// Returns `None` under the same conditions as [`mul_div_floor`] — `denom == 0`
/// or the (rounded-up) quotient overflows `u128`. The corner the floor variant
/// doesn't see: `floor == u128::MAX` with a non-zero remainder. Adding 1 would
/// wrap to 0; we return `None` so the caller treats it as saturation rather
/// than silent rollover.
///
/// Used by the rounding-up half of Whirlpool's sqrt-price math (token_a in →
/// sqrt_price drop, where the LP-protective direction rounds the new price
/// *up* so the trader gets marginally less output, not more).
pub fn mul_div_ceil(a: u128, b: u128, denom: u128) -> Option<u128> {
    if denom == 0 {
        return None;
    }
    let prod = U256::from(a).checked_mul(U256::from(b))?;
    let denom_u256 = U256::from(denom);
    let quotient = prod / denom_u256;
    let remainder = prod % denom_u256;
    let rounded = if remainder.is_zero() {
        quotient
    } else {
        quotient.checked_add(U256::one())?
    };
    if rounded.bits() > 128 {
        None
    } else {
        Some(rounded.low_u128())
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

    // ----- mul_div_ceil -------------------------------------------------

    #[test]
    fn ceil_zero_inputs_are_zero() {
        assert_eq!(mul_div_ceil(0, 12_345, 7), Some(0));
        assert_eq!(mul_div_ceil(12_345, 0, 7), Some(0));
    }

    #[test]
    fn ceil_zero_denominator_returns_none() {
        assert_eq!(mul_div_ceil(1, 1, 0), None);
        assert_eq!(mul_div_ceil(0, 0, 0), None);
        assert_eq!(mul_div_ceil(u128::MAX, u128::MAX, 0), None);
    }

    #[test]
    fn ceil_matches_floor_on_exact_division() {
        // No remainder → ceil and floor agree.
        assert_eq!(mul_div_ceil(7, 11, 1), Some(77));
        assert_eq!(mul_div_ceil(100, 100, 100), Some(100));
        assert_eq!(
            mul_div_ceil(1u128 << 60, 1u128 << 60, 1),
            Some(1u128 << 120),
        );
    }

    #[test]
    fn ceil_rounds_up_when_remainder_nonzero() {
        // 7 * 11 = 77; 77 / 10 = 7 floor, 8 ceil.
        assert_eq!(mul_div_floor(7, 11, 10), Some(7));
        assert_eq!(mul_div_ceil(7, 11, 10), Some(8));
    }

    #[test]
    fn ceil_overflow_quotient_returns_none() {
        // Same overflow path the floor variant rejects — even before the
        // +1, the bare quotient already passes 2^128.
        assert_eq!(mul_div_ceil(u128::MAX, u128::MAX, 1), None);
        assert_eq!(mul_div_ceil(u128::MAX, u128::MAX, 2), None);
    }

    #[test]
    fn ceil_saturating_self_division_returns_max() {
        // MAX^2 / MAX = MAX exactly (no remainder), so ceil == floor == MAX.
        // This is the case the bits()-check must NOT trip on.
        assert_eq!(
            mul_div_ceil(u128::MAX, u128::MAX, u128::MAX),
            Some(u128::MAX),
        );
    }

    #[test]
    fn ceil_returns_none_when_increment_pushes_past_u128_max() {
        // The corner the floor variant doesn't see: floor lands on MAX with
        // a non-zero remainder, so ceil would need MAX+1 — we must return
        // None instead of wrapping to 0.
        //
        // Construction: a*b = 2^129 - 1 = (2^43 - 1) * (2^86 + 2^43 + 1),
        // both factors fitting comfortably in u128.
        //   denom = 2  ⇒ floor = (2^129 - 1) / 2 = 2^128 - 1 = u128::MAX
        //              ⇒ remainder = 1
        //              ⇒ ceil would need MAX + 1.
        let a: u128 = (1u128 << 43) - 1;
        let b: u128 = (1u128 << 86) + (1u128 << 43) + 1;
        // Sanity-check the construction via the floor path.
        assert_eq!(mul_div_floor(a, b, 2), Some(u128::MAX));
        // And ceil must refuse rather than wrap.
        assert_eq!(mul_div_ceil(a, b, 2), None);
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

        /// `mul_div_ceil` agrees with `mul_div_floor` whenever `a*b` is
        /// exactly divisible by `d` (zero remainder ⇒ nothing to round up).
        /// Cap inputs so `a*b` fits in u128 and we can pick guaranteed-clean
        /// divisors directly.
        #[test]
        fn prop_ceil_equals_floor_on_exact_division(
            a in 0u128..=(1u128 << 63),
            b in 0u128..=(1u128 << 63),
        ) {
            let prod = a * b;
            prop_assume!(prod > 0);
            // d = 1 and d = prod both leave zero remainder by construction.
            for d in [1u128, prod] {
                prop_assert_eq!(mul_div_ceil(a, b, d), mul_div_floor(a, b, d));
            }
        }

        /// Structural relationship: `ceil = floor + (remainder != 0)`. If
        /// this drifts, one of the two functions has lost its rounding
        /// semantics. Also covers the corner case where ceil overflows
        /// while floor doesn't (floor == MAX with non-zero remainder).
        #[test]
        fn prop_ceil_equals_floor_plus_remainder_indicator(
            a in any::<u128>(),
            b in any::<u128>(),
            d in 1u128..=u128::MAX,
        ) {
            let floor = mul_div_floor(a, b, d);
            let ceil = mul_div_ceil(a, b, d);
            // Compute remainder via U256 to avoid u128 overflow on a*b.
            let prod = U256::from(a) * U256::from(b);
            let rem = prod % U256::from(d);
            match (floor, ceil) {
                (Some(f), Some(c)) => {
                    let expected = if rem.is_zero() { f } else { f + 1 };
                    prop_assert_eq!(c, expected);
                }
                (Some(f), None) => {
                    // Only legal when floor == MAX and there's a remainder
                    // (so ceil would be MAX+1 and we correctly bail).
                    prop_assert_eq!(f, u128::MAX);
                    prop_assert!(!rem.is_zero());
                }
                (None, None) => {
                    // Both reject — same upstream overflow path.
                }
                (None, Some(_)) => {
                    prop_assert!(
                        false,
                        "ceil succeeded where floor failed: a={}, b={}, d={}",
                        a, b, d,
                    );
                }
            }
        }
    }
}
