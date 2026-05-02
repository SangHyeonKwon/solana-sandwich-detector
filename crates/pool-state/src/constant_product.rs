//! Uniswap V2 style constant-product AMM math.
//!
//! Used by Raydium V4 (25bps fee) and Raydium CPMM (configurable fee).
//!
//! Invariant: `new_reserve_in * new_reserve_out >= reserve_in * reserve_out`
//! (k grows by the fee portion that stays in the pool).

use swap_events::types::SwapDirection;

/// Fully-specified constant-product pool state at a point in time.
///
/// `base` = the token being quoted (usually SPL token side).
/// `quote` = the pricing token (usually SOL or USDC).
/// A [`SwapDirection::Buy`] means quote → base; [`SwapDirection::Sell`] is base → quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstantProduct {
    pub base_reserve: u128,
    pub quote_reserve: u128,
    /// Numerator of the swap fee (e.g. 25 for 0.25%).
    pub fee_num: u64,
    /// Denominator of the swap fee (e.g. 10_000).
    pub fee_den: u64,
}

impl ConstantProduct {
    pub fn new(base_reserve: u128, quote_reserve: u128, fee_num: u64, fee_den: u64) -> Self {
        Self {
            base_reserve,
            quote_reserve,
            fee_num,
            fee_den,
        }
    }

    /// Reserves as `(base, quote)`.
    pub fn reserves(&self) -> (u128, u128) {
        (self.base_reserve, self.quote_reserve)
    }

    /// Spot price = quote / base (in smallest units). Used for price-impact math.
    /// Returns `None` if either reserve is zero.
    ///
    /// **Precision contract**: both reserves are `u128` and routinely exceed
    /// `2^53` (the largest integer f64 represents exactly), so each cast
    /// loses up to ~`2^-53` of relative precision and the division adds
    /// another ULP. The quotient is therefore good to ~`3 × 2^-52`
    /// relative — ~12 orders of magnitude below the bps (~`2^-14`)
    /// tolerance that the only downstream consumers (`price_impact_bps as
    /// u32`, `Severity::from_loss_ratio`) operate at, so exact-rational
    /// arithmetic isn't justified. See `whirlpool_spot_price_b_per_a` /
    /// `q64_to_f64` for the matching rationale on the Whirlpool side.
    pub fn spot_price(&self) -> Option<f64> {
        if self.base_reserve == 0 || self.quote_reserve == 0 {
            return None;
        }
        Some(self.quote_reserve as f64 / self.base_reserve as f64)
    }

    /// Simulate a swap without mutating the pool. Returns the output amount.
    ///
    /// Uses the standard Uniswap V2 formula:
    ///   `amount_out = reserve_out * amount_in_with_fee / (reserve_in + amount_in_with_fee)`
    pub fn simulate_swap(&self, amount_in: u64, direction: SwapDirection) -> u64 {
        let (reserve_in, reserve_out) = match direction {
            SwapDirection::Buy => (self.quote_reserve, self.base_reserve),
            SwapDirection::Sell => (self.base_reserve, self.quote_reserve),
        };
        if amount_in == 0 || reserve_in == 0 || reserve_out == 0 {
            return 0;
        }

        let amount_in_u128 = amount_in as u128;
        let fee_den = self.fee_den as u128;
        let fee_num = self.fee_num as u128;
        if fee_den == 0 || fee_num >= fee_den {
            return 0;
        }

        let amount_in_with_fee = amount_in_u128
            .checked_mul(fee_den - fee_num)
            .and_then(|n| n.checked_div(fee_den))
            .unwrap_or(0);

        let numerator = match amount_in_with_fee.checked_mul(reserve_out) {
            Some(n) => n,
            None => return 0,
        };
        let denominator = reserve_in.saturating_add(amount_in_with_fee);
        if denominator == 0 {
            return 0;
        }

        let out = numerator / denominator;
        if out > u64::MAX as u128 {
            u64::MAX
        } else {
            out as u64
        }
    }

    /// Apply a swap and return `(amount_out, new_pool_state)`.
    ///
    /// Full `amount_in` is added to the input-side reserve (the fee stays in
    /// the pool as LP rewards — that's how k grows).
    pub fn apply_swap(&self, amount_in: u64, direction: SwapDirection) -> (u64, Self) {
        let amount_out = self.simulate_swap(amount_in, direction);
        let amount_in_u128 = amount_in as u128;
        let amount_out_u128 = amount_out as u128;

        let new_state = match direction {
            SwapDirection::Buy => Self {
                base_reserve: self.base_reserve.saturating_sub(amount_out_u128),
                quote_reserve: self.quote_reserve.saturating_add(amount_in_u128),
                ..*self
            },
            SwapDirection::Sell => Self {
                base_reserve: self.base_reserve.saturating_add(amount_in_u128),
                quote_reserve: self.quote_reserve.saturating_sub(amount_out_u128),
                ..*self
            },
        };
        (amount_out, new_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero-fee identity: swap 10 quote into a 100/100 pool → output follows x*y=k exactly.
    /// Integer math: out = 100 * 10 / 110 = 9.
    #[test]
    fn zero_fee_symmetric() {
        let pool = ConstantProduct::new(100, 100, 0, 10_000);
        let (out, new) = pool.apply_swap(10, SwapDirection::Buy);
        assert_eq!(out, 9);
        assert_eq!(new.base_reserve, 91);
        assert_eq!(new.quote_reserve, 110);
        // k should be >= original (grows with fee; equal with 0 fee except for int rounding)
        assert!(new.base_reserve * new.quote_reserve >= 100 * 100 - 10); // rounding slack
    }

    /// Raydium V4 uses 25bps fee (fee_num=25, fee_den=10_000).
    /// Verifies the fee reduces amount_out by roughly 0.25%.
    #[test]
    fn raydium_v4_fee_rate() {
        let with_fee = ConstantProduct::new(1_000_000, 1_000_000, 25, 10_000);
        let no_fee = ConstantProduct::new(1_000_000, 1_000_000, 0, 10_000);

        let out_fee = with_fee.simulate_swap(10_000, SwapDirection::Buy);
        let out_no_fee = no_fee.simulate_swap(10_000, SwapDirection::Buy);

        // With fee should be strictly less
        assert!(out_fee < out_no_fee);
        // Difference should be on the order of 25bps of out_no_fee
        let diff_bps = (out_no_fee - out_fee) as f64 / out_no_fee as f64 * 10_000.0;
        assert!(
            (20.0..=30.0).contains(&diff_bps),
            "fee diff {:.1}bps outside expected ~25bps",
            diff_bps
        );
    }

    /// Sandwich price impact: frontrun pushes price, victim gets worse rate.
    #[test]
    fn sandwich_price_impact() {
        let pool_0 = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);

        // Baseline: victim would buy in pool_0
        let baseline = pool_0.simulate_swap(100_000_000, SwapDirection::Buy);

        // Attacker frontruns with 500M quote
        let (_fr_out, pool_1) = pool_0.apply_swap(500_000_000, SwapDirection::Buy);

        // Victim's actual swap in pool_1 (post-frontrun)
        let actual = pool_1.simulate_swap(100_000_000, SwapDirection::Buy);

        // Victim got strictly less than the baseline
        assert!(actual < baseline);
        // The difference is the victim's loss in the base token
        let loss = baseline - actual;
        assert!(loss > 0);
    }

    /// Simulate then apply must agree: apply_swap's out == simulate_swap's out.
    #[test]
    fn simulate_apply_consistency() {
        let pool = ConstantProduct::new(500_000_000, 2_000_000_000, 30, 10_000);
        let sim = pool.simulate_swap(50_000_000, SwapDirection::Sell);
        let (out, _) = pool.apply_swap(50_000_000, SwapDirection::Sell);
        assert_eq!(sim, out);
    }

    /// Zero-reserve pool yields zero output, doesn't panic.
    #[test]
    fn degenerate_inputs() {
        let empty = ConstantProduct::new(0, 0, 25, 10_000);
        assert_eq!(empty.simulate_swap(1000, SwapDirection::Buy), 0);

        let no_in = ConstantProduct::new(100, 100, 25, 10_000);
        assert_eq!(no_in.simulate_swap(0, SwapDirection::Buy), 0);

        let bad_fee = ConstantProduct::new(100, 100, 10_001, 10_000);
        assert_eq!(bad_fee.simulate_swap(10, SwapDirection::Buy), 0);
    }

    /// Reversal check: Buy then Sell should (modulo fees) approximately cancel.
    #[test]
    fn buy_sell_roundtrip_decays() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let (bought, pool_1) = pool.apply_swap(10_000_000, SwapDirection::Buy);
        let (received, _) = pool_1.apply_swap(bought, SwapDirection::Sell);

        // User sent 10M quote, bought some base, sold it back — should receive
        // slightly less than 10M (fee drag: ~2x 25bps = ~50bps)
        assert!(received < 10_000_000);
        let drag_bps = (10_000_000 - received) as f64 / 10_000_000.0 * 10_000.0;
        assert!(
            (40.0..=60.0).contains(&drag_bps),
            "roundtrip drag {:.1}bps outside expected ~50bps",
            drag_bps
        );
    }

    /// Spot price reflects quote/base ratio.
    #[test]
    fn spot_price_ratio() {
        let pool = ConstantProduct::new(1_000, 2_000, 25, 10_000);
        assert_eq!(pool.spot_price(), Some(2.0));
        let empty = ConstantProduct::new(0, 100, 25, 10_000);
        assert_eq!(empty.spot_price(), None);
    }
}
