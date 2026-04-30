//! Counterfactual sandwich replay.
//!
//! Given a detected sandwich triplet and the pool's state just before the
//! frontrun executed, replay the three swaps through the AMM math and compute:
//!
//!   * `victim_loss` — how much less the victim received compared to what
//!     they would have received in a world where the frontrun didn't happen.
//!     This is the deterministic measure of extraction.
//!   * `attacker_profit_real` — the attacker's actual gross profit via AMM
//!     math (versus the naive `backrun.amount_out - frontrun.amount_in`
//!     subtraction, which ignores price impact dynamics).
//!   * `price_impact_bps` — how much the frontrun moved the spot price.
//!
//! All values are in the quote-token smallest unit (typically lamports for
//! SOL-quoted pools, or USDC micro-units for USDC-quoted pools).

use swap_events::types::{AmmReplayTrace, SandwichAttack, SwapDirection};

use crate::ConstantProduct;

/// Result of replaying a sandwich through AMM math.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossEstimate {
    /// Quote-token smallest units the victim lost (always ≥ 0).
    pub victim_loss: i64,
    /// Attacker's gross profit via AMM replay (can be negative if unprofitable).
    pub attacker_profit_real: i64,
    /// Price impact of the frontrun in basis points.
    pub price_impact_bps: u32,
    /// What the victim would have received without the frontrun.
    pub counterfactual_victim_out: u64,
    /// What the victim actually received.
    pub actual_victim_out: u64,
}

/// Replay a detected sandwich through the pool's pre-frontrun state.
///
/// Returns `None` if the frontrun and victim are in different directions
/// (shouldn't happen for a real sandwich — detector guarantees this).
pub fn compute_loss(attack: &SandwichAttack, pool_0: ConstantProduct) -> Option<LossEstimate> {
    compute_loss_with_trace(attack, pool_0).map(|(loss, _trace)| loss)
}

/// Like [`compute_loss`] but also returns an [`AmmReplayTrace`] with the pool
/// reserves at each step. Surfaced on `SandwichAttack.amm_replay` so a reader
/// can recompute the victim loss themselves from the raw arithmetic.
pub fn compute_loss_with_trace(
    attack: &SandwichAttack,
    pool_0: ConstantProduct,
) -> Option<(LossEstimate, AmmReplayTrace)> {
    // Defensive: the detector already ensures victim.direction == frontrun.direction
    // and backrun.direction == opposite. Bail if those invariants break.
    if attack.victim.direction != attack.frontrun.direction {
        return None;
    }
    if attack.backrun.direction == attack.frontrun.direction {
        return None;
    }

    let spot_0 = pool_0.spot_price()?;

    // 1. Frontrun applied to pool_0 → pool_1
    let (_fr_out, pool_1) = pool_0.apply_swap(attack.frontrun.amount_in, attack.frontrun.direction);

    // 2. Victim in pool_1 (actual)
    let (actual_victim_out, pool_2) =
        pool_1.apply_swap(attack.victim.amount_in, attack.victim.direction);

    // 3. Victim in pool_0 (counterfactual — what they would have received)
    let counterfactual_victim_out =
        pool_0.simulate_swap(attack.victim.amount_in, attack.victim.direction);

    // Normalise victim loss into quote-token smallest units (lamports for
    // SOL-quoted pools, micro-USDC for USDC-quoted) regardless of sandwich
    // direction. Aggregation across many pools only makes sense when every
    // value is in the same currency; raw base-token diffs would mix memecoin
    // units across pools.
    let raw_victim_delta = counterfactual_victim_out.saturating_sub(actual_victim_out) as f64;
    let victim_loss = match attack.victim.direction {
        // Buy victim received base tokens; the shortfall is in base units.
        // Convert to quote at the pre-frontrun spot (quote per base) — this
        // is the price the victim would have traded against if unfrontrun.
        SwapDirection::Buy => (raw_victim_delta * spot_0) as i64,
        // Sell victim received quote directly; already in quote units.
        SwapDirection::Sell => raw_victim_delta as i64,
    };

    // 4. Backrun in pool_2 (post-victim state)
    let (backrun_out, pool_3) =
        pool_2.apply_swap(attack.backrun.amount_in, attack.backrun.direction);

    // Attacker's gross profit. Both legs denominate in the same token:
    //   Buy-first sandwich:  frontrun.amount_in = quote, backrun_out = quote  → quote
    //   Sell-first sandwich: frontrun.amount_in = base,  backrun_out = base   → base
    // Normalise Sell-first to quote using spot_0 so every attack aggregates
    // in quote-token smallest units.
    let raw_profit = (backrun_out as i64) - (attack.frontrun.amount_in as i64);
    let attacker_profit_real = match attack.frontrun.direction {
        SwapDirection::Buy => raw_profit,
        SwapDirection::Sell => (raw_profit as f64 * spot_0) as i64,
    };

    let spot_1 = pool_1.spot_price()?;
    let price_impact_bps = (((spot_1 - spot_0) / spot_0).abs() * 10_000.0) as u32;

    let loss = LossEstimate {
        victim_loss,
        attacker_profit_real,
        price_impact_bps,
        counterfactual_victim_out,
        actual_victim_out,
    };

    let trace = AmmReplayTrace {
        reserves_pre: reserves_to_u64(&pool_0),
        reserves_post_front: reserves_to_u64(&pool_1),
        reserves_post_victim: reserves_to_u64(&pool_2),
        reserves_post_back: reserves_to_u64(&pool_3),
        spot_price_pre: spot_0,
        spot_price_post_front: spot_1,
        counterfactual_victim_out,
        actual_victim_out,
        fee_num: pool_0.fee_num as u32,
        fee_den: pool_0.fee_den as u32,
    };

    Some((loss, trace))
}

/// Narrow the u128 reserve representation to (u64, u64) for the replay trace.
/// SPL-token reserves fit comfortably in u64; we saturate anyway so a malformed
/// pool doesn't wrap.
fn reserves_to_u64(pool: &ConstantProduct) -> (u64, u64) {
    let (base, quote) = pool.reserves();
    (
        base.min(u64::MAX as u128) as u64,
        quote.min(u64::MAX as u128) as u64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_events::types::{DexType, SwapDirection, SwapEvent};

    fn swap(
        sig: &str,
        signer: &str,
        dir: SwapDirection,
        amount_in: u64,
        amount_out: u64,
    ) -> SwapEvent {
        SwapEvent {
            signature: sig.into(),
            signer: signer.into(),
            dex: DexType::RaydiumV4,
            pool: "P".into(),
            direction: dir,
            token_mint: "M".into(),
            amount_in,
            amount_out,
            tx_index: 0,
            slot: None,
            fee: None,
        }
    }

    fn make_attack(frontrun: SwapEvent, victim: SwapEvent, backrun: SwapEvent) -> SandwichAttack {
        SandwichAttack {
            slot: 100,
            attacker: frontrun.signer.clone(),
            pool: frontrun.pool.clone(),
            dex: frontrun.dex,
            frontrun,
            victim,
            backrun,
            estimated_attacker_profit: None,
            victim_loss_lamports: None,
            frontrun_slot: None,
            backrun_slot: None,
            detection_method: None,
            bundle_provenance: None,
            confidence: None,
            net_profit: None,
            attacker_profit: None,
            price_impact_bps: None,
            evidence: None,
            amm_replay: None,
            attack_signature: None,
            timestamp_ms: None,
            attack_type: None,
            severity: None,
            confidence_level: None,
            slot_leader: None,
            is_wide_sandwich: false,
            receipts: vec![],
            victim_signer: None,
            victim_amount_in: None,
            victim_amount_out: None,
            victim_amount_out_expected: None,
        }
    }

    /// Happy-path sandwich: frontrun moves price, victim eats the loss, backrun profits.
    #[test]
    fn sandwich_produces_positive_victim_loss_and_profit() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 500_000_000, 0),
            swap("v", "vic", SwapDirection::Buy, 100_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, 0, 0), // amount_in = frontrun's base out
        );
        // Attacker bought some base in frontrun; sell it all back
        let (fr_out, _) = pool.apply_swap(500_000_000, SwapDirection::Buy);
        let mut attack = attack;
        attack.backrun.amount_in = fr_out;

        let loss = compute_loss(&attack, pool).unwrap();
        assert!(loss.victim_loss > 0, "victim should lose in a sandwich");
        assert!(loss.actual_victim_out < loss.counterfactual_victim_out);
        assert!(loss.price_impact_bps > 0);
    }

    /// Tiny frontrun → negligible victim loss.
    #[test]
    fn small_frontrun_small_loss() {
        let pool = ConstantProduct::new(1_000_000_000_000, 1_000_000_000_000, 25, 10_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 1_000, 0),
            swap("v", "vic", SwapDirection::Buy, 1_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, 1_000, 0),
        );

        let loss = compute_loss(&attack, pool).unwrap();
        // With a 1000:1_000_000_000_000 ratio, loss is effectively zero
        assert!(loss.victim_loss <= 1);
    }

    /// Direction mismatch (victim opposite from frontrun) — invalid sandwich, return None.
    #[test]
    fn rejects_direction_mismatch() {
        let pool = ConstantProduct::new(1_000_000, 1_000_000, 25, 10_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000, 0),
            swap("v", "vic", SwapDirection::Sell, 50_000, 0), // wrong direction
            swap("b", "atk", SwapDirection::Sell, 100_000, 0),
        );
        assert!(compute_loss(&attack, pool).is_none());
    }

    /// Backrun same direction as frontrun — invalid.
    #[test]
    fn rejects_same_direction_backrun() {
        let pool = ConstantProduct::new(1_000_000, 1_000_000, 25, 10_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000, 0),
            swap("v", "vic", SwapDirection::Buy, 50_000, 0),
            swap("b", "atk", SwapDirection::Buy, 100_000, 0), // wrong direction
        );
        assert!(compute_loss(&attack, pool).is_none());
    }
}
