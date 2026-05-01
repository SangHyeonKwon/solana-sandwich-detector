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

use swap_events::types::{
    AmmReplayTrace, MeteoraDlmmReplayTrace, SandwichAttack, SwapDirection, WhirlpoolReplayTrace,
};

use crate::meteora_dlmm::bin_array::ParsedBinArray;
use crate::meteora_dlmm::{cross_bin_swap, DlmmBinState, DlmmPool};
use crate::orca_whirlpool::swap_math;
use crate::orca_whirlpool::tick_array::ParsedTickArray;
use crate::orca_whirlpool::WhirlpoolPool;
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
    /// Per-step model fidelity (Tier 3.2): signed bps gap between what our
    /// `apply_swap` predicts the swap output should be (given the reserves
    /// we used) and the parser-observed `SwapEvent.amount_out`. Near-zero
    /// = our reserves and AMM math match the chain. Far from zero =
    /// distrust the rest of this `LossEstimate`. `None` when the parser-
    /// extracted output was 0 (no usable observation to compare against).
    /// Fed into [`Signal::InvariantResidual`].
    pub residual_bps_frontrun: Option<i32>,
    pub residual_bps_victim: Option<i32>,
    pub residual_bps_backrun: Option<i32>,
    /// What the attacker would have netted if the victim had not traded
    /// (Tier 3.5). Computed by replaying `frontrun → backrun` on the
    /// post-frontrun pool, skipping the victim. Same quote-token unit and
    /// Buy/Sell normalisation as `attacker_profit_real`. Fed into
    /// [`Signal::CounterfactualAttackerProfit`].
    pub counterfactual_attacker_profit_no_victim: i64,
    /// Confidence interval on `victim_loss` (Tier 3.3). Width is derived
    /// from the worst per-step parser-vs-model gap (`residual_bps_*`):
    /// half-width = max(|residual|) / 10_000 applied multiplicatively to
    /// the point estimate. `None` on both bounds when no step has a usable
    /// observation (parser silent on every leg) or the point estimate is
    /// non-positive (no meaningful CI on a contradicted detection).
    /// Lower is clamped at 0 — `victim_loss` is by construction ≥ 0.
    pub victim_loss_lower: Option<i64>,
    pub victim_loss_upper: Option<i64>,
}

/// Compute a signed basis-point residual between an AMM-predicted output
/// and what chain logs reported. Returns `None` when `observed` is zero
/// (parser failure or empty swap), in which case no useful comparison
/// exists. The result is clamped to `i32` so a runaway pool doesn't
/// overflow downstream signal payloads.
fn residual_bps(predicted: u64, observed: u64) -> Option<i32> {
    if observed == 0 {
        return None;
    }
    let delta = predicted as i128 - observed as i128;
    let scaled = delta.saturating_mul(10_000) / observed as i128;
    Some(scaled.clamp(i32::MIN as i128, i32::MAX as i128) as i32)
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
    let (fr_out, pool_1) = pool_0.apply_swap(attack.frontrun.amount_in, attack.frontrun.direction);

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

    // Counterfactual attacker (Tier 3.5): replay the backrun on pool_1 (post-
    // frontrun, no victim) and see what the attacker would have netted if
    // the victim's tx hadn't happened. A "true" sandwich shows
    // counterfactual_attacker_profit_no_victim ≤ 0 — extraction depends on
    // the victim. Strongly-positive counterfactual = arbitrage that
    // happened to bracket an unrelated tx.
    let (backrun_out_no_victim, _pool_no_victim) =
        pool_1.apply_swap(attack.backrun.amount_in, attack.backrun.direction);
    let raw_profit_no_victim = backrun_out_no_victim as i64 - attack.frontrun.amount_in as i64;
    let counterfactual_attacker_profit_no_victim = match attack.frontrun.direction {
        SwapDirection::Buy => raw_profit_no_victim,
        SwapDirection::Sell => (raw_profit_no_victim as f64 * spot_0) as i64,
    };

    // Per-step residuals (Tier 3.2): predicted (our AMM math) vs. observed
    // (what the parser pulled from token-balance changes on chain).
    let residual_bps_frontrun = residual_bps(fr_out, attack.frontrun.amount_out);
    let residual_bps_victim = residual_bps(actual_victim_out, attack.victim.amount_out);
    let residual_bps_backrun = residual_bps(backrun_out, attack.backrun.amount_out);

    // Victim-loss confidence interval (Tier 3.3): widen the point estimate
    // by the worst per-step model/parser disagreement. The intuition is
    // that residual_bps_* directly bounds how far our reservoir-based
    // victim_out predictions can drift from chain truth, so the loss
    // (which is a difference of two such predictions) inherits the same
    // relative uncertainty as a first-order envelope.
    let max_abs_residual_bps = [
        residual_bps_frontrun,
        residual_bps_victim,
        residual_bps_backrun,
    ]
    .iter()
    .filter_map(|x| x.map(|v| v.unsigned_abs()))
    .max();
    let (victim_loss_lower, victim_loss_upper) = match max_abs_residual_bps {
        // A residual ≥ 100% means the model is so out of step with chain
        // truth that quoting a numeric CI would imply more precision than
        // we have. Saturating-large residuals (e.g. parser-observed
        // amount_out close to zero) push max_abs to i32::MAX.unsigned_abs(),
        // so this guard is mandatory rather than aesthetic.
        Some(max_abs) if victim_loss > 0 && max_abs < 10_000 => {
            let half_width = max_abs as f64 / 10_000.0;
            let lower = ((victim_loss as f64) * (1.0 - half_width)).max(0.0) as i64;
            let upper = ((victim_loss as f64) * (1.0 + half_width)) as i64;
            (Some(lower), Some(upper))
        }
        _ => (None, None),
    };

    let loss = LossEstimate {
        victim_loss,
        attacker_profit_real,
        price_impact_bps,
        counterfactual_victim_out,
        actual_victim_out,
        residual_bps_frontrun,
        residual_bps_victim,
        residual_bps_backrun,
        counterfactual_attacker_profit_no_victim,
        victim_loss_lower,
        victim_loss_upper,
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

/// Replay a detected sandwich through a Whirlpool pool, returning the
/// loss estimate paired with a per-step [`WhirlpoolReplayTrace`].
///
/// Mirrors [`compute_loss_with_trace`] for the V3-style swap math:
/// same `LossEstimate` shape, same `Option` failure modes, plus a
/// snapshot of `(sqrt_price, liquidity, tick_current)` at the four
/// canonical checkpoints (pre-frontrun, post-frontrun, post-victim,
/// post-back) so a reader can re-derive victim_loss from the raw
/// concentrated-liquidity arithmetic.
///
/// `tick_arrays` is the caller's pre-fetched view of the Whirlpool's
/// TickArrays, in any order — the helper sorts per-leg by swap
/// direction. Pass `&[]` to disable the cross-tick fallback (tests do
/// this for the within-tick-only paths). Production callers obtain
/// the arrays via [`crate::PoolStateLookup::tick_arrays`].
///
/// Returns `None` when:
///   * direction invariants break (same as [`compute_loss`]),
///   * any leg's swap can't be computed by either the within-tick
///     fast path or the cross-tick fallback (caller fed too few
///     `tick_arrays`, liquidity drains to zero mid-walk, etc).
pub fn compute_loss_whirlpool_with_trace(
    attack: &SandwichAttack,
    pool_0: WhirlpoolPool,
    fee_num: u128,
    fee_den: u128,
    base_is_token_a: bool,
    tick_arrays: &[ParsedTickArray],
) -> Option<(LossEstimate, WhirlpoolReplayTrace)> {
    // Direction sanity (mirrors compute_loss_with_trace).
    if attack.victim.direction != attack.frontrun.direction {
        return None;
    }
    if attack.backrun.direction == attack.frontrun.direction {
        return None;
    }

    // Map SwapDirection (Buy/Sell, in *quote* terms) to Whirlpool's
    // `a_to_b` flag (token_a in vs token_b in). The on-chain a/b axis
    // doesn't line up with our base/quote axis universally — the parser
    // records the orientation in `base_is_token_a`, and we flip
    // accordingly:
    //   * Sell = base in. base = token_a ⇒ a_to_b = true.
    //                     base = token_b ⇒ a_to_b = false.
    //   * Buy  = quote in. base = token_a ⇒ a_to_b = false.
    //                      base = token_b ⇒ a_to_b = true.
    let frontrun_a_to_b = match attack.frontrun.direction {
        SwapDirection::Sell => base_is_token_a,
        SwapDirection::Buy => !base_is_token_a,
    };
    let victim_a_to_b = frontrun_a_to_b; // detector ensures same direction
    let backrun_a_to_b = !frontrun_a_to_b;

    // Whirlpool spot is denominated `token_b / token_a`; flip when base
    // sits on token_b so the rest of the loss math runs in quote/base
    // units (the same axis as ConstantProduct's spot_price).
    let spot_b_per_a_0 = whirlpool_spot_price_b_per_a(pool_0);
    let quote_per_base_0 = if base_is_token_a {
        spot_b_per_a_0
    } else {
        1.0 / spot_b_per_a_0
    };

    // 1. Frontrun on pool_0.
    let (pool_1, fr_out, _fr_fee) = try_swap_with_fallback(
        pool_0,
        attack.frontrun.amount_in as u128,
        frontrun_a_to_b,
        fee_num,
        fee_den,
        tick_arrays,
    )?;

    // 2. Victim on pool_1 (actual outcome).
    let (pool_2, actual_victim_out, _v_fee) = try_swap_with_fallback(
        pool_1,
        attack.victim.amount_in as u128,
        victim_a_to_b,
        fee_num,
        fee_den,
        tick_arrays,
    )?;

    // 3. Counterfactual: victim on pool_0 (no frontrun).
    let (_pool_no_frontrun, counterfactual_victim_out, _) = try_swap_with_fallback(
        pool_0,
        attack.victim.amount_in as u128,
        victim_a_to_b,
        fee_num,
        fee_den,
        tick_arrays,
    )?;

    // Loss in quote-token smallest units (same normalisation as
    // ConstantProduct path).
    let raw_victim_delta = (counterfactual_victim_out as i64 - actual_victim_out as i64).max(0);
    let victim_loss = match attack.victim.direction {
        SwapDirection::Buy => (raw_victim_delta as f64 * quote_per_base_0) as i64,
        SwapDirection::Sell => raw_victim_delta,
    };

    // 4. Backrun on pool_2.
    let (pool_3, backrun_out, _b_fee) = try_swap_with_fallback(
        pool_2,
        attack.backrun.amount_in as u128,
        backrun_a_to_b,
        fee_num,
        fee_den,
        tick_arrays,
    )?;

    let raw_profit = (backrun_out as i64) - (attack.frontrun.amount_in as i64);
    let attacker_profit_real = match attack.frontrun.direction {
        SwapDirection::Buy => raw_profit,
        SwapDirection::Sell => (raw_profit as f64 * quote_per_base_0) as i64,
    };

    let spot_b_per_a_1 = whirlpool_spot_price_b_per_a(pool_1);
    let quote_per_base_1 = if base_is_token_a {
        spot_b_per_a_1
    } else {
        1.0 / spot_b_per_a_1
    };
    let price_impact_bps =
        (((quote_per_base_1 - quote_per_base_0) / quote_per_base_0).abs() * 10_000.0) as u32;

    // Counterfactual attacker (Tier 3.5): backrun on pool_1 (no victim).
    let (_pool_no_victim, backrun_out_no_victim, _) = try_swap_with_fallback(
        pool_1,
        attack.backrun.amount_in as u128,
        backrun_a_to_b,
        fee_num,
        fee_den,
        tick_arrays,
    )?;
    let raw_profit_no_victim = backrun_out_no_victim as i64 - attack.frontrun.amount_in as i64;
    let counterfactual_attacker_profit_no_victim = match attack.frontrun.direction {
        SwapDirection::Buy => raw_profit_no_victim,
        SwapDirection::Sell => (raw_profit_no_victim as f64 * quote_per_base_0) as i64,
    };

    // Per-step residuals (Tier 3.2). apply_swap_within_tick returns u128
    // amounts but parser observations are u64; saturate-narrow before
    // diffing.
    let residual_bps_frontrun = residual_bps(narrow_u64(fr_out), attack.frontrun.amount_out);
    let residual_bps_victim = residual_bps(narrow_u64(actual_victim_out), attack.victim.amount_out);
    let residual_bps_backrun = residual_bps(narrow_u64(backrun_out), attack.backrun.amount_out);

    // CI on victim_loss (Tier 3.3) — same envelope rule as ConstantProduct
    // path so vigil-v1 receipts come out shaped identically across DEX
    // kinds.
    let max_abs_residual_bps = [
        residual_bps_frontrun,
        residual_bps_victim,
        residual_bps_backrun,
    ]
    .iter()
    .filter_map(|x| x.map(|v| v.unsigned_abs()))
    .max();
    let (victim_loss_lower, victim_loss_upper) = match max_abs_residual_bps {
        Some(max_abs) if victim_loss > 0 && max_abs < 10_000 => {
            let half_width = max_abs as f64 / 10_000.0;
            let lower = ((victim_loss as f64) * (1.0 - half_width)).max(0.0) as i64;
            let upper = ((victim_loss as f64) * (1.0 + half_width)) as i64;
            (Some(lower), Some(upper))
        }
        _ => (None, None),
    };

    let loss = LossEstimate {
        victim_loss,
        attacker_profit_real,
        price_impact_bps,
        counterfactual_victim_out: narrow_u64(counterfactual_victim_out),
        actual_victim_out: narrow_u64(actual_victim_out),
        residual_bps_frontrun,
        residual_bps_victim,
        residual_bps_backrun,
        counterfactual_attacker_profit_no_victim,
        victim_loss_lower,
        victim_loss_upper,
    };

    let trace = WhirlpoolReplayTrace {
        sqrt_price_pre: pool_0.sqrt_price_q64,
        sqrt_price_post_front: pool_1.sqrt_price_q64,
        sqrt_price_post_victim: pool_2.sqrt_price_q64,
        sqrt_price_post_back: pool_3.sqrt_price_q64,
        liquidity_pre: pool_0.liquidity,
        liquidity_post_front: pool_1.liquidity,
        liquidity_post_victim: pool_2.liquidity,
        liquidity_post_back: pool_3.liquidity,
        tick_current_pre: pool_0.tick_current_index,
        tick_current_post_front: pool_1.tick_current_index,
        tick_current_post_victim: pool_2.tick_current_index,
        tick_current_post_back: pool_3.tick_current_index,
        counterfactual_victim_out: narrow_u64(counterfactual_victim_out),
        actual_victim_out: narrow_u64(actual_victim_out),
        // fee_num / fee_den come in as u128 to match the swap-math
        // layer; Whirlpool's on-chain fee_rate is u16 of hundredths-
        // of-bps against a u32 1_000_000 denominator, so narrowing
        // here is lossless for any legal pool.
        fee_num: fee_num as u32,
        fee_den: fee_den as u32,
    };

    Some((loss, trace))
}

/// Like [`compute_loss_whirlpool_with_trace`] but discards the trace.
/// Use this when the caller only needs the [`LossEstimate`] (e.g.,
/// downstream code that doesn't surface the per-step replay view).
pub fn compute_loss_whirlpool(
    attack: &SandwichAttack,
    pool_0: WhirlpoolPool,
    fee_num: u128,
    fee_den: u128,
    base_is_token_a: bool,
    tick_arrays: &[ParsedTickArray],
) -> Option<LossEstimate> {
    compute_loss_whirlpool_with_trace(
        attack,
        pool_0,
        fee_num,
        fee_den,
        base_is_token_a,
        tick_arrays,
    )
    .map(|(loss, _trace)| loss)
}

/// Whirlpool spot price (token_b per token_a) from a Q64.64 sqrt_price.
/// `f64` precision is fine for the bps-level downstream uses (severity,
/// price_impact_bps, sandwich-direction normalisation); exact rational
/// arithmetic isn't justified.
fn whirlpool_spot_price_b_per_a(pool: WhirlpoolPool) -> f64 {
    let sp = pool.sqrt_price_q64 as f64 / (1u128 << 64) as f64;
    sp * sp
}

/// Saturating-narrow a u128 swap-leg amount to u64. Real Whirlpool swap
/// outputs always fit in u64 (SPL token amounts), but the math layer
/// returns u128 and we want a deterministic floor on malformed inputs.
fn narrow_u64(amount: u128) -> u64 {
    amount.min(u64::MAX as u128) as u64
}

/// Try to apply a single swap leg, falling back from within-tick to
/// cross-tick when the within-tick guard trips. Empty `tick_arrays`
/// disables the fallback — the within-tick result is the only chance.
///
/// Return shape matches [`WhirlpoolPool::apply_swap_within_tick`]:
/// `(new_pool, amount_out, fee_amount)`.
fn try_swap_with_fallback(
    pool: WhirlpoolPool,
    amount: u128,
    a_to_b: bool,
    fee_num: u128,
    fee_den: u128,
    tick_arrays: &[ParsedTickArray],
) -> Option<(WhirlpoolPool, u128, u128)> {
    if let Some(r) = pool.apply_swap_within_tick(amount, a_to_b, fee_num, fee_den) {
        return Some(r);
    }
    if tick_arrays.is_empty() {
        return None;
    }
    let sorted = sort_arrays_for_direction(tick_arrays, a_to_b);
    let r = swap_math::cross_tick_swap(pool, amount, a_to_b, fee_num, fee_den, &sorted)?;
    Some((r.pool, r.amount_out, r.fee_amount))
}

/// Wrap caller-supplied `tick_arrays` in the `Vec<Option<ParsedTickArray>>`
/// shape `cross_tick_swap` expects, sorted into swap order:
///   * `a_to_b = true`  ⇒ descending `start_tick_index` (tick decreasing).
///   * `a_to_b = false` ⇒ ascending  `start_tick_index` (tick increasing).
fn sort_arrays_for_direction(
    arrays: &[ParsedTickArray],
    a_to_b: bool,
) -> Vec<Option<ParsedTickArray>> {
    let mut sorted = arrays.to_vec();
    if a_to_b {
        sorted.sort_by_key(|a| std::cmp::Reverse(a.start_tick_index));
    } else {
        sorted.sort_by_key(|a| a.start_tick_index);
    }
    sorted.into_iter().map(Some).collect()
}

/// Replay a DLMM sandwich through cross-bin walks (Phase 2).
///
/// Each leg goes through [`cross_bin_swap`]; bins drain ⇒ walker
/// advances `active_id` ± 1 until input is exhausted or the walker
/// exits the supplied window. Within-bin sandwiches still produce
/// `victim_loss = 0` (the constant-sum invariant — frontrun doesn't
/// move price inside one bin), but cross-bin sandwiches now produce
/// non-zero loss because the frontrun pushes `active_id` through
/// price levels and the victim eats those worse prices.
///
/// Returns `None` on:
///   * direction-mismatched legs (detector invariant violation),
///   * any leg's `cross_bin_swap` failing — out-of-window, iteration
///     cap, arithmetic overflow,
///   * empty `arrays` slice (no liquidity reachable),
///   * the active bin being absent from the supplied window (shouldn't
///     happen; enrich centers the window on `active_id`'s array).
///
/// `arrays` is the BinArray window enrich fetched (typically 5
/// arrays, center ± 2). `pool.active_id` seeds the walker; the
/// initial bin's price drives the quote-axis conversion. The
/// underlying [`DlmmBinState`] is cloned per leg so the four
/// counterfactual replays don't pollute each other.
pub fn compute_loss_dlmm(
    attack: &SandwichAttack,
    pool: &DlmmPool,
    arrays: &[ParsedBinArray],
    base_is_token_a: bool,
) -> Option<LossEstimate> {
    compute_loss_dlmm_with_trace(attack, pool, arrays, base_is_token_a).map(|(loss, _trace)| loss)
}

/// Like [`compute_loss_dlmm`] but also returns a
/// [`MeteoraDlmmReplayTrace`] suitable for surfacing on
/// `SandwichAttack.dlmm_replay`. The trace lets a reader recompute
/// victim loss themselves from the per-step `active_id` transitions,
/// the pre-frontrun bin price (Q64.64), and the fee parameters.
///
/// Same `None` conditions as [`compute_loss_dlmm`]: direction mismatch,
/// any leg's `cross_bin_swap` failing, empty arrays, or the active
/// bin missing from the supplied window.
pub fn compute_loss_dlmm_with_trace(
    attack: &SandwichAttack,
    pool: &DlmmPool,
    arrays: &[ParsedBinArray],
    base_is_token_a: bool,
) -> Option<(LossEstimate, MeteoraDlmmReplayTrace)> {
    if attack.victim.direction != attack.frontrun.direction {
        return None;
    }
    if attack.backrun.direction == attack.frontrun.direction {
        return None;
    }

    let initial_state = DlmmBinState::from_arrays(arrays, pool.bin_step)?;
    let initial_active_id = pool.active_id;
    let initial_snap = initial_state.get(initial_active_id)?;
    let bin_price_q64 = initial_snap.price;
    if bin_price_q64 == 0 {
        return None;
    }

    // SwapDirection (Buy/Sell, quote terms) ⇒ DLMM `swap_for_y`. The
    // DLMM x/y axis is V3's a/b axis, so the mapping mirrors
    // Whirlpool's frontrun_a_to_b derivation:
    //   * Sell = base in. base = x ⇒ swap_for_y. base = y ⇒ !swap_for_y.
    //   * Buy  = quote in. base = x ⇒ !swap_for_y. base = y ⇒ swap_for_y.
    let frontrun_swap_for_y = match attack.frontrun.direction {
        SwapDirection::Sell => base_is_token_a,
        SwapDirection::Buy => !base_is_token_a,
    };
    let victim_swap_for_y = frontrun_swap_for_y;
    let backrun_swap_for_y = !frontrun_swap_for_y;

    // 1. Frontrun on initial state → state_1.
    let mut state_1 = initial_state.clone();
    let fr = cross_bin_swap(
        attack.frontrun.amount_in,
        initial_active_id,
        &mut state_1,
        frontrun_swap_for_y,
        pool,
    )?;
    let active_after_front = fr.final_active_id;

    // 2. Victim on state_1 → state_2.
    let mut state_2 = state_1.clone();
    let v = cross_bin_swap(
        attack.victim.amount_in,
        active_after_front,
        &mut state_2,
        victim_swap_for_y,
        pool,
    )?;

    // 3. Counterfactual victim on initial state.
    let mut state_counter = initial_state.clone();
    let v_counter = cross_bin_swap(
        attack.victim.amount_in,
        initial_active_id,
        &mut state_counter,
        victim_swap_for_y,
        pool,
    )?;

    // 4. Backrun on state_2.
    let mut state_3 = state_2.clone();
    let b = cross_bin_swap(
        attack.backrun.amount_in,
        v.final_active_id,
        &mut state_3,
        backrun_swap_for_y,
        pool,
    )?;

    // 5. Counterfactual: backrun on state_1 (no victim).
    let mut state_no_v = state_1.clone();
    let b_no_v = cross_bin_swap(
        attack.backrun.amount_in,
        active_after_front,
        &mut state_no_v,
        backrun_swap_for_y,
        pool,
    )?;

    // Quote-axis conversion. Initial bin price is the spot at the
    // pre-frontrun moment — same convention as Whirlpool's
    // `quote_per_base_0`.
    let price_f64 = q64_to_f64(bin_price_q64);
    let quote_per_base = if base_is_token_a {
        price_f64
    } else {
        1.0 / price_f64
    };

    let actual_victim_out = v.amount_out;
    let counterfactual_victim_out = v_counter.amount_out;
    let raw_victim_delta = (counterfactual_victim_out as i64 - actual_victim_out as i64).max(0);
    let victim_loss = match attack.victim.direction {
        SwapDirection::Buy => (raw_victim_delta as f64 * quote_per_base) as i64,
        SwapDirection::Sell => raw_victim_delta,
    };

    let raw_profit = b.amount_out as i64 - attack.frontrun.amount_in as i64;
    let attacker_profit_real = match attack.frontrun.direction {
        SwapDirection::Buy => raw_profit,
        SwapDirection::Sell => (raw_profit as f64 * quote_per_base) as i64,
    };

    let raw_profit_no_v = b_no_v.amount_out as i64 - attack.frontrun.amount_in as i64;
    let counterfactual_attacker_profit_no_victim = match attack.frontrun.direction {
        SwapDirection::Buy => raw_profit_no_v,
        SwapDirection::Sell => (raw_profit_no_v as f64 * quote_per_base) as i64,
    };

    // price_impact_bps: first-order approximation, `bins_moved *
    // bin_step`. The exact spread is `(1 + bin_step/10_000)^n - 1`;
    // the linearisation drops the (1 + x)^n - 1 ≈ nx Taylor remainder.
    // For realistic sandwiches (n ≤ 5, bin_step ≤ 25) the relative
    // error is <0.1%, well below the bps reporting precision. Past
    // ~50 bins (rare) the linearisation underestimates by a few
    // percent — exact computation via `bin_price` ratio is a Phase 3
    // refinement, behind variable-fee plumbing in priority since the
    // approximation is already within the noise floor for the bps
    // surface Vigil consumes.
    let active_id_diff = (active_after_front - initial_active_id).unsigned_abs();
    let price_impact_bps = active_id_diff.saturating_mul(pool.bin_step as u32);

    let residual_bps_frontrun = residual_bps(fr.amount_out, attack.frontrun.amount_out);
    let residual_bps_victim = residual_bps(v.amount_out, attack.victim.amount_out);
    let residual_bps_backrun = residual_bps(b.amount_out, attack.backrun.amount_out);

    let max_abs_residual_bps = [
        residual_bps_frontrun,
        residual_bps_victim,
        residual_bps_backrun,
    ]
    .iter()
    .filter_map(|x| x.map(|v| v.unsigned_abs()))
    .max();
    let (victim_loss_lower, victim_loss_upper) = match max_abs_residual_bps {
        Some(max_abs) if victim_loss > 0 && max_abs < 10_000 => {
            let half_width = max_abs as f64 / 10_000.0;
            let lower = ((victim_loss as f64) * (1.0 - half_width)).max(0.0) as i64;
            let upper = ((victim_loss as f64) * (1.0 + half_width)) as i64;
            (Some(lower), Some(upper))
        }
        _ => (None, None),
    };

    let loss = LossEstimate {
        victim_loss,
        attacker_profit_real,
        price_impact_bps,
        counterfactual_victim_out,
        actual_victim_out,
        residual_bps_frontrun,
        residual_bps_victim,
        residual_bps_backrun,
        counterfactual_attacker_profit_no_victim,
        victim_loss_lower,
        victim_loss_upper,
    };

    let trace = MeteoraDlmmReplayTrace {
        active_id_pre: initial_active_id,
        active_id_post_front: active_after_front,
        active_id_post_victim: v.final_active_id,
        active_id_post_back: b.final_active_id,
        bin_price_pre: bin_price_q64,
        counterfactual_victim_out,
        actual_victim_out,
        bin_step: pool.bin_step,
        // Caller-friendly numerator/denominator. Phase 1 step 4
        // restructured fee math so `total_fee_rate / DLMM_FEE_PRECISION`
        // is the canonical fraction; surface that here so a reader
        // doesn't have to derive `base_factor * bin_step * 10` from
        // `bin_step` alone.
        // Propagate `None` rather than masking with `0`: an
        // overflow in `total_fee_rate` (only reachable in Phase 3
        // variable-fee plumbing) shouldn't silently surface a "no
        // fee" trace.
        fee_num: pool.total_fee_rate()? as u64,
        fee_den: crate::meteora_dlmm::DLMM_FEE_PRECISION,
    };

    Some((loss, trace))
}

/// Q64.64 fixed-point → `f64`. Same precision-tradeoff rationale as
/// `whirlpool_spot_price_b_per_a`: bps-level downstream uses (severity,
/// price-axis conversion) don't justify exact-rational arithmetic.
fn q64_to_f64(price_q64: u128) -> f64 {
    (price_q64 as f64) / (1u128 << 64) as f64
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
            victim_loss_lamports_lower: None,
            victim_loss_lamports_upper: None,
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
            whirlpool_replay: None,
            dlmm_replay: None,
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

    // ----- Tier 3.2 / 3.5 — residuals + counterfactual attacker ----------

    /// When the parser-observed `amount_out` matches our AMM math (i.e. we
    /// pre-computed it via `apply_swap` on the same pool), every per-step
    /// residual_bps is exactly zero. This is the self-consistency check —
    /// if the model and the observation come from the same place, gap is
    /// nil; non-zero residual in production therefore means the chain
    /// disagreed with our model.
    #[test]
    fn residuals_zero_when_observations_match_model() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        // Pre-compute every step's output via the same pool math, then plant
        // those values as the parser-observed `amount_out`s.
        let (fr_out, pool_1) = pool.apply_swap(500_000_000, SwapDirection::Buy);
        let (victim_out, pool_2) = pool_1.apply_swap(100_000_000, SwapDirection::Buy);
        let (back_out, _pool_3) = pool_2.apply_swap(fr_out, SwapDirection::Sell);

        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 500_000_000, fr_out),
            swap("v", "vic", SwapDirection::Buy, 100_000_000, victim_out),
            swap("b", "atk", SwapDirection::Sell, fr_out, back_out),
        );
        let loss = compute_loss(&attack, pool).unwrap();

        assert_eq!(loss.residual_bps_frontrun, Some(0));
        assert_eq!(loss.residual_bps_victim, Some(0));
        assert_eq!(loss.residual_bps_backrun, Some(0));
    }

    /// `amount_out = 0` on a SwapEvent means the parser didn't extract a
    /// usable observation. The residual for that step is `None` so callers
    /// can choose not to emit a misleading zero.
    #[test]
    fn residuals_none_when_observation_is_zero() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 500_000_000, 0),
            swap("v", "vic", SwapDirection::Buy, 100_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, 100_000_000, 0),
        );
        let loss = compute_loss(&attack, pool).unwrap();
        assert!(loss.residual_bps_frontrun.is_none());
        assert!(loss.residual_bps_victim.is_none());
        assert!(loss.residual_bps_backrun.is_none());
    }

    /// When the parser observation differs from our model output by exactly
    /// 5%, the residual_bps comes back as 500. Sanity check on the bps
    /// arithmetic and sign convention (predicted > observed → positive).
    #[test]
    fn residuals_signed_and_in_basis_points() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let (fr_out, _) = pool.apply_swap(500_000_000, SwapDirection::Buy);
        // Observed = predicted × 0.95 → predicted is ~5.26% higher than
        // observed → residual_bps ≈ +526.
        let observed_smaller = (fr_out as f64 * 0.95) as u64;
        let attack = make_attack(
            swap(
                "f",
                "atk",
                SwapDirection::Buy,
                500_000_000,
                observed_smaller,
            ),
            swap("v", "vic", SwapDirection::Buy, 100_000_000, 1), // any nonzero
            swap("b", "atk", SwapDirection::Sell, 1, 1),
        );
        let loss = compute_loss(&attack, pool).unwrap();
        let residual = loss.residual_bps_frontrun.unwrap();
        // Predicted > observed → positive. Magnitude in the right ballpark.
        assert!(residual > 400 && residual < 700, "residual {residual}");
    }

    /// Pure sandwich: replaying the backrun on the post-frontrun pool with
    /// the victim *removed* leaves the attacker at a loss. Without the
    /// victim's price impact pushing the pool further, the backrun unwinds
    /// the frontrun against fees only — no extraction.
    #[test]
    fn counterfactual_attacker_negative_without_victim() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let (fr_out, _) = pool.apply_swap(500_000_000, SwapDirection::Buy);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 500_000_000, 0),
            swap("v", "vic", SwapDirection::Buy, 100_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, fr_out, 0),
        );

        let loss = compute_loss(&attack, pool).unwrap();
        assert!(
            loss.attacker_profit_real > 0,
            "with-victim profit should be positive for a sandwich",
        );
        assert!(
            loss.counterfactual_attacker_profit_no_victim <= 0,
            "without-victim profit should be ≤ 0 — extraction needs the victim, got {}",
            loss.counterfactual_attacker_profit_no_victim,
        );
    }

    // ----- Tier 3.3 — victim_loss confidence interval --------------------

    /// All amount_outs zero ⇒ residuals all None ⇒ no CI emitted. Sandwich
    /// detector still reports a victim_loss point estimate, but without a
    /// parser-observed reference there's no basis to widen it.
    #[test]
    fn victim_loss_ci_none_when_no_residuals_observed() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 500_000_000, 0),
            swap("v", "vic", SwapDirection::Buy, 100_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, 100_000_000, 0),
        );
        let loss = compute_loss(&attack, pool).unwrap();
        assert!(loss.victim_loss > 0);
        assert!(loss.victim_loss_lower.is_none());
        assert!(loss.victim_loss_upper.is_none());
    }

    /// Observations match the model exactly ⇒ residuals are all 0 ⇒ CI
    /// degenerates to `[point, point]`. The CI is *present* (we have
    /// observations to constrain it with) but zero-width.
    #[test]
    fn victim_loss_ci_collapses_when_residuals_zero() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let (fr_out, pool_1) = pool.apply_swap(500_000_000, SwapDirection::Buy);
        let (victim_out, pool_2) = pool_1.apply_swap(100_000_000, SwapDirection::Buy);
        let (back_out, _) = pool_2.apply_swap(fr_out, SwapDirection::Sell);

        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 500_000_000, fr_out),
            swap("v", "vic", SwapDirection::Buy, 100_000_000, victim_out),
            swap("b", "atk", SwapDirection::Sell, fr_out, back_out),
        );
        let loss = compute_loss(&attack, pool).unwrap();
        assert!(loss.victim_loss > 0);
        assert_eq!(loss.victim_loss_lower, Some(loss.victim_loss));
        assert_eq!(loss.victim_loss_upper, Some(loss.victim_loss));
    }

    /// Inject a 5% gap (~500 bps) on just the frontrun observation; leave
    /// victim and backrun observations zero so their residuals stay None.
    /// The CI half-width should track the single nonzero residual.
    #[test]
    fn victim_loss_ci_widens_with_residual_size() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let (fr_out, _) = pool.apply_swap(500_000_000, SwapDirection::Buy);
        let observed_smaller = (fr_out as f64 * 0.95) as u64;
        let attack = make_attack(
            swap(
                "f",
                "atk",
                SwapDirection::Buy,
                500_000_000,
                observed_smaller,
            ),
            swap("v", "vic", SwapDirection::Buy, 100_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, 100_000_000, 0),
        );
        let loss = compute_loss(&attack, pool).unwrap();
        let lower = loss.victim_loss_lower.expect("CI lower set");
        let upper = loss.victim_loss_upper.expect("CI upper set");
        assert!(lower <= loss.victim_loss && loss.victim_loss <= upper);
        // Half-width = max(|residual|) / 10000 ≈ 526 / 10000 ≈ 5.26%.
        let half_width_pct = (upper - lower) as f64 / 2.0 / loss.victim_loss as f64;
        assert!(
            (0.04..=0.07).contains(&half_width_pct),
            "expected ~5% half-width, got {half_width_pct}",
        );
    }

    /// Saturating-large residual (parser observed near-zero amount_out)
    /// triggers the ≥100% guard ⇒ CI suppressed rather than reported as
    /// a wildly inflated band.
    #[test]
    fn victim_loss_ci_suppressed_when_residual_saturates() {
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let attack = make_attack(
            // observed=1 forces residual_bps to saturate near i32::MAX —
            // model says "huge output", chain says "1 unit".
            swap("f", "atk", SwapDirection::Buy, 500_000_000, 1),
            swap("v", "vic", SwapDirection::Buy, 100_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, 100_000_000, 0),
        );
        let loss = compute_loss(&attack, pool).unwrap();
        assert!(loss.victim_loss > 0);
        assert!(loss.victim_loss_lower.is_none());
        assert!(loss.victim_loss_upper.is_none());
    }

    /// Loss point estimate ≤ 0 (e.g. malformed detection) ⇒ no CI. A
    /// confidence interval on a contradicted detection would invite false
    /// positives downstream.
    #[test]
    fn victim_loss_ci_none_when_loss_non_positive() {
        // Build a scenario where the victim doesn't actually lose: tiny
        // frontrun on a deep pool means counterfactual ≈ actual ≈ 0 loss.
        let pool = ConstantProduct::new(1_000_000_000_000, 1_000_000_000_000, 25, 10_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 1_000, 999),
            swap("v", "vic", SwapDirection::Buy, 1_000, 999),
            swap("b", "atk", SwapDirection::Sell, 1_000, 999),
        );
        let loss = compute_loss(&attack, pool).unwrap();
        assert!(loss.victim_loss <= 0);
        assert!(loss.victim_loss_lower.is_none());
        assert!(loss.victim_loss_upper.is_none());
    }

    // ----- Tier 3.4 — Whirlpool within-tick replay -----------------------

    fn make_whirlpool(liquidity: u128, tick: i32, spacing: u16) -> WhirlpoolPool {
        let sp = crate::orca_whirlpool::tick_math::sqrt_price_at_tick(tick);
        WhirlpoolPool {
            liquidity,
            sqrt_price_q64: sp,
            tick_current_index: tick,
            tick_spacing: spacing,
            fee_rate_hundredths_bps: 3_000,
        }
    }

    /// Happy-path within-tick sandwich: large pool, modest swap amounts
    /// that don't approach the next tick boundary. `base_is_token_a=true`
    /// means the parser oriented base = mint_a — Buy maps to b→a.
    #[test]
    fn whirlpool_within_tick_sandwich_produces_loss() {
        let pool_0 = make_whirlpool(1_000_000_000_000, 10, 64);

        // Pre-simulate the frontrun so the backrun's amount_in matches
        // what the attacker actually got out (same shape as
        // sandwich_produces_positive_victim_loss_and_profit above).
        // base=token_a, Buy ⇒ a_to_b=false.
        let (_, fr_out, _) = pool_0
            .apply_swap_within_tick(100_000_000, false, 3_000, 1_000_000)
            .expect("frontrun within-tick");

        let mut attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000_000, 0),
            swap("v", "vic", SwapDirection::Buy, 10_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, 0, 0),
        );
        attack.backrun.amount_in = fr_out as u64;

        let loss = compute_loss_whirlpool(&attack, pool_0, 3_000, 1_000_000, true, &[])
            .expect("within-tick replay should succeed on this fixture");
        assert!(
            loss.victim_loss > 0,
            "expected positive victim loss, got {}",
            loss.victim_loss,
        );
        assert!(loss.actual_victim_out < loss.counterfactual_victim_out);
        assert!(loss.price_impact_bps > 0);
    }

    /// Cross-tick attempt: tiny liquidity + huge frontrun ⇒
    /// apply_swap_within_tick bails on the very first leg, and
    /// compute_loss_whirlpool propagates None. Caller (enrich_attack)
    /// uses this to route the attack to CrossTickUnsupported.
    #[test]
    fn whirlpool_cross_tick_returns_none() {
        let pool_0 = make_whirlpool(1_000, 10, 64);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 1_000_000_000, 0),
            swap("v", "vic", SwapDirection::Buy, 1, 0),
            swap("b", "atk", SwapDirection::Sell, 1, 0),
        );
        assert!(compute_loss_whirlpool(&attack, pool_0, 3_000, 1_000_000, true, &[]).is_none(),);
    }

    /// Direction mismatch (victim opposite frontrun) — same invariant
    /// the ConstantProduct path enforces, mirrored here.
    #[test]
    fn whirlpool_rejects_direction_mismatch() {
        let pool_0 = make_whirlpool(1_000_000_000_000, 10, 64);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000, 0),
            swap("v", "vic", SwapDirection::Sell, 100_000, 0),
            swap("b", "atk", SwapDirection::Sell, 100_000, 0),
        );
        assert!(compute_loss_whirlpool(&attack, pool_0, 3_000, 1_000_000, true, &[]).is_none(),);
    }

    #[test]
    fn whirlpool_rejects_same_direction_backrun() {
        let pool_0 = make_whirlpool(1_000_000_000_000, 10, 64);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000, 0),
            swap("v", "vic", SwapDirection::Buy, 100_000, 0),
            swap("b", "atk", SwapDirection::Buy, 100_000, 0),
        );
        assert!(compute_loss_whirlpool(&attack, pool_0, 3_000, 1_000_000, true, &[]).is_none(),);
    }

    /// Multi-LP TickArray fixture for the cross-tick test below. Same
    /// shape as the cross_tick_swap unit tests: LP1 covers `[-128,
    /// 128]` with 1B liquidity, LP2 covers `[-2048, 2048]` with 500M.
    /// Pool starts at tick=0 with both LPs active (1.5B total).
    fn double_lp_arrays() -> Vec<crate::orca_whirlpool::tick_array::ParsedTickArray> {
        use crate::orca_whirlpool::tick_array::{ParsedTickArray, TickData, TICK_ARRAY_SIZE};
        fn array(start: i32, slots: &[(usize, i128)]) -> ParsedTickArray {
            let mut ticks = [TickData::default(); TICK_ARRAY_SIZE];
            for (i, net) in slots {
                ticks[*i] = TickData {
                    initialised: true,
                    liquidity_net: *net,
                };
            }
            ParsedTickArray {
                start_tick_index: start,
                ticks,
            }
        }
        vec![
            array(0, &[(2, -1_000_000_000), (32, -500_000_000)]),
            array(-5632, &[(86, 1_000_000_000), (56, 500_000_000)]),
        ]
    }

    /// Cross-tick fallback fires when within-tick can't resolve a leg.
    /// Pool sits at tick=0 with sqrt_price exactly on the lower boundary
    /// of the active band (`apply_swap_within_tick` bails on a→b right
    /// away). With `tick_arrays` supplied, `compute_loss_whirlpool`
    /// routes through `cross_tick_swap` and the replay succeeds.
    #[test]
    fn whirlpool_cross_tick_fallback_unblocks_boundary_starts() {
        use crate::orca_whirlpool::{swap_math, tick_math};
        let pool_0 = WhirlpoolPool {
            liquidity: 1_500_000_000,
            sqrt_price_q64: tick_math::sqrt_price_at_tick(0),
            tick_current_index: 0,
            tick_spacing: 64,
            fee_rate_hundredths_bps: 3_000,
        };
        let arrays = double_lp_arrays();

        // Sell-first sandwich with base=token_a ⇒ frontrun a→b. The pool's
        // sqrt_price sits exactly on the tick=0 boundary, so the
        // within-tick guard refuses the very first leg — the test would
        // be vacuous if `tick_arrays = &[]`.
        let mut attack = make_attack(
            swap("f", "atk", SwapDirection::Sell, 1_000_000, 0),
            swap("v", "vic", SwapDirection::Sell, 100_000, 0),
            swap("b", "atk", SwapDirection::Buy, 0, 0),
        );
        // Pre-simulate the frontrun (cross-tick) so backrun.amount_in
        // matches the attacker's actual output.
        let mut sorted = arrays.clone();
        sorted.sort_by_key(|a| std::cmp::Reverse(a.start_tick_index));
        let sorted: Vec<Option<_>> = sorted.into_iter().map(Some).collect();
        let fr = swap_math::cross_tick_swap(pool_0, 1_000_000, true, 3_000, 1_000_000, &sorted)
            .expect("frontrun cross-tick should resolve");
        attack.backrun.amount_in = fr.amount_out.min(u64::MAX as u128) as u64;

        // Within-tick only ⇒ first leg bails ⇒ replay fails.
        assert!(
            compute_loss_whirlpool(&attack, pool_0, 3_000, 1_000_000, true, &[]).is_none(),
            "without tick_arrays the boundary-seated pool can't be replayed",
        );

        // Cross-tick arrays supplied ⇒ fallback fires, replay succeeds.
        let loss = compute_loss_whirlpool(&attack, pool_0, 3_000, 1_000_000, true, &arrays)
            .expect("cross-tick fallback should resolve all legs");
        assert!(loss.victim_loss > 0, "got victim_loss={}", loss.victim_loss);
        assert!(loss.actual_victim_out < loss.counterfactual_victim_out);
    }

    /// Trace captures the per-step pool state so a reader can re-derive
    /// the swap arithmetic from raw sqrt_price / liquidity / tick.
    /// Pin the four checkpoints against the inputs the helper saw, plus
    /// the direction-correct sqrt_price drop (a→b ⇒ price decreasing).
    #[test]
    fn whirlpool_trace_captures_per_step_state() {
        let pool_0 = make_whirlpool(1_000_000_000_000, 10, 64);
        // Pre-simulate the frontrun (within-tick at this fixture) so the
        // backrun's amount_in matches the attacker's actual output.
        let (_, fr_out, _) = pool_0
            .apply_swap_within_tick(100_000_000, false, 3_000, 1_000_000)
            .expect("frontrun within-tick");
        let mut attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000_000, 0),
            swap("v", "vic", SwapDirection::Buy, 10_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, 0, 0),
        );
        attack.backrun.amount_in = fr_out as u64;

        let (loss, trace) =
            compute_loss_whirlpool_with_trace(&attack, pool_0, 3_000, 1_000_000, true, &[])
                .expect("within-tick replay should resolve");

        // Pre-frontrun checkpoint matches the input pool exactly.
        assert_eq!(trace.sqrt_price_pre, pool_0.sqrt_price_q64);
        assert_eq!(trace.liquidity_pre, pool_0.liquidity);
        assert_eq!(trace.tick_current_pre, pool_0.tick_current_index);

        // Buy-first sandwich with base_is_token_a=true ⇒ frontrun is
        // b→a ⇒ sqrt_price *rises*. Subsequent leg cycles back partway.
        assert!(trace.sqrt_price_post_front > trace.sqrt_price_pre);
        assert!(trace.sqrt_price_post_victim >= trace.sqrt_price_post_front);
        // Backrun is a→b (Sell) ⇒ sqrt_price drops back below post-victim.
        assert!(trace.sqrt_price_post_back < trace.sqrt_price_post_victim);

        // Within-tick path keeps liquidity constant across all four
        // checkpoints (no tick boundary crossed at this fixture's scale).
        assert_eq!(trace.liquidity_pre, trace.liquidity_post_front);
        assert_eq!(trace.liquidity_post_front, trace.liquidity_post_victim);
        assert_eq!(trace.liquidity_post_victim, trace.liquidity_post_back);

        // Trace's victim figures match the LossEstimate.
        assert_eq!(trace.actual_victim_out, loss.actual_victim_out);
        assert_eq!(
            trace.counterfactual_victim_out,
            loss.counterfactual_victim_out,
        );
        // Fee fields propagate.
        assert_eq!(trace.fee_num, 3_000);
        assert_eq!(trace.fee_den, 1_000_000);
    }

    /// `base_is_token_a=false` (base sits on token_b — happens when
    /// mint_a is the recognised quote, e.g. a SOL-quoted pool with SOL
    /// on the a-side and the memecoin on the b-side). The a/b swap
    /// direction flips relative to the base_is_token_a=true case, but
    /// the loss accounting compensates via `quote_per_base = 1/spot`,
    /// so the same-shape sandwich still produces a positive victim
    /// loss.
    #[test]
    fn whirlpool_base_on_token_b_produces_loss_too() {
        let pool_0 = make_whirlpool(1_000_000_000_000, 10, 64);
        // base=token_b, Buy ⇒ a_to_b=true.
        let (_, fr_out, _) = pool_0
            .apply_swap_within_tick(100_000_000, true, 3_000, 1_000_000)
            .expect("frontrun within-tick");
        let mut attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000_000, 0),
            swap("v", "vic", SwapDirection::Buy, 10_000_000, 0),
            swap("b", "atk", SwapDirection::Sell, 0, 0),
        );
        attack.backrun.amount_in = fr_out as u64;

        let loss = compute_loss_whirlpool(&attack, pool_0, 3_000, 1_000_000, false, &[])
            .expect("within-tick replay should succeed (base on token_b)");
        assert!(loss.victim_loss > 0);
        assert!(loss.actual_victim_out < loss.counterfactual_victim_out);
    }

    // ----- Tier 4 — corpus expansion (golden + adversarial) --------------

    /// Sell-first happy-path mirror of
    /// `whirlpool_within_tick_sandwich_produces_loss`. The Buy-first case
    /// already pins one direction; this one guards against accidental
    /// asymmetry in the a/b axis mapping that could let only one
    /// direction extract victim loss.
    #[test]
    fn whirlpool_sell_first_sandwich_produces_loss() {
        let pool_0 = make_whirlpool(1_000_000_000_000, 10, 64);
        // base=token_a, Sell ⇒ a_to_b=true.
        let (_, fr_out, _) = pool_0
            .apply_swap_within_tick(100_000_000, true, 3_000, 1_000_000)
            .expect("frontrun within-tick");
        let mut attack = make_attack(
            swap("f", "atk", SwapDirection::Sell, 100_000_000, 0),
            swap("v", "vic", SwapDirection::Sell, 10_000_000, 0),
            swap("b", "atk", SwapDirection::Buy, 0, 0),
        );
        attack.backrun.amount_in = fr_out as u64;

        let loss = compute_loss_whirlpool(&attack, pool_0, 3_000, 1_000_000, true, &[])
            .expect("within-tick replay should succeed for Sell-first");
        assert!(
            loss.victim_loss > 0,
            "expected positive victim loss, got {}",
            loss.victim_loss,
        );
        assert!(loss.actual_victim_out < loss.counterfactual_victim_out);
        assert!(loss.price_impact_bps > 0);
    }

    /// Cross-tick replay surfaces a populated trace. The within-tick
    /// trace test pins the trace shape against the within-tick path; this
    /// test mirrors it for the cross-tick fallback path so a regression
    /// where the fallback drops trace fields gets caught.
    #[test]
    fn whirlpool_cross_tick_trace_captures_state_progression() {
        use crate::orca_whirlpool::{swap_math, tick_math};
        let pool_0 = WhirlpoolPool {
            liquidity: 1_500_000_000,
            sqrt_price_q64: tick_math::sqrt_price_at_tick(0),
            tick_current_index: 0,
            tick_spacing: 64,
            fee_rate_hundredths_bps: 3_000,
        };
        let arrays = double_lp_arrays();

        let mut attack = make_attack(
            swap("f", "atk", SwapDirection::Sell, 1_000_000, 0),
            swap("v", "vic", SwapDirection::Sell, 100_000, 0),
            swap("b", "atk", SwapDirection::Buy, 0, 0),
        );
        let mut sorted = arrays.clone();
        sorted.sort_by_key(|a| std::cmp::Reverse(a.start_tick_index));
        let sorted: Vec<Option<_>> = sorted.into_iter().map(Some).collect();
        let fr = swap_math::cross_tick_swap(pool_0, 1_000_000, true, 3_000, 1_000_000, &sorted)
            .expect("frontrun cross-tick should resolve");
        attack.backrun.amount_in = fr.amount_out.min(u64::MAX as u128) as u64;

        let (loss, trace) =
            compute_loss_whirlpool_with_trace(&attack, pool_0, 3_000, 1_000_000, true, &arrays)
                .expect("cross-tick replay should resolve");

        // Pre-state mirrors the fixture exactly.
        assert_eq!(trace.sqrt_price_pre, tick_math::sqrt_price_at_tick(0));
        assert_eq!(trace.liquidity_pre, 1_500_000_000);
        assert_eq!(trace.tick_current_pre, 0);

        // Sell-first sandwich: frontrun + victim are a→b ⇒ sqrt_price
        // strictly drops on each leg. Backrun is b→a ⇒ rises back up.
        assert!(trace.sqrt_price_post_front < trace.sqrt_price_pre);
        assert!(trace.sqrt_price_post_victim <= trace.sqrt_price_post_front);
        assert!(trace.sqrt_price_post_back > trace.sqrt_price_post_victim);

        // Trace's victim figures align with the LossEstimate (same data
        // source — just two views of the same replay).
        assert_eq!(trace.actual_victim_out, loss.actual_victim_out);
        assert_eq!(
            trace.counterfactual_victim_out,
            loss.counterfactual_victim_out,
        );
    }

    /// Adversarial: a Whirlpool with zero active liquidity can't service
    /// a swap. `cross_tick_swap`'s first guard rejects it (liquidity == 0
    /// short-circuit), so `compute_loss_whirlpool` returns None and the
    /// caller routes the attack to `CrossTickUnsupported`. Pin the
    /// short-circuit so a future relaxation (e.g. "walk into the next
    /// LP") doesn't silently change behaviour without a corresponding
    /// trace-shape decision.
    #[test]
    fn whirlpool_zero_liquidity_returns_none() {
        use crate::orca_whirlpool::tick_math;
        let pool_0 = WhirlpoolPool {
            liquidity: 0,
            sqrt_price_q64: tick_math::sqrt_price_at_tick(0),
            tick_current_index: 0,
            tick_spacing: 64,
            fee_rate_hundredths_bps: 3_000,
        };
        let arrays = double_lp_arrays();
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000, 0),
            swap("v", "vic", SwapDirection::Buy, 10_000, 0),
            swap("b", "atk", SwapDirection::Sell, 100_000, 0),
        );
        assert!(
            compute_loss_whirlpool(&attack, pool_0, 3_000, 1_000_000, true, &arrays).is_none(),
            "zero-liquidity pool should fail replay even with tick_arrays supplied",
        );
    }

    // ----- DLMM (Phase 2 cross-bin) --------------------------------------
    //
    // Phase 2 replays the sandwich through `cross_bin_swap` so cross-bin
    // walks produce real (non-zero) victim_loss. Within-bin sandwiches
    // still satisfy the constant-sum invariant (loss = 0) since the
    // walker terminates after one bin and active_id doesn't move.

    use crate::meteora_dlmm::bin_array::{ParsedBin, MAX_BIN_PER_ARRAY};
    use solana_sdk::pubkey::Pubkey;

    fn dlmm_pool() -> DlmmPool {
        DlmmPool {
            active_id: 0,
            bin_step: 25,
            base_factor: 8000,
            base_fee_power_factor: 0,
            protocol_share: 0,
        }
    }

    /// Build a 1-array window where every bin holds the supplied
    /// reserves. Array index 0 ⇒ bins `[0, 69]` ⇒ `pool.active_id = 0`
    /// lands at `bins[0]`. Bin price stays lazy-cached (`0`) so the
    /// `DlmmBinState::from_arrays` path exercises the recompute branch.
    fn dlmm_uniform_window(amount_x: u64, amount_y: u64) -> Vec<ParsedBinArray> {
        let bins = (0..MAX_BIN_PER_ARRAY)
            .map(|_| ParsedBin {
                amount_x,
                amount_y,
                price: 0,
                liquidity_supply: 1_000_000_000,
            })
            .collect();
        vec![ParsedBinArray {
            index: 0,
            version: 1,
            lb_pair: Pubkey::new_unique(),
            bins,
        }]
    }

    /// Within-bin sandwich: comfortable reserves, walker terminates in
    /// one iteration per leg, `victim_loss = 0` per the constant-sum
    /// invariant, `price_impact_bps = 0` (active_id didn't move).
    #[test]
    fn dlmm_within_bin_sandwich_yields_zero_loss() {
        let pool = dlmm_pool();
        let arrays = dlmm_uniform_window(1_000_000_000, 1_000_000_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000, 0),
            swap("v", "vic", SwapDirection::Buy, 50_000, 0),
            swap("b", "atk", SwapDirection::Sell, 100_000, 0),
        );
        let loss = compute_loss_dlmm(&attack, &pool, &arrays, true).unwrap();
        assert_eq!(
            loss.victim_loss, 0,
            "within-bin replay must yield zero loss"
        );
        assert_eq!(loss.actual_victim_out, loss.counterfactual_victim_out);
        assert_eq!(loss.price_impact_bps, 0);
    }

    /// Cross-bin sandwich whose walker exits the supplied window: tiny
    /// bin reserves + 1B input ⇒ walker drains every bin in the array
    /// and runs out of window ⇒ `cross_bin_swap` returns `None` ⇒
    /// enrich reports `CrossTickUnsupported`. Replaces the old "any
    /// drain ⇒ None" Phase 1 contract.
    #[test]
    fn dlmm_cross_bin_out_of_window_returns_none() {
        let pool = dlmm_pool();
        // 70 bins * 100 Y = 7_000 Y; need much more X to drain that.
        let arrays = dlmm_uniform_window(0, 100);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 1_000_000_000, 0),
            swap("v", "vic", SwapDirection::Buy, 50_000, 0),
            swap("b", "atk", SwapDirection::Sell, 1_000_000_000, 0),
        );
        assert!(compute_loss_dlmm(&attack, &pool, &arrays, true).is_none());
    }

    /// Direction mismatch bails before any cross-bin work.
    #[test]
    fn dlmm_rejects_direction_mismatch() {
        let pool = dlmm_pool();
        let arrays = dlmm_uniform_window(1_000_000_000, 1_000_000_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000, 0),
            swap("v", "vic", SwapDirection::Sell, 50_000, 0),
            swap("b", "atk", SwapDirection::Sell, 100_000, 0),
        );
        assert!(compute_loss_dlmm(&attack, &pool, &arrays, true).is_none());
    }

    /// `base_is_token_a = false` (base on y-axis): exercise the
    /// SwapDirection ⇒ swap_for_y mapping flip. Within-bin so loss = 0,
    /// but the !base_is_token_a branch runs.
    #[test]
    fn dlmm_within_bin_base_is_y_axis() {
        let pool = dlmm_pool();
        let arrays = dlmm_uniform_window(1_000_000_000, 1_000_000_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 100_000, 0),
            swap("v", "vic", SwapDirection::Buy, 50_000, 0),
            swap("b", "atk", SwapDirection::Sell, 100_000, 0),
        );
        let loss = compute_loss_dlmm(&attack, &pool, &arrays, false).unwrap();
        assert_eq!(loss.victim_loss, 0);
        assert_eq!(loss.actual_victim_out, loss.counterfactual_victim_out);
    }

    /// Cross-bin sandwich that *fits* in the window: a multi-bin
    /// frontrun moves active_id, victim eats worse-priced bins ⇒
    /// `victim_loss > 0` and `price_impact_bps > 0`. Pin the Phase 2
    /// promise: real DLMM extraction surfaces here.
    #[test]
    fn dlmm_cross_bin_within_window_produces_loss() {
        let pool = dlmm_pool();
        // Each bin holds 1k of *both* axes — Buy direction means Y→X
        // (since base = token_a), so we need x reserves to drain.
        // Walker advances a handful of bins (frontrun consumes ~5k X),
        // staying inside array 0's bin range [0, 69].
        let arrays = dlmm_uniform_window(1_000, 1_000);
        let attack = make_attack(
            swap("f", "atk", SwapDirection::Buy, 5_000, 0),
            swap("v", "vic", SwapDirection::Buy, 5_000, 0),
            swap("b", "atk", SwapDirection::Sell, 5_000, 0),
        );
        let loss = compute_loss_dlmm(&attack, &pool, &arrays, true).unwrap();
        // Cross-bin walk: active_id moved, victim ate worse prices.
        // The exact loss depends on the price progression, but it
        // must be non-zero.
        assert!(
            loss.actual_victim_out < loss.counterfactual_victim_out,
            "actual={} expected < counterfactual={}",
            loss.actual_victim_out,
            loss.counterfactual_victim_out,
        );
        // price_impact_bps = bins_moved * bin_step. With bin_step=25
        // and a handful of bins moved, expect >0.
        assert!(loss.price_impact_bps > 0);
    }
}
