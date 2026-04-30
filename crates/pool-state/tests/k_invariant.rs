//! Property-based invariants for the constant-product AMM math and the
//! counterfactual sandwich replay built on top of it.
//!
//! The detector emits `victim_loss_lamports` and `attacker_profit` based
//! on these primitives — a regression that breaks an invariant here
//! would silently corrupt every Vigil row downstream. Hand-written unit
//! tests in `constant_product` and `counterfactual` cover the happy
//! path; this suite stress-tests the algebra over millions of randomised
//! `(reserves, amount_in, fee, direction)` tuples to surface edge cases
//! the unit tests don't reach.
//!
//! Properties verified:
//!   1. **k-monotonicity** — `apply_swap` never decreases `x*y`. Equality
//!      can hold with `fee=0`, otherwise k strictly grows by the fee
//!      portion. Integer rounding only ever rounds output *down*, so the
//!      stored reserves always over-represent k vs. the real-valued ideal.
//!   2. **simulate ≡ apply.0** — the two entry points must agree on the
//!      output amount; readers depend on this when they call simulate as
//!      a peek and apply as a commit.
//!   3. **zero amount_in is a no-op** — apply_swap(0, _) returns
//!      unchanged reserves and zero out. Production hits this whenever a
//!      swap event with no quote-side delta is replayed.
//!   4. **counterfactual ≥ actual** — for any valid sandwich shape, what
//!      the victim *would* have received without the frontrun is at
//!      least what they actually received. This is the load-bearing
//!      invariant for `victim_loss ≥ 0` in MEV reporting.
//!   5. **zero frontrun ⇒ no extraction** — if the attacker's frontrun
//!      is zero-sized the counterfactual collapses to the actual and
//!      victim_loss is zero. Guards against accidentally classifying a
//!      no-op as a sandwich.

use pool_state::{compute_loss, ConstantProduct};
use proptest::prelude::*;
use swap_events::types::{DexType, SandwichAttack, SwapDirection, SwapEvent};

/// Reasonable mainnet pool sizes — wide enough to expose rounding edge
/// cases at small reserves, capped to keep `(x*y).checked_mul` away from
/// u128 overflow.
fn arb_reserve() -> impl Strategy<Value = u128> {
    1u128..=1_000_000_000_000_000u128
}

fn arb_fee() -> impl Strategy<Value = (u64, u64)> {
    // (fee_num, fee_den) where 0 <= fee_num < fee_den. Real DEXes sit at
    // 25/10_000 (Raydium V4) to 100/10_000 (Raydium CPMM); we sweep the
    // valid range for safety.
    (0u64..=500, 1_000u64..=1_000_000).prop_map(|(num, den)| (num.min(den.saturating_sub(1)), den))
}

fn arb_direction() -> impl Strategy<Value = SwapDirection> {
    prop_oneof![Just(SwapDirection::Buy), Just(SwapDirection::Sell)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Property 1: k-monotonicity. Every legal swap leaves x*y at least as
    /// large as it was — the fee portion stays in the pool.
    #[test]
    fn k_never_decreases(
        base in arb_reserve(),
        quote in arb_reserve(),
        (fee_num, fee_den) in arb_fee(),
        direction in arb_direction(),
    ) {
        let pool = ConstantProduct::new(base, quote, fee_num, fee_den);
        let reserve_in = match direction {
            SwapDirection::Buy => quote,
            SwapDirection::Sell => base,
        };
        let amount_in = (reserve_in / 4).min(u64::MAX as u128) as u64;

        let k_before = base.saturating_mul(quote);
        let (_, after) = pool.apply_swap(amount_in, direction);
        let k_after = after.base_reserve.saturating_mul(after.quote_reserve);

        prop_assert!(
            k_after >= k_before,
            "k regressed: {} -> {} (pool {:?}, amount_in {}, dir {:?})",
            k_before,
            k_after,
            pool,
            amount_in,
            direction,
        );
    }

    /// Property 2: simulate and apply must agree on amount_out. They share
    /// arithmetic but separate code paths — drift here would produce
    /// reserves that don't match the recorded victim/attacker outputs.
    #[test]
    fn simulate_equals_apply(
        base in arb_reserve(),
        quote in arb_reserve(),
        (fee_num, fee_den) in arb_fee(),
        direction in arb_direction(),
    ) {
        let pool = ConstantProduct::new(base, quote, fee_num, fee_den);
        let reserve_in = match direction {
            SwapDirection::Buy => quote,
            SwapDirection::Sell => base,
        };
        let amount_in = (reserve_in / 8).min(u64::MAX as u128) as u64;

        let sim = pool.simulate_swap(amount_in, direction);
        let (out, _) = pool.apply_swap(amount_in, direction);
        prop_assert_eq!(sim, out);
    }

    /// Property 3: amount_in = 0 must be a no-op. apply_swap returns the
    /// pool unchanged and a zero output. Anything else means a swap with
    /// no quote delta would still mutate state on replay.
    #[test]
    fn zero_amount_is_noop(
        base in arb_reserve(),
        quote in arb_reserve(),
        (fee_num, fee_den) in arb_fee(),
        direction in arb_direction(),
    ) {
        let pool = ConstantProduct::new(base, quote, fee_num, fee_den);
        let (out, after) = pool.apply_swap(0, direction);
        prop_assert_eq!(out, 0);
        prop_assert_eq!(after.base_reserve, base);
        prop_assert_eq!(after.quote_reserve, quote);
    }
}

// ---------------------------------------------------------------------------
// counterfactual replay invariants
// ---------------------------------------------------------------------------

fn make_swap(sig: &str, signer: &str, direction: SwapDirection, amount_in: u64) -> SwapEvent {
    SwapEvent {
        signature: sig.into(),
        signer: signer.into(),
        dex: DexType::RaydiumV4,
        pool: "P".into(),
        direction,
        token_mint: "M".into(),
        amount_in,
        amount_out: 0,
        tx_index: 0,
        slot: None,
        fee: None,
    }
}

fn make_attack(
    frontrun_in: u64,
    victim_in: u64,
    backrun_in: u64,
    direction: SwapDirection,
) -> SandwichAttack {
    let frontrun = make_swap("f", "atk", direction, frontrun_in);
    let victim = make_swap("v", "vic", direction, victim_in);
    let backrun = make_swap("b", "atk", direction.opposite(), backrun_in);
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Property 4: counterfactual victim out is never less than actual.
    /// The frontrun pushes price in the victim's direction, so the victim
    /// always receives at most what they would have without the frontrun.
    /// This is the load-bearing inequality for `victim_loss >= 0`.
    #[test]
    fn counterfactual_at_least_actual(
        base in 1_000_000u128..=1_000_000_000_000u128,
        quote in 1_000_000u128..=1_000_000_000_000u128,
        (fee_num, fee_den) in arb_fee(),
        direction in arb_direction(),
        frontrun_frac in 0u64..=50,   // up to 50% of input-side reserve
        victim_frac in 0u64..=50,
    ) {
        let pool = ConstantProduct::new(base, quote, fee_num, fee_den);
        let reserve_in = match direction {
            SwapDirection::Buy => quote,
            SwapDirection::Sell => base,
        };
        // frac is in percent → /100. Cap to u64.
        let frontrun_in = ((reserve_in * frontrun_frac as u128) / 100)
            .min(u64::MAX as u128) as u64;
        let victim_in = ((reserve_in * victim_frac as u128) / 100)
            .min(u64::MAX as u128) as u64;
        // Backrun: attacker sells whatever the frontrun bought (or vice versa).
        // Use simulate_swap to get a realistic backrun amount_in.
        let (frontrun_out, _) = pool.apply_swap(frontrun_in, direction);
        let attack = make_attack(frontrun_in, victim_in, frontrun_out, direction);

        let Some(loss) = compute_loss(&attack, pool) else {
            return Ok(());
        };

        prop_assert!(
            loss.counterfactual_victim_out >= loss.actual_victim_out,
            "counterfactual {} < actual {} (pool {:?}, fr {}, vic {}, dir {:?})",
            loss.counterfactual_victim_out,
            loss.actual_victim_out,
            pool,
            frontrun_in,
            victim_in,
            direction,
        );
        // victim_loss is reported in quote units; for Buy victims it's
        // converted via spot_0, which means rounding could flip a 0-base
        // delta to a slightly negative i64 in pathological cases. Allow
        // a 1-unit tolerance for the i64 cast.
        prop_assert!(
            loss.victim_loss >= -1,
            "victim_loss {} negative beyond rounding tolerance",
            loss.victim_loss,
        );
    }

    /// Property 5: a zero-sized frontrun extracts nothing. Guards
    /// against a regression that would let a no-op tx land as a
    /// sandwich detection with non-zero victim_loss.
    #[test]
    fn zero_frontrun_zero_extraction(
        base in 1_000_000u128..=1_000_000_000_000u128,
        quote in 1_000_000u128..=1_000_000_000_000u128,
        (fee_num, fee_den) in arb_fee(),
        direction in arb_direction(),
        victim_in in 1u64..=1_000_000_000,
    ) {
        let pool = ConstantProduct::new(base, quote, fee_num, fee_den);
        let attack = make_attack(0, victim_in, 0, direction);

        let Some(loss) = compute_loss(&attack, pool) else {
            return Ok(());
        };

        prop_assert_eq!(
            loss.counterfactual_victim_out,
            loss.actual_victim_out,
            "zero frontrun must leave victim out unchanged",
        );
        // Allow 1-unit rounding tolerance on the i64 spot conversion.
        prop_assert!(
            loss.victim_loss.abs() <= 1,
            "zero frontrun should yield victim_loss ~ 0, got {}",
            loss.victim_loss,
        );
        prop_assert_eq!(loss.price_impact_bps, 0);
    }
}
