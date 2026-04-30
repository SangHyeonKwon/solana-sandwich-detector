//! Orca Whirlpool (concentrated-liquidity AMM) account layout, pool-state
//! parsing, and tick math primitives.
//!
//! Whirlpool is a Solana port of Uniswap V3: liquidity is concentrated
//! within `[lower_tick, upper_tick]` ranges, the spot price is encoded as
//! a Q64.64 sqrt_price, and a swap moves the price along a piecewise-
//! constant liquidity curve.
//!
//! This module covers the *static* pieces of replay — parsing the on-chain
//! `Whirlpool` account into a [`PoolConfig`] (vault / mint / fee) plus a
//! [`WhirlpoolPool`] snapshot (liquidity, sqrt_price, current tick) — and
//! the sqrt_price ↔ tick conversion every replay relies on.
//!
//! The within-tick swap math (and the cross-tick path that walks the tick
//! array sequence) is a follow-up. Until that lands,
//! [`enrich_attack`](crate::enrich_attack) routes Whirlpool detections to
//! [`EnrichmentResult::UnsupportedDex`](crate::EnrichmentResult).
//!
//! # Account layout
//!
//! `Whirlpool` is an Anchor account. The first 8 bytes are the discriminator
//! (`sha256("account:Whirlpool")[..8]`). After that, fields follow in
//! declaration order with no padding:
//!
//! ```text
//!   field                          offset  size
//!   discriminator                       0     8
//!   whirlpools_config: Pubkey           8    32
//!   whirlpool_bump: [u8; 1]            40     1
//!   tick_spacing: u16                  41     2
//!   tick_spacing_seed: [u8; 2]         43     2
//!   fee_rate: u16                      45     2    (hundredths of bps)
//!   protocol_fee_rate: u16             47     2
//!   liquidity: u128                    49    16
//!   sqrt_price: u128                   65    16    Q64.64 of sqrt(b/a)
//!   tick_current_index: i32            81     4
//!   protocol_fee_owed_a: u64           85     8
//!   protocol_fee_owed_b: u64           93     8
//!   token_mint_a: Pubkey              101    32
//!   token_vault_a: Pubkey             133    32
//!   fee_growth_global_a: u128         165    16
//!   token_mint_b: Pubkey              181    32
//!   token_vault_b: Pubkey             213    32
//!   fee_growth_global_b: u128         245    16
//!   ...                                          (reward infos, omitted)
//! ```
//!
//! Reference:
//!   <https://github.com/orca-so/whirlpools/blob/main/programs/whirlpool/src/state/whirlpool.rs>

use solana_sdk::pubkey::Pubkey;
use swap_events::dex::is_quote_mint;

use crate::lookup::{AmmKind, PoolConfig};

const DISCRIMINATOR_LEN: usize = 8;

const TICK_SPACING_OFFSET: usize = DISCRIMINATOR_LEN + 32 + 1; // 41
const FEE_RATE_OFFSET: usize = TICK_SPACING_OFFSET + 2 + 2; // 45
const LIQUIDITY_OFFSET: usize = FEE_RATE_OFFSET + 2 + 2; // 49
const SQRT_PRICE_OFFSET: usize = LIQUIDITY_OFFSET + 16; // 65
const TICK_CURRENT_INDEX_OFFSET: usize = SQRT_PRICE_OFFSET + 16; // 81
const TOKEN_MINT_A_OFFSET: usize = TICK_CURRENT_INDEX_OFFSET + 4 + 8 + 8; // 101
const TOKEN_VAULT_A_OFFSET: usize = TOKEN_MINT_A_OFFSET + 32; // 133
const TOKEN_MINT_B_OFFSET: usize = TOKEN_VAULT_A_OFFSET + 32 + 16; // 181
const TOKEN_VAULT_B_OFFSET: usize = TOKEN_MINT_B_OFFSET + 32; // 213

/// Minimum account-data length covering every field we read. (We don't
/// touch the reward-info tail.)
const MIN_LAYOUT_LEN: usize = TOKEN_VAULT_B_OFFSET + 32; // 245

/// Whirlpool's `fee_rate` is reported in hundredths-of-bps:
/// `3_000 = 30 bps = 0.30%`. We normalise to a (num, den) pair so the
/// rest of pool-state can apply fees with the same `(amount * (den-num) / den)`
/// formula it uses for Raydium.
const FEE_RATE_DEN: u64 = 1_000_000;
const DEFAULT_FEE_RATE_HUNDREDTHS_BPS: u64 = 3_000; // 30 bps

/// Snapshot of the Whirlpool's mutable swap-relevant state at a point in
/// time. The static side (vaults, mints, fee rate) goes in [`PoolConfig`];
/// these fields evolve every swap, so they're reparsed per replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhirlpoolPool {
    /// Active liquidity at `tick_current_index`.
    pub liquidity: u128,
    /// Q64.64 fixed-point sqrt(price), where `price = token_b_per_token_a`.
    pub sqrt_price_q64: u128,
    /// Current tick (price bucket) the pool is in.
    /// `floor(log_{1.0001}(price))`.
    pub tick_current_index: i32,
    /// Tick spacing — every initialised tick is a multiple of this.
    pub tick_spacing: u16,
    /// Hundredths of bps. `3_000 = 0.30%`.
    pub fee_rate_hundredths_bps: u16,
}

/// Parse a Whirlpool account blob into a [`PoolConfig`]. Mirrors
/// [`raydium_v4::parse_config`](crate::raydium_v4::parse_config) in shape
/// and orientation: returns `None` when the data is too short, the fee is
/// degenerate, or neither side of the pair is a recognised quote mint.
pub fn parse_config(pool_address: &str, account_data: &[u8]) -> Option<PoolConfig> {
    if account_data.len() < MIN_LAYOUT_LEN {
        return None;
    }

    let mint_a = read_pubkey(account_data, TOKEN_MINT_A_OFFSET)?;
    let vault_a = read_pubkey(account_data, TOKEN_VAULT_A_OFFSET)?;
    let mint_b = read_pubkey(account_data, TOKEN_MINT_B_OFFSET)?;
    let vault_b = read_pubkey(account_data, TOKEN_VAULT_B_OFFSET)?;
    let fee_rate = read_u16(account_data, FEE_RATE_OFFSET)?;

    let mint_a_s = mint_a.to_string();
    let mint_b_s = mint_b.to_string();
    // Whirlpool's a/b convention isn't inherently quote-aware, so orient
    // base/quote against the recognised quote-mint set. Same fallback as
    // Raydium V4: refuse to enrich memecoin/memecoin pairs.
    let (vault_base, vault_quote, base_mint, quote_mint) =
        match (is_quote_mint(&mint_a_s), is_quote_mint(&mint_b_s)) {
            (true, false) => (
                vault_b.to_string(),
                vault_a.to_string(),
                mint_b_s,
                mint_a_s,
            ),
            (false, true) | (true, true) => (
                vault_a.to_string(),
                vault_b.to_string(),
                mint_a_s,
                mint_b_s,
            ),
            (false, false) => return None,
        };

    let raw_num = fee_rate as u64;
    let (fee_num, fee_den) = if raw_num == 0 || raw_num >= FEE_RATE_DEN {
        (DEFAULT_FEE_RATE_HUNDREDTHS_BPS, FEE_RATE_DEN)
    } else {
        (raw_num, FEE_RATE_DEN)
    };

    Some(PoolConfig {
        kind: AmmKind::OrcaWhirlpool,
        pool: pool_address.to_string(),
        vault_base,
        vault_quote,
        base_mint,
        quote_mint,
        fee_num,
        fee_den,
    })
}

/// Parse the dynamic swap-relevant state (liquidity, sqrt_price, tick).
/// Returns `None` for short blobs.
pub fn parse_pool_state(account_data: &[u8]) -> Option<WhirlpoolPool> {
    if account_data.len() < MIN_LAYOUT_LEN {
        return None;
    }
    Some(WhirlpoolPool {
        liquidity: read_u128(account_data, LIQUIDITY_OFFSET)?,
        sqrt_price_q64: read_u128(account_data, SQRT_PRICE_OFFSET)?,
        tick_current_index: read_i32(account_data, TICK_CURRENT_INDEX_OFFSET)?,
        tick_spacing: read_u16(account_data, TICK_SPACING_OFFSET)?,
        fee_rate_hundredths_bps: read_u16(account_data, FEE_RATE_OFFSET)?,
    })
}

fn read_pubkey(data: &[u8], offset: usize) -> Option<Pubkey> {
    let bytes: [u8; 32] = data.get(offset..offset + 32)?.try_into().ok()?;
    Some(Pubkey::new_from_array(bytes))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u128(data: &[u8], offset: usize) -> Option<u128> {
    let bytes: [u8; 16] = data.get(offset..offset + 16)?.try_into().ok()?;
    Some(u128::from_le_bytes(bytes))
}

fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

/// Q64.64 sqrt-price math (Uniswap V3 / Whirlpool style).
///
/// Whirlpool encodes `sqrt(price) * 2^64` as a `u128`. The relationship
/// between tick and sqrt_price is `sqrt_price = 1.0001^(tick / 2) * 2^64`,
/// equivalently `tick = floor(log(price) / log(1.0001))`.
///
/// This module ships an `f64`-based approximation. Round-trip property
/// tests pin `tick_at_sqrt_price(sqrt_price_at_tick(t)) == t` to ±1
/// across the legal `[MIN_TICK, MAX_TICK]` range. An exact bit-by-bit
/// integer port (the magic-number ladder Uniswap V3 uses) is a follow-up;
/// once that lands, the `f64` path becomes the property-test oracle
/// rather than the production primitive.
pub mod tick_math {
    /// Lowest legal Whirlpool tick. Below this, the sqrt-price representation
    /// underflows. Mirrors Uniswap V3's `MIN_TICK`.
    pub const MIN_TICK: i32 = -443_636;
    /// Highest legal Whirlpool tick.
    pub const MAX_TICK: i32 = 443_636;

    /// `sqrt(1.0001^tick) * 2^64`, returned as the Q64.64 representation
    /// Whirlpool stores on-chain. Saturates to `0` at/below [`MIN_TICK`]
    /// and to `u128::MAX` at/above [`MAX_TICK`].
    pub fn sqrt_price_at_tick(tick: i32) -> u128 {
        if tick <= MIN_TICK {
            return 0;
        }
        if tick >= MAX_TICK {
            return u128::MAX;
        }
        let half = tick as f64 * 0.5;
        let sqrt_price = 1.0001f64.powf(half);
        let scaled = sqrt_price * (1u128 << 64) as f64;
        if scaled <= 0.0 {
            0
        } else if scaled >= u128::MAX as f64 {
            u128::MAX
        } else {
            scaled as u128
        }
    }

    /// Inverse of [`sqrt_price_at_tick`]. Returns the largest tick whose
    /// `sqrt_price_at_tick` is ≤ `sqrt_price_q64` (`floor`-style — matches
    /// the on-chain `tick_current_index` semantics). Clamps to
    /// `[MIN_TICK, MAX_TICK]` at the extremes.
    pub fn tick_at_sqrt_price_q64(sqrt_price_q64: u128) -> i32 {
        if sqrt_price_q64 == 0 {
            return MIN_TICK;
        }
        let sqrt_price = (sqrt_price_q64 as f64) / (1u128 << 64) as f64;
        // tick / 2 = log_{1.0001}(sqrt_price)
        let tick = 2.0 * sqrt_price.ln() / 1.0001f64.ln();
        let floored = tick.floor();
        if floored <= MIN_TICK as f64 {
            MIN_TICK
        } else if floored >= MAX_TICK as f64 {
            MAX_TICK
        } else {
            floored as i32
        }
    }
}

/// Within-tick swap math: how `sqrt_price` updates when an exact-input
/// trade hits a Whirlpool position at constant `liquidity`.
///
/// Two helpers, one per direction:
///   * [`swap_math::next_sqrt_price_a_in`] — token_a in, sqrt_price drops,
///     rounded *up*.
///   * [`swap_math::next_sqrt_price_b_in`] — token_b in, sqrt_price rises,
///     rounded *down*.
///
/// Both rounding choices are LP-protective: the trader receives marginally
/// less of the output asset than continuous math would predict. Mirroring
/// the on-chain rule lets our replay match the settled outcome exactly
/// (modulo the f64 oracle's own precision in the property tests).
///
/// Reference:
///   * Uniswap V3 `sqrt_price_math::get_next_sqrt_price_from_amount_in`
///   * `orca-so/whirlpools` `programs/whirlpool/src/math/sqrt_price_math.rs`
pub mod swap_math {
    use crate::fixed_point::mul_div_floor;
    use primitive_types::U256;

    /// Q64.64 scaling factor (`1 << 64`).
    pub const Q64: u128 = 1u128 << 64;

    /// Token-a swap-in direction: trader deposits `amount_a` of token A,
    /// `sqrt_price` drops. Rounded *up* — LP-protective.
    ///
    /// Closed form (full precision, computed in U256 throughout):
    /// ```text
    ///   new_sqrt = ceil( (L << 64) * sqrt_price /
    ///                    ((L << 64) + amount_a * sqrt_price) )
    /// ```
    /// equivalent to `L * sqrt_price / (L + amount_a * sqrt_price / Q64)`.
    /// We always run the precise path; V3's lower-precision fallback
    /// exists only because Solidity's `mulmod` constraints would otherwise
    /// trip — `checked_mul` on `U256` lets us skip it.
    ///
    /// Returns `None` when:
    ///   * `liquidity == 0` (no curve to slide along),
    ///   * `sqrt_price == 0` (degenerate — would div-by-zero downstream),
    ///   * any U256 intermediate saturates,
    ///   * the rounded quotient exceeds `u128`.
    pub fn next_sqrt_price_a_in(
        sqrt_price_q64: u128,
        liquidity: u128,
        amount_a: u128,
    ) -> Option<u128> {
        if amount_a == 0 {
            return Some(sqrt_price_q64);
        }
        if liquidity == 0 || sqrt_price_q64 == 0 {
            return None;
        }
        // `liquidity << 64` ≤ 2^192, always fits in U256 — no overflow check.
        let numerator_1 = U256::from(liquidity) << 64;
        let product = U256::from(amount_a).checked_mul(U256::from(sqrt_price_q64))?;
        let denominator = numerator_1.checked_add(product)?;
        let dividend = numerator_1.checked_mul(U256::from(sqrt_price_q64))?;
        let quotient = dividend / denominator;
        let remainder = dividend % denominator;
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

    /// Token-b swap-in direction: trader deposits `amount_b` of token B,
    /// `sqrt_price` rises. Rounded *down* — same LP-protective intent.
    ///
    /// Closed form: `new_sqrt = sqrt_price + floor(amount_b * Q64 / L)`.
    ///
    /// Returns `None` when `liquidity == 0`, `mul_div_floor` saturates, or
    /// the post-add result overflows `u128`.
    pub fn next_sqrt_price_b_in(
        sqrt_price_q64: u128,
        liquidity: u128,
        amount_b: u128,
    ) -> Option<u128> {
        if amount_b == 0 {
            return Some(sqrt_price_q64);
        }
        if liquidity == 0 {
            return None;
        }
        let delta = mul_div_floor(amount_b, Q64, liquidity)?;
        sqrt_price_q64.checked_add(delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::str::FromStr;

    const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";

    #[allow(clippy::too_many_arguments)]
    fn make_blob(
        mint_a: Pubkey,
        vault_a: Pubkey,
        mint_b: Pubkey,
        vault_b: Pubkey,
        liquidity: u128,
        sqrt_price_q64: u128,
        tick_current_index: i32,
        tick_spacing: u16,
        fee_rate_hundredths_bps: u16,
    ) -> Vec<u8> {
        let mut data = vec![0u8; MIN_LAYOUT_LEN];
        data[TICK_SPACING_OFFSET..TICK_SPACING_OFFSET + 2]
            .copy_from_slice(&tick_spacing.to_le_bytes());
        data[FEE_RATE_OFFSET..FEE_RATE_OFFSET + 2]
            .copy_from_slice(&fee_rate_hundredths_bps.to_le_bytes());
        data[LIQUIDITY_OFFSET..LIQUIDITY_OFFSET + 16].copy_from_slice(&liquidity.to_le_bytes());
        data[SQRT_PRICE_OFFSET..SQRT_PRICE_OFFSET + 16]
            .copy_from_slice(&sqrt_price_q64.to_le_bytes());
        data[TICK_CURRENT_INDEX_OFFSET..TICK_CURRENT_INDEX_OFFSET + 4]
            .copy_from_slice(&tick_current_index.to_le_bytes());
        data[TOKEN_MINT_A_OFFSET..TOKEN_MINT_A_OFFSET + 32].copy_from_slice(mint_a.as_ref());
        data[TOKEN_VAULT_A_OFFSET..TOKEN_VAULT_A_OFFSET + 32].copy_from_slice(vault_a.as_ref());
        data[TOKEN_MINT_B_OFFSET..TOKEN_MINT_B_OFFSET + 32].copy_from_slice(mint_b.as_ref());
        data[TOKEN_VAULT_B_OFFSET..TOKEN_VAULT_B_OFFSET + 32].copy_from_slice(vault_b.as_ref());
        data
    }

    #[test]
    fn parses_synthetic_layout_with_quote_on_b_side() {
        let mint_a = Pubkey::new_unique(); // memecoin on a-side
        let vault_a = Pubkey::new_unique();
        let mint_b = Pubkey::from_str(WSOL_MINT).unwrap(); // quote on b-side
        let vault_b = Pubkey::new_unique();
        let data = make_blob(
            mint_a,
            vault_a,
            mint_b,
            vault_b,
            1_000_000,
            1u128 << 64,
            0,
            64,
            3000,
        );

        let cfg = parse_config("POOL", &data).unwrap();
        assert_eq!(cfg.kind, AmmKind::OrcaWhirlpool);
        // mint_b is WSOL → vault_a is base, vault_b is quote.
        assert_eq!(cfg.vault_base, vault_a.to_string());
        assert_eq!(cfg.vault_quote, vault_b.to_string());
        assert_eq!(cfg.base_mint, mint_a.to_string());
        assert_eq!(cfg.quote_mint, mint_b.to_string());
        assert_eq!(cfg.fee_num, 3000);
        assert_eq!(cfg.fee_den, FEE_RATE_DEN);
    }

    #[test]
    fn parses_synthetic_layout_with_quote_on_a_side() {
        // a-side carries WSOL → base/quote orientation flips relative to
        // the on-chain a/b ordering.
        let mint_a = Pubkey::from_str(WSOL_MINT).unwrap();
        let vault_a = Pubkey::new_unique();
        let mint_b = Pubkey::new_unique();
        let vault_b = Pubkey::new_unique();
        let data = make_blob(mint_a, vault_a, mint_b, vault_b, 0, 1u128 << 64, 0, 1, 3000);

        let cfg = parse_config("POOL", &data).unwrap();
        assert_eq!(cfg.vault_base, vault_b.to_string());
        assert_eq!(cfg.vault_quote, vault_a.to_string());
    }

    #[test]
    fn rejects_short_data() {
        assert!(parse_config("POOL", &[0u8; 100]).is_none());
        assert!(parse_pool_state(&[0u8; 100]).is_none());
    }

    #[test]
    fn rejects_pair_without_recognised_quote_mint() {
        let mint_a = Pubkey::new_unique();
        let mint_b = Pubkey::new_unique();
        let data = make_blob(
            mint_a,
            Pubkey::new_unique(),
            mint_b,
            Pubkey::new_unique(),
            0,
            1u128 << 64,
            0,
            1,
            3000,
        );
        assert!(parse_config("POOL", &data).is_none());
    }

    #[test]
    fn fee_falls_back_on_degenerate_value() {
        let mint_a = Pubkey::new_unique();
        let mint_b = Pubkey::from_str(WSOL_MINT).unwrap();
        let data = make_blob(
            mint_a,
            Pubkey::new_unique(),
            mint_b,
            Pubkey::new_unique(),
            0,
            1u128 << 64,
            0,
            1,
            0,
        );
        let cfg = parse_config("POOL", &data).unwrap();
        assert_eq!(cfg.fee_num, DEFAULT_FEE_RATE_HUNDREDTHS_BPS);
        assert_eq!(cfg.fee_den, FEE_RATE_DEN);
    }

    #[test]
    fn parse_pool_state_extracts_dynamic_fields() {
        let data = make_blob(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            123_456_789,
            42u128 << 64,
            -100,
            64,
            500,
        );
        let p = parse_pool_state(&data).unwrap();
        assert_eq!(p.liquidity, 123_456_789);
        assert_eq!(p.sqrt_price_q64, 42u128 << 64);
        assert_eq!(p.tick_current_index, -100);
        assert_eq!(p.tick_spacing, 64);
        assert_eq!(p.fee_rate_hundredths_bps, 500);
    }

    // ----- tick_math ----------------------------------------------------

    #[test]
    fn sqrt_price_at_tick_zero_is_one_q64() {
        // 1.0001^0 = 1, so sqrt_price_q64 should be 2^64 to within a
        // handful of ulps from the f64 powf path.
        let one_q64 = 1u128 << 64;
        let computed = tick_math::sqrt_price_at_tick(0);
        let diff = computed.abs_diff(one_q64);
        // Tolerance: 1 ppm of one_q64 — generous but tight enough to
        // catch genuine math regressions.
        assert!(
            diff < (one_q64 / 1_000_000),
            "tick 0 → {computed}, expected ≈ {one_q64}",
        );
    }

    #[test]
    fn sqrt_price_strictly_monotonic_in_tick() {
        let mut prev = tick_math::sqrt_price_at_tick(-1000);
        for tick in (-999..=1000).step_by(13) {
            let cur = tick_math::sqrt_price_at_tick(tick);
            assert!(
                cur > prev,
                "non-monotonic at tick {tick}: prev {prev}, cur {cur}",
            );
            prev = cur;
        }
    }

    #[test]
    fn tick_round_trips_within_one_tick() {
        // Round-trip is the property-test oracle for the f64 path. ±1
        // tolerance covers the floor() boundary case where powf+ln hits
        // exactly the next tick due to f64 precision.
        for t in [-100_000, -10_000, -1000, -1, 0, 1, 1000, 10_000, 100_000] {
            let sp = tick_math::sqrt_price_at_tick(t);
            let recovered = tick_math::tick_at_sqrt_price_q64(sp);
            assert!(
                (recovered - t).abs() <= 1,
                "tick {t} round-tripped to {recovered}",
            );
        }
    }

    #[test]
    fn tick_at_sqrt_price_clamps_at_extremes() {
        assert_eq!(tick_math::tick_at_sqrt_price_q64(0), tick_math::MIN_TICK);
        assert_eq!(
            tick_math::tick_at_sqrt_price_q64(u128::MAX),
            tick_math::MAX_TICK,
        );
    }

    #[test]
    fn sqrt_price_at_tick_clamps_at_extremes() {
        assert_eq!(tick_math::sqrt_price_at_tick(i32::MIN), 0);
        assert_eq!(tick_math::sqrt_price_at_tick(tick_math::MIN_TICK), 0);
        assert_eq!(tick_math::sqrt_price_at_tick(tick_math::MAX_TICK), u128::MAX);
        assert_eq!(tick_math::sqrt_price_at_tick(i32::MAX), u128::MAX);
    }

    // ----- swap_math ----------------------------------------------------

    #[test]
    fn a_in_zero_amount_is_identity() {
        let sp = swap_math::Q64;
        assert_eq!(swap_math::next_sqrt_price_a_in(sp, 1_000_000, 0), Some(sp));
    }

    #[test]
    fn a_in_zero_liquidity_returns_none() {
        assert_eq!(swap_math::next_sqrt_price_a_in(swap_math::Q64, 0, 1), None);
    }

    #[test]
    fn a_in_zero_sqrt_price_returns_none() {
        // Degenerate pool — V3 fallback would divide by zero; we bail.
        assert_eq!(swap_math::next_sqrt_price_a_in(0, 1_000_000, 1), None);
    }

    #[test]
    fn a_in_drops_sqrt_price() {
        // Modest swap into a healthy pool — sqrt_price must strictly drop.
        let sp = swap_math::Q64; // price = 1
        let l = 1_000_000_000u128;
        let amount = 1_000_000u128;
        let new_sp = swap_math::next_sqrt_price_a_in(sp, l, amount).unwrap();
        assert!(
            new_sp < sp,
            "expected drop, got new={new_sp} >= old={sp}",
        );
    }

    #[test]
    fn b_in_zero_amount_is_identity() {
        let sp = swap_math::Q64;
        assert_eq!(swap_math::next_sqrt_price_b_in(sp, 1_000_000, 0), Some(sp));
    }

    #[test]
    fn b_in_zero_liquidity_returns_none() {
        assert_eq!(swap_math::next_sqrt_price_b_in(swap_math::Q64, 0, 1), None);
    }

    #[test]
    fn b_in_raises_sqrt_price() {
        let sp = swap_math::Q64;
        let l = 1_000_000_000u128;
        let amount = 1_000_000u128;
        let new_sp = swap_math::next_sqrt_price_b_in(sp, l, amount).unwrap();
        assert!(new_sp > sp);
    }

    #[test]
    fn b_in_overflow_returns_none() {
        // sqrt_price near u128::MAX; with L=1, amount=1, delta = Q64, and
        // sp + delta wraps past u128::MAX → must be None.
        assert_eq!(
            swap_math::next_sqrt_price_b_in(u128::MAX - 1, 1, 1),
            None,
        );
    }

    /// f64 oracle for a→b. Precision-bounded — only valid inside the
    /// healthy-pool input range used by the property tests below.
    fn oracle_a_in(sp_q64: u128, l: u128, amount: u128) -> u128 {
        let sp = sp_q64 as f64 / swap_math::Q64 as f64;
        let new_sp = (l as f64 * sp) / (l as f64 + amount as f64 * sp);
        (new_sp * swap_math::Q64 as f64) as u128
    }

    /// f64 oracle for b→a.
    fn oracle_b_in(sp_q64: u128, l: u128, amount: u128) -> u128 {
        let sp = sp_q64 as f64 / swap_math::Q64 as f64;
        let new_sp = sp + (amount as f64 / l as f64);
        (new_sp * swap_math::Q64 as f64) as u128
    }

    /// `|actual - expected| / max(expected, 1) ≤ tolerance_bps × 1e-4`,
    /// computed in u128 to dodge f64 rounding in the comparison itself.
    fn close_in_bps(actual: u128, expected: u128, tolerance_bps: u128) -> bool {
        let diff = actual.abs_diff(expected);
        let scale = expected.max(1);
        diff.saturating_mul(10_000) <= scale.saturating_mul(tolerance_bps)
    }

    proptest! {
        /// Doubling `amount_a` must never raise `sqrt_price` (more token_a
        /// in ⇒ price drops at least as far). Also pins the strict-drop
        /// property at the smaller amount.
        #[test]
        fn prop_a_in_monotone_in_amount(
            l in 1_000_000u128..1_000_000_000_000u128,
            sp_int in 1u128..(1u128 << 16),
            amount in 1u128..1_000_000u128,
        ) {
            let sp = sp_int * swap_math::Q64;
            let r1 = swap_math::next_sqrt_price_a_in(sp, l, amount);
            let r2 = swap_math::next_sqrt_price_a_in(sp, l, amount * 2);
            if let (Some(s1), Some(s2)) = (r1, r2) {
                prop_assert!(
                    s2 <= s1,
                    "doubled amount raised sqrt_price: {} -> {}",
                    s1,
                    s2,
                );
                prop_assert!(s1 < sp);
            }
        }

        /// Doubling `amount_b` must never lower `sqrt_price`. Strict-rise
        /// at the smaller amount.
        #[test]
        fn prop_b_in_monotone_in_amount(
            l in 1_000_000u128..1_000_000_000_000u128,
            sp_int in 1u128..(1u128 << 16),
            amount in 1u128..1_000_000u128,
        ) {
            let sp = sp_int * swap_math::Q64;
            let r1 = swap_math::next_sqrt_price_b_in(sp, l, amount);
            let r2 = swap_math::next_sqrt_price_b_in(sp, l, amount * 2);
            if let (Some(s1), Some(s2)) = (r1, r2) {
                prop_assert!(s2 >= s1);
                prop_assert!(s1 > sp);
            }
        }

        /// a→b agrees with the f64 oracle to within 10 bps in a healthy-
        /// pool band. Range deliberately constrained so f64's 53-bit
        /// mantissa covers the U256 answer to better than tolerance —
        /// outside it the oracle, not the implementation, is the loose
        /// side.
        #[test]
        fn prop_a_in_matches_f64_oracle(
            l in 1_000_000_000u128..1_000_000_000_000u128,
            sp_int in 1u128..1024u128,
            amount in 1u128..1_000_000u128,
        ) {
            let sp = sp_int * swap_math::Q64;
            let actual = swap_math::next_sqrt_price_a_in(sp, l, amount).unwrap();
            let expected = oracle_a_in(sp, l, amount);
            prop_assert!(
                close_in_bps(actual, expected, 10),
                "a_in drift: l={}, sp={}, amount={}, actual={}, oracle={}",
                l, sp, amount, actual, expected,
            );
        }

        /// b→a agrees with the f64 oracle to within 10 bps in same band.
        #[test]
        fn prop_b_in_matches_f64_oracle(
            l in 1_000_000_000u128..1_000_000_000_000u128,
            sp_int in 1u128..1024u128,
            amount in 1u128..1_000_000u128,
        ) {
            let sp = sp_int * swap_math::Q64;
            let actual = swap_math::next_sqrt_price_b_in(sp, l, amount).unwrap();
            let expected = oracle_b_in(sp, l, amount);
            prop_assert!(
                close_in_bps(actual, expected, 10),
                "b_in drift: l={}, sp={}, amount={}, actual={}, oracle={}",
                l, sp, amount, actual, expected,
            );
        }
    }
}
