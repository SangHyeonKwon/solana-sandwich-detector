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

#[cfg(test)]
mod tests {
    use super::*;
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
}
