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

use std::str::FromStr;

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

/// Whirlpool program ID on Solana mainnet. Used by [`tick_array::tick_array_pda`]
/// to derive the on-chain TickArray account address from `(whirlpool,
/// start_tick_index)`. Decoded once per call from the hardcoded base58 —
/// the cost is a few microseconds and we'd rather not pull a `pubkey!`
/// macro into the dependency graph just for a constant.
pub fn whirlpool_program_id() -> Pubkey {
    Pubkey::from_str("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc")
        .expect("whirlpool program id is a hardcoded valid base58 pubkey")
}

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

impl WhirlpoolPool {
    /// Apply an exact-input swap that stays *within* the current
    /// initialised tick range. The range is `[tick_lower, tick_upper]`
    /// where both bounds are multiples of `tick_spacing` and bracket
    /// `tick_current_index`; within that band liquidity is constant, so
    /// [`swap_math::compute_swap_step_exact_in`] resolves the result in a
    /// single call.
    ///
    /// Returns `None` if the swap would cross a tick boundary — the
    /// cross-tick path needs `liquidity_net` from the next initialised
    /// TickArray entry, which lands in step 3-γ/δ. The within-tick
    /// guard is also why the caller can rely on `liquidity` not
    /// changing in the returned pool.
    ///
    /// `a_to_b = true`  → token_a in, sqrt_price drops.
    /// `a_to_b = false` → token_b in, sqrt_price rises.
    ///
    /// Returns `(new_pool, amount_out, fee_amount)`. `amount_in +
    /// fee_amount` reflects the full gross input consumed (the
    /// `compute_swap_step_exact_in` invariant).
    pub fn apply_swap_within_tick(
        &self,
        amount_in: u128,
        a_to_b: bool,
        fee_num: u128,
        fee_den: u128,
    ) -> Option<(WhirlpoolPool, u128, u128)> {
        let tick_lower = floor_to_spacing(self.tick_current_index, self.tick_spacing as i32);
        let tick_upper = tick_lower + self.tick_spacing as i32;
        let target_sqrt_price = if a_to_b {
            tick_math::sqrt_price_at_tick(tick_lower)
        } else {
            tick_math::sqrt_price_at_tick(tick_upper)
        };
        let r = swap_math::compute_swap_step_exact_in(
            self.sqrt_price_q64,
            target_sqrt_price,
            self.liquidity,
            amount_in,
            fee_num,
            fee_den,
        )?;
        // Reaching the target means the segment ran out of curve before
        // amount_remaining did — i.e. the swap crossed the tick boundary.
        // That's outside this method's contract; bail.
        if r.sqrt_price_next == target_sqrt_price {
            return None;
        }
        let new_pool = WhirlpoolPool {
            sqrt_price_q64: r.sqrt_price_next,
            tick_current_index: tick_math::tick_at_sqrt_price_q64(r.sqrt_price_next),
            ..*self
        };
        Some((new_pool, r.amount_out, r.fee_amount))
    }
}

/// Floor `tick` to the nearest multiple of `spacing` ≤ `tick`. Rust's
/// integer division truncates toward zero, which mishandles negative
/// ticks (`-3 / 64 = 0` instead of the `-64` we need for the bracket
/// containing `-3`). This helper does the proper floor.
fn floor_to_spacing(tick: i32, spacing: i32) -> i32 {
    let q = tick / spacing;
    let r = tick % spacing;
    if r < 0 {
        (q - 1) * spacing
    } else {
        q * spacing
    }
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
    // Raydium V4: refuse to enrich memecoin/memecoin pairs. Track which
    // side base lands on (`base_is_token_a`) so the swap-math layer can
    // map SwapDirection → a_to_b correctly — Whirlpool's V3-style math
    // is keyed on a/b, not base/quote.
    let (vault_base, vault_quote, base_mint, quote_mint, base_is_token_a) =
        match (is_quote_mint(&mint_a_s), is_quote_mint(&mint_b_s)) {
            (true, false) => (
                vault_b.to_string(),
                vault_a.to_string(),
                mint_b_s,
                mint_a_s,
                // mint_a is quote ⇒ base sits on mint_b ⇒ token_b.
                false,
            ),
            (false, true) | (true, true) => (
                vault_a.to_string(),
                vault_b.to_string(),
                mint_a_s,
                mint_b_s,
                // mint_b is quote (or both are: pick mint_a as base) ⇒
                // base sits on mint_a ⇒ token_a.
                true,
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
        base_is_token_a,
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
    use crate::fixed_point::{mul_div_ceil, mul_div_floor};
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

    /// Token-a delta required to slide `sqrt_price` across the closed
    /// interval `[sp_lower, sp_upper]` at constant `liquidity`.
    ///
    /// Closed form:
    /// ```text
    ///   amount_a = L * Q64 * (sp_upper - sp_lower) / (sp_lower * sp_upper)
    /// ```
    ///
    /// `round_up = true` is the LP-protective direction (the LP receives at
    /// least this many tokens A); `false` is for the trader-receiving side
    /// (the trader receives at most this many). Mirrors V3
    /// `SqrtPriceMath::getAmount0Delta`.
    ///
    /// Returns `None` when:
    ///   * `liquidity == 0`,
    ///   * `sp_lower == 0` (would div-by-zero downstream),
    ///   * `sp_lower > sp_upper` (caller error — the helper requires a
    ///     pre-ordered pair),
    ///   * any U256 intermediate or the rounded result overflows `u128`.
    pub fn delta_amount_a(
        sp_lower: u128,
        sp_upper: u128,
        liquidity: u128,
        round_up: bool,
    ) -> Option<u128> {
        if liquidity == 0 || sp_lower == 0 || sp_lower > sp_upper {
            return None;
        }
        if sp_lower == sp_upper {
            return Some(0);
        }
        let numerator_1 = U256::from(liquidity) << 64;
        let numerator_2 = U256::from(sp_upper - sp_lower);
        let dividend = numerator_1.checked_mul(numerator_2)?;
        let result = if round_up {
            // V3: divRoundingUp(mulDivRoundingUp(N1, N2, sp_upper), sp_lower).
            // Two-step ceil: divide by the larger denominator first to keep
            // the intermediate small, then by the smaller.
            let denom_upper = U256::from(sp_upper);
            let q1 = dividend / denom_upper;
            let r1 = dividend % denom_upper;
            let upper_div = if r1.is_zero() {
                q1
            } else {
                q1.checked_add(U256::one())?
            };
            let denom_lower = U256::from(sp_lower);
            let q2 = upper_div / denom_lower;
            let r2 = upper_div % denom_lower;
            if r2.is_zero() {
                q2
            } else {
                q2.checked_add(U256::one())?
            }
        } else {
            // floor: dividend / sp_upper / sp_lower.
            dividend / U256::from(sp_upper) / U256::from(sp_lower)
        };
        if result.bits() > 128 {
            None
        } else {
            Some(result.low_u128())
        }
    }

    /// Token-b delta required to slide `sqrt_price` across `[sp_lower,
    /// sp_upper]` at constant `liquidity`. Closed form:
    /// ```text
    ///   amount_b = L * (sp_upper - sp_lower) / Q64
    /// ```
    /// Mirrors V3 `SqrtPriceMath::getAmount1Delta`.
    pub fn delta_amount_b(
        sp_lower: u128,
        sp_upper: u128,
        liquidity: u128,
        round_up: bool,
    ) -> Option<u128> {
        if liquidity == 0 || sp_lower > sp_upper {
            return None;
        }
        if sp_lower == sp_upper {
            return Some(0);
        }
        let diff = sp_upper - sp_lower;
        if round_up {
            mul_div_ceil(liquidity, diff, Q64)
        } else {
            mul_div_floor(liquidity, diff, Q64)
        }
    }

    /// Outcome of a single within-tick exact-input swap step.
    ///
    /// `amount_in` is the *consumed* portion (excluding fee); `fee_amount`
    /// is the LP cut taken from the gross `amount_remaining` the caller
    /// passed in. Invariant: `amount_in + fee_amount ≤ amount_remaining + 1`
    /// (the `+1` is V3's standard 1-unit ceiling slack on the fee path; we
    /// mirror it so chain-vs-replay diffs stay below detector resolution).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SwapStepResult {
        pub sqrt_price_next: u128,
        pub amount_in: u128,
        pub amount_out: u128,
        pub fee_amount: u128,
    }

    /// One within-tick step of an exact-input swap.
    ///
    /// The caller supplies the segment's target `sqrt_price` (the next
    /// initialised tick boundary or a user-imposed limit) along with the
    /// gross `amount_remaining`; the result tells the caller whether the
    /// segment ran to completion (`sqrt_price_next == sqrt_price_target`)
    /// or was capped by `amount_remaining`.
    ///
    /// Direction is inferred from `sqrt_price_target` vs `sqrt_price_current`:
    ///   * `current >= target` → a→b (token_a in, price drops),
    ///   * `current <  target` → b→a (token_b in, price rises).
    ///
    /// Mirrors V3 `SwapMath::computeSwapStep` with the exact-input branch
    /// only — sandwich replay never feeds an exact-output swap, so the
    /// negative-`amount_remaining` half is dead code we don't carry.
    ///
    /// `fee_num / fee_den` is the LP fee fraction (e.g. Whirlpool's 30bps
    /// pool: `fee_num=3000, fee_den=1_000_000`). Returns `None` on
    /// degenerate inputs (`liquidity == 0`, `fee_den == 0`,
    /// `fee_num >= fee_den`) or any arithmetic saturation downstream.
    pub fn compute_swap_step_exact_in(
        sqrt_price_current: u128,
        sqrt_price_target: u128,
        liquidity: u128,
        amount_remaining: u128,
        fee_num: u128,
        fee_den: u128,
    ) -> Option<SwapStepResult> {
        if liquidity == 0 || fee_den == 0 || fee_num >= fee_den {
            return None;
        }
        let zero_for_one = sqrt_price_current >= sqrt_price_target;
        // Strip the LP fee off `amount_remaining` so the curve-traversal
        // math sees only the net amount that actually moves sqrt_price.
        let amount_less_fee = mul_div_floor(amount_remaining, fee_den - fee_num, fee_den)?;

        // Amount needed to walk all the way to `target`. Round *up* — LP-
        // protective: we'd rather slightly under-advance than over-advance.
        let amount_in_to_target = if zero_for_one {
            delta_amount_a(sqrt_price_target, sqrt_price_current, liquidity, true)?
        } else {
            delta_amount_b(sqrt_price_current, sqrt_price_target, liquidity, true)?
        };

        // Does the remaining input cover the full segment, or are we
        // capped short of `target`?
        let (sqrt_price_next, reaches_target) = if amount_less_fee >= amount_in_to_target {
            (sqrt_price_target, true)
        } else if zero_for_one {
            (
                next_sqrt_price_a_in(sqrt_price_current, liquidity, amount_less_fee)?,
                false,
            )
        } else {
            (
                next_sqrt_price_b_in(sqrt_price_current, liquidity, amount_less_fee)?,
                false,
            )
        };

        // Recompute amount_in / amount_out at the resolved next price.
        // `amount_in` is rounded *up* (LP gets at least this much in);
        // `amount_out` is rounded *down* (trader gets at most this much
        // out). Both are LP-protective.
        let (amount_in, amount_out) = if zero_for_one {
            let lo = sqrt_price_next;
            let hi = sqrt_price_current;
            let a_in = if reaches_target {
                amount_in_to_target
            } else {
                delta_amount_a(lo, hi, liquidity, true)?
            };
            let b_out = delta_amount_b(lo, hi, liquidity, false)?;
            (a_in, b_out)
        } else {
            let lo = sqrt_price_current;
            let hi = sqrt_price_next;
            let b_in = if reaches_target {
                amount_in_to_target
            } else {
                delta_amount_b(lo, hi, liquidity, true)?
            };
            let a_out = delta_amount_a(lo, hi, liquidity, false)?;
            (b_in, a_out)
        };

        // Fee allocation. When the segment was cap-limited, *all* the
        // remaining gross gets consumed and the slack becomes the fee —
        // this is V3's `amountRemaining - amountIn` trick that ensures
        // `amount_in + fee_amount == amount_remaining` exactly on the
        // !reach path. When the segment ran to target, recompute the fee
        // proportional to the consumed `amount_in` (rounded up).
        let fee_amount = if !reaches_target {
            amount_remaining.checked_sub(amount_in)?
        } else {
            mul_div_ceil(amount_in, fee_num, fee_den - fee_num)?
        };

        Some(SwapStepResult {
            sqrt_price_next,
            amount_in,
            amount_out,
            fee_amount,
        })
    }
}

/// Whirlpool TickArray account: 88-tick chunk indexed by `start_tick_index`.
///
/// The cross-tick walk (step 3-δ) iterates across one or more arrays to
/// traverse a swap, applying `liquidity_net` at each crossed initialised
/// tick. This module covers parsing only — the walk algorithm itself
/// lives in [`swap_math`] (or its successor); we just expose the data it
/// needs.
///
/// Account layout (Anchor `#[account(zero_copy(unsafe))]`, `#[repr(C)]`):
/// ```text
///   field                            offset       size
///   discriminator                         0          8
///   start_tick_index: i32                 8          4
///   padding                              12          4    (i128 alignment)
///   ticks: [Tick; 88]                    16     88*128
///   whirlpool: Pubkey                 11280         32
/// ```
///
/// Each `Tick` (`#[repr(C)]` `bool + 15-pad + i128 + 4*u128 + [u128;3]`):
/// ```text
///   field                       inner offset  size
///   initialized: bool                       0    1
///   padding                                 1   15
///   liquidity_net: i128                    16   16
///   liquidity_gross: u128                  32   16
///   fee_growth_outside_a: u128             48   16
///   fee_growth_outside_b: u128             64   16
///   reward_growths_outside: [u128;3]       80   48
///   ----- total                                 128
/// ```
///
/// We deliberately drop everything but `initialized` and `liquidity_net`
/// — the cross-tick walk only crosses *initialised* ticks and only needs
/// the net delta to update active liquidity. The other fields are LP
/// accounting state that doesn't affect swap math.
///
/// Reference:
///   <https://github.com/orca-so/whirlpools/blob/main/programs/whirlpool/src/state/tick.rs>
pub mod tick_array {
    use solana_sdk::pubkey::Pubkey;

    /// Number of ticks per `TickArray` account (Whirlpool program
    /// constant — fixed by the on-chain layout).
    pub const TICK_ARRAY_SIZE: usize = 88;

    const DISCRIMINATOR_LEN: usize = 8;
    /// On-chain `Tick` size with `#[repr(C)]` padding.
    const TICK_LEN: usize = 128;

    const TICK_OFFSET_INITIALISED: usize = 0;
    const TICK_OFFSET_LIQUIDITY_NET: usize = 16;

    const OFFSET_START_TICK: usize = DISCRIMINATOR_LEN;
    /// Ticks start at offset 16: `start_tick_index` + 4 bytes of
    /// `#[repr(C)]` padding to align the i128 inside each Tick.
    const OFFSET_TICKS: usize = OFFSET_START_TICK + 4 + 4;
    /// Minimum account-data length covering every tick we read. The
    /// trailing `whirlpool: Pubkey` field is intentionally skipped — the
    /// caller already knows the parent pool, so re-parsing it is dead
    /// work.
    pub const MIN_LAYOUT_LEN: usize = OFFSET_TICKS + TICK_LEN * TICK_ARRAY_SIZE;

    /// Subset of on-chain `Tick` fields the cross-tick walk needs.
    ///
    /// `liquidity_gross`, `fee_growth_outside_*`, and
    /// `reward_growths_outside` are LP accounting and don't affect swap
    /// traversal — leaving them on the wire keeps the parser narrow.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct TickData {
        /// Whether an LP position has a boundary at this tick. Cross-
        /// tick walk skips uninitialised slots — `liquidity_net` is
        /// meaningless on those.
        pub initialised: bool,
        /// Net liquidity delta when crossing this tick in the b→a
        /// direction (tick increasing). Signed: LP position upper-edges
        /// subtract, lower-edges add. The a→b walk applies the
        /// negation (V3 convention).
        pub liquidity_net: i128,
    }

    /// One parsed TickArray account.
    #[derive(Debug, Clone)]
    pub struct ParsedTickArray {
        /// Tick index of the first slot. Always a multiple of
        /// `tick_spacing * TICK_ARRAY_SIZE`.
        pub start_tick_index: i32,
        pub ticks: [TickData; TICK_ARRAY_SIZE],
    }

    impl ParsedTickArray {
        /// Tick index of the slot at position `i` (0..[`TICK_ARRAY_SIZE`]).
        /// `tick_spacing` isn't stored on the array — it's a property of
        /// the parent Whirlpool — so the caller passes it in.
        pub fn tick_index_at(&self, i: usize, tick_spacing: u16) -> i32 {
            self.start_tick_index + (i as i32) * (tick_spacing as i32)
        }
    }

    /// Parse a `TickArray` account blob. Returns `None` for blobs shorter
    /// than [`MIN_LAYOUT_LEN`].
    ///
    /// `initialized` bytes other than `0` or `1` are treated as
    /// uninitialised — defensive against malformed accounts. The on-
    /// chain serialiser only ever writes `0` or `1`, so this only kicks
    /// in when something has corrupted the data.
    pub fn parse_tick_array(data: &[u8]) -> Option<ParsedTickArray> {
        if data.len() < MIN_LAYOUT_LEN {
            return None;
        }
        let start_tick_index = read_i32(data, OFFSET_START_TICK)?;
        let mut ticks = [TickData::default(); TICK_ARRAY_SIZE];
        for (i, slot) in ticks.iter_mut().enumerate() {
            let tick_offset = OFFSET_TICKS + i * TICK_LEN;
            let initialised_byte = *data.get(tick_offset + TICK_OFFSET_INITIALISED)?;
            let initialised = initialised_byte == 1;
            let liquidity_net = read_i128(data, tick_offset + TICK_OFFSET_LIQUIDITY_NET)?;
            *slot = TickData {
                initialised,
                liquidity_net,
            };
        }
        Some(ParsedTickArray {
            start_tick_index,
            ticks,
        })
    }

    /// Tick span (in ticks) one TickArray account covers, given the
    /// parent pool's `tick_spacing`. Always `TICK_ARRAY_SIZE *
    /// tick_spacing`.
    pub fn ticks_per_array_span(tick_spacing: u16) -> i32 {
        (tick_spacing as i32) * (TICK_ARRAY_SIZE as i32)
    }

    /// `start_tick_index` of the TickArray that contains `tick_current`.
    /// Always a multiple of `ticks_per_array_span(tick_spacing)`. Floors
    /// negative ticks toward `-∞` (Rust's `/` would round toward zero,
    /// landing in the array *above* a negative tick).
    pub fn start_tick_index_for(tick_current: i32, tick_spacing: u16) -> i32 {
        super::floor_to_spacing(tick_current, ticks_per_array_span(tick_spacing))
    }

    /// Whirlpool TickArray PDA. Seeds:
    /// `[b"tick_array", whirlpool, start_tick_index_decimal_string]`.
    /// Returned tuple is `(pda, bump)` from
    /// `Pubkey::find_program_address`.
    ///
    /// Note that the third seed is the *base-10 ASCII* of
    /// `start_tick_index` (including a leading minus for negatives) —
    /// not its little-endian byte representation. Mirroring the Whirlpool
    /// program's own derivation is the only thing that makes the PDA
    /// match the on-chain account.
    pub fn tick_array_pda(whirlpool: &Pubkey, start_tick_index: i32) -> (Pubkey, u8) {
        let start_str = start_tick_index.to_string();
        Pubkey::find_program_address(
            &[b"tick_array", whirlpool.as_ref(), start_str.as_bytes()],
            &super::whirlpool_program_id(),
        )
    }

    fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
        let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
        Some(i32::from_le_bytes(bytes))
    }

    fn read_i128(data: &[u8], offset: usize) -> Option<i128> {
        let bytes: [u8; 16] = data.get(offset..offset + 16)?.try_into().ok()?;
        Some(i128::from_le_bytes(bytes))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Build a synthetic TickArray blob with the given start index
        /// and a sparse list of `(slot, initialised, liquidity_net)`
        /// overrides. Bytes outside the overrides are zero.
        fn make_blob(start_tick_index: i32, overrides: &[(usize, bool, i128)]) -> Vec<u8> {
            let mut data = vec![0u8; MIN_LAYOUT_LEN];
            data[OFFSET_START_TICK..OFFSET_START_TICK + 4]
                .copy_from_slice(&start_tick_index.to_le_bytes());
            for (i, initialised, liquidity_net) in overrides {
                let tick_offset = OFFSET_TICKS + i * TICK_LEN;
                data[tick_offset + TICK_OFFSET_INITIALISED] = u8::from(*initialised);
                data[tick_offset + TICK_OFFSET_LIQUIDITY_NET
                    ..tick_offset + TICK_OFFSET_LIQUIDITY_NET + 16]
                    .copy_from_slice(&liquidity_net.to_le_bytes());
            }
            data
        }

        #[test]
        fn parse_extracts_start_tick_and_ticks() {
            let blob = make_blob(
                -2816, // 64 * 88 * (-1/2) — a plausible negative-region start.
                &[(5, true, 1_000_000_000), (44, true, -500_000_000)],
            );
            let p = parse_tick_array(&blob).unwrap();
            assert_eq!(p.start_tick_index, -2816);
            assert!(p.ticks[5].initialised);
            assert_eq!(p.ticks[5].liquidity_net, 1_000_000_000);
            assert!(p.ticks[44].initialised);
            assert_eq!(p.ticks[44].liquidity_net, -500_000_000);
            // Untouched slots default to uninitialised, zero net.
            assert!(!p.ticks[0].initialised);
            assert_eq!(p.ticks[0].liquidity_net, 0);
            assert!(!p.ticks[87].initialised);
        }

        #[test]
        fn parse_rejects_short_blob() {
            assert!(parse_tick_array(&[0u8; 100]).is_none());
            assert!(parse_tick_array(&vec![0u8; MIN_LAYOUT_LEN - 1]).is_none());
            assert!(parse_tick_array(&vec![0u8; MIN_LAYOUT_LEN]).is_some());
        }

        #[test]
        fn tick_index_at_uses_caller_supplied_spacing() {
            let p = parse_tick_array(&make_blob(0, &[])).unwrap();
            assert_eq!(p.tick_index_at(0, 64), 0);
            assert_eq!(p.tick_index_at(1, 64), 64);
            assert_eq!(p.tick_index_at(87, 64), 87 * 64);
            // Negative starts propagate cleanly.
            let p = parse_tick_array(&make_blob(-5632, &[])).unwrap();
            assert_eq!(p.tick_index_at(0, 64), -5632);
            assert_eq!(p.tick_index_at(10, 64), -5632 + 10 * 64);
        }

        #[test]
        fn non_canonical_initialised_byte_treated_as_uninitialised() {
            // bool serialisation is 0 or 1; anything else means the blob
            // has been tampered with or corrupted. Treat as
            // uninitialised so the walk doesn't mis-apply liquidity_net.
            let mut blob = make_blob(0, &[]);
            blob[OFFSET_TICKS + TICK_OFFSET_INITIALISED] = 0xFF;
            let p = parse_tick_array(&blob).unwrap();
            assert!(!p.ticks[0].initialised);
        }

        #[test]
        fn liquidity_net_round_trips_signed_extremes() {
            let blob = make_blob(
                0,
                &[(0, true, i128::MAX), (1, true, i128::MIN), (2, true, -1)],
            );
            let p = parse_tick_array(&blob).unwrap();
            assert_eq!(p.ticks[0].liquidity_net, i128::MAX);
            assert_eq!(p.ticks[1].liquidity_net, i128::MIN);
            assert_eq!(p.ticks[2].liquidity_net, -1);
        }

        #[test]
        fn start_tick_index_for_handles_positives_and_zero() {
            // tick_spacing=64 ⇒ array span = 88 * 64 = 5632.
            assert_eq!(start_tick_index_for(0, 64), 0);
            assert_eq!(start_tick_index_for(5631, 64), 0);
            assert_eq!(start_tick_index_for(5632, 64), 5632);
            assert_eq!(start_tick_index_for(11264, 64), 11264);
            assert_eq!(start_tick_index_for(11265, 64), 11264);
        }

        #[test]
        fn start_tick_index_for_floors_negatives_toward_minus_infinity() {
            // The case where Rust's `/` would land in the array *above*
            // (because trunc-toward-zero on negatives). Pin the proper
            // floor.
            assert_eq!(start_tick_index_for(-1, 64), -5632);
            assert_eq!(start_tick_index_for(-5632, 64), -5632);
            assert_eq!(start_tick_index_for(-5633, 64), -11264);
            assert_eq!(start_tick_index_for(-11264, 64), -11264);
        }

        #[test]
        fn ticks_per_array_span_is_size_times_spacing() {
            assert_eq!(ticks_per_array_span(1), 88);
            assert_eq!(ticks_per_array_span(64), 88 * 64);
            assert_eq!(ticks_per_array_span(128), 88 * 128);
        }

        #[test]
        fn tick_array_pda_is_deterministic() {
            // PDA derivation is content-addressable: same (pool,
            // start_tick_index) ⇒ same PDA. Pin determinism without
            // hardcoding a mainnet address — the program-id constant
            // already pins us to the right curve.
            let pool = Pubkey::new_unique();
            let (pda1, bump1) = tick_array_pda(&pool, 5632);
            let (pda2, bump2) = tick_array_pda(&pool, 5632);
            assert_eq!(pda1, pda2);
            assert_eq!(bump1, bump2);
            // Different start_tick_index ⇒ different PDA.
            let (pda_other, _) = tick_array_pda(&pool, 0);
            assert_ne!(pda1, pda_other);
            // Different pool ⇒ different PDA.
            let other_pool = Pubkey::new_unique();
            let (pda_other_pool, _) = tick_array_pda(&other_pool, 5632);
            assert_ne!(pda1, pda_other_pool);
        }

        #[test]
        fn tick_array_pda_handles_negative_start_tick_index() {
            // Negative starts go through `to_string()` ⇒ leading minus.
            // Mirror the Whirlpool program's seed exactly is what makes
            // the PDA match on-chain. Just pin determinism here; the
            // cross-tick walk's integration tests will exercise the
            // negative-index path against real fixtures.
            let pool = Pubkey::new_unique();
            let (pda, _) = tick_array_pda(&pool, -5632);
            assert_eq!(pda, tick_array_pda(&pool, -5632).0);
            assert_ne!(pda, tick_array_pda(&pool, 5632).0);
        }
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
        assert_eq!(
            tick_math::sqrt_price_at_tick(tick_math::MAX_TICK),
            u128::MAX
        );
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
        assert!(new_sp < sp, "expected drop, got new={new_sp} >= old={sp}",);
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
        assert_eq!(swap_math::next_sqrt_price_b_in(u128::MAX - 1, 1, 1), None,);
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

    // ----- delta_amount_a / delta_amount_b -----------------------------

    #[test]
    fn delta_amount_a_zero_diff_is_zero() {
        let sp = swap_math::Q64;
        assert_eq!(swap_math::delta_amount_a(sp, sp, 1_000_000, true), Some(0));
        assert_eq!(swap_math::delta_amount_a(sp, sp, 1_000_000, false), Some(0));
    }

    #[test]
    fn delta_amount_a_rejects_inverted_bounds() {
        // sp_lower > sp_upper is a caller error.
        let sp_lo = 2 * swap_math::Q64;
        let sp_hi = swap_math::Q64;
        assert_eq!(
            swap_math::delta_amount_a(sp_lo, sp_hi, 1_000_000, true),
            None
        );
    }

    #[test]
    fn delta_amount_a_round_up_is_at_least_round_down() {
        // Same segment, both directions. Round-up ≥ round-down by ≤1 unit.
        let sp_lo = swap_math::Q64;
        let sp_hi = sp_lo + (sp_lo / 1000); // +0.1%
        let l = 1_000_000_000u128;
        let up = swap_math::delta_amount_a(sp_lo, sp_hi, l, true).unwrap();
        let down = swap_math::delta_amount_a(sp_lo, sp_hi, l, false).unwrap();
        assert!(up >= down);
        // Ceiling-vs-floor differ by at most the two-step rounding (≤2).
        assert!(up - down <= 2);
    }

    #[test]
    fn delta_amount_b_zero_diff_is_zero() {
        let sp = swap_math::Q64;
        assert_eq!(swap_math::delta_amount_b(sp, sp, 1_000_000, true), Some(0));
    }

    #[test]
    fn delta_amount_b_round_up_is_floor_or_floor_plus_one() {
        // Single mul_div_floor vs mul_div_ceil ⇒ at most +1 unit.
        let sp_lo = swap_math::Q64;
        let sp_hi = sp_lo + 12_345;
        let l = 1_234_567_890u128;
        let up = swap_math::delta_amount_b(sp_lo, sp_hi, l, true).unwrap();
        let down = swap_math::delta_amount_b(sp_lo, sp_hi, l, false).unwrap();
        assert!(up == down || up == down + 1);
    }

    // ----- compute_swap_step_exact_in ----------------------------------

    /// 30 bps fee, healthy pool, modest amount. Caps short of an
    /// arbitrarily distant target ⇒ `!reach`, full `amount_remaining`
    /// consumed, sqrt_price drops (a→b).
    #[test]
    fn swap_step_a_to_b_capped_uses_all_remaining() {
        let sp_current = swap_math::Q64;
        let sp_target = swap_math::Q64 / 2; // far below — won't reach
        let l = 1_000_000_000u128;
        let amount = 100_000u128;
        let r = swap_math::compute_swap_step_exact_in(
            sp_current, sp_target, l, amount, 3_000, 1_000_000,
        )
        .unwrap();
        assert!(r.sqrt_price_next < sp_current);
        assert!(
            r.sqrt_price_next > sp_target,
            "shouldn't have reached target"
        );
        assert_eq!(r.amount_in + r.fee_amount, amount);
        assert!(r.amount_out > 0);
    }

    /// Same shape, b→a direction. Target far above current.
    #[test]
    fn swap_step_b_to_a_capped_uses_all_remaining() {
        let sp_current = swap_math::Q64;
        let sp_target = swap_math::Q64 * 2;
        let l = 1_000_000_000u128;
        let amount = 100_000u128;
        let r = swap_math::compute_swap_step_exact_in(
            sp_current, sp_target, l, amount, 3_000, 1_000_000,
        )
        .unwrap();
        assert!(r.sqrt_price_next > sp_current);
        assert!(r.sqrt_price_next < sp_target);
        assert_eq!(r.amount_in + r.fee_amount, amount);
        assert!(r.amount_out > 0);
    }

    /// Tiny target, oversized `amount_remaining` ⇒ `reach`, leftover
    /// stays in `amount_remaining - amount_in - fee_amount` (caller's
    /// next segment problem).
    #[test]
    fn swap_step_a_to_b_reaches_target_with_excess_remaining() {
        let sp_current = swap_math::Q64;
        let sp_target = sp_current - (sp_current / 10_000); // 1 bp drop, very close
        let l = 1_000_000_000u128;
        let amount = 1_000_000_000u128; // way more than needed
        let r = swap_math::compute_swap_step_exact_in(
            sp_current, sp_target, l, amount, 3_000, 1_000_000,
        )
        .unwrap();
        assert_eq!(r.sqrt_price_next, sp_target);
        // Reach path: amount_in + fee may overshoot amount_remaining by ≤1
        // due to V3's ceiling fee, but here amount is enormous so the
        // residual is well-defined.
        assert!(r.amount_in + r.fee_amount <= amount);
        assert!(r.amount_out > 0);
    }

    #[test]
    fn swap_step_rejects_zero_liquidity() {
        assert_eq!(
            swap_math::compute_swap_step_exact_in(
                swap_math::Q64,
                swap_math::Q64 / 2,
                0,
                100,
                3_000,
                1_000_000,
            ),
            None,
        );
    }

    #[test]
    fn swap_step_rejects_degenerate_fee() {
        let sp = swap_math::Q64;
        // fee >= den — non-physical.
        assert_eq!(
            swap_math::compute_swap_step_exact_in(sp, sp / 2, 1_000_000, 100, 1_000_000, 1_000_000),
            None,
        );
        assert_eq!(
            swap_math::compute_swap_step_exact_in(sp, sp / 2, 1_000_000, 100, 1, 0),
            None,
        );
    }

    proptest! {
        /// Fee balance: `amount_in + fee_amount` is bounded by
        /// `amount_remaining` on `!reach`, and by `amount_remaining + 1`
        /// on `reach` (V3's standard 1-unit ceiling slack on the fee
        /// recomputation). Direction-correct sqrt_price update either way.
        #[test]
        fn prop_swap_step_a_to_b_invariants(
            l in 1_000_000u128..1_000_000_000_000u128,
            sp_int in 2u128..(1u128 << 16),
            target_frac in 1u128..100u128, // target = current * (100 - target_frac) / 100
            amount in 1u128..1_000_000u128,
            fee_bps in 1u128..1_000u128, // up to 10 bps
        ) {
            let sp_current = sp_int * swap_math::Q64;
            let sp_target = sp_current * (100 - target_frac) / 100;
            let r = swap_math::compute_swap_step_exact_in(
                sp_current, sp_target, l, amount, fee_bps * 100, 1_000_000,
            );
            if let Some(r) = r {
                prop_assert!(r.sqrt_price_next <= sp_current);
                prop_assert!(r.sqrt_price_next >= sp_target);
                let total = r.amount_in.saturating_add(r.fee_amount);
                if r.sqrt_price_next == sp_target {
                    // reach: ≤ amount_remaining + 1 (ceiling fee slack)
                    prop_assert!(total <= amount + 1, "reach overshot: total={}, amount={}", total, amount);
                } else {
                    // !reach: exact equality
                    prop_assert_eq!(total, amount);
                }
            }
        }

        /// b→a mirror: sqrt_price rises, same fee balance shape.
        #[test]
        fn prop_swap_step_b_to_a_invariants(
            l in 1_000_000u128..1_000_000_000_000u128,
            sp_int in 1u128..(1u128 << 14),
            target_frac in 1u128..100u128,
            amount in 1u128..1_000_000u128,
            fee_bps in 1u128..1_000u128,
        ) {
            let sp_current = sp_int * swap_math::Q64;
            let sp_target = sp_current * (100 + target_frac) / 100;
            let r = swap_math::compute_swap_step_exact_in(
                sp_current, sp_target, l, amount, fee_bps * 100, 1_000_000,
            );
            if let Some(r) = r {
                prop_assert!(r.sqrt_price_next >= sp_current);
                prop_assert!(r.sqrt_price_next <= sp_target);
                let total = r.amount_in.saturating_add(r.fee_amount);
                if r.sqrt_price_next == sp_target {
                    prop_assert!(total <= amount + 1);
                } else {
                    prop_assert_eq!(total, amount);
                }
            }
        }
    }

    // ----- floor_to_spacing / apply_swap_within_tick --------------------

    #[test]
    fn floor_to_spacing_handles_positive_negative_and_exact() {
        // Exact multiples stay put.
        assert_eq!(floor_to_spacing(0, 64), 0);
        assert_eq!(floor_to_spacing(64, 64), 64);
        assert_eq!(floor_to_spacing(-64, 64), -64);
        // Positive non-multiple floors down toward zero.
        assert_eq!(floor_to_spacing(65, 64), 64);
        assert_eq!(floor_to_spacing(127, 64), 64);
        // Negative non-multiple floors *down* (toward -∞), not toward zero —
        // this is the case the naive `tick / spacing * spacing` gets wrong.
        assert_eq!(floor_to_spacing(-3, 64), -64);
        assert_eq!(floor_to_spacing(-65, 64), -128);
    }

    fn make_pool(
        sqrt_price_q64: u128,
        liquidity: u128,
        tick_current: i32,
        spacing: u16,
    ) -> WhirlpoolPool {
        WhirlpoolPool {
            liquidity,
            sqrt_price_q64,
            tick_current_index: tick_current,
            tick_spacing: spacing,
            fee_rate_hundredths_bps: 3000,
        }
    }

    /// Pool fixture seated *strictly inside* the `[tick_lower, tick_upper]`
    /// band so a→b and b→a both have room to move without hitting a
    /// boundary on the first sub-tick step.
    fn pool_inside_band() -> WhirlpoolPool {
        // tick = 10, spacing = 64 ⇒ tick_lower = 0, tick_upper = 64.
        // sqrt_price_at_tick(10) sits well between the two boundaries.
        let tick = 10;
        let sp = tick_math::sqrt_price_at_tick(tick);
        make_pool(sp, 1_000_000_000, tick, 64)
    }

    #[test]
    fn within_tick_a_to_b_small_amount_stays_in_range() {
        // Modest swap on a 1B-liquidity pool — well below the
        // tick_lower=0 boundary, so the result stays in-band.
        let pool = pool_inside_band();
        let (new_pool, out, fee) = pool
            .apply_swap_within_tick(100_000, true, 3_000, 1_000_000)
            .expect("within-tick swap should succeed");
        assert!(new_pool.sqrt_price_q64 < pool.sqrt_price_q64);
        // New tick stays within [tick_lower, tick_upper) = [0, 64).
        assert!(new_pool.tick_current_index >= 0);
        assert!(new_pool.tick_current_index < 64);
        assert!(out > 0);
        assert!(fee > 0);
        // Liquidity invariant within the tick range.
        assert_eq!(new_pool.liquidity, pool.liquidity);
    }

    #[test]
    fn within_tick_b_to_a_small_amount_stays_in_range() {
        let pool = pool_inside_band();
        let (new_pool, out, _fee) = pool
            .apply_swap_within_tick(100_000, false, 3_000, 1_000_000)
            .expect("within-tick swap should succeed");
        assert!(new_pool.sqrt_price_q64 > pool.sqrt_price_q64);
        assert!(out > 0);
    }

    #[test]
    fn within_tick_returns_none_when_swap_crosses_boundary() {
        // Same starting position as the success cases, but tiny liquidity
        // + huge amount means the swap walks past the boundary easily.
        // apply_swap_within_tick must bail rather than silently extrapolate
        // liquidity past where it's defined.
        let tick = 10;
        let sp = tick_math::sqrt_price_at_tick(tick);
        let pool = make_pool(sp, 1_000, tick, 64);
        assert!(pool
            .apply_swap_within_tick(u64::MAX as u128, true, 3_000, 1_000_000)
            .is_none());
    }

    #[test]
    fn within_tick_zero_liquidity_returns_none() {
        let tick = 10;
        let sp = tick_math::sqrt_price_at_tick(tick);
        let pool = make_pool(sp, 0, tick, 64);
        assert!(pool
            .apply_swap_within_tick(100, true, 3_000, 1_000_000)
            .is_none());
    }

    #[test]
    fn within_tick_at_lower_boundary_aborts_a_to_b() {
        // Pathological starting state: sqrt_price sits *exactly* on the
        // tick_lower boundary. An a→b swap can't proceed without crossing,
        // so the within-tick path bails — production callers should treat
        // this as the cross-tick walk's job (step 3-γ/δ).
        let pool = make_pool(swap_math::Q64, 1_000_000_000, 0, 64);
        assert!(pool
            .apply_swap_within_tick(100_000, true, 3_000, 1_000_000)
            .is_none());
    }

    #[test]
    fn within_tick_negative_tick_uses_correct_lower_bound() {
        // tick = -3, spacing 64 ⇒ tick_lower = -64, tick_upper = 0. An
        // a→b swap should target sqrt_price_at_tick(-64) and stay within
        // the band as long as it doesn't reach.
        let sp = tick_math::sqrt_price_at_tick(-3);
        let pool = make_pool(sp, 1_000_000_000, -3, 64);
        let (new_pool, _, _) = pool
            .apply_swap_within_tick(10_000, true, 3_000, 1_000_000)
            .expect("should stay within [-64, 0]");
        assert!(new_pool.sqrt_price_q64 < sp);
        assert!(new_pool.tick_current_index >= -64);
    }
}
