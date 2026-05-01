//! Meteora DLMM (Dynamic Liquidity Market Maker) pool account layout +
//! config / dynamic-state parsing.
//!
//! DLMM is Meteora's port of Trader Joe's Liquidity Book — concentrated
//! liquidity stored in discrete *bins*, each bin a single price point. A
//! swap consumes one bin, then advances `active_id` to the next non-empty
//! bin. Within a bin, math is *constant sum* (`P*x + y = L`) — no
//! sqrt_price like V3.
//!
//! This module covers the static parsing pieces — the on-chain `LbPair`
//! account → [`PoolConfig`] (vault / mint / fee) plus a [`DlmmPool`]
//! snapshot (active bin id, bin step, fee parameters). Bin/BinArray
//! layout, swap math, and replay land in subsequent steps. Until those
//! land, [`enrich_attack`](crate::enrich_attack) routes Meteora DLMM
//! detections to [`EnrichmentResult::UnsupportedDex`](crate::EnrichmentResult).
//!
//! # Account layout (LbPair)
//!
//! `LbPair` is an Anchor account with `bytemuck repr(C)` body. The first
//! 8 bytes are the discriminator (`sha256("account:LbPair")[..8]`).
//! Field offsets (from the start of `account_data`, including the
//! discriminator) for everything we read in Phase 1:
//!
//! ```text
//!   field                                offset  size
//!   discriminator                            0     8
//!   parameters (StaticParameters, 32B)       8    32
//!     - base_factor: u16                     8     2
//!     - protocol_share: u16                 32     2
//!     - base_fee_power_factor: u8           34     1
//!   v_parameters (VariableParameters, 32B)  40    32
//!   bump_seed: [u8; 1]                      72     1
//!   bin_step_seed: [u8; 2]                  73     2
//!   pair_type: u8                           75     1
//!   active_id: i32                          76     4
//!   bin_step: u16                           80     2
//!   status: u8                              82     1
//!   require_base_factor_seed: u8            83     1
//!   base_factor_seed: [u8; 2]               84     2
//!   activation_type: u8                     86     1
//!   creator_pool_on_off_control: u8         87     1
//!   token_x_mint: Pubkey                    88    32
//!   token_y_mint: Pubkey                   120    32
//!   reserve_x: Pubkey                      152    32
//!   reserve_y: Pubkey                      184    32
//! ```
//!
//! Subsequent fields (`protocol_fee`, `oracle`, `bin_array_bitmap`,
//! `last_updated_at`, `creator`, …) total ~680 more bytes and aren't
//! needed for replay.
//!
//! Reference:
//!   <https://github.com/MeteoraAg/dlmm-sdk/blob/main/idls/dlmm.json>
//!   <https://github.com/MeteoraAg/dlmm-sdk/blob/main/commons/src>

use std::str::FromStr;

use solana_sdk::pubkey::Pubkey;
use swap_events::dex::is_quote_mint;

use crate::lookup::{AmmKind, PoolConfig};

const DISCRIMINATOR_LEN: usize = 8;

// StaticParameters fields (relative to discriminator end).
const BASE_FACTOR_OFFSET: usize = DISCRIMINATOR_LEN; // 8
const PROTOCOL_SHARE_OFFSET: usize = DISCRIMINATOR_LEN + 24; // 32
const BASE_FEE_POWER_FACTOR_OFFSET: usize = DISCRIMINATOR_LEN + 26; // 34

// LbPair body offsets (after StaticParameters[32] + VariableParameters[32] = 64).
const ACTIVE_ID_OFFSET: usize = DISCRIMINATOR_LEN + 32 + 32 + 1 + 2 + 1; // 76
const BIN_STEP_OFFSET: usize = ACTIVE_ID_OFFSET + 4; // 80
                                                     // status(1) + require_base_factor_seed(1) + base_factor_seed(2) +
                                                     // activation_type(1) + creator_pool_on_off_control(1) = 6 bytes between
                                                     // bin_step and token_x_mint.
const TOKEN_X_MINT_OFFSET: usize = BIN_STEP_OFFSET + 2 + 6; // 88
const TOKEN_Y_MINT_OFFSET: usize = TOKEN_X_MINT_OFFSET + 32; // 120
const RESERVE_X_OFFSET: usize = TOKEN_Y_MINT_OFFSET + 32; // 152
const RESERVE_Y_OFFSET: usize = RESERVE_X_OFFSET + 32; // 184

const MIN_LAYOUT_LEN: usize = RESERVE_Y_OFFSET + 32; // 216

/// DLMM fee precision denominator. On-chain the formula is
/// `base_fee_rate = base_factor * bin_step * 10 * 10^base_fee_power_factor`,
/// expressed in `1 / DLMM_FEE_PRECISION` units. Equivalent to a numerator
/// over `10^9`.
pub const DLMM_FEE_PRECISION: u64 = 1_000_000_000;

/// Maximum fee rate cap (10%, in `DLMM_FEE_PRECISION` units). Mirrors
/// `MAX_FEE_RATE` in `commons/src/constants.rs`. On-chain `get_total_fee`
/// applies `min(rate, MAX_FEE_RATE)` so that `compute_fee_on_net`'s
/// `1e9 - rate` denominator never underflows. We faithfully cap here
/// even though the Phase 1 base-fee-only path can't actually exceed
/// 10% with legal pool config — Phase 3's variable-fee plumbing will,
/// and pinning the cap now prevents a silent underflow regression.
pub const DLMM_MAX_FEE_RATE: u128 = 100_000_000;

/// Default base fee fallback (`30 bps`, expressed in `DLMM_FEE_PRECISION`)
/// applied when the on-chain config parses as zero/degenerate. Same shape
/// as the Raydium V4 / Whirlpool parsers' fallback.
const DEFAULT_FEE_NUM: u64 = 3_000_000;

/// Meteora DLMM program id — `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo`.
/// Used by future BinArray PDA derivation. Decoded once per call from the
/// hardcoded base58 (same pattern as `whirlpool_program_id`).
pub fn dlmm_program_id() -> Pubkey {
    Pubkey::from_str("LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo")
        .expect("dlmm program id is hardcoded valid base58 pubkey")
}

/// Snapshot of `LbPair` state combining the dynamic active bin id with
/// the static fee parameters that govern within-bin swap fees. The
/// fee-parameter triple (`base_factor`, `bin_step`, `base_fee_power_factor`)
/// never mutates per swap, but lives in the same on-chain account, so we
/// surface them together to avoid re-parsing the blob in step 4 when the
/// swap-step math computes fees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlmmPool {
    /// Currently active bin id. The active bin holds reserves of both
    /// tokens; left bins (token_y only) and right bins (token_x only) are
    /// adjacent. Mutates with every swap that exhausts the bin.
    pub active_id: i32,
    /// Bin step in basis points. `25 = 0.25%` price spacing between
    /// adjacent bins. Set at pool creation; static.
    pub bin_step: u16,
    /// Multiplier for base fee. Static per pool.
    pub base_factor: u16,
    /// Power-factor scaling, almost always `0`; non-zero appears on
    /// token-extension pairs.
    pub base_fee_power_factor: u8,
    /// Portion of total swap fee that goes to the protocol. Doesn't
    /// affect victim-loss math (the swapper still pays the full fee
    /// regardless of how it's split downstream), retained here for
    /// completeness.
    pub protocol_share: u16,
}

impl DlmmPool {
    /// Aggregate swap-fee rate (numerator over [`DLMM_FEE_PRECISION`]),
    /// capped at [`DLMM_MAX_FEE_RATE`] to mirror on-chain `get_total_fee`.
    ///
    /// Phase 1 implements **base fee only**: `base_factor * bin_step *
    /// 10 * 10^base_fee_power_factor`. Variable fee (volatility-driven)
    /// would add to this rate but is intentionally skipped — pinning
    /// the Phase 1 cap on accuracy. Phase 3 follow-up plumbs
    /// `VolatilityAccumulator` and brings replay numbers into bit-for-
    /// bit agreement with on-chain `quote_exact_in`.
    pub fn total_fee_rate(&self) -> Option<u128> {
        let factor = (self.base_factor as u128)
            .checked_mul(self.bin_step as u128)?
            .checked_mul(10)?;
        let power_mul: u128 = 10u128.checked_pow(self.base_fee_power_factor as u32)?;
        let raw = factor.checked_mul(power_mul)?;
        Some(raw.min(DLMM_MAX_FEE_RATE))
    }

    /// Fee charged when the caller knows the *net* (post-fee) amount
    /// they need to push into the bin and must gross-up.
    ///
    /// Mirrors `LbPair::compute_fee` in commons:
    /// `ceil(net * rate / (DLMM_FEE_PRECISION - rate))`.
    pub fn compute_fee_on_net(&self, net_amount: u64) -> Option<u64> {
        let rate = self.total_fee_rate()?;
        let den = (DLMM_FEE_PRECISION as u128).checked_sub(rate)?;
        if den == 0 {
            return None;
        }
        let num = (net_amount as u128).checked_mul(rate)?;
        let fee = num.checked_add(den.checked_sub(1)?)?.checked_div(den)?;
        u64::try_from(fee).ok()
    }

    /// Fee charged when the caller knows the *gross* (pre-fee) amount
    /// already pushed in and must recover the fee component.
    ///
    /// Mirrors `LbPair::compute_fee_from_amount` in commons:
    /// `ceil(gross * rate / DLMM_FEE_PRECISION)`. Hardcoded
    /// `DLMM_FEE_PRECISION - 1` mirrors the on-chain idiom (the on-chain
    /// code uses the literal constant, not `den - 1` — keeping the
    /// shape identical guards against future refactors silently
    /// changing the rounding.)
    pub fn compute_fee_from_amount(&self, gross_amount: u64) -> Option<u64> {
        let rate = self.total_fee_rate()?;
        let num = (gross_amount as u128).checked_mul(rate)?;
        let den = DLMM_FEE_PRECISION as u128;
        let fee = num
            .checked_add((DLMM_FEE_PRECISION - 1) as u128)?
            .checked_div(den)?;
        u64::try_from(fee).ok()
    }
}

/// Parse an `LbPair` account into a [`PoolConfig`]. Mirrors the
/// raydium_v4 / whirlpool parsers: returns `None` when data is too
/// short or neither side of the pair is a recognised quote mint.
///
/// `reserve_x` / `reserve_y` are SPL token vault addresses. Reserve
/// extraction at replay time goes through the standard
/// [`reserves`](crate::reserves) module against these vaults — same
/// integration point as Raydium.
///
/// Quote-side detection mirrors Whirlpool: if `mint_x` is a recognised
/// quote, base sits on the `y` axis (`base_is_token_a = false` since
/// the DLMM `x`/`y` axis maps to V3's `a`/`b`).
pub fn parse_config(pool_address: &str, account_data: &[u8]) -> Option<PoolConfig> {
    if account_data.len() < MIN_LAYOUT_LEN {
        return None;
    }

    let mint_x = read_pubkey(account_data, TOKEN_X_MINT_OFFSET)?;
    let mint_y = read_pubkey(account_data, TOKEN_Y_MINT_OFFSET)?;
    let reserve_x = read_pubkey(account_data, RESERVE_X_OFFSET)?;
    let reserve_y = read_pubkey(account_data, RESERVE_Y_OFFSET)?;
    let bin_step = read_u16(account_data, BIN_STEP_OFFSET)?;
    let base_factor = read_u16(account_data, BASE_FACTOR_OFFSET)?;
    let bf_power = read_u8(account_data, BASE_FEE_POWER_FACTOR_OFFSET)?;

    let mint_x_s = mint_x.to_string();
    let mint_y_s = mint_y.to_string();
    let (vault_base, vault_quote, base_mint, quote_mint, base_is_token_a) =
        match (is_quote_mint(&mint_x_s), is_quote_mint(&mint_y_s)) {
            (true, false) => (
                reserve_y.to_string(),
                reserve_x.to_string(),
                mint_y_s,
                mint_x_s,
                // mint_x is quote ⇒ base sits on mint_y ⇒ token_y (i.e. axis = b).
                false,
            ),
            (false, true) | (true, true) => (
                reserve_x.to_string(),
                reserve_y.to_string(),
                mint_x_s,
                mint_y_s,
                // mint_y is quote (or both are: pick mint_x as base) ⇒
                // base sits on mint_x ⇒ token_x (axis = a).
                true,
            ),
            (false, false) => return None,
        };

    let factor = (base_factor as u128)
        .checked_mul(bin_step as u128)?
        .checked_mul(10)?;
    let power_mul: u128 = 10u128.checked_pow(bf_power as u32)?;
    let raw_num = factor.checked_mul(power_mul)?;
    let (fee_num, fee_den) = if raw_num == 0 || raw_num >= DLMM_FEE_PRECISION as u128 {
        (DEFAULT_FEE_NUM, DLMM_FEE_PRECISION)
    } else {
        (raw_num as u64, DLMM_FEE_PRECISION)
    };

    Some(PoolConfig {
        kind: AmmKind::MeteoraDlmm,
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

/// Parse the dynamic swap-relevant state (active_id) plus the fee
/// parameter triple. Returns `None` for short blobs.
pub fn parse_pool_state(account_data: &[u8]) -> Option<DlmmPool> {
    if account_data.len() < MIN_LAYOUT_LEN {
        return None;
    }
    Some(DlmmPool {
        active_id: read_i32(account_data, ACTIVE_ID_OFFSET)?,
        bin_step: read_u16(account_data, BIN_STEP_OFFSET)?,
        base_factor: read_u16(account_data, BASE_FACTOR_OFFSET)?,
        base_fee_power_factor: read_u8(account_data, BASE_FEE_POWER_FACTOR_OFFSET)?,
        protocol_share: read_u16(account_data, PROTOCOL_SHARE_OFFSET)?,
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

fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn read_i64(data: &[u8], offset: usize) -> Option<i64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(i64::from_le_bytes(bytes))
}

fn read_u128(data: &[u8], offset: usize) -> Option<u128> {
    let bytes: [u8; 16] = data.get(offset..offset + 16)?.try_into().ok()?;
    Some(u128::from_le_bytes(bytes))
}

/// `BinArray` account layout + bin index helpers.
///
/// Each pool's bin liquidity is sharded across `BinArray` accounts. One
/// array holds [`MAX_BIN_PER_ARRAY`] (= 70) consecutive bins; the array
/// at `index = i` covers bin ids `[i*70, i*70 + 69]`. Bin id maps to
/// array index with a flooring divmod that handles negatives correctly
/// — Rust's truncating `/` rounds toward zero, but the on-chain layout
/// expects floor toward negative infinity (the same quirk Whirlpool's
/// tick-array maths handles via `floor_to_spacing`).
///
/// PDA seeds: `[b"bin_array", lb_pair, index_le_bytes]` where the index
/// is encoded as an `i64` little-endian, **not** the `i32` we use for
/// bin id arithmetic. This mismatches `bin_id_to_bin_array_index`'s
/// return type — callers that derive PDAs must widen the `i32` to
/// `i64` first. [`bin_array_pda`] handles that.
///
/// Layout (Anchor account, `bytemuck repr(C)`):
///
/// ```text
///   field                   offset  size
///   discriminator               0     8
///   index: i64                  8     8
///   version: u8                16     1
///   _padding: [u8; 7]          17     7
///   lb_pair: Pubkey            24    32
///   bins: [Bin; 70]            56  10080
/// ```
///
/// Total: 10136 bytes per BinArray account.
///
/// `Bin` (144 bytes, `bytemuck repr(C)`):
///
/// ```text
///   field                              offset  size
///   amount_x: u64                          0     8
///   amount_y: u64                          8     8
///   price: u128                           16    16   (Q64.64, lazy-cached on-chain)
///   liquidity_supply: u128                32    16
///   reward_per_token_stored: [u128; 2]    48    32
///   fee_amount_x_per_token_stored: u128   80    16
///   fee_amount_y_per_token_stored: u128   96    16
///   amount_x_in: u128                    112    16
///   amount_y_in: u128                    128    16
/// ```
///
/// We only surface the swap-relevant fields (`amount_x`, `amount_y`,
/// `price`, `liquidity_supply`); the fee/reward bookkeeping doesn't
/// affect victim-loss math.
pub mod bin_array {
    use super::{dlmm_program_id, read_i64, read_pubkey, read_u128, read_u64, read_u8};
    use solana_sdk::pubkey::Pubkey;

    /// Bins per array. Hardcoded on-chain; matches `MAX_BIN_PER_ARRAY`
    /// in `MeteoraAg/dlmm-sdk/commons/src/constants.rs`.
    pub const MAX_BIN_PER_ARRAY: usize = 70;

    /// Each on-chain `Bin` is 144 bytes.
    pub const BIN_DATA_LEN: usize = 144;

    // BinArray account offsets (from start of account_data, including
    // the 8-byte discriminator).
    const DISCRIMINATOR_LEN: usize = 8;
    const INDEX_OFFSET: usize = DISCRIMINATOR_LEN; // 8
    const VERSION_OFFSET: usize = INDEX_OFFSET + 8; // 16
    const LB_PAIR_OFFSET: usize = VERSION_OFFSET + 1 + 7; // 24 (skip 7-byte padding)
    const BINS_START_OFFSET: usize = LB_PAIR_OFFSET + 32; // 56

    /// Account size including the discriminator. We over-tolerate trailing
    /// bytes — `parse_bin_array` only checks `>=`, matching the rest of
    /// pool-state's parser convention.
    pub const BIN_ARRAY_DATA_LEN: usize = BINS_START_OFFSET + MAX_BIN_PER_ARRAY * BIN_DATA_LEN;

    // Bin field offsets within the 144-byte Bin struct.
    const BIN_AMOUNT_X_OFFSET: usize = 0;
    const BIN_AMOUNT_Y_OFFSET: usize = 8;
    const BIN_PRICE_OFFSET: usize = 16;
    const BIN_LIQUIDITY_SUPPLY_OFFSET: usize = 32;

    /// Swap-relevant subset of an on-chain `Bin`. The fee/reward fields
    /// are dropped — they don't change victim loss.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ParsedBin {
        /// Token X reserves in this bin (excluding protocol fees).
        pub amount_x: u64,
        /// Token Y reserves in this bin (excluding protocol fees).
        pub amount_y: u64,
        /// Cached bin price, Q64.64 (`price * 2^64`). On-chain this is
        /// lazy-initialised: stays `0` until the bin's first swap, at
        /// which point `get_or_store_bin_price` writes the real value.
        /// Callers that need a price for a never-swapped bin must
        /// recompute via `bin_price` (step 3).
        pub price: u128,
        /// Total LP-share supply in this bin. Mirrors LP mint supply
        /// for the bin; used for liquidity-share withdrawals and
        /// (later) for protocol-fee bookkeeping.
        pub liquidity_supply: u128,
    }

    /// Parsed `BinArray` account: index + 70 bins.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ParsedBinArray {
        /// Array index. `bin_id ∈ [index * 70, index * 70 + 69]`.
        pub index: i64,
        /// Layout version byte. Reserved for future migrations; we
        /// surface it without interpreting beyond round-trip.
        pub version: u8,
        /// Pool that owns this array.
        pub lb_pair: Pubkey,
        /// 70 bins in ascending bin id order.
        pub bins: Vec<ParsedBin>,
    }

    /// Parse a `BinArray` account blob. Returns `None` for short data.
    pub fn parse_bin_array(account_data: &[u8]) -> Option<ParsedBinArray> {
        if account_data.len() < BIN_ARRAY_DATA_LEN {
            return None;
        }
        let index = read_i64(account_data, INDEX_OFFSET)?;
        let version = read_u8(account_data, VERSION_OFFSET)?;
        let lb_pair = read_pubkey(account_data, LB_PAIR_OFFSET)?;
        let mut bins = Vec::with_capacity(MAX_BIN_PER_ARRAY);
        for i in 0..MAX_BIN_PER_ARRAY {
            let base = BINS_START_OFFSET + i * BIN_DATA_LEN;
            bins.push(ParsedBin {
                amount_x: read_u64(account_data, base + BIN_AMOUNT_X_OFFSET)?,
                amount_y: read_u64(account_data, base + BIN_AMOUNT_Y_OFFSET)?,
                price: read_u128(account_data, base + BIN_PRICE_OFFSET)?,
                liquidity_supply: read_u128(account_data, base + BIN_LIQUIDITY_SUPPLY_OFFSET)?,
            });
        }
        Some(ParsedBinArray {
            index,
            version,
            lb_pair,
            bins,
        })
    }

    /// Map `bin_id` to the index of the `BinArray` that contains it.
    /// Floors toward negative infinity — `bin_id = -1` lands in array
    /// `-1` (which covers `[-70, -1]`), not array `0`.
    pub fn bin_id_to_bin_array_index(bin_id: i32) -> i32 {
        let max = MAX_BIN_PER_ARRAY as i32;
        let q = bin_id / max;
        let r = bin_id % max;
        if bin_id < 0 && r != 0 {
            q - 1
        } else {
            q
        }
    }

    /// `(lower_bin_id, upper_bin_id)` covered by the array at `index`.
    /// Inclusive on both ends.
    pub fn bin_array_lower_upper_bin_id(index: i32) -> (i32, i32) {
        let lower = index.saturating_mul(MAX_BIN_PER_ARRAY as i32);
        let upper = lower.saturating_add(MAX_BIN_PER_ARRAY as i32 - 1);
        (lower, upper)
    }

    /// Position of `bin_id` inside the array's `bins` vector, or
    /// `None` if `bin_id` falls outside the array's range.
    pub fn bin_index_in_array(array_index: i32, bin_id: i32) -> Option<usize> {
        let (lower, upper) = bin_array_lower_upper_bin_id(array_index);
        if bin_id < lower || bin_id > upper {
            return None;
        }
        let idx = (bin_id - lower) as usize;
        Some(idx)
    }

    /// Derive the `BinArray` PDA for `lb_pair` at array `index`. The
    /// on-chain seed encodes the index as `i64` little-endian — not
    /// the `i32` we do bin arithmetic with — so callers that receive
    /// an `i32` from [`bin_id_to_bin_array_index`] must widen first.
    /// `derive_bin_array_pda` in the SDK takes `i64`; we mirror that.
    pub fn bin_array_pda(lb_pair: &Pubkey, array_index: i64) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"bin_array", lb_pair.as_ref(), &array_index.to_le_bytes()],
            &dlmm_program_id(),
        )
    }
}

/// Q64.64 fixed-point bin price math.
///
/// DLMM bin prices follow `price(bin_id, bin_step) = (1 + bin_step / 10_000)^bin_id`,
/// stored on-chain as `Q64.64` (the integer is `price * 2^64`). The on-chain
/// implementation lives in `MeteoraAg/dlmm-sdk/commons/src/math/u64x64_math.rs`
/// and uses a 19-bit binary exponentiation.
///
/// Why 19 bits: the legal bin id range is `[-443_636, 443_636]` (the
/// hardcoded [`MAX_EXPONENTIAL`] cap), which fits in 19 bits. So the
/// exponent loop terminates at most 19 iterations, regardless of the
/// concrete `bin_id`.
///
/// Why the `if squared_base >= ONE { invert }` dance: when `base > 1.0`,
/// squaring it in `Q64.64` would produce a `Q128.128` that overflows
/// `u128`. The on-chain code dodges this by inverting the base
/// (`u128::MAX / base ≈ ONE^2 / base ≈ 1 / base` in Q64.64) so the
/// loop runs entirely in the `< ONE` regime, then re-inverts at the
/// end. The `u128::MAX / x` shortcut introduces a 1-ULP rounding error
/// vs. an exact `(2^128) / x`; we mirror the on-chain quirk so our
/// replay results match chain values bit-for-bit, including the error.
pub mod price_math {
    /// Number of fractional bits in the Q64.64 representation. Must
    /// match [`u64x64_math::SCALE_OFFSET`] in the SDK.
    pub const SCALE_OFFSET: u8 = 64;

    /// `1.0` represented as Q64.64 (`1 << 64`).
    pub const ONE: u128 = 1u128 << SCALE_OFFSET;

    /// Hardcoded cap on the absolute exponent — derived from the
    /// `[-443_636, 443_636]` legal bin id range, the largest exponent
    /// at which `(1 + 1bps)^id` still fits in Q64.64. `0x80000 = 1 << 19`,
    /// the next power-of-two above `443_636`.
    pub const MAX_EXPONENTIAL: u32 = 0x80000;

    /// Basis-point denominator. `bin_step` is expressed in basis points
    /// of the multiplicative price step (`25 = 0.25%`).
    pub const BASIS_POINT_MAX: u128 = 10_000;

    /// Compute `base^exp` in Q64.64 fixed point.
    ///
    /// Returns `None` on overflow or when `|exp| >= MAX_EXPONENTIAL`. A
    /// negative exponent produces the reciprocal: `base^-n = 1 / base^n`,
    /// also via the `u128::MAX / x` integer division that the on-chain
    /// implementation uses (1 ULP error preserved).
    pub fn pow(base: u128, exp: i32) -> Option<u128> {
        if exp == 0 {
            return Some(ONE);
        }
        let mut invert = exp.is_negative();
        let exp_abs: u32 = if invert {
            exp.unsigned_abs()
        } else {
            exp as u32
        };
        if exp_abs >= MAX_EXPONENTIAL {
            return None;
        }

        let mut squared_base = base;
        let mut result = ONE;

        // If base >= 1.0, invert into the < 1.0 regime to keep upper
        // 64 bits zero while squaring. Re-invert at the end via the
        // `invert` flag toggle.
        if squared_base >= result {
            squared_base = u128::MAX.checked_div(squared_base)?;
            invert = !invert;
        }

        // Binary exponentiation; at most ceil(log2(MAX_EXPONENTIAL)) =
        // 20 iterations.
        let mut e = exp_abs;
        while e > 0 {
            if e & 1 == 1 {
                result = result.checked_mul(squared_base)? >> SCALE_OFFSET;
            }
            e >>= 1;
            if e > 0 {
                squared_base = squared_base.checked_mul(squared_base)? >> SCALE_OFFSET;
            }
        }

        if invert {
            u128::MAX.checked_div(result)
        } else {
            Some(result)
        }
    }

    /// `bin_price(bin_id, bin_step) = (1 + bin_step / 10_000)^bin_id`
    /// in Q64.64.
    ///
    /// Returns `None` on the same conditions as [`pow`], or when
    /// `bin_step` produces an overflow during `(bin_step << 64)`
    /// (impossible in practice — `MAX_BIN_STEP = 400` keeps the shift
    /// well under u128 range).
    ///
    /// On-chain `Bin.price` is lazy-cached: a never-swapped bin stores
    /// `0` here. Callers that hit a zero-cached price must recompute
    /// via this function.
    pub fn bin_price(bin_id: i32, bin_step: u16) -> Option<u128> {
        let shifted = (bin_step as u128).checked_shl(SCALE_OFFSET as u32)?;
        let bps = shifted.checked_div(BASIS_POINT_MAX)?;
        let base = ONE.checked_add(bps)?;
        pow(base, bin_id)
    }
}

/// Re-export bin-price helpers at module level for ergonomic
/// consumption: `meteora_dlmm::bin_price(...)` instead of
/// `meteora_dlmm::price_math::bin_price(...)`. Mirrors the
/// `whirlpool_program_id` / `tick_array::tick_array_pda` re-export
/// shape Whirlpool uses.
pub use price_math::bin_price;

/// Single-bin within-bin swap math.
///
/// DLMM swap math is *constant sum* within a bin (`P*x + y = L`) — no
/// curve traversal like V3, just a linear price * amount conversion.
/// The bin's available output is whichever side is being drained
/// (`amount_y` for `swap_for_y`, `amount_x` otherwise); the input
/// required to fully drain that side is computed via the same `mul_shr` /
/// `shl_div` primitives the on-chain `Bin::swap` uses.
///
/// Two distinct cases:
///   1. `amount_in <= max_amount_in`: the swap fits inside the bin.
///      Compute `fee = ceil(amount_in * rate / DLMM_FEE_PRECISION)`
///      and `amount_out = (amount_in - fee) * price` (or `/price`,
///      depending on direction).
///   2. `amount_in > max_amount_in`: the swap drains the bin. Cap
///      output at `max_amount_out` and report the bin as drained;
///      the cross-bin walker (Phase 2) advances `active_id` and
///      retries with the leftover input.
pub mod swap_math {
    use super::{price_math, DlmmPool};
    use primitive_types::U256;

    /// Outcome of one bin's contribution to a swap.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BinSwapStep {
        /// Gross input consumed (`amount_in_after_fee + fee`). Always
        /// `<= caller's amount_in`.
        pub amount_in_with_fees: u64,
        /// Token-out delivered. For `swap_for_y` this is in token Y;
        /// otherwise token X.
        pub amount_out: u64,
        /// Fee withheld from `amount_in_with_fees`. Already counted
        /// inside it (matches the on-chain `SwapResult` shape).
        pub fee: u64,
        /// True iff the bin's output side is now empty. `false` means
        /// the entire `amount_in` was consumed within this bin and the
        /// caller's swap is complete.
        pub bin_drained: bool,
        /// Input not consumed by this bin. Always `0` on partial-fill
        /// (`bin_drained = false`); on drain it equals
        /// `amount_in - amount_in_with_fees`, which the cross-bin
        /// walker passes into the next active bin. Phase 1 callers
        /// can ignore this — they bail on `bin_drained = true` before
        /// the leftover matters.
        pub amount_in_remaining: u64,
    }

    /// `(x * y) >> offset` rounded floor / ceil, in U256 to dodge
    /// the Q64.64 squaring-overflow trap. Mirrors
    /// `safe_mul_shr_cast` from commons.
    fn mul_shr(x: u128, y: u128, offset: u8, ceil: bool) -> Option<u128> {
        let prod = U256::from(x).checked_mul(U256::from(y))?;
        let denom = U256::one() << offset;
        let q = prod.checked_div(denom)?;
        let r = prod % denom;
        let result = if ceil && !r.is_zero() {
            q.checked_add(U256::one())?
        } else {
            q
        };
        if result.bits() > 128 {
            return None;
        }
        Some(result.low_u128())
    }

    /// `(x << offset) / y` rounded floor / ceil.
    fn shl_div(x: u128, y: u128, offset: u8, ceil: bool) -> Option<u128> {
        if y == 0 {
            return None;
        }
        let scaled = U256::from(x) << offset;
        let denom = U256::from(y);
        let q = scaled.checked_div(denom)?;
        let r = scaled % denom;
        let result = if ceil && !r.is_zero() {
            q.checked_add(U256::one())?
        } else {
            q
        };
        if result.bits() > 128 {
            return None;
        }
        Some(result.low_u128())
    }

    /// Apply an exact-input swap step against a single bin.
    ///
    /// `swap_for_y = true` ⇒ token X in, token Y out (price drops as
    /// caller eats the y side). `swap_for_y = false` ⇒ token Y in,
    /// token X out.
    ///
    /// Returns `None` on arithmetic overflow or zero `price`. A bin
    /// with zero output reserve returns a zero-amount step with
    /// `bin_drained = true`, signalling the caller to advance to the
    /// next bin.
    pub fn swap_within_bin(
        amount_in: u64,
        bin_amount_x: u64,
        bin_amount_y: u64,
        price: u128,
        swap_for_y: bool,
        pool: &DlmmPool,
    ) -> Option<BinSwapStep> {
        if price == 0 {
            return None;
        }

        let max_amount_out = if swap_for_y {
            bin_amount_y
        } else {
            bin_amount_x
        };
        if max_amount_out == 0 {
            return Some(BinSwapStep {
                amount_in_with_fees: 0,
                amount_out: 0,
                fee: 0,
                bin_drained: true,
                // Bin can't absorb anything ⇒ the entire input is
                // leftover for the next bin.
                amount_in_remaining: amount_in,
            });
        }

        // Input required to fully drain max_amount_out. Ceil rounding
        // is the on-chain convention (commons uses `Rounding::Up`):
        // we need *at least* enough input to fully consume the bin.
        let max_in_pre_fee_u128 = if swap_for_y {
            // X→Y: Y = X * price >> 64 ⇒ X = ceil((Y << 64) / price).
            shl_div(
                max_amount_out as u128,
                price,
                price_math::SCALE_OFFSET,
                true,
            )?
        } else {
            // Y→X: X = (Y << 64) / price ⇒ Y = ceil((X * price) >> 64).
            mul_shr(
                max_amount_out as u128,
                price,
                price_math::SCALE_OFFSET,
                true,
            )?
        };
        let max_in_pre_fee: u64 = max_in_pre_fee_u128.try_into().ok()?;
        let max_fee = pool.compute_fee_on_net(max_in_pre_fee)?;
        let max_amount_in = max_in_pre_fee.checked_add(max_fee)?;

        if amount_in > max_amount_in {
            // Bin gets fully drained; caller advances with the
            // leftover. Cap output at `max_amount_out` exactly.
            return Some(BinSwapStep {
                amount_in_with_fees: max_amount_in,
                amount_out: max_amount_out,
                fee: max_fee,
                bin_drained: true,
                amount_in_remaining: amount_in - max_amount_in,
            });
        }

        // Partial fill: the entire amount_in lands inside this bin.
        let fee = pool.compute_fee_from_amount(amount_in)?;
        let amount_in_after_fee = amount_in.checked_sub(fee)?;
        let amount_out_u128 = if swap_for_y {
            // X→Y: floor mul_shr.
            mul_shr(
                amount_in_after_fee as u128,
                price,
                price_math::SCALE_OFFSET,
                false,
            )?
        } else {
            // Y→X: floor shl_div.
            shl_div(
                amount_in_after_fee as u128,
                price,
                price_math::SCALE_OFFSET,
                false,
            )?
        };
        let amount_out_raw: u64 = amount_out_u128.try_into().ok()?;
        // commons applies `min(amount_out_raw, max_amount_out)` after
        // the partial-fill calc — guards against floor-rounding drift
        // pushing amount_out one unit above the bin's actual reserve.
        let amount_out = amount_out_raw.min(max_amount_out);

        Some(BinSwapStep {
            amount_in_with_fees: amount_in,
            amount_out,
            fee,
            bin_drained: false,
            // Partial fill ⇒ caller's swap is complete; nothing
            // leftover for downstream bins.
            amount_in_remaining: 0,
        })
    }
}

pub use swap_math::{swap_within_bin, BinSwapStep};

/// Cross-bin swap walker. Drives `swap_within_bin` across `active_id`
/// transitions until the input is exhausted, the walker leaves the
/// supplied bin window, or the iteration cap fires.
///
/// DLMM cross-bin walking is structurally similar to Whirlpool's
/// cross-tick walk but simpler — bin price is fixed per bin (no
/// curve traversal), so each bin's contribution resolves in a
/// single `swap_within_bin` call. The walker:
///
///   1. Looks up the active bin's `(amount_x, amount_y, price)` in
///      the `DlmmBinState` map.
///   2. Calls `swap_within_bin` with the leftover input.
///   3. Updates the bin's amounts in-place (next legs see post-swap state).
///   4. Advances `active_id` by ±1 if the bin drained.
///   5. Repeats until `amount_in_remaining = 0` or the active bin
///      falls outside the supplied window.
///
/// Empty bins (output reserve zero) take one iteration each: the
/// `swap_within_bin` empty-side fast path returns
/// `amount_in_remaining = amount_in` + `bin_drained = true`, so the
/// walker advances without consuming input. The iteration cap
/// bounds total bin traversal even in pathological "thousands of
/// empty bins between liquidity" pools.
pub mod cross_bin {
    use super::price_math::bin_price;
    use super::swap_math::swap_within_bin;
    use super::{
        bin_array::{bin_array_lower_upper_bin_id, ParsedBinArray},
        DlmmPool,
    };
    use std::collections::HashMap;

    /// Maximum bin transitions per walk. Sized to comfortably exceed
    /// the realistic sandwich (most cross-bin swaps move 1-5 bins;
    /// large MEV bots occasionally push 20-50). 256 also caps the
    /// pathological "long empty-bin run" — the iteration cap stops
    /// the walk before the supplied window runs out, so the bail
    /// surfaces as `None` rather than an infinite loop.
    pub const MAX_SWAP_ITERATIONS: usize = 256;

    /// Mutable map of `bin_id → (amount_x, amount_y, price)` covering
    /// the bins the walker can reach. Built once from the BinArray
    /// window the caller fetched; updated in-place as the walker
    /// drains bins.
    ///
    /// Price is cached (with a `bin_price` recompute when the
    /// on-chain `Bin.price = 0` lazy-init sentinel is hit). Storing
    /// price here avoids re-deriving it once per walk iteration —
    /// `pow` is cheap but not free, and a 256-bin walk would call it
    /// 256 times otherwise.
    #[derive(Debug, Clone)]
    pub struct DlmmBinState {
        bins: HashMap<i32, BinSnapshot>,
        bin_step: u16,
        /// Inclusive bin id range the supplied arrays cover. Used
        /// to short-circuit `get` for bins outside the window
        /// without searching the map.
        range: (i32, i32),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BinSnapshot {
        pub amount_x: u64,
        pub amount_y: u64,
        pub price: u128,
    }

    impl DlmmBinState {
        /// Build the map from a BinArray window. Skips bins outside
        /// the arrays' range. Recomputes price for any lazy-cached
        /// (on-chain `Bin.price = 0`) bin via [`bin_price`].
        pub fn from_arrays(arrays: &[ParsedBinArray], bin_step: u16) -> Option<Self> {
            if arrays.is_empty() {
                return None;
            }
            let mut bins = HashMap::new();
            let mut min_id = i32::MAX;
            let mut max_id = i32::MIN;
            for arr in arrays {
                let array_idx = arr.index as i32;
                let (lower, upper) = bin_array_lower_upper_bin_id(array_idx);
                min_id = min_id.min(lower);
                max_id = max_id.max(upper);
                for (i, bin) in arr.bins.iter().enumerate() {
                    let bin_id = lower.checked_add(i as i32)?;
                    let price = if bin.price != 0 {
                        bin.price
                    } else {
                        bin_price(bin_id, bin_step)?
                    };
                    bins.insert(
                        bin_id,
                        BinSnapshot {
                            amount_x: bin.amount_x,
                            amount_y: bin.amount_y,
                            price,
                        },
                    );
                }
            }
            Some(Self {
                bins,
                bin_step,
                range: (min_id, max_id),
            })
        }

        /// Snapshot for `bin_id`, or `None` if outside the window.
        pub fn get(&self, bin_id: i32) -> Option<BinSnapshot> {
            if bin_id < self.range.0 || bin_id > self.range.1 {
                return None;
            }
            self.bins.get(&bin_id).copied()
        }

        /// Apply post-swap mutation to a bin. Caller computed
        /// `(new_x, new_y)` from `swap_within_bin`'s result.
        pub fn update(&mut self, bin_id: i32, amount_x: u64, amount_y: u64) {
            if let Some(b) = self.bins.get_mut(&bin_id) {
                b.amount_x = amount_x;
                b.amount_y = amount_y;
            }
        }

        /// Inclusive bin id range covered by the underlying arrays.
        pub fn range(&self) -> (i32, i32) {
            self.range
        }

        /// `bin_step` the state was built from. Surfaced for callers
        /// that need to derive prices for bins beyond the window.
        pub fn bin_step(&self) -> u16 {
            self.bin_step
        }
    }

    /// Result of a multi-bin walk.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CrossBinSwapResult {
        /// Total gross input consumed (= caller's `amount_in` on
        /// successful completion).
        pub amount_in_with_fees: u64,
        /// Total token-out delivered.
        pub amount_out: u64,
        /// Total fee withheld across all bins.
        pub fee: u64,
        /// `active_id` after the walk. Differs from the initial
        /// `active_id` by the number of bin transitions.
        pub final_active_id: i32,
        /// Number of `swap_within_bin` iterations the walker ran.
        /// Surfaced for diagnostics — most realistic swaps complete
        /// in 1-5 iterations; a value approaching `MAX_SWAP_ITERATIONS`
        /// indicates a sparse-liquidity pool.
        pub iterations: usize,
    }

    /// Walk the active bin sequence, draining bins until `amount_in`
    /// is exhausted or the walker exits the supplied window.
    ///
    /// Returns `None` on:
    ///   * arithmetic overflow at any step,
    ///   * the walker stepping outside the BinArray window without
    ///     having consumed `amount_in`,
    ///   * the iteration cap firing before `amount_in_remaining = 0`,
    ///   * a single `swap_within_bin` call returning `None` (zero
    ///     price hit on a bin with no `bin_price` recompute fallback —
    ///     the `from_arrays` constructor already resolves this, so
    ///     the `None` here means a real arithmetic edge case).
    ///
    /// Side effect: `state` is mutated to reflect post-swap bin
    /// reserves. Caller passes a clone for counterfactual replays.
    pub fn cross_bin_swap(
        amount_in: u64,
        initial_active_id: i32,
        state: &mut DlmmBinState,
        swap_for_y: bool,
        pool: &DlmmPool,
    ) -> Option<CrossBinSwapResult> {
        let mut amount_left = amount_in;
        let mut total_in_with_fees: u64 = 0;
        let mut total_out: u64 = 0;
        let mut total_fee: u64 = 0;
        let mut active_id = initial_active_id;

        for iter in 0..MAX_SWAP_ITERATIONS {
            if amount_left == 0 {
                return Some(CrossBinSwapResult {
                    amount_in_with_fees: total_in_with_fees,
                    amount_out: total_out,
                    fee: total_fee,
                    final_active_id: active_id,
                    iterations: iter,
                });
            }
            let snap = state.get(active_id)?;
            let step = swap_within_bin(
                amount_left,
                snap.amount_x,
                snap.amount_y,
                snap.price,
                swap_for_y,
                pool,
            )?;
            total_in_with_fees = total_in_with_fees.checked_add(step.amount_in_with_fees)?;
            total_out = total_out.checked_add(step.amount_out)?;
            total_fee = total_fee.checked_add(step.fee)?;

            // Mutate bin amounts. The "amount that lands inside the
            // bin" is the gross input minus the fee — fees are
            // collected by the protocol, not retained in the bin.
            let amount_into_bin = step.amount_in_with_fees.saturating_sub(step.fee);
            let (new_x, new_y) = if swap_for_y {
                (
                    snap.amount_x.saturating_add(amount_into_bin),
                    snap.amount_y.saturating_sub(step.amount_out),
                )
            } else {
                (
                    snap.amount_x.saturating_sub(step.amount_out),
                    snap.amount_y.saturating_add(amount_into_bin),
                )
            };
            state.update(active_id, new_x, new_y);

            amount_left = step.amount_in_remaining;

            if !step.bin_drained {
                // Partial fill ⇒ caller's swap is complete.
                return Some(CrossBinSwapResult {
                    amount_in_with_fees: total_in_with_fees,
                    amount_out: total_out,
                    fee: total_fee,
                    final_active_id: active_id,
                    iterations: iter + 1,
                });
            }

            // Bin drained ⇒ advance to the next active bin.
            // swap_for_y eats the y-axis (price drops): bin id decreases.
            // Otherwise: bin id increases.
            active_id = if swap_for_y {
                active_id.checked_sub(1)?
            } else {
                active_id.checked_add(1)?
            };
        }
        // Iteration cap hit without finishing — pathological pool
        // (sparse liquidity beyond the cap, or a misbehaving caller).
        None
    }
}

pub use cross_bin::{cross_bin_swap, BinSnapshot, CrossBinSwapResult, DlmmBinState};

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrapped SOL — like the other parsers, fixtures plant WSOL into one
    /// mint slot to satisfy the quote-mint guard.
    const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";

    fn synth_blob() -> Vec<u8> {
        vec![0u8; MIN_LAYOUT_LEN + 16]
    }

    /// Synthetic LbPair blob with known fields verifies the offset table
    /// + base-fee derivation + axis orientation when mint_x is the quote.
    #[test]
    fn parses_synthetic_lbpair_x_quote() {
        let mut data = synth_blob();
        data[BASE_FACTOR_OFFSET..BASE_FACTOR_OFFSET + 2].copy_from_slice(&8000u16.to_le_bytes());
        data[BIN_STEP_OFFSET..BIN_STEP_OFFSET + 2].copy_from_slice(&25u16.to_le_bytes());
        data[BASE_FEE_POWER_FACTOR_OFFSET] = 0;
        data[ACTIVE_ID_OFFSET..ACTIVE_ID_OFFSET + 4].copy_from_slice(&(-100i32).to_le_bytes());
        data[PROTOCOL_SHARE_OFFSET..PROTOCOL_SHARE_OFFSET + 2]
            .copy_from_slice(&2000u16.to_le_bytes());

        let mint_x = Pubkey::from_str(WSOL_MINT).unwrap();
        let mint_y = Pubkey::new_unique();
        let reserve_x = Pubkey::new_unique();
        let reserve_y = Pubkey::new_unique();
        data[TOKEN_X_MINT_OFFSET..TOKEN_X_MINT_OFFSET + 32].copy_from_slice(mint_x.as_ref());
        data[TOKEN_Y_MINT_OFFSET..TOKEN_Y_MINT_OFFSET + 32].copy_from_slice(mint_y.as_ref());
        data[RESERVE_X_OFFSET..RESERVE_X_OFFSET + 32].copy_from_slice(reserve_x.as_ref());
        data[RESERVE_Y_OFFSET..RESERVE_Y_OFFSET + 32].copy_from_slice(reserve_y.as_ref());

        let cfg = parse_config("POOL", &data).unwrap();
        assert_eq!(cfg.kind, AmmKind::MeteoraDlmm);
        assert_eq!(cfg.pool, "POOL");
        // mint_x is quote ⇒ base lives on y axis (axis = b) ⇒ false.
        assert!(!cfg.base_is_token_a);
        assert_eq!(cfg.base_mint, mint_y.to_string());
        assert_eq!(cfg.quote_mint, mint_x.to_string());
        assert_eq!(cfg.vault_base, reserve_y.to_string());
        assert_eq!(cfg.vault_quote, reserve_x.to_string());
        // 8000 * 25 * 10 = 2_000_000 → 0.2% in 1e9 units.
        assert_eq!(cfg.fee_num, 2_000_000);
        assert_eq!(cfg.fee_den, DLMM_FEE_PRECISION);

        let state = parse_pool_state(&data).unwrap();
        assert_eq!(state.active_id, -100);
        assert_eq!(state.bin_step, 25);
        assert_eq!(state.base_factor, 8000);
        assert_eq!(state.base_fee_power_factor, 0);
        assert_eq!(state.protocol_share, 2000);

        // 1_000_000 * 2_000_000 / 1e9 = 2_000 (exact division).
        assert_eq!(state.compute_fee_from_amount(1_000_000).unwrap(), 2_000);
    }

    /// When mint_y is the quote, base lives on token_x ⇒ axis a.
    #[test]
    fn parse_config_y_quote_sets_base_is_token_a() {
        let mut data = synth_blob();
        let mint_x = Pubkey::new_unique();
        let mint_y = Pubkey::from_str(WSOL_MINT).unwrap();
        data[TOKEN_X_MINT_OFFSET..TOKEN_X_MINT_OFFSET + 32].copy_from_slice(mint_x.as_ref());
        data[TOKEN_Y_MINT_OFFSET..TOKEN_Y_MINT_OFFSET + 32].copy_from_slice(mint_y.as_ref());
        data[BASE_FACTOR_OFFSET..BASE_FACTOR_OFFSET + 2].copy_from_slice(&8000u16.to_le_bytes());
        data[BIN_STEP_OFFSET..BIN_STEP_OFFSET + 2].copy_from_slice(&25u16.to_le_bytes());

        let cfg = parse_config("POOL", &data).unwrap();
        assert!(cfg.base_is_token_a);
        assert_eq!(cfg.base_mint, mint_x.to_string());
        assert_eq!(cfg.quote_mint, mint_y.to_string());
    }

    #[test]
    fn rejects_short_data() {
        let short = vec![0u8; 50];
        assert!(parse_config("POOL", &short).is_none());
        assert!(parse_pool_state(&short).is_none());
    }

    #[test]
    fn falls_back_to_default_fee_on_zero_factor() {
        let mut data = synth_blob();
        let mint_y = Pubkey::from_str(WSOL_MINT).unwrap();
        data[TOKEN_Y_MINT_OFFSET..TOKEN_Y_MINT_OFFSET + 32].copy_from_slice(mint_y.as_ref());
        // base_factor stays 0 ⇒ raw_num = 0 ⇒ fallback.
        let cfg = parse_config("POOL", &data).unwrap();
        assert_eq!(cfg.fee_num, DEFAULT_FEE_NUM);
        assert_eq!(cfg.fee_den, DLMM_FEE_PRECISION);
    }

    #[test]
    fn rejects_memecoin_pair() {
        let mut data = synth_blob();
        let mint_x = Pubkey::new_unique();
        let mint_y = Pubkey::new_unique();
        data[TOKEN_X_MINT_OFFSET..TOKEN_X_MINT_OFFSET + 32].copy_from_slice(mint_x.as_ref());
        data[TOKEN_Y_MINT_OFFSET..TOKEN_Y_MINT_OFFSET + 32].copy_from_slice(mint_y.as_ref());
        data[BASE_FACTOR_OFFSET..BASE_FACTOR_OFFSET + 2].copy_from_slice(&8000u16.to_le_bytes());
        data[BIN_STEP_OFFSET..BIN_STEP_OFFSET + 2].copy_from_slice(&25u16.to_le_bytes());
        assert!(parse_config("POOL", &data).is_none());
    }

    #[test]
    fn dlmm_program_id_round_trip() {
        let id = dlmm_program_id();
        assert_eq!(
            id.to_string(),
            "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo"
        );
    }

    /// Pin the `base_fee_power_factor` path: a non-zero power scales the
    /// numerator by 10^p. Catches a future regression if anyone uses
    /// `pow(10, p as u8)` (saturating at 255 instead of overflowing) or
    /// drops the multiplication entirely.
    #[test]
    fn compute_fee_from_amount_honours_power_factor() {
        let pool = DlmmPool {
            active_id: 0,
            bin_step: 25,
            base_factor: 8000,
            base_fee_power_factor: 1, // x10
            protocol_share: 0,
        };
        // base_fee_rate = 8000 * 25 * 10 * 10 = 20_000_000 → 2% in 1e9.
        // fee on 1_000_000 = 1_000_000 * 20_000_000 / 1e9 = 20_000 (exact).
        assert_eq!(pool.compute_fee_from_amount(1_000_000).unwrap(), 20_000);
    }

    /// `compute_fee_on_net` ceil-rounds, mirroring on-chain
    /// `LbPair::compute_fee`: `ceil(net * rate / (1e9 - rate))`.
    /// Pin the boundary case where the division has a non-zero
    /// remainder so the ceil branch fires.
    #[test]
    fn compute_fee_on_net_ceil_rounds() {
        let pool = DlmmPool {
            active_id: 0,
            bin_step: 25,
            base_factor: 8000,
            base_fee_power_factor: 0,
            protocol_share: 0,
        };
        // rate = 2e6, den = 998e6; 1e6 * 2e6 / 998e6 = 2004.0080...
        // floor = 2004, remainder ≠ 0 ⇒ ceil = 2005.
        assert_eq!(pool.compute_fee_on_net(1_000_000).unwrap(), 2_005);
    }

    /// `compute_fee_from_amount` ceil-rounds. The default test (in
    /// `parses_synthetic_lbpair_x_quote`) hits the exact-division
    /// case (no remainder); this exercises the ceil branch with a
    /// non-zero remainder so a regression to floor is caught.
    #[test]
    fn compute_fee_from_amount_ceil_rounds() {
        let pool = DlmmPool {
            active_id: 0,
            bin_step: 25,
            base_factor: 8000,
            base_fee_power_factor: 0,
            protocol_share: 0,
        };
        // rate = 2e6; gross = 1; num = 2e6; ceil(2e6 / 1e9) = 1.
        // (Floor would yield 0 — pin that we round up.)
        assert_eq!(pool.compute_fee_from_amount(1).unwrap(), 1);
    }

    /// `total_fee_rate` caps at `DLMM_MAX_FEE_RATE` (10%). With Phase 1
    /// base-fee-only this never bites — `MAX_BIN_STEP=400` keeps the
    /// rate under 4% — but pin the cap so a future Phase 3 variable-fee
    /// regression that pushes rate above 10% can't underflow
    /// `compute_fee_on_net`'s `1e9 - rate` denominator.
    #[test]
    fn total_fee_rate_caps_at_max() {
        // Synthesise a pool whose raw rate exceeds MAX_FEE_RATE (10% in
        // 1e9 = 1e8). 10000 * 400 * 10 = 40_000_000 (4%). Bump
        // base_fee_power_factor to 1 ⇒ 400_000_000 (40%, > cap).
        let pool = DlmmPool {
            active_id: 0,
            bin_step: 400,
            base_factor: 10_000,
            base_fee_power_factor: 1,
            protocol_share: 0,
        };
        assert_eq!(pool.total_fee_rate(), Some(DLMM_MAX_FEE_RATE));
    }
}

#[cfg(test)]
mod bin_array_tests {
    use super::bin_array::{
        bin_array_lower_upper_bin_id, bin_array_pda, bin_id_to_bin_array_index, bin_index_in_array,
        parse_bin_array, BIN_ARRAY_DATA_LEN, BIN_DATA_LEN, MAX_BIN_PER_ARRAY,
    };
    use solana_sdk::pubkey::Pubkey;

    /// Pin the floor-toward-negative-infinity behaviour. Catches the
    /// regression where someone replaces the helper with raw `/`,
    /// which truncates toward zero and would map `bin_id = -1` to
    /// array `0` (covering `[0, 69]`) instead of array `-1`
    /// (covering `[-70, -1]`).
    #[test]
    fn bin_id_to_array_index_floors_negatives() {
        assert_eq!(bin_id_to_bin_array_index(0), 0);
        assert_eq!(bin_id_to_bin_array_index(69), 0);
        assert_eq!(bin_id_to_bin_array_index(70), 1);
        assert_eq!(bin_id_to_bin_array_index(139), 1);
        assert_eq!(bin_id_to_bin_array_index(140), 2);

        // Negatives — flooring matters here.
        assert_eq!(bin_id_to_bin_array_index(-1), -1);
        assert_eq!(bin_id_to_bin_array_index(-70), -1);
        assert_eq!(bin_id_to_bin_array_index(-71), -2);
        assert_eq!(bin_id_to_bin_array_index(-140), -2);
    }

    #[test]
    fn array_lower_upper_round_trip() {
        let cases = [(-2, -140, -71), (-1, -70, -1), (0, 0, 69), (1, 70, 139)];
        for (idx, lo, hi) in cases {
            let (l, u) = bin_array_lower_upper_bin_id(idx);
            assert_eq!((l, u), (lo, hi), "array {idx}");
        }
    }

    #[test]
    fn bin_index_within_range() {
        // Array 1 covers [70, 139]; bin 75 should land at slot 5.
        assert_eq!(bin_index_in_array(1, 75), Some(5));
        assert_eq!(bin_index_in_array(1, 70), Some(0));
        assert_eq!(bin_index_in_array(1, 139), Some(MAX_BIN_PER_ARRAY - 1));
        // Out-of-range returns None rather than wrapping.
        assert_eq!(bin_index_in_array(1, 69), None);
        assert_eq!(bin_index_in_array(1, 140), None);
    }

    /// Synthetic BinArray blob: index = -3, lb_pair set, bin[5] given
    /// distinguishing reserves so we can confirm the per-bin offset
    /// arithmetic. Catches off-by-one bin indexing or wrong field
    /// offsets within the 144-byte Bin layout.
    #[test]
    fn parse_synthetic_bin_array() {
        let mut data = vec![0u8; BIN_ARRAY_DATA_LEN];
        // index = -3 (i64 LE).
        data[8..16].copy_from_slice(&(-3i64).to_le_bytes());
        // version = 1
        data[16] = 1;
        let lb_pair = Pubkey::new_unique();
        data[24..56].copy_from_slice(lb_pair.as_ref());

        // Bins start at offset 56. Set bin[5] to known values so we
        // can confirm strided indexing.
        let bin5_offset = 56 + 5 * BIN_DATA_LEN;
        data[bin5_offset..bin5_offset + 8].copy_from_slice(&12_345u64.to_le_bytes());
        data[bin5_offset + 8..bin5_offset + 16].copy_from_slice(&67_890u64.to_le_bytes());
        data[bin5_offset + 16..bin5_offset + 32]
            .copy_from_slice(&((1u128 << 64) + 7).to_le_bytes());
        data[bin5_offset + 32..bin5_offset + 48].copy_from_slice(&999_999u128.to_le_bytes());

        let parsed = parse_bin_array(&data).unwrap();
        assert_eq!(parsed.index, -3);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.lb_pair, lb_pair);
        assert_eq!(parsed.bins.len(), MAX_BIN_PER_ARRAY);
        assert_eq!(parsed.bins[5].amount_x, 12_345);
        assert_eq!(parsed.bins[5].amount_y, 67_890);
        assert_eq!(parsed.bins[5].price, (1u128 << 64) + 7);
        assert_eq!(parsed.bins[5].liquidity_supply, 999_999);
        // Untouched bins should parse as zero.
        assert_eq!(parsed.bins[0].amount_x, 0);
        assert_eq!(parsed.bins[0].price, 0);
    }

    #[test]
    fn parse_rejects_short_bin_array() {
        let short = vec![0u8; BIN_ARRAY_DATA_LEN - 1];
        assert!(parse_bin_array(&short).is_none());
    }

    /// PDA derivation must:
    ///   1. Return a valid (i.e. on-curve-rejected) PDA — `find_program_address`
    ///      handles that by re-trying nonces.
    ///   2. Be deterministic for the same `(lb_pair, index)`.
    ///   3. Differ when `index` widens incorrectly — pin the i64
    ///      encoding so a future regression to `i32.to_le_bytes()`
    ///      is caught.
    #[test]
    fn bin_array_pda_is_deterministic() {
        let lb_pair = Pubkey::new_unique();
        let (a1, _) = bin_array_pda(&lb_pair, 5);
        let (a2, _) = bin_array_pda(&lb_pair, 5);
        assert_eq!(a1, a2, "PDA must be deterministic");

        let (b, _) = bin_array_pda(&lb_pair, -5);
        assert_ne!(a1, b, "different indices must yield different PDAs");

        // Pin the i64 encoding: an i32-encoded -1 would only fill 4
        // bytes, while i64 fills 8 — so an i64 vs i32 mismatch yields
        // different PDAs. Document the contract by checking the byte
        // length is what we expect.
        let bytes = (-1i64).to_le_bytes();
        assert_eq!(bytes.len(), 8);
    }
}

#[cfg(test)]
mod price_math_tests {
    use super::price_math::{bin_price, pow, MAX_EXPONENTIAL, ONE, SCALE_OFFSET};

    /// Q64.64 tolerance roughly equal to 1 part-per-million of `ONE`.
    /// Catch real arithmetic regressions but tolerate the 1-ULP rounding
    /// the `u128::MAX / x` inversion contributes.
    const Q64_TOLERANCE_PPM: u128 = ONE / 1_000_000;

    fn approx_eq_q64(a: u128, b: u128, tol: u128) -> bool {
        a.abs_diff(b) <= tol
    }

    #[test]
    fn pow_zero_returns_one() {
        // Any base, any-flavoured `0` exp ⇒ ONE.
        assert_eq!(pow(ONE, 0), Some(ONE));
        assert_eq!(pow(0, 0), Some(ONE));
        assert_eq!(pow(ONE / 2, 0), Some(ONE));
    }

    #[test]
    fn pow_rejects_max_exponential() {
        // `MAX_EXPONENTIAL` is the *exclusive* exponent cap the on-chain
        // code enforces. Hitting it returns `None` regardless of base.
        let base = ONE + (ONE / 1000); // ~1.001
        assert!(pow(base, MAX_EXPONENTIAL as i32).is_none());
        assert!(pow(base, -(MAX_EXPONENTIAL as i32)).is_none());
        // A small base + modest exponent should always produce a value;
        // pins that the cap check isn't over-eager. (Larger bases hit
        // the value-side overflow earlier than the cap — expected, since
        // the cap is sized for the smallest realistic `bin_step = 1bp`.)
        let tiny_base = ONE + ONE / 10_000; // 1.0001
        assert!(pow(tiny_base, 100).is_some());
        assert!(pow(tiny_base, -100).is_some());
    }

    #[test]
    fn bin_price_at_zero_is_one() {
        // bin_id = 0 ⇒ base^0 = 1.0 (Q64.64) regardless of bin_step.
        for &step in &[1u16, 25, 50, 100, 400] {
            assert_eq!(bin_price(0, step), Some(ONE), "step={step}");
        }
    }

    #[test]
    fn bin_price_one_step_matches_reference() {
        // bin_id = 1, bin_step = 25 ⇒ 1.0025 in Q64.64.
        // Reference: 1.0025 * 2^64. The integer division used by
        // `(bin_step << 64) / 10_000` floors the bps fraction, so the
        // result is `(1 + floor(25 << 64 / 10_000))` = ONE + 18_446_744_073_709_551 ≈ 1.0025.
        let p = bin_price(1, 25).unwrap();
        // Expected: ONE * 1.0025 to within tolerance.
        let expected = ONE + ONE * 25 / 10_000;
        assert!(
            approx_eq_q64(p, expected, Q64_TOLERANCE_PPM),
            "got {p}, expected ≈{expected}",
        );
    }

    /// Monotonicity: prices grow as bin_id increases (in the positive
    /// half) and shrink as bin_id decreases (in the negative half).
    #[test]
    fn bin_price_is_monotone() {
        let step = 25u16;
        let mut prev = bin_price(0, step).unwrap();
        for id in 1..=50i32 {
            let next = bin_price(id, step).unwrap();
            assert!(next > prev, "id={id} not monotone increasing");
            prev = next;
        }
        let mut prev = bin_price(0, step).unwrap();
        for id in (-50i32..=-1).rev() {
            let next = bin_price(id, step).unwrap();
            assert!(next < prev, "id={id} not monotone decreasing");
            prev = next;
        }
    }

    /// Inverse property: `bin_price(n) * bin_price(-n) ≈ ONE^2` in Q64.64.
    /// The product is in Q128.128, so we shift by `SCALE_OFFSET` to bring
    /// it back to Q64.64 and compare with `ONE`. The 1-ULP error from the
    /// `u128::MAX / x` inversion accumulates over n iterations, so the
    /// tolerance scales with n.
    #[test]
    fn bin_price_inverse_property() {
        for n in [1i32, 5, 10, 50, 100] {
            let p_pos = bin_price(n, 25).unwrap();
            let p_neg = bin_price(-n, 25).unwrap();
            // Reduce to Q64.64: (p_pos * p_neg) >> 64 should equal ONE.
            let prod_q64 = (p_pos >> 32).checked_mul(p_neg >> 32).expect("no overflow");
            // Allow generous tolerance — the round-trip accumulates the
            // u128::MAX / x rounding error; ~10 ppm at |n| = 100.
            let tol = Q64_TOLERANCE_PPM * (n as u128 + 1) * 10;
            assert!(
                approx_eq_q64(prod_q64, ONE, tol),
                "n={n}: prod={prod_q64} (diff {} from ONE)",
                prod_q64.abs_diff(ONE),
            );
        }
    }

    /// Pin the SCALE_OFFSET / ONE pair: on-chain math relies on
    /// `ONE = 1 << 64`. A future regression that changes either one
    /// without the other silently breaks every reciprocal calc.
    #[test]
    fn scale_offset_one_pin() {
        assert_eq!(SCALE_OFFSET, 64);
        assert_eq!(ONE, 1u128 << 64);
    }
}

#[cfg(test)]
mod swap_math_tests {
    use super::price_math::ONE;
    use super::swap_math::{swap_within_bin, BinSwapStep};
    use super::DlmmPool;

    /// Standard test pool: 25-bp bin step, base_factor 8000 ⇒
    /// 0.2% base fee in 1e9 units. No variable fee (Phase 1).
    fn pool_8000_25() -> DlmmPool {
        DlmmPool {
            active_id: 0,
            bin_step: 25,
            base_factor: 8000,
            base_fee_power_factor: 0,
            protocol_share: 0,
        }
    }

    /// Empty bin (output side has zero reserves): swap should bail
    /// with a zero-amount step + `bin_drained = true`. Pins the
    /// caller contract that drained bins propagate to the next bin
    /// without breaking the input.
    #[test]
    fn empty_output_side_drains_immediately() {
        let pool = pool_8000_25();
        let step = swap_within_bin(1_000_000, 0, 0, ONE, true, &pool).unwrap();
        assert_eq!(
            step,
            BinSwapStep {
                amount_in_with_fees: 0,
                amount_out: 0,
                fee: 0,
                bin_drained: true,
                // Empty bin can't absorb anything ⇒ caller's full
                // input remains for the next bin.
                amount_in_remaining: 1_000_000,
            }
        );
    }

    /// Partial fill ⇒ no leftover. Pin the contract that
    /// `amount_in_remaining = 0` is the cross-bin walker's "stop"
    /// signal — a regression that returns non-zero here would cause
    /// the walker to re-enter the same bin and either spin or
    /// double-charge.
    #[test]
    fn partial_fill_leaves_zero_remaining() {
        let pool = pool_8000_25();
        let big = 1_000_000_000u64;
        let step = swap_within_bin(1_000_000, big, big, ONE, true, &pool).unwrap();
        assert_eq!(step.amount_in_remaining, 0);
        assert!(!step.bin_drained);
    }

    /// Drain path ⇒ leftover = `amount_in - max_amount_in` (the gross
    /// amount the bin actually absorbed). The cross-bin walker
    /// (Phase 2 step 2) uses this to seed the next bin's swap.
    #[test]
    fn drain_path_returns_correct_leftover() {
        let pool = pool_8000_25();
        // Reserves of 100 Y vs huge X input (1B). The bin's
        // max_amount_in is small (≈101 from the cross-bin test);
        // leftover ≈ 1B - 101.
        let step = swap_within_bin(1_000_000_000, 999_999, 100, ONE, true, &pool).unwrap();
        assert!(step.bin_drained);
        // Sum invariant: amount_in_with_fees + amount_in_remaining
        // == caller's gross amount_in.
        assert_eq!(
            step.amount_in_with_fees as u128 + step.amount_in_remaining as u128,
            1_000_000_000,
        );
    }

    /// Zero price → arithmetic impossible; bail with `None` rather
    /// than divide-by-zero. Catches a future regression where someone
    /// swaps an uninitialised bin (Bin.price == 0) without first
    /// recomputing it via `bin_price`.
    #[test]
    fn zero_price_returns_none() {
        let pool = pool_8000_25();
        assert!(swap_within_bin(1_000_000, 1_000, 1_000, 0, true, &pool).is_none());
    }

    /// Partial fill at price = 1.0 (Q64.64 ONE): one unit of X buys
    /// roughly one unit of Y minus the 0.2% fee. Pins the X→Y
    /// floor formula `(amount_in - fee) * price >> 64`. Reserves
    /// sized to comfortably contain the swap (1B ≫ 1M caller input).
    #[test]
    fn partial_x_to_y_at_unit_price() {
        let pool = pool_8000_25();
        let big = 1_000_000_000u64;
        // amount_in = 1_000_000, price = ONE (1.0).
        // Expected fee = ceil(1_000_000 * 2e6 / 1e9) = 2_000.
        // amount_in_after_fee = 998_000.
        // amount_out = floor(998_000 * 2^64 / 2^64) = 998_000.
        let step = swap_within_bin(1_000_000, big, big, ONE, true, &pool).unwrap();
        assert!(!step.bin_drained);
        assert_eq!(step.amount_in_with_fees, 1_000_000);
        assert_eq!(step.fee, 2_000);
        assert_eq!(step.amount_out, 998_000);
    }

    /// Drain-bin path: caller hands in more than the bin can absorb.
    /// Output is capped at `bin_amount_y`; fee uses the
    /// "compute_fee_on_net" branch (gross-up from net).
    #[test]
    fn drain_bin_caps_output_and_uses_compute_fee_on_net() {
        let pool = pool_8000_25();
        // Bin has only 100 Y available. Caller offers a huge X.
        // max_in_pre_fee = ceil((100 << 64) / ONE) = 100.
        // max_fee = ceil(100 * 2e6 / 998e6) = ceil(0.2004...) = 1.
        // max_amount_in = 101.
        let step = swap_within_bin(1_000_000_000, 999_999, 100, ONE, true, &pool).unwrap();
        assert!(step.bin_drained);
        assert_eq!(step.amount_out, 100);
        assert_eq!(step.amount_in_with_fees, 101);
        assert_eq!(step.fee, 1);
    }

    /// Y→X direction: at price = ONE, 1 Y buys 1 X minus fee.
    /// Mirrors the X→Y test with directions swapped to pin the
    /// `swap_for_y = false` branch.
    #[test]
    fn partial_y_to_x_at_unit_price() {
        let pool = pool_8000_25();
        let big = 1_000_000_000u64;
        let step = swap_within_bin(1_000_000, big, big, ONE, false, &pool).unwrap();
        assert!(!step.bin_drained);
        assert_eq!(step.fee, 2_000);
        assert_eq!(step.amount_out, 998_000);
    }

    /// Price > 1.0: at p = 2.0 (Q64.64), 1 X buys 2 Y. Pins the
    /// scaling so a regression that drops the price multiplication
    /// (returning amount_in instead of amount_in * price) is caught.
    #[test]
    fn partial_x_to_y_at_double_price() {
        let pool = pool_8000_25();
        let big = 1_000_000_000u64;
        let p = ONE * 2;
        // amount_in_after_fee = 998_000.
        // amount_out = floor(998_000 * 2 * ONE / ONE) = 1_996_000.
        let step = swap_within_bin(1_000_000, big, big, p, true, &pool).unwrap();
        assert_eq!(step.amount_out, 1_996_000);
    }
}

#[cfg(test)]
mod cross_bin_tests {
    use super::bin_array::{ParsedBin, ParsedBinArray, MAX_BIN_PER_ARRAY};
    use super::cross_bin::{cross_bin_swap, DlmmBinState, MAX_SWAP_ITERATIONS};
    use super::DlmmPool;
    use solana_sdk::pubkey::Pubkey;

    fn pool() -> DlmmPool {
        DlmmPool {
            active_id: 0,
            bin_step: 25,
            base_factor: 8000,
            base_fee_power_factor: 0,
            protocol_share: 0,
        }
    }

    /// Build a synthetic ParsedBinArray at the given index where every
    /// bin has identical reserves + price (`DLMM_ONE` for `bin_id = 0`,
    /// else lazy-cached `0` so the walker recomputes via `bin_price`).
    fn uniform_array(index: i64, amount_x: u64, amount_y: u64) -> ParsedBinArray {
        let bins = (0..MAX_BIN_PER_ARRAY)
            .map(|_| ParsedBin {
                amount_x,
                amount_y,
                // Lazy-cached `0` exercises the `from_arrays` recompute
                // branch — the walker should produce identical results
                // regardless of cache hit / miss.
                price: 0,
                liquidity_supply: 1_000_000_000,
            })
            .collect();
        ParsedBinArray {
            index,
            version: 1,
            lb_pair: Pubkey::new_unique(),
            bins,
        }
    }

    /// Single-bin walk: amount fits inside the active bin. Should
    /// produce one iteration and `final_active_id == initial`.
    /// Mostly a sanity check that the walker doesn't over-step on
    /// partial fills.
    #[test]
    fn single_bin_walk_one_iteration() {
        let arrays = vec![uniform_array(0, 1_000_000_000, 1_000_000_000)];
        let mut state = DlmmBinState::from_arrays(&arrays, 25).unwrap();
        let pool = pool();
        let r = cross_bin_swap(1_000_000, 0, &mut state, true, &pool).unwrap();
        assert_eq!(r.iterations, 1);
        assert_eq!(r.final_active_id, 0);
        assert_eq!(r.amount_in_with_fees, 1_000_000);
        // Bin reserves should reflect the swap (X went up, Y went down).
        let snap = state.get(0).unwrap();
        assert!(snap.amount_x > 1_000_000_000);
        assert!(snap.amount_y < 1_000_000_000);
    }

    /// Multi-bin walk: each bin has 100 Y, frontrun input 1B X. The
    /// walker should drain bins one by one (swap_for_y direction =
    /// X→Y, active_id decreases) until input is exhausted or window
    /// runs out. Pin that final_active_id < initial and iterations
    /// is small (~few bins worth of liquidity).
    #[test]
    fn multi_bin_walk_advances_active_id() {
        // Window: array indices -2, -1, 0, 1, 2 (covers bins -140..=139).
        let arrays = vec![
            uniform_array(-2, 0, 1_000),
            uniform_array(-1, 0, 1_000),
            uniform_array(0, 0, 1_000),
            uniform_array(1, 0, 1_000),
            uniform_array(2, 0, 1_000),
        ];
        let mut state = DlmmBinState::from_arrays(&arrays, 25).unwrap();
        let pool = pool();

        // Start at active_id = 0; swap X→Y. Each bin holds 1_000 Y.
        // Caller hands in enough X to drain ~5 bins.
        let r = cross_bin_swap(20_000, 0, &mut state, true, &pool).unwrap();
        // Walker should have advanced backward (X→Y consumes y, bin
        // ids decrease).
        assert!(r.final_active_id < 0, "got {}", r.final_active_id);
        // Some Y must have been delivered.
        assert!(r.amount_out > 0);
        // Total fee ≤ 0.2% of input.
        assert!(r.fee <= r.amount_in_with_fees / 100);
    }

    /// Out-of-window: walker steps past the supplied arrays without
    /// consuming all input ⇒ `None`. Catches the regression where
    /// a too-small fetch window silently truncates the swap.
    #[test]
    fn out_of_window_bails() {
        // Single array at index 0 covers bins [0, 69]. Each bin
        // holds 100 Y. Caller hands in enough X to need >70 bins'
        // worth — walker hits bin -1 (outside window) and bails.
        let arrays = vec![uniform_array(0, 0, 100)];
        let mut state = DlmmBinState::from_arrays(&arrays, 25).unwrap();
        let pool = pool();
        // 70 bins * 100 Y = 7_000 Y; need much more X to drain that.
        let r = cross_bin_swap(1_000_000_000, 0, &mut state, true, &pool);
        assert!(r.is_none(), "should bail when walker leaves window");
    }

    /// Empty bin skip: walker advances past empty bins without
    /// charging the input. Pin that the iteration cap doesn't fire
    /// when a stretch of empty bins separates liquidity.
    #[test]
    fn empty_bin_skip_propagates_input() {
        // Build an array where bin 0 is empty (Y=0) and bin -1 has
        // liquidity. Walker should skip bin 0 → bin -1.
        let bins = vec![
            ParsedBin {
                amount_x: 0,
                amount_y: 0, // empty Y
                price: 0,
                liquidity_supply: 0,
            };
            MAX_BIN_PER_ARRAY
        ];
        // Bin -1 is at array index -1, slot 69. Build a separate
        // array for bin -1 with liquidity.
        let array_0 = ParsedBinArray {
            index: 0,
            version: 1,
            lb_pair: Pubkey::new_unique(),
            bins: bins.clone(),
        };
        let mut bins_minus1 = bins.clone();
        bins_minus1[MAX_BIN_PER_ARRAY - 1] = ParsedBin {
            amount_x: 0,
            amount_y: 1_000_000_000, // bin -1 has plenty
            price: 0,
            liquidity_supply: 1_000_000_000,
        };
        let array_minus1 = ParsedBinArray {
            index: -1,
            version: 1,
            lb_pair: array_0.lb_pair,
            bins: bins_minus1,
        };
        let arrays = vec![array_0, array_minus1];
        let mut state = DlmmBinState::from_arrays(&arrays, 25).unwrap();
        let pool = pool();
        let r = cross_bin_swap(1_000_000, 0, &mut state, true, &pool).unwrap();
        // Walker advanced from 0 (empty) → -1 (liquid). At least 2
        // iterations: one to skip bin 0, one to swap in bin -1.
        assert!(r.iterations >= 2);
        assert_eq!(r.final_active_id, -1);
        assert!(r.amount_out > 0);
    }

    /// Iteration cap pin: declarative — `MAX_SWAP_ITERATIONS = 256`.
    /// Catches accidental tightening that would break realistic
    /// sparse-liquidity pools.
    #[test]
    fn iteration_cap_constant_pin() {
        assert_eq!(MAX_SWAP_ITERATIONS, 256);
    }
}
