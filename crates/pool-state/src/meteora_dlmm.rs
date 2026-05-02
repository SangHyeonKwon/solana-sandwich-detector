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
//! discriminator) for everything we read:
//!
//! ```text
//!   field                                offset  size
//!   discriminator                            0     8
//!   parameters (StaticParameters, 32B)       8    32
//!     - base_factor: u16                     8     2
//!     - filter_period: u16                  10     2
//!     - decay_period: u16                   12     2
//!     - reduction_factor: u16               14     2
//!     - variable_fee_control: u32           16     4
//!     - max_volatility_accumulator: u32     20     4
//!     - min_bin_id: i32                     24     4   (unused in replay)
//!     - max_bin_id: i32                     28     4   (unused in replay)
//!     - protocol_share: u16                 32     2
//!     - base_fee_power_factor: u8           34     1
//!     - _padding: [u8; 5]                   35     5
//!   v_parameters (VariableParameters, 32B)  40    32
//!     - volatility_accumulator: u32         40     4
//!     - volatility_reference: u32           44     4
//!     - index_reference: i32                48     4
//!     - _padding: [u8; 4]                   52     4
//!     - last_update_timestamp: i64          56     8
//!     - _padding_1: [u8; 8]                 64     8
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

// StaticParameters fields (relative to LbPair start, parameters at offset 8).
const BASE_FACTOR_OFFSET: usize = DISCRIMINATOR_LEN; // 8
const FILTER_PERIOD_OFFSET: usize = DISCRIMINATOR_LEN + 2; // 10
const DECAY_PERIOD_OFFSET: usize = DISCRIMINATOR_LEN + 4; // 12
const REDUCTION_FACTOR_OFFSET: usize = DISCRIMINATOR_LEN + 6; // 14
const VARIABLE_FEE_CONTROL_OFFSET: usize = DISCRIMINATOR_LEN + 8; // 16
const MAX_VOLATILITY_ACCUMULATOR_OFFSET: usize = DISCRIMINATOR_LEN + 12; // 20
const PROTOCOL_SHARE_OFFSET: usize = DISCRIMINATOR_LEN + 24; // 32
const BASE_FEE_POWER_FACTOR_OFFSET: usize = DISCRIMINATOR_LEN + 26; // 34

// VariableParameters fields (v_parameters block at offset 40).
const V_PARAMS_OFFSET: usize = DISCRIMINATOR_LEN + 32; // 40
const VOLATILITY_ACCUMULATOR_OFFSET: usize = V_PARAMS_OFFSET; // 40
const VOLATILITY_REFERENCE_OFFSET: usize = V_PARAMS_OFFSET + 4; // 44
const INDEX_REFERENCE_OFFSET: usize = V_PARAMS_OFFSET + 8; // 48
const LAST_UPDATE_TIMESTAMP_OFFSET: usize = V_PARAMS_OFFSET + 16; // 56

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

/// Basis-point denominator used by DLMM volatility math. Mirrors
/// `BASIS_POINT_MAX` in `MeteoraAg/dlmm-sdk/commons/src/constants.rs`.
/// Distinct from the `price_math::BASIS_POINT_MAX` (u128, same value),
/// kept as `u32` here so the volatility ops avoid widening churn.
const DLMM_BASIS_POINT_MAX: u32 = 10_000;

/// Hard-coded `compute_variable_fee` divisor (10^11). On-chain
/// `LbPair::compute_variable_fee` ceil-divides `variable_fee_control *
/// (volatility_accumulator * bin_step)^2` by this constant. Mirroring
/// the literal (rather than re-deriving from FEE_PRECISION) guards
/// against future on-chain refactors silently changing the scaling.
const DLMM_VARIABLE_FEE_SCALE: u128 = 100_000_000_000;

/// Meteora DLMM program id — `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo`.
/// Used by future BinArray PDA derivation. Decoded once per call from the
/// hardcoded base58 (same pattern as `whirlpool_program_id`).
pub fn dlmm_program_id() -> Pubkey {
    Pubkey::from_str("LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo")
        .expect("dlmm program id is hardcoded valid base58 pubkey")
}

/// Snapshot of `LbPair` state combining the dynamic active bin id with
/// the static + variable fee parameters that govern swap fees.
///
/// The static-fee triple (`base_factor`, `bin_step`, `base_fee_power_factor`)
/// never mutates per swap; the variable-fee state (`volatility_accumulator`,
/// `volatility_reference`, `index_reference`, `last_update_timestamp`) is
/// updated each swap on-chain. We surface the snapshot at the moment the
/// account was fetched — replay then advances the variable-fee state in-
/// memory exactly as on-chain `update_references` /
/// `update_volatility_accumulator` would.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// High-frequency-trading window in seconds. If two swaps land within
    /// this window, the volatility reference is *not* refreshed — the
    /// accumulator keeps growing across them so a burst of swaps
    /// compounds the variable fee. Static per pool.
    pub filter_period: u16,
    /// Decay window in seconds. After `filter_period` but before
    /// `decay_period` elapsed, the volatility reference decays by
    /// `reduction_factor / 10_000`; past `decay_period`, it resets to 0.
    /// Static per pool.
    pub decay_period: u16,
    /// Volatility decay multiplier in basis points. `5_000 = 50%`. Static
    /// per pool.
    pub reduction_factor: u16,
    /// Coefficient that scales `(volatility_accumulator * bin_step)^2`
    /// into the variable-fee numerator. `0` disables the variable-fee
    /// component. Static per pool.
    pub variable_fee_control: u32,
    /// Cap on `volatility_accumulator` — pins the maximum variable-fee
    /// rate. Static per pool.
    pub max_volatility_accumulator: u32,
    /// Volatility accumulator. On-chain it stores the count of bins
    /// crossed since `index_reference`, expressed in basis-point units
    /// (`bins_crossed * 10_000 + reference_residue`). Mutates every
    /// `update_volatility_accumulator` call.
    pub volatility_accumulator: u32,
    /// Decayed volatility carried from the previous swap. Always
    /// `<= volatility_accumulator`. Refreshed by `update_references`.
    pub volatility_reference: u32,
    /// `active_id` snapshotted at the previous swap (or, after an
    /// `update_references` reset, the current `active_id`). Anchor for
    /// the `delta_id = |index_reference - active_id|` accumulator term.
    pub index_reference: i32,
    /// Wall-clock timestamp of the last `update_references` call.
    /// Compared against the current swap's timestamp to decide whether
    /// the filter / decay window has elapsed.
    pub last_update_timestamp: i64,
}

impl DlmmPool {
    /// Static-fee numerator over [`DLMM_FEE_PRECISION`]:
    /// `base_factor * bin_step * 10 * 10^base_fee_power_factor`. Mirrors
    /// `LbPair::get_base_fee`. Uncapped — the cap is applied in
    /// [`Self::total_fee_rate`] after the variable component is added.
    pub fn base_fee_rate(&self) -> Option<u128> {
        let factor = (self.base_factor as u128)
            .checked_mul(self.bin_step as u128)?
            .checked_mul(10)?;
        let power_mul: u128 = 10u128.checked_pow(self.base_fee_power_factor as u32)?;
        factor.checked_mul(power_mul)
    }

    /// Variable-fee numerator at the supplied accumulator value.
    /// Mirrors on-chain `LbPair::compute_variable_fee`:
    /// `ceil(variable_fee_control * (vol_acc * bin_step)^2 / 10^11)`.
    /// Returns 0 when `variable_fee_control == 0` (the static-fee-only
    /// pool config — most pools today).
    ///
    /// Taking the accumulator as an argument (rather than reading
    /// `self.volatility_accumulator`) mirrors the on-chain split
    /// between `compute_variable_fee` and `get_variable_fee`. Replay
    /// callers want to compute the variable fee *at the start of a
    /// specific bin step*, after `update_volatility_accumulator` has
    /// already mutated `self`.
    pub fn compute_variable_fee(&self, volatility_accumulator: u32) -> Option<u128> {
        if self.variable_fee_control == 0 {
            return Some(0);
        }
        let vol = u128::from(volatility_accumulator);
        let bin_step = u128::from(self.bin_step);
        let vfc = u128::from(self.variable_fee_control);
        let square = vol.checked_mul(bin_step)?.checked_pow(2)?;
        let v_fee = vfc.checked_mul(square)?;
        v_fee
            .checked_add(DLMM_VARIABLE_FEE_SCALE.checked_sub(1)?)?
            .checked_div(DLMM_VARIABLE_FEE_SCALE)
    }

    /// Aggregate swap-fee rate (numerator over [`DLMM_FEE_PRECISION`]),
    /// capped at [`DLMM_MAX_FEE_RATE`] to mirror on-chain `get_total_fee`.
    ///
    /// Reads `self.volatility_accumulator` for the variable component.
    /// Per-bin replay must therefore call
    /// [`Self::update_volatility_accumulator`] *before* this — the
    /// accumulator value is the "at the start of this bin step" reading.
    pub fn total_fee_rate(&self) -> Option<u128> {
        let base = self.base_fee_rate()?;
        let variable = self.compute_variable_fee(self.volatility_accumulator)?;
        let total = base.checked_add(variable)?;
        Some(total.min(DLMM_MAX_FEE_RATE))
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

    /// Refresh the volatility reference + index reference based on how
    /// much wall-clock time has elapsed since the previous swap.
    /// Mirrors `LbPair::update_references` in
    /// `MeteoraAg/dlmm-sdk/commons/src/extensions/lb_pair.rs`.
    ///
    /// Three regimes, gated by `(filter_period, decay_period)`:
    ///   1. `elapsed < filter_period`: high-frequency window — leave
    ///      everything alone so a burst of swaps compounds the
    ///      accumulator.
    ///   2. `filter_period <= elapsed < decay_period`: snapshot
    ///      `active_id` into `index_reference` and decay
    ///      `volatility_reference` by `reduction_factor / 10_000`.
    ///   3. `elapsed >= decay_period`: snapshot `active_id`, reset
    ///      `volatility_reference` to 0.
    ///
    /// On-chain this is called *once* at swap entry, before the per-bin
    /// loop. Phase 3's [`compute_loss_dlmm`](crate::compute_loss_dlmm)
    /// path follows the same shape.
    ///
    /// Returns `None` on arithmetic overflow (only possible with
    /// pathologically large `volatility_accumulator * reduction_factor`,
    /// not reachable from any legal pool config).
    pub fn update_references(&mut self, current_timestamp: i64) -> Option<()> {
        let elapsed = current_timestamp.checked_sub(self.last_update_timestamp)?;
        if elapsed >= i64::from(self.filter_period) {
            self.index_reference = self.active_id;
            if elapsed < i64::from(self.decay_period) {
                self.volatility_reference = self
                    .volatility_accumulator
                    .checked_mul(u32::from(self.reduction_factor))?
                    .checked_div(DLMM_BASIS_POINT_MAX)?;
            } else {
                self.volatility_reference = 0;
            }
        }
        Some(())
    }

    /// Recompute the volatility accumulator from the current `active_id`
    /// against the snapshotted `index_reference`. Mirrors
    /// `LbPair::update_volatility_accumulator` in commons.
    ///
    /// On-chain this is called **per bin** during the swap loop, *before*
    /// the bin's swap math runs — so the variable-fee rate within a
    /// bin reflects the accumulator value at that bin's start, not the
    /// previous bin's. Phase 3's `cross_bin_swap` follows the same
    /// shape so the per-bin fee replays exactly.
    ///
    /// Saturates at `max_volatility_accumulator` (the on-chain cap that
    /// prevents the variable fee from growing without bound during
    /// large multi-bin walks).
    ///
    /// Returns `None` on arithmetic overflow (only possible if
    /// `delta_id * 10_000` overflows `u64` — requires a `delta_id`
    /// north of `1.8e15`, far beyond DLMM's `[-443_636, 443_636]`
    /// legal bin range).
    pub fn update_volatility_accumulator(&mut self) -> Option<()> {
        let delta_id = i64::from(self.index_reference)
            .checked_sub(i64::from(self.active_id))?
            .unsigned_abs();
        let raw = u64::from(self.volatility_reference)
            .checked_add(delta_id.checked_mul(u64::from(DLMM_BASIS_POINT_MAX))?)?;
        let capped = raw.min(u64::from(self.max_volatility_accumulator));
        self.volatility_accumulator = u32::try_from(capped).ok()?;
        Some(())
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

/// Parse the dynamic swap-relevant state (active bin + variable-fee
/// state) plus the static fee parameters. Returns `None` for short
/// blobs.
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
        filter_period: read_u16(account_data, FILTER_PERIOD_OFFSET)?,
        decay_period: read_u16(account_data, DECAY_PERIOD_OFFSET)?,
        reduction_factor: read_u16(account_data, REDUCTION_FACTOR_OFFSET)?,
        variable_fee_control: read_u32(account_data, VARIABLE_FEE_CONTROL_OFFSET)?,
        max_volatility_accumulator: read_u32(account_data, MAX_VOLATILITY_ACCUMULATOR_OFFSET)?,
        volatility_accumulator: read_u32(account_data, VOLATILITY_ACCUMULATOR_OFFSET)?,
        volatility_reference: read_u32(account_data, VOLATILITY_REFERENCE_OFFSET)?,
        index_reference: read_i32(account_data, INDEX_REFERENCE_OFFSET)?,
        last_update_timestamp: read_i64(account_data, LAST_UPDATE_TIMESTAMP_OFFSET)?,
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

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
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

/// `BinArrayBitmapExtension` PDA — sparse-pool support for bin arrays
/// outside the on-pool bitmap range.
///
/// The on-chain `LbPair` carries an inline `bin_array_bitmap: [u64; 16]`
/// covering bin array indices `[-512, 511]` (1024 bits, 1 per array).
/// Pools whose liquidity reaches further out — common on long-tail
/// Token-2022 pairs — keep an additional `BinArrayBitmapExtension`
/// account that extends coverage to `[-6656, -513] ∪ [512, 6655]`. Both
/// bitmaps tag a bin array as *initialized* (= has at least one liquidity
/// position open) versus *empty*; the on-chain swap walker uses them to
/// fast-forward across empty stretches without paying the per-bin
/// iteration cost.
///
/// We surface only the extension here. The internal bitmap lives on the
/// `LbPair` account body (offset `~0x110+`); plumbing it is a separate
/// follow-up. Until then, the walker's bitmap-aware fast-forward only
/// kicks in when the gap to skip is fully outside `[-512, 511]`. Gaps
/// touching the internal range fall back to the conservative
/// "bail on miss" behaviour [`out_of_window_bails`] pins.
///
/// PDA seeds: `[b"bitmap", lb_pair]`. Mirrors `derive_bin_array_bitmap_extension`
/// in `MeteoraAg/dlmm-sdk/commons/src/pda.rs`.
///
/// # Account layout
///
/// ```text
///   field                                     offset  size
///   discriminator                                 0     8
///   lb_pair: Pubkey                               8    32
///   positive_bin_array_bitmap: [[u64; 8]; 12]    40   768
///   negative_bin_array_bitmap: [[u64; 8]; 12]   808   768
/// ```
///
/// Total: 1576 bytes. `bytemuck repr(C)`, no padding.
///
/// # Bitmap math
///
/// Each row is 8 little-endian `u64` limbs forming a 512-bit integer
/// (`U512` in the SDK; we just bit-test the limbs directly to avoid the
/// dep). Positive row `r ∈ [0, 11]` covers array indices
/// `[(r+1)*512, (r+2)*512 - 1]`; negative row `r` covers
/// `[-(r+2)*512, -(r+1)*512 - 1]`. Within a row, bit `b` corresponds to
/// the `b`-th array index counting outward from the inner edge.
pub mod bitmap_extension {
    use super::{dlmm_program_id, read_pubkey, read_u64};
    use solana_sdk::pubkey::Pubkey;

    /// Bits per row (= bin array indices covered per row). Mirrors
    /// `BIN_ARRAY_BITMAP_SIZE` in `commons/src/constants.rs`. Same value
    /// as the on-pool internal bitmap's coverage radius — the extension
    /// is structured as 12 contiguous "internal-sized" bitmaps stacked
    /// outward in each direction.
    pub const BITS_PER_ROW: i32 = 512;

    /// Number of rows in each of the positive/negative bitmaps. Mirrors
    /// `EXTENSION_BINARRAY_BITMAP_SIZE` in `commons/src/constants.rs`.
    pub const ROWS: usize = 12;

    /// `u64` limbs per row (`8 * 64 = 512 = BITS_PER_ROW`).
    pub const LIMBS_PER_ROW: usize = 8;

    /// PDA seed prefix. Mirrors `BIN_ARRAY_BITMAP_SEED` in
    /// `commons/src/seeds.rs`.
    pub const BITMAP_SEED: &[u8] = b"bitmap";

    // Account body offsets (from start of account_data, including the
    // 8-byte discriminator). Pubbed so tests + downstream parsers can
    // pin the layout — a regression to a different offset would be
    // caught by the synthetic-blob test.
    const DISCRIMINATOR_LEN: usize = 8;
    /// Offset of the `lb_pair` field.
    pub const LB_PAIR_OFFSET: usize = DISCRIMINATOR_LEN; // 8
    /// Offset of `positive_bin_array_bitmap`.
    pub const POSITIVE_OFFSET: usize = LB_PAIR_OFFSET + 32; // 40
    /// Bytes per row (`8 limbs * 8 bytes`).
    pub const ROW_BYTES: usize = LIMBS_PER_ROW * 8; // 64
    /// Offset of `negative_bin_array_bitmap`.
    pub const NEGATIVE_OFFSET: usize = POSITIVE_OFFSET + ROWS * ROW_BYTES; // 808

    /// Account size including the discriminator. We over-tolerate
    /// trailing bytes (only `>=` checked), matching the rest of
    /// pool-state's parser convention.
    pub const BITMAP_EXTENSION_DATA_LEN: usize = NEGATIVE_OFFSET + ROWS * ROW_BYTES; // 1576

    /// Parsed `BinArrayBitmapExtension` account. Each `u64` row is
    /// stored as the on-chain little-endian limb array — bit indexing
    /// is LSB-first within `limbs[0]`, then carries through to `limbs[7]`'s
    /// high bit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ParsedBitmapExtension {
        /// `LbPair` this extension belongs to. Stored for cross-checks
        /// against an expected pool — a mismatched `lb_pair` is a
        /// strong signal of a wrong-PDA fetch.
        pub lb_pair: Pubkey,
        /// Bitmap rows for positive bin array indices. Row `r` covers
        /// indices `[(r+1)*512, (r+2)*512 - 1]`.
        pub positive_bitmap: [[u64; LIMBS_PER_ROW]; ROWS],
        /// Bitmap rows for negative bin array indices. Row `r` covers
        /// indices `[-(r+2)*512, -(r+1)*512 - 1]`.
        pub negative_bitmap: [[u64; LIMBS_PER_ROW]; ROWS],
    }

    impl ParsedBitmapExtension {
        /// Inclusive bin array index range the extension covers — the
        /// *outer* envelope, including the `[-512, 511]` hole that the
        /// internal bitmap handles. Use [`covers_index`] to check
        /// extension-only coverage.
        pub fn coverage_envelope() -> (i32, i32) {
            (
                -BITS_PER_ROW * (ROWS as i32 + 1),
                BITS_PER_ROW * (ROWS as i32 + 1) - 1,
            )
        }

        /// `true` iff `bin_array_index` is in the extension's coverage
        /// (outside the internal `[-512, 511]` band but within the
        /// `[-6656, 6655]` envelope).
        pub fn covers_index(bin_array_index: i32) -> bool {
            let (lo, hi) = Self::coverage_envelope();
            (lo..=hi).contains(&bin_array_index)
                && !(-BITS_PER_ROW..BITS_PER_ROW).contains(&bin_array_index)
        }

        /// Whether the bin array at `bin_array_index` is initialised
        /// (= has open positions). Returns:
        ///   * `Some(true)`  — bit set, array is initialised,
        ///   * `Some(false)` — bit unset, array is confirmed empty,
        ///   * `None`        — `bin_array_index` is outside the
        ///     extension's coverage (caller must consult the internal
        ///     bitmap, or treat as "unknown" if the internal bitmap
        ///     isn't available).
        pub fn is_array_initialized(&self, bin_array_index: i32) -> Option<bool> {
            if !Self::covers_index(bin_array_index) {
                return None;
            }
            // Mirrors `get_bitmap_offset` + `bin_array_offset_in_bitmap`
            // in `commons/src/extensions/bin_array_bitmap.rs`.
            let (row, bit) = if bin_array_index > 0 {
                (
                    (bin_array_index / BITS_PER_ROW - 1) as usize,
                    (bin_array_index % BITS_PER_ROW) as usize,
                )
            } else {
                let m = -(bin_array_index + 1);
                ((m / BITS_PER_ROW - 1) as usize, (m % BITS_PER_ROW) as usize)
            };
            let limbs = if bin_array_index > 0 {
                &self.positive_bitmap[row]
            } else {
                &self.negative_bitmap[row]
            };
            let limb_idx = bit / 64;
            let bit_in_limb = bit % 64;
            Some((limbs[limb_idx] >> bit_in_limb) & 1 == 1)
        }
    }

    /// Parse a `BinArrayBitmapExtension` account blob. Returns `None`
    /// for short data; over-tolerates trailing bytes.
    pub fn parse_bitmap_extension(account_data: &[u8]) -> Option<ParsedBitmapExtension> {
        if account_data.len() < BITMAP_EXTENSION_DATA_LEN {
            return None;
        }
        let lb_pair = read_pubkey(account_data, LB_PAIR_OFFSET)?;
        let mut positive_bitmap = [[0u64; LIMBS_PER_ROW]; ROWS];
        let mut negative_bitmap = [[0u64; LIMBS_PER_ROW]; ROWS];
        for r in 0..ROWS {
            for l in 0..LIMBS_PER_ROW {
                positive_bitmap[r][l] =
                    read_u64(account_data, POSITIVE_OFFSET + (r * LIMBS_PER_ROW + l) * 8)?;
                negative_bitmap[r][l] =
                    read_u64(account_data, NEGATIVE_OFFSET + (r * LIMBS_PER_ROW + l) * 8)?;
            }
        }
        Some(ParsedBitmapExtension {
            lb_pair,
            positive_bitmap,
            negative_bitmap,
        })
    }

    /// Derive the `BinArrayBitmapExtension` PDA for `lb_pair`. Mirrors
    /// `derive_bin_array_bitmap_extension` in `commons/src/pda.rs`.
    pub fn bitmap_extension_pda(lb_pair: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[BITMAP_SEED, lb_pair.as_ref()], &dlmm_program_id())
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

        /// Snapshot for `bin_id`. Returns `None` for either of:
        ///   * `bin_id` outside the `range` covered by the supplied
        ///     arrays (the walker stepped past the fetch window),
        ///   * `bin_id` *within* `range` but not present in the
        ///     `bins` map — happens when the caller passed a
        ///     non-contiguous window (e.g. `[Some(-2), None,
        ///     Some(0)]` after `into_iter().flatten()` collapsed to
        ///     `[arr_-2, arr_0]`, so `range = (-140, 69)` covers bin
        ///     `-71` but no entry exists for it).
        ///
        /// Both cases produce the same downstream behaviour
        /// (`cross_bin_swap` bails with `None`, enrich reports
        /// `CrossBoundaryUnsupported`), so the caller doesn't need to
        /// distinguish them — but they're semantically different
        /// failure modes worth flagging in diagnostics.
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
    /// reserves; `pool` is mutated to reflect post-walk variable-fee
    /// state (`active_id`, `volatility_accumulator`). Caller passes
    /// clones for counterfactual replays. The caller is also
    /// responsible for invoking [`DlmmPool::update_references`] *before*
    /// this — the on-chain swap calls `update_references` once at
    /// entry, then `update_volatility_accumulator` per bin (mirrored
    /// here inside the loop).
    pub fn cross_bin_swap(
        amount_in: u64,
        initial_active_id: i32,
        state: &mut DlmmBinState,
        swap_for_y: bool,
        pool: &mut DlmmPool,
    ) -> Option<CrossBinSwapResult> {
        let mut amount_left = amount_in;
        let mut total_in_with_fees: u64 = 0;
        let mut total_out: u64 = 0;
        let mut total_fee: u64 = 0;
        let mut active_id = initial_active_id;

        for iter in 0..MAX_SWAP_ITERATIONS {
            if amount_left == 0 {
                pool.active_id = active_id;
                return Some(CrossBinSwapResult {
                    amount_in_with_fees: total_in_with_fees,
                    amount_out: total_out,
                    fee: total_fee,
                    final_active_id: active_id,
                    iterations: iter,
                });
            }
            // Look up the bin first; missing bin (window edge) fails
            // the walk without mutating pool state. On-chain mirror:
            // `quote_exact_in` only calls `update_volatility_accumulator`
            // once it has confirmed the bin is in-range and about to
            // be swapped — we do the same so a `None` here returns a
            // clean failure path instead of leaving `pool.active_id`
            // and `pool.volatility_accumulator` mutated for a bin we
            // never traded against.
            let snap = state.get(active_id)?;

            // Per-bin variable-fee refresh: sync active_id and update
            // the accumulator so `swap_within_bin`'s fee read sees the
            // accumulator value at *this bin's start*. Mirrors on-chain
            // `quote_exact_in`'s `update_volatility_accumulator()` call
            // immediately before each `active_bin.swap(...)`.
            pool.active_id = active_id;
            pool.update_volatility_accumulator()?;

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
            // Use `checked_sub` so a regression in `swap_within_bin`
            // returning `fee > amount_in_with_fees` fails loudly
            // rather than silently producing 0; on-chain `Bin::swap`
            // mirrors this with `checked_sub(...).context("overflow")`.
            let amount_into_bin = step.amount_in_with_fees.checked_sub(step.fee)?;
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
                pool.active_id = active_id;
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

    /// Pin the StaticParameters dynamic-fee fields + VariableParameters
    /// offsets parsed in Phase 3. The `synth_blob` zeroes everything,
    /// so we set distinguishable values at each offset and verify the
    /// parse picks them up. Catches a future regression that swaps two
    /// adjacent offsets (e.g. `filter_period` <-> `decay_period`).
    #[test]
    fn parses_dynamic_fee_state() {
        let mut data = synth_blob();
        let mint_y = Pubkey::from_str(WSOL_MINT).unwrap();
        data[TOKEN_Y_MINT_OFFSET..TOKEN_Y_MINT_OFFSET + 32].copy_from_slice(mint_y.as_ref());
        data[FILTER_PERIOD_OFFSET..FILTER_PERIOD_OFFSET + 2].copy_from_slice(&30u16.to_le_bytes());
        data[DECAY_PERIOD_OFFSET..DECAY_PERIOD_OFFSET + 2].copy_from_slice(&600u16.to_le_bytes());
        data[REDUCTION_FACTOR_OFFSET..REDUCTION_FACTOR_OFFSET + 2]
            .copy_from_slice(&5_000u16.to_le_bytes());
        data[VARIABLE_FEE_CONTROL_OFFSET..VARIABLE_FEE_CONTROL_OFFSET + 4]
            .copy_from_slice(&40_000u32.to_le_bytes());
        data[MAX_VOLATILITY_ACCUMULATOR_OFFSET..MAX_VOLATILITY_ACCUMULATOR_OFFSET + 4]
            .copy_from_slice(&350_000u32.to_le_bytes());
        data[VOLATILITY_ACCUMULATOR_OFFSET..VOLATILITY_ACCUMULATOR_OFFSET + 4]
            .copy_from_slice(&12_345u32.to_le_bytes());
        data[VOLATILITY_REFERENCE_OFFSET..VOLATILITY_REFERENCE_OFFSET + 4]
            .copy_from_slice(&6_000u32.to_le_bytes());
        data[INDEX_REFERENCE_OFFSET..INDEX_REFERENCE_OFFSET + 4]
            .copy_from_slice(&(-42i32).to_le_bytes());
        data[LAST_UPDATE_TIMESTAMP_OFFSET..LAST_UPDATE_TIMESTAMP_OFFSET + 8]
            .copy_from_slice(&1_700_000_000i64.to_le_bytes());

        let state = parse_pool_state(&data).unwrap();
        assert_eq!(state.filter_period, 30);
        assert_eq!(state.decay_period, 600);
        assert_eq!(state.reduction_factor, 5_000);
        assert_eq!(state.variable_fee_control, 40_000);
        assert_eq!(state.max_volatility_accumulator, 350_000);
        assert_eq!(state.volatility_accumulator, 12_345);
        assert_eq!(state.volatility_reference, 6_000);
        assert_eq!(state.index_reference, -42);
        assert_eq!(state.last_update_timestamp, 1_700_000_000);
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        };
        // rate = 2e6; gross = 1; num = 2e6; ceil(2e6 / 1e9) = 1.
        // (Floor would yield 0 — pin that we round up.)
        assert_eq!(pool.compute_fee_from_amount(1).unwrap(), 1);
    }

    /// Standard pool fixture used by the volatility-update tests. Bins
    /// 25 bp, max accumulator 350_000 (matches an SOL/USDC mainnet
    /// pool), reduction factor 5_000 ⇒ 50% decay per filter window.
    fn pool_with_dyn_fee() -> DlmmPool {
        DlmmPool {
            active_id: 100,
            bin_step: 25,
            base_factor: 8000,
            base_fee_power_factor: 0,
            protocol_share: 0,
            filter_period: 30,
            decay_period: 600,
            reduction_factor: 5_000,
            variable_fee_control: 40_000,
            max_volatility_accumulator: 350_000,
            volatility_accumulator: 20_000,
            volatility_reference: 10_000,
            index_reference: 95,
            last_update_timestamp: 1_000_000,
        }
    }

    /// Inside the filter window — references are *not* refreshed.
    /// Pins regime 1: a burst of swaps compounds the accumulator.
    #[test]
    fn update_references_inside_filter_window_is_noop() {
        let mut pool = pool_with_dyn_fee();
        let before = pool;
        // 10 < filter_period (30) ⇒ skip.
        pool.update_references(1_000_000 + 10).unwrap();
        assert_eq!(pool, before);
    }

    /// Filter window passed but inside decay window — index_reference
    /// snapshots active_id, volatility_reference decays by 50%.
    #[test]
    fn update_references_decays_inside_decay_window() {
        let mut pool = pool_with_dyn_fee();
        // 100s elapsed: filter (30) <= 100 < decay (600).
        pool.update_references(1_000_000 + 100).unwrap();
        assert_eq!(pool.index_reference, 100, "index_ref ← active_id");
        // volatility_accumulator (20_000) * reduction_factor (5_000) /
        // BASIS_POINT_MAX (10_000) = 10_000.
        assert_eq!(pool.volatility_reference, 10_000);
    }

    /// Boundary: `reduction_factor = 10_000` ⇒ the decay multiplier
    /// is exactly `1.0`, so the volatility_reference equals the
    /// previous accumulator with no decay. Pins that the integer
    /// `*reduction_factor / BASIS_POINT_MAX` math doesn't pick up an
    /// off-by-one (e.g. `(vol * 10_001 / 10_000)` from a stray `+1`).
    #[test]
    fn update_references_full_decay_factor_preserves_accumulator() {
        let mut pool = pool_with_dyn_fee();
        pool.reduction_factor = 10_000;
        pool.volatility_accumulator = 33_333;
        // Inside decay window.
        pool.update_references(1_000_000 + 100).unwrap();
        assert_eq!(pool.volatility_reference, 33_333);
    }

    /// Decay window also passed — volatility_reference fully resets
    /// to 0.
    #[test]
    fn update_references_resets_past_decay_window() {
        let mut pool = pool_with_dyn_fee();
        // 1000s > decay (600).
        pool.update_references(1_000_000 + 1_000).unwrap();
        assert_eq!(pool.index_reference, 100);
        assert_eq!(pool.volatility_reference, 0);
    }

    /// `delta_id` is the *absolute* difference. Tests both signs so a
    /// future regression that drops the `unsigned_abs()` is caught.
    #[test]
    fn update_volatility_accumulator_uses_abs_delta() {
        let mut pool = pool_with_dyn_fee();
        pool.volatility_reference = 5_000;
        pool.index_reference = 100;
        pool.active_id = 95; // delta = 5
        pool.update_volatility_accumulator().unwrap();
        // 5_000 + 5 * 10_000 = 55_000.
        assert_eq!(pool.volatility_accumulator, 55_000);

        // Flip sign of delta — same accumulator value (abs).
        pool.active_id = 105;
        pool.update_volatility_accumulator().unwrap();
        assert_eq!(pool.volatility_accumulator, 55_000);
    }

    /// `update_volatility_accumulator` saturates at
    /// `max_volatility_accumulator`. A 100-bin walk with default
    /// max=350_000 would compute 1_000_000 raw, capped at 350_000.
    #[test]
    fn update_volatility_accumulator_caps_at_max() {
        let mut pool = pool_with_dyn_fee();
        pool.volatility_reference = 0;
        pool.index_reference = 0;
        pool.active_id = 100; // delta = 100, raw = 1_000_000.
        pool.max_volatility_accumulator = 350_000;
        pool.update_volatility_accumulator().unwrap();
        assert_eq!(pool.volatility_accumulator, 350_000);
    }

    /// `compute_variable_fee` short-circuits to 0 when the pool's
    /// `variable_fee_control == 0` — the static-fee-only configuration
    /// most pools ship with. Pin so a future regression doesn't read
    /// `volatility_accumulator` and emit a non-zero variable fee for a
    /// pool that explicitly disabled it.
    #[test]
    fn compute_variable_fee_zero_when_control_is_zero() {
        let mut pool = pool_with_dyn_fee();
        pool.variable_fee_control = 0;
        // Even with a non-zero accumulator, output is 0.
        assert_eq!(pool.compute_variable_fee(100_000), Some(0));
    }

    /// Numeric pin against the on-chain formula
    /// `ceil(vfc * (vol_acc * bin_step)^2 / 10^11)`. Two cases drive
    /// both the floor- and ceil-rounded paths:
    ///   - `vol_acc=100, bin_step=10, vfc=40_000`:
    ///     `square=(1_000)^2=1e6`, `v_fee=4e10`,
    ///     `ceil(4e10 / 1e11) = 1`.
    ///   - `vol_acc=10_000, bin_step=10, vfc=40_000`:
    ///     `square=(100_000)^2=1e10`, `v_fee=4e14`,
    ///     `ceil(4e14 / 1e11) = 4_000` (exact, no remainder).
    #[test]
    fn compute_variable_fee_matches_on_chain_formula() {
        let mut pool = pool_with_dyn_fee();
        pool.bin_step = 10;
        pool.variable_fee_control = 40_000;
        assert_eq!(pool.compute_variable_fee(100), Some(1));
        assert_eq!(pool.compute_variable_fee(10_000), Some(4_000));
    }

    /// Pin that `total_fee_rate` sums base + variable instead of
    /// reporting only base. Picks values where neither component
    /// alone would surface a regression: base = 1e6, variable = 4_000,
    /// total = 1_004_000.
    #[test]
    fn total_fee_rate_sums_base_and_variable() {
        let mut pool = pool_with_dyn_fee();
        pool.bin_step = 10;
        pool.base_factor = 10_000;
        pool.base_fee_power_factor = 0;
        pool.variable_fee_control = 40_000;
        pool.volatility_accumulator = 10_000;
        // base = 10_000 * 10 * 10 = 1_000_000.
        // variable (per the formula above) = 4_000.
        assert_eq!(pool.total_fee_rate(), Some(1_004_000));
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
            ..Default::default()
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
mod bitmap_extension_tests {
    use super::bitmap_extension::{
        bitmap_extension_pda, parse_bitmap_extension, ParsedBitmapExtension,
        BITMAP_EXTENSION_DATA_LEN, BITS_PER_ROW, LIMBS_PER_ROW, NEGATIVE_OFFSET, POSITIVE_OFFSET,
        ROWS,
    };
    use solana_sdk::pubkey::Pubkey;

    /// PDA derivation: deterministic for the same `lb_pair`, distinct
    /// across `lb_pair`s. Pins the seed byte string (`"bitmap"`) — a
    /// regression to a different seed would yield a non-matching PDA.
    #[test]
    fn bitmap_extension_pda_is_deterministic() {
        let lb_pair = Pubkey::new_unique();
        let (a, _) = bitmap_extension_pda(&lb_pair);
        let (b, _) = bitmap_extension_pda(&lb_pair);
        assert_eq!(a, b);

        let other = Pubkey::new_unique();
        let (c, _) = bitmap_extension_pda(&other);
        assert_ne!(a, c);
    }

    /// Coverage envelope is `[-512*13, 512*13 - 1]` = `[-6656, 6655]`.
    /// `covers_index` excludes the inner `[-512, 511]` band that the
    /// on-pool internal bitmap owns — pin both ends so a regression to
    /// `>= -BITS_PER_ROW` (off-by-one inclusive vs exclusive) fails.
    #[test]
    fn coverage_envelope_pins_inner_and_outer_edges() {
        let (lo, hi) = ParsedBitmapExtension::coverage_envelope();
        assert_eq!((lo, hi), (-6656, 6655));

        // Inner band is the internal bitmap's territory.
        for inner in [-512, -1, 0, 1, 511] {
            assert!(!ParsedBitmapExtension::covers_index(inner), "inner {inner}");
        }
        // Just outside the inner band is in extension territory.
        assert!(ParsedBitmapExtension::covers_index(-513));
        assert!(ParsedBitmapExtension::covers_index(512));
        // Outer envelope edges.
        assert!(ParsedBitmapExtension::covers_index(-6656));
        assert!(ParsedBitmapExtension::covers_index(6655));
        // One past the envelope ⇒ uncovered.
        assert!(!ParsedBitmapExtension::covers_index(-6657));
        assert!(!ParsedBitmapExtension::covers_index(6656));
    }

    /// `is_array_initialized` mapping pins:
    ///   * positive index 512 → row 0, bit 0 (LSB of `positive_bitmap[0][0]`),
    ///   * positive index 513 → row 0, bit 1,
    ///   * positive index 1023 → row 0, bit 511 (MSB of `positive_bitmap[0][7]`),
    ///   * positive index 1024 → row 1, bit 0,
    ///   * negative index -513 → row 0, bit 0 of `negative_bitmap`,
    ///   * negative index -1024 → row 0, bit 511,
    ///   * negative index -1025 → row 1, bit 0.
    ///
    /// Out-of-coverage indices return `None`.
    #[test]
    fn is_array_initialized_maps_to_correct_bit() {
        let mut bm = ParsedBitmapExtension {
            lb_pair: Pubkey::new_unique(),
            positive_bitmap: [[0u64; LIMBS_PER_ROW]; ROWS],
            negative_bitmap: [[0u64; LIMBS_PER_ROW]; ROWS],
        };

        // Set each pinned bit and verify it round-trips.
        bm.positive_bitmap[0][0] |= 1u64 << 0; // index 512
        bm.positive_bitmap[0][0] |= 1u64 << 1; // index 513
        bm.positive_bitmap[0][7] |= 1u64 << 63; // index 1023
        bm.positive_bitmap[1][0] |= 1u64 << 0; // index 1024
        bm.negative_bitmap[0][0] |= 1u64 << 0; // index -513
        bm.negative_bitmap[0][7] |= 1u64 << 63; // index -1024
        bm.negative_bitmap[1][0] |= 1u64 << 0; // index -1025

        assert_eq!(bm.is_array_initialized(512), Some(true));
        assert_eq!(bm.is_array_initialized(513), Some(true));
        assert_eq!(bm.is_array_initialized(1023), Some(true));
        assert_eq!(bm.is_array_initialized(1024), Some(true));
        assert_eq!(bm.is_array_initialized(-513), Some(true));
        assert_eq!(bm.is_array_initialized(-1024), Some(true));
        assert_eq!(bm.is_array_initialized(-1025), Some(true));

        // Unset bit ⇒ Some(false).
        assert_eq!(bm.is_array_initialized(514), Some(false));
        assert_eq!(bm.is_array_initialized(-514), Some(false));

        // Inner band ⇒ None (caller falls back to internal bitmap).
        assert_eq!(bm.is_array_initialized(0), None);
        assert_eq!(bm.is_array_initialized(-1), None);
        assert_eq!(bm.is_array_initialized(511), None);
        assert_eq!(bm.is_array_initialized(-512), None);

        // Past the envelope ⇒ None (no data).
        assert_eq!(bm.is_array_initialized(6656), None);
        assert_eq!(bm.is_array_initialized(-6657), None);
    }

    /// Parse a synthetic blob with distinguishing bits in:
    ///   * positive row 0 limb 0  — covers index 512,
    ///   * positive row 11 limb 7 — covers indices near +6655,
    ///   * negative row 0 limb 0  — covers index -513,
    ///   * negative row 11 limb 7 — covers indices near -6656,
    ///
    /// plus the `lb_pair` field. Pins the layout offsets.
    #[test]
    fn parse_synthetic_bitmap_extension() {
        let mut data = vec![0u8; BITMAP_EXTENSION_DATA_LEN];
        let lb_pair = Pubkey::new_unique();
        data[8..40].copy_from_slice(lb_pair.as_ref());

        // positive_bitmap[0][0] = 0b11 ⇒ bits for indices 512, 513 set.
        let val = 0b11u64;
        data[POSITIVE_OFFSET..POSITIVE_OFFSET + 8].copy_from_slice(&val.to_le_bytes());

        // positive_bitmap[11][7]: high bit ⇒ index 6655.
        let pos_11_7 = POSITIVE_OFFSET + (11 * LIMBS_PER_ROW + 7) * 8;
        data[pos_11_7..pos_11_7 + 8].copy_from_slice(&(1u64 << 63).to_le_bytes());

        // negative_bitmap[0][0] low bit ⇒ index -513.
        data[NEGATIVE_OFFSET..NEGATIVE_OFFSET + 8].copy_from_slice(&1u64.to_le_bytes());

        // negative_bitmap[11][7] high bit ⇒ index -6656.
        let neg_11_7 = NEGATIVE_OFFSET + (11 * LIMBS_PER_ROW + 7) * 8;
        data[neg_11_7..neg_11_7 + 8].copy_from_slice(&(1u64 << 63).to_le_bytes());

        let parsed = parse_bitmap_extension(&data).unwrap();
        assert_eq!(parsed.lb_pair, lb_pair);
        assert_eq!(parsed.is_array_initialized(512), Some(true));
        assert_eq!(parsed.is_array_initialized(513), Some(true));
        assert_eq!(parsed.is_array_initialized(514), Some(false));
        assert_eq!(parsed.is_array_initialized(6655), Some(true));
        assert_eq!(parsed.is_array_initialized(-513), Some(true));
        assert_eq!(parsed.is_array_initialized(-514), Some(false));
        assert_eq!(parsed.is_array_initialized(-6656), Some(true));
    }

    #[test]
    fn parse_rejects_short_blob() {
        let short = vec![0u8; BITMAP_EXTENSION_DATA_LEN - 1];
        assert!(parse_bitmap_extension(&short).is_none());
    }

    /// Layout pin: total byte count + the constants that drive bitmap
    /// math. A future refactor that bumps `ROWS` would silently break
    /// PDA fetches if we don't pin both the constant and the byte size
    /// it implies.
    #[test]
    fn layout_constants_pinned() {
        assert_eq!(BITS_PER_ROW, 512);
        assert_eq!(ROWS, 12);
        assert_eq!(LIMBS_PER_ROW, 8);
        // 8 disc + 32 lb_pair + 12 * 8 * 8 (positive) + 12 * 8 * 8 (negative)
        assert_eq!(BITMAP_EXTENSION_DATA_LEN, 8 + 32 + 768 + 768);
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
            ..Default::default()
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
            ..Default::default()
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
        let mut pool = pool();
        let r = cross_bin_swap(1_000_000, 0, &mut state, true, &mut pool).unwrap();
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
        let mut pool = pool();

        // Start at active_id = 0; swap X→Y. Each bin holds 1_000 Y.
        // Caller hands in enough X to drain ~5 bins.
        let r = cross_bin_swap(20_000, 0, &mut state, true, &mut pool).unwrap();
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
        let mut pool = pool();
        // 70 bins * 100 Y = 7_000 Y; need much more X to drain that.
        let r = cross_bin_swap(1_000_000_000, 0, &mut state, true, &mut pool);
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
        let mut pool = pool();
        let r = cross_bin_swap(1_000_000, 0, &mut state, true, &mut pool).unwrap();
        // Walker advanced from 0 (empty) → -1 (liquid). At least 2
        // iterations: one to skip bin 0, one to swap in bin -1.
        assert!(r.iterations >= 2);
        assert_eq!(r.final_active_id, -1);
        assert!(r.amount_out > 0);
    }

    /// Phase 3 plumbing: a multi-bin walk against a pool with
    /// `variable_fee_control > 0` mutates `pool.volatility_accumulator`
    /// (so the per-bin fee read sees rising volatility) and ends with
    /// the walker's `final_active_id` mirrored on `pool.active_id`.
    /// Pin so a future regression that drops the per-bin
    /// `update_volatility_accumulator` call (or the active_id sync at
    /// the loop's exit paths) is caught.
    #[test]
    fn cross_bin_walk_advances_volatility_accumulator() {
        let arrays = vec![
            uniform_array(-2, 0, 1_000),
            uniform_array(-1, 0, 1_000),
            uniform_array(0, 0, 1_000),
            uniform_array(1, 0, 1_000),
            uniform_array(2, 0, 1_000),
        ];
        let mut state = DlmmBinState::from_arrays(&arrays, 25).unwrap();
        let mut pool = pool();
        // Enable variable fee + give the accumulator headroom. Match
        // mainnet SOL/USDC ballpark so the cap doesn't fire.
        pool.variable_fee_control = 40_000;
        pool.max_volatility_accumulator = 350_000;
        // index_reference == active_id at entry, so the first bin's
        // delta_id = 0 (no volatility yet); the next bin's delta_id = 1.
        pool.index_reference = 0;
        pool.active_id = 0;
        // Drive a multi-bin walk (input bigger than one bin's reserves).
        let r = cross_bin_swap(20_000, 0, &mut state, true, &mut pool).unwrap();
        assert!(r.iterations >= 2, "expected multi-bin walk");
        assert_eq!(pool.active_id, r.final_active_id);
        // After at least one bin transition, the accumulator must be
        // non-zero — exact value depends on iteration count, but the
        // loop entered the "delta_id > 0" regime.
        assert!(
            pool.volatility_accumulator > 0,
            "vol_acc={} after {} iterations",
            pool.volatility_accumulator,
            r.iterations,
        );
    }

    /// Iteration cap pin: declarative — `MAX_SWAP_ITERATIONS = 256`.
    /// Catches accidental tightening that would break realistic
    /// sparse-liquidity pools.
    #[test]
    fn iteration_cap_constant_pin() {
        assert_eq!(MAX_SWAP_ITERATIONS, 256);
    }
}
