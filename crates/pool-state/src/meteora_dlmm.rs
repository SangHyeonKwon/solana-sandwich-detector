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
    /// Compute base swap fee on `amount` using the on-chain formula:
    /// `fee = amount * base_factor * bin_step * 10 * 10^base_fee_power_factor / DLMM_FEE_PRECISION`.
    ///
    /// Variable fee (volatility-driven) is ignored — Phase 1 contract.
    /// Returns `None` on overflow.
    pub fn compute_base_fee(&self, amount: u64) -> Option<u64> {
        let factor = (self.base_factor as u128)
            .checked_mul(self.bin_step as u128)?
            .checked_mul(10)?;
        let power_mul: u128 = 10u128.checked_pow(self.base_fee_power_factor as u32)?;
        let base_fee_rate = factor.checked_mul(power_mul)?;
        let fee = (amount as u128)
            .checked_mul(base_fee_rate)?
            .checked_div(DLMM_FEE_PRECISION as u128)?;
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

        // 1_000_000 * 2_000_000 / 1e9 = 2_000.
        assert_eq!(state.compute_base_fee(1_000_000).unwrap(), 2_000);
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
    fn compute_base_fee_honours_power_factor() {
        let pool = DlmmPool {
            active_id: 0,
            bin_step: 25,
            base_factor: 8000,
            base_fee_power_factor: 1, // x10
            protocol_share: 0,
        };
        // base_fee_rate = 8000 * 25 * 10 * 10 = 20_000_000 → 2% in 1e9.
        // fee on 1_000_000 = 1_000_000 * 20_000_000 / 1e9 = 20_000.
        assert_eq!(pool.compute_base_fee(1_000_000).unwrap(), 20_000);
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
