//! Raydium Concentrated Liquidity Market Maker (CLMM) account layout
//! and pool-state parsing.
//!
//! Raydium CLMM is a Solana-native V3-style concentrated-liquidity AMM.
//! The swap math (sqrt_price walked through TickArrays under piecewise
//! liquidity) is identical to Orca Whirlpool's; only the on-chain
//! account layouts differ. This module provides the static parsing
//! pieces: `PoolState` yields vaults / mints / `amm_config` pubkey /
//! dynamic state, and `AmmConfig` yields the trade fee. The V3 math
//! itself stays in [`crate::orca_whirlpool`] (and the eventual replay
//! layer above it).
//!
//! Why fee comes from a separate account: Raydium CLMM stores the
//! per-tier fee schedule on a shared `AmmConfig` account (one config
//! per tick-spacing tier, many pools share each), referenced by pubkey
//! from `PoolState.amm_config`. Whirlpool inlines `fee_rate` directly
//! on the pool account, so its [`parse_config`](crate::orca_whirlpool::parse_config)
//! takes one buffer; ours takes two.
//!
//! # Account layouts
//!
//! ## `PoolState` (Anchor account, discriminator
//! `sha256("account:PoolState")[..8]`)
//!
//! ```text
//!   field                          offset  size
//!   discriminator                       0     8
//!   bump: [u8; 1]                       8     1
//!   amm_config: Pubkey                  9    32
//!   owner: Pubkey                      41    32
//!   token_mint_0: Pubkey               73    32
//!   token_mint_1: Pubkey              105    32
//!   token_vault_0: Pubkey             137    32
//!   token_vault_1: Pubkey             169    32
//!   observation_key: Pubkey           201    32
//!   mint_decimals_0: u8               233     1
//!   mint_decimals_1: u8               234     1
//!   tick_spacing: u16                 235     2
//!   liquidity: u128                   237    16
//!   sqrt_price_x64: u128              253    16    Q64.64 of sqrt(token_1/token_0)
//!   tick_current: i32                 269     4
//!   ...                                          (fee growth, swap totals, reward infos, omitted)
//! ```
//!
//! ## `AmmConfig` (Anchor account, discriminator
//! `sha256("account:AmmConfig")[..8]`)
//!
//! ```text
//!   field                          offset  size
//!   discriminator                       0     8
//!   bump: u8                            8     1
//!   index: u16                          9     2
//!   owner: Pubkey                      11    32
//!   protocol_fee_rate: u32             43     4
//!   trade_fee_rate: u32                47     4    (LP fee, hundredths-of-bps)
//!   tick_spacing: u16                  51     2
//!   ...                                          (fund fee, padding, omitted)
//! ```
//!
//! References:
//!   * <https://github.com/raydium-io/raydium-clmm/blob/master/programs/amm/src/states/pool.rs>
//!   * <https://github.com/raydium-io/raydium-clmm/blob/master/programs/amm/src/states/config.rs>

use std::str::FromStr;

use solana_sdk::pubkey::Pubkey;
use swap_events::dex::is_quote_mint;

use crate::lookup::{AmmKind, PoolConfig};
use crate::orca_whirlpool::WhirlpoolPool;

const DISCRIMINATOR_LEN: usize = 8;

// PoolState offsets (relative to the start of the account data, including
// the 8-byte Anchor discriminator).
const AMM_CONFIG_OFFSET: usize = DISCRIMINATOR_LEN + 1; // 9
const TOKEN_MINT_0_OFFSET: usize = AMM_CONFIG_OFFSET + 32 + 32; // 73 (skip owner)
const TOKEN_MINT_1_OFFSET: usize = TOKEN_MINT_0_OFFSET + 32; // 105
const TOKEN_VAULT_0_OFFSET: usize = TOKEN_MINT_1_OFFSET + 32; // 137
const TOKEN_VAULT_1_OFFSET: usize = TOKEN_VAULT_0_OFFSET + 32; // 169
const TICK_SPACING_OFFSET: usize = TOKEN_VAULT_1_OFFSET + 32 + 32 + 1 + 1; // 235 (skip observation_key + mint_decimals_0/1)
const LIQUIDITY_OFFSET: usize = TICK_SPACING_OFFSET + 2; // 237
const SQRT_PRICE_OFFSET: usize = LIQUIDITY_OFFSET + 16; // 253
const TICK_CURRENT_OFFSET: usize = SQRT_PRICE_OFFSET + 16; // 269

/// Minimum `PoolState` length covering every field we read. The account
/// itself is much larger (carries fee-growth globals, swap totals,
/// reward infos, and the tick-array bitmap) — we don't touch any of
/// those, so a short blob shorter than this minimum is the only
/// rejection condition.
const POOL_STATE_MIN_LEN: usize = TICK_CURRENT_OFFSET + 4; // 273

// AmmConfig offsets.
const TRADE_FEE_RATE_OFFSET: usize = DISCRIMINATOR_LEN + 1 + 2 + 32 + 4; // 47
const AMM_CONFIG_MIN_LEN: usize = TRADE_FEE_RATE_OFFSET + 4; // 51

/// Raydium CLMM uses the same `1_000_000` denominator Whirlpool does
/// for its hundredths-of-bps fee numerator (e.g. `2_500 / 1_000_000`
/// = 25 bps). Pinned as a constant so the `compute_loss_*` math
/// reads it from `PoolConfig` and doesn't have to know which V3
/// DEX it came from.
const FEE_RATE_DEN: u64 = 1_000_000;

/// Sane fallback when `trade_fee_rate` reads as 0 or pathologically
/// large. Mirrors Whirlpool's `DEFAULT_FEE_RATE_HUNDREDTHS_BPS = 3_000`
/// (30 bps) — a reasonable middle-of-the-pack rate that won't wildly
/// distort price-impact math if we ever land here in production.
const DEFAULT_TRADE_FEE_RATE: u64 = 3_000;

/// Raydium CLMM program ID on Solana mainnet. Used by the
/// [`tick_array`] submodule to derive `TickArrayState` account PDAs.
pub fn raydium_clmm_program_id() -> Pubkey {
    Pubkey::from_str("CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK")
        .expect("raydium clmm program id is a hardcoded valid base58 pubkey")
}

/// Pubkey of the `AmmConfig` account a given pool references. Returned
/// so the caller (`RpcPoolLookup`) can fetch the config blob in a
/// second RPC round-trip and pass it back into [`parse_config`]. We
/// don't take an RPC client here so the parsing layer stays
/// pure-function.
pub fn parse_amm_config_pubkey(pool_state_data: &[u8]) -> Option<Pubkey> {
    if pool_state_data.len() < POOL_STATE_MIN_LEN {
        return None;
    }
    read_pubkey(pool_state_data, AMM_CONFIG_OFFSET)
}

/// Combine a `PoolState` blob and its referenced `AmmConfig` blob into
/// a [`PoolConfig`]. Mirrors [`crate::orca_whirlpool::parse_config`] in
/// shape and orientation: returns `None` when either blob is too short,
/// the fee is degenerate, or neither side of the pair is a recognised
/// quote mint.
///
/// Caller pattern (`RpcPoolLookup::pool_config`):
/// 1. Fetch `PoolState` account, extract `amm_config` pubkey via
///    [`parse_amm_config_pubkey`].
/// 2. Fetch the `AmmConfig` account at that pubkey.
/// 3. Pass both buffers into this function.
pub fn parse_config(
    pool_address: &str,
    pool_state_data: &[u8],
    amm_config_data: &[u8],
) -> Option<PoolConfig> {
    if pool_state_data.len() < POOL_STATE_MIN_LEN {
        return None;
    }
    if amm_config_data.len() < AMM_CONFIG_MIN_LEN {
        return None;
    }

    let mint_0 = read_pubkey(pool_state_data, TOKEN_MINT_0_OFFSET)?;
    let mint_1 = read_pubkey(pool_state_data, TOKEN_MINT_1_OFFSET)?;
    let vault_0 = read_pubkey(pool_state_data, TOKEN_VAULT_0_OFFSET)?;
    let vault_1 = read_pubkey(pool_state_data, TOKEN_VAULT_1_OFFSET)?;
    let trade_fee_rate = read_u32(amm_config_data, TRADE_FEE_RATE_OFFSET)?;

    let mint_0_s = mint_0.to_string();
    let mint_1_s = mint_1.to_string();
    // Same orientation logic as the Whirlpool path: refuse to enrich
    // memecoin/memecoin pairs (no recognised quote on either side),
    // pin which side base lands on so the V3 swap-math layer can map
    // SwapDirection → a_to_b correctly. Raydium's "0/1" indices are
    // exactly Whirlpool's "a/b".
    let (vault_base, vault_quote, base_mint, quote_mint, base_is_token_a) =
        match (is_quote_mint(&mint_0_s), is_quote_mint(&mint_1_s)) {
            (true, false) => (
                vault_1.to_string(),
                vault_0.to_string(),
                mint_1_s,
                mint_0_s,
                // mint_0 is quote ⇒ base sits on mint_1 ⇒ token_b.
                false,
            ),
            (false, true) | (true, true) => (
                vault_0.to_string(),
                vault_1.to_string(),
                mint_0_s,
                mint_1_s,
                // mint_1 is quote (or both are: pick mint_0 as base) ⇒
                // base sits on mint_0 ⇒ token_a.
                true,
            ),
            (false, false) => return None,
        };

    let raw_num = trade_fee_rate as u64;
    let (fee_num, fee_den) = if raw_num == 0 || raw_num >= FEE_RATE_DEN {
        (DEFAULT_TRADE_FEE_RATE, FEE_RATE_DEN)
    } else {
        (raw_num, FEE_RATE_DEN)
    };

    Some(PoolConfig {
        kind: AmmKind::RaydiumClmm,
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
/// Returns a [`WhirlpoolPool`] because Raydium CLMM and Whirlpool have
/// identical V3-style swap-math state — there's no value in a separate
/// `RaydiumClmmPool` struct since the replay layer
/// (`compute_loss_whirlpool_with_trace`) consumes the same shape either
/// way. The `fee_rate_hundredths_bps` field on [`WhirlpoolPool`] is left
/// zeroed because Raydium CLMM keeps fee on the `AmmConfig` account, not
/// the pool — the replay path reads `fee_num`/`fee_den` from
/// [`PoolConfig`] anyway, so this field is unused regardless of source
/// DEX.
pub fn parse_pool_state(account_data: &[u8]) -> Option<WhirlpoolPool> {
    if account_data.len() < POOL_STATE_MIN_LEN {
        return None;
    }
    Some(WhirlpoolPool {
        liquidity: read_u128(account_data, LIQUIDITY_OFFSET)?,
        sqrt_price_q64: read_u128(account_data, SQRT_PRICE_OFFSET)?,
        tick_current_index: read_i32(account_data, TICK_CURRENT_OFFSET)?,
        tick_spacing: read_u16(account_data, TICK_SPACING_OFFSET)?,
        // Unused for Raydium CLMM — see doc comment above.
        fee_rate_hundredths_bps: 0,
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

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

fn read_u128(data: &[u8], offset: usize) -> Option<u128> {
    let bytes: [u8; 16] = data.get(offset..offset + 16)?.try_into().ok()?;
    Some(u128::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// USDC mint — recognised as a quote token by `is_quote_mint`.
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    /// SOL wrapped mint — also a recognised quote.
    const WSOL: &str = "So11111111111111111111111111111111111111112";

    fn pad_to(buf: &mut Vec<u8>, target: usize) {
        if buf.len() < target {
            buf.resize(target, 0);
        }
    }

    fn write_pubkey(buf: &mut Vec<u8>, offset: usize, pubkey: &Pubkey) {
        pad_to(buf, offset + 32);
        buf[offset..offset + 32].copy_from_slice(&pubkey.to_bytes());
    }

    fn write_pubkey_str(buf: &mut Vec<u8>, offset: usize, pubkey: &str) {
        let pk = Pubkey::from_str(pubkey).expect("valid base58 pubkey in test");
        write_pubkey(buf, offset, &pk);
    }

    fn write_u16(buf: &mut Vec<u8>, offset: usize, value: u16) {
        pad_to(buf, offset + 2);
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(buf: &mut Vec<u8>, offset: usize, value: u32) {
        pad_to(buf, offset + 4);
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_i32(buf: &mut Vec<u8>, offset: usize, value: i32) {
        pad_to(buf, offset + 4);
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u128(buf: &mut Vec<u8>, offset: usize, value: u128) {
        pad_to(buf, offset + 16);
        buf[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
    }

    /// Build a `PoolState` blob from raw `Pubkey`s. Tests that need
    /// known mints (USDC / WSOL / etc.) wrap with `_with_mints` below.
    #[allow(clippy::too_many_arguments)]
    fn build_pool_state(
        amm_config: &Pubkey,
        mint_0: &Pubkey,
        mint_1: &Pubkey,
        vault_0: &Pubkey,
        vault_1: &Pubkey,
        tick_spacing: u16,
        liquidity: u128,
        sqrt_price: u128,
        tick_current: i32,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; POOL_STATE_MIN_LEN];
        write_pubkey(&mut buf, AMM_CONFIG_OFFSET, amm_config);
        write_pubkey(&mut buf, TOKEN_MINT_0_OFFSET, mint_0);
        write_pubkey(&mut buf, TOKEN_MINT_1_OFFSET, mint_1);
        write_pubkey(&mut buf, TOKEN_VAULT_0_OFFSET, vault_0);
        write_pubkey(&mut buf, TOKEN_VAULT_1_OFFSET, vault_1);
        write_u16(&mut buf, TICK_SPACING_OFFSET, tick_spacing);
        write_u128(&mut buf, LIQUIDITY_OFFSET, liquidity);
        write_u128(&mut buf, SQRT_PRICE_OFFSET, sqrt_price);
        write_i32(&mut buf, TICK_CURRENT_OFFSET, tick_current);
        buf
    }

    fn build_amm_config(trade_fee_rate: u32) -> Vec<u8> {
        let mut buf = vec![0u8; AMM_CONFIG_MIN_LEN];
        write_u32(&mut buf, TRADE_FEE_RATE_OFFSET, trade_fee_rate);
        buf
    }

    #[test]
    fn parse_amm_config_pubkey_extracts_referenced_config() {
        let amm_config = Pubkey::new_unique();
        let usdc = Pubkey::from_str(USDC).unwrap();
        let blob = build_pool_state(
            &amm_config,
            &usdc,
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            4,
            1,
            1,
            0,
        );
        let pk = parse_amm_config_pubkey(&blob).expect("pubkey extracted");
        assert_eq!(pk, amm_config);
    }

    #[test]
    fn parse_amm_config_pubkey_rejects_short_blob() {
        let short = vec![0u8; POOL_STATE_MIN_LEN - 1];
        assert!(parse_amm_config_pubkey(&short).is_none());
    }

    #[test]
    fn parse_config_orients_quote_when_mint_1_is_quote() {
        // mint_0 = memecoin, mint_1 = USDC ⇒ base = mint_0 (token_a),
        // quote = mint_1.
        let meme = Pubkey::new_unique();
        let usdc = Pubkey::from_str(USDC).unwrap();
        let vault_base = Pubkey::new_unique();
        let vault_quote = Pubkey::new_unique();
        let pool_state = build_pool_state(
            &Pubkey::new_unique(),
            &meme,
            &usdc,
            &vault_base,
            &vault_quote,
            64,
            1,
            1,
            0,
        );
        let amm_config = build_amm_config(2_500); // 25 bps
        let cfg = parse_config("POOL_ADDR", &pool_state, &amm_config).expect("parses");
        assert_eq!(cfg.kind, AmmKind::RaydiumClmm);
        assert_eq!(cfg.pool, "POOL_ADDR");
        assert_eq!(cfg.base_mint, meme.to_string());
        assert_eq!(cfg.quote_mint, USDC);
        assert_eq!(cfg.vault_base, vault_base.to_string());
        assert_eq!(cfg.vault_quote, vault_quote.to_string());
        assert_eq!(cfg.fee_num, 2_500);
        assert_eq!(cfg.fee_den, FEE_RATE_DEN);
        assert!(cfg.base_is_token_a);
    }

    #[test]
    fn parse_config_orients_quote_when_mint_0_is_quote() {
        // mint_0 = WSOL, mint_1 = memecoin ⇒ base = mint_1 (token_b),
        // quote = mint_0.
        let meme = Pubkey::new_unique();
        let wsol = Pubkey::from_str(WSOL).unwrap();
        let vault_quote = Pubkey::new_unique();
        let vault_base = Pubkey::new_unique();
        let pool_state = build_pool_state(
            &Pubkey::new_unique(),
            &wsol,
            &meme,
            &vault_quote,
            &vault_base,
            64,
            1,
            1,
            0,
        );
        let amm_config = build_amm_config(500); // 5 bps
        let cfg = parse_config("POOL_ADDR", &pool_state, &amm_config).expect("parses");
        assert_eq!(cfg.base_mint, meme.to_string());
        assert_eq!(cfg.quote_mint, WSOL);
        assert!(!cfg.base_is_token_a);
        assert_eq!(cfg.fee_num, 500);
    }

    #[test]
    fn parse_config_rejects_memecoin_memecoin_pair() {
        // Neither side a recognised quote ⇒ refuse to enrich.
        let pool_state = build_pool_state(
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            64,
            1,
            1,
            0,
        );
        let amm_config = build_amm_config(2_500);
        assert!(parse_config("POOL_ADDR", &pool_state, &amm_config).is_none());
    }

    #[test]
    fn parse_config_falls_back_on_zero_fee_rate() {
        // A degenerate fee shouldn't kill the whole config — fall back
        // to 30 bps and let the replay path use that. Same defensive
        // shape Whirlpool uses.
        let usdc = Pubkey::from_str(USDC).unwrap();
        let pool_state = build_pool_state(
            &Pubkey::new_unique(),
            &usdc,
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            64,
            1,
            1,
            0,
        );
        let amm_config = build_amm_config(0);
        let cfg = parse_config("POOL_ADDR", &pool_state, &amm_config).expect("parses");
        assert_eq!(cfg.fee_num, DEFAULT_TRADE_FEE_RATE);
        assert_eq!(cfg.fee_den, FEE_RATE_DEN);
    }

    #[test]
    fn parse_config_rejects_short_pool_state() {
        let short = vec![0u8; POOL_STATE_MIN_LEN - 1];
        let amm_config = build_amm_config(2_500);
        assert!(parse_config("POOL_ADDR", &short, &amm_config).is_none());
    }

    #[test]
    fn parse_config_rejects_short_amm_config() {
        let usdc = Pubkey::from_str(USDC).unwrap();
        let pool_state = build_pool_state(
            &Pubkey::new_unique(),
            &usdc,
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            64,
            1,
            1,
            0,
        );
        let short_config = vec![0u8; AMM_CONFIG_MIN_LEN - 1];
        assert!(parse_config("POOL_ADDR", &pool_state, &short_config).is_none());
    }

    #[test]
    fn parse_pool_state_extracts_dynamic_fields() {
        let pool_state = build_pool_state(
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            64,
            1_234_567_890_u128,
            0x1234_5678_9ABC_DEF0_u128 << 64,
            -42_i32,
        );
        let p = parse_pool_state(&pool_state).expect("parses");
        assert_eq!(p.liquidity, 1_234_567_890);
        assert_eq!(p.sqrt_price_q64, 0x1234_5678_9ABC_DEF0_u128 << 64);
        assert_eq!(p.tick_current_index, -42);
        assert_eq!(p.tick_spacing, 64);
        assert_eq!(p.fee_rate_hundredths_bps, 0);
    }

    #[test]
    fn parse_pool_state_rejects_short_blob() {
        let short = vec![0u8; POOL_STATE_MIN_LEN - 1];
        assert!(parse_pool_state(&short).is_none());
    }

    /// `write_pubkey_str` is only used for the textual-pubkey test
    /// helpers; reference it from a synthetic test so the unused
    /// warning doesn't fire under `-D warnings`.
    #[test]
    fn write_pubkey_str_round_trips_known_constant() {
        let mut buf = vec![0u8; 32];
        write_pubkey_str(&mut buf, 0, USDC);
        let parsed = read_pubkey(&buf, 0).unwrap();
        assert_eq!(parsed.to_string(), USDC);
    }
}

/// `TickArrayState` account parsing + PDA derivation for the cross-tick
/// replay path. Mirrors [`crate::orca_whirlpool::tick_array`] in shape
/// (so `compute_loss_whirlpool_with_trace` consumes either DEX through
/// the same [`crate::orca_whirlpool::tick_array::ParsedTickArray`]
/// carrier) but diverges on three points:
///
///   * `TICK_ARRAY_SIZE = 60` (Whirlpool: 88).
///   * `TickState` is 168 bytes (Whirlpool's `Tick` is 128) and lacks an
///     explicit `initialised: bool` — we derive it from
///     `liquidity_gross != 0`, mirroring Raydium's own SDK.
///   * PDA seeds use `start_tick_index.to_be_bytes()` (raw 4-byte i32
///     big-endian); Whirlpool uses the decimal ASCII string. The
///     program ID also differs — see [`raydium_clmm_program_id`].
///
/// Reference:
///   <https://github.com/raydium-io/raydium-clmm/blob/master/programs/amm/src/states/tick_array.rs>
pub mod tick_array {
    use solana_sdk::pubkey::Pubkey;

    use crate::orca_whirlpool::tick_array::{ParsedTickArray, TickData};

    /// Number of ticks per `TickArrayState` account. Raydium-specific —
    /// Whirlpool's TickArray packs 88.
    pub const TICK_ARRAY_SIZE: usize = 60;

    const DISCRIMINATOR_LEN: usize = 8;
    const POOL_ID_LEN: usize = 32;
    /// On-chain `TickState` size with `#[repr(C)]` padding. 168 bytes
    /// covers `tick: i32` + 4 bytes alignment padding for the next
    /// i128, plus `liquidity_net: i128`, `liquidity_gross: u128`,
    /// `fee_growth_outside_{0,1}_x64: u128`, `reward_growths_outside_x64:
    /// [u128; 3]`, and trailing padding bytes — the LP-accounting
    /// fields after `liquidity_gross` aren't read here.
    const TICK_LEN: usize = 168;

    /// Within a `TickState`, `liquidity_net` sits at offset 8 — after
    /// the 4-byte `tick` field plus 4 bytes of `#[repr(C)]` padding for
    /// i128 alignment. Whirlpool's `Tick` carries a `bool` + 15-byte
    /// padding before its own `liquidity_net`; Raydium starts with the
    /// `tick: i32` instead. Same final offset though.
    ///
    /// Caveat for future fixture-test work: this offset assumes i128
    /// has 8-byte alignment under `#[repr(C)]` on Solana's BPF target,
    /// which matches the Raydium source comment (`// alignment padding
    /// to 8 — 4 bytes — for next i128`). If a mainnet fixture diff
    /// surfaces a parser disagreement here, the most likely cause is
    /// that the on-chain layout actually uses 16-byte i128 alignment —
    /// in which case `liquidity_net` would land at offset 16 and
    /// `liquidity_gross` at 32. Adjust both constants together.
    const TICK_OFFSET_LIQUIDITY_NET: usize = 8;
    /// `liquidity_gross` immediately follows `liquidity_net`. Used to
    /// derive `initialised` — Raydium's `TickState` has no explicit
    /// boolean (the official SDK treats `liquidity_gross != 0` as the
    /// initialised condition; ticks with no LP boundary have zero gross
    /// liquidity by construction).
    const TICK_OFFSET_LIQUIDITY_GROSS: usize = 24;

    const OFFSET_START_TICK: usize = DISCRIMINATOR_LEN + POOL_ID_LEN; // 40
    const OFFSET_TICKS: usize = OFFSET_START_TICK + 4; // 44

    /// Minimum account-data length covering every tick we read. The
    /// trailing `initialized_tick_count: u8`, `recent_epoch: u64`, and
    /// 107-byte padding are intentionally skipped — none feed the
    /// cross-tick walk.
    pub const MIN_LAYOUT_LEN: usize = OFFSET_TICKS + TICK_LEN * TICK_ARRAY_SIZE;

    /// Parse a Raydium CLMM `TickArrayState` account blob into a
    /// [`ParsedTickArray`] (Whirlpool-shaped — the V3 swap-math layer
    /// only cares about `start_tick_index`, `tick_index_at`, and
    /// per-slot `(initialised, liquidity_net)`). Returns `None` for
    /// blobs shorter than [`MIN_LAYOUT_LEN`].
    ///
    /// `liquidity_gross != 0` derives the `initialised` flag — Raydium
    /// doesn't carry one explicitly, but a tick with no LP boundary has
    /// zero gross liquidity by construction. The walker correctly skips
    /// such slots via the same path Whirlpool uses for explicit
    /// `initialised: false`.
    pub fn parse_tick_array(data: &[u8]) -> Option<ParsedTickArray> {
        if data.len() < MIN_LAYOUT_LEN {
            return None;
        }
        let start_tick_index = read_i32(data, OFFSET_START_TICK)?;
        let mut ticks = vec![TickData::default(); TICK_ARRAY_SIZE];
        for (i, slot) in ticks.iter_mut().enumerate() {
            let tick_offset = OFFSET_TICKS + i * TICK_LEN;
            let liquidity_net = read_i128(data, tick_offset + TICK_OFFSET_LIQUIDITY_NET)?;
            let liquidity_gross = read_u128(data, tick_offset + TICK_OFFSET_LIQUIDITY_GROSS)?;
            *slot = TickData {
                initialised: liquidity_gross != 0,
                liquidity_net,
            };
        }
        Some(ParsedTickArray {
            start_tick_index,
            ticks,
        })
    }

    /// Tick span (in ticks) one Raydium TickArray account covers, given
    /// the parent pool's `tick_spacing`. Always
    /// [`TICK_ARRAY_SIZE`]` * tick_spacing` — diverges from Whirlpool's
    /// 88-based span, so callers that mix DEXes must pick the right
    /// helper per-attack.
    pub fn ticks_per_array_span(tick_spacing: u16) -> i32 {
        (tick_spacing as i32) * (TICK_ARRAY_SIZE as i32)
    }

    /// `start_tick_index` of the Raydium TickArray that contains
    /// `tick_current`. Floors negative ticks toward `-∞` (Rust's `/`
    /// would round toward zero, landing in the array *above* a negative
    /// tick).
    pub fn start_tick_index_for(tick_current: i32, tick_spacing: u16) -> i32 {
        crate::orca_whirlpool::floor_to_spacing(tick_current, ticks_per_array_span(tick_spacing))
    }

    /// Raydium CLMM TickArray PDA. Seeds:
    /// `[b"tick_array", pool, start_tick_index_be_bytes]`.
    /// Returned tuple is `(pda, bump)` from
    /// [`Pubkey::find_program_address`].
    ///
    /// The third seed is the *raw 4-byte big-endian* representation of
    /// `start_tick_index` — not the decimal ASCII Whirlpool uses.
    /// Mirroring Raydium's own derivation is the only thing that makes
    /// the PDA match the on-chain account.
    pub fn tick_array_pda(pool: &Pubkey, start_tick_index: i32) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[
                b"tick_array",
                pool.as_ref(),
                &start_tick_index.to_be_bytes(),
            ],
            &super::raydium_clmm_program_id(),
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

    fn read_u128(data: &[u8], offset: usize) -> Option<u128> {
        let bytes: [u8; 16] = data.get(offset..offset + 16)?.try_into().ok()?;
        Some(u128::from_le_bytes(bytes))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Build a synthetic Raydium TickArray blob with sparse
        /// `(slot, liquidity_net, liquidity_gross)` overrides. Slots
        /// not listed have zero gross + zero net (parse as
        /// uninitialised).
        fn make_blob(start_tick_index: i32, overrides: &[(usize, i128, u128)]) -> Vec<u8> {
            let mut data = vec![0u8; MIN_LAYOUT_LEN];
            data[OFFSET_START_TICK..OFFSET_START_TICK + 4]
                .copy_from_slice(&start_tick_index.to_le_bytes());
            for (i, liquidity_net, liquidity_gross) in overrides {
                let tick_offset = OFFSET_TICKS + i * TICK_LEN;
                data[tick_offset + TICK_OFFSET_LIQUIDITY_NET
                    ..tick_offset + TICK_OFFSET_LIQUIDITY_NET + 16]
                    .copy_from_slice(&liquidity_net.to_le_bytes());
                data[tick_offset + TICK_OFFSET_LIQUIDITY_GROSS
                    ..tick_offset + TICK_OFFSET_LIQUIDITY_GROSS + 16]
                    .copy_from_slice(&liquidity_gross.to_le_bytes());
            }
            data
        }

        #[test]
        fn parse_extracts_start_tick_and_initialised_ticks() {
            let blob = make_blob(
                -3840, // 60 * 64 negation — plausible negative-region start.
                &[
                    (5, 1_000_000_000, 1_000_000_000),
                    (44, -500_000_000, 700_000_000),
                ],
            );
            let p = parse_tick_array(&blob).unwrap();
            assert_eq!(p.start_tick_index, -3840);
            assert_eq!(p.ticks.len(), TICK_ARRAY_SIZE);
            assert!(p.ticks[5].initialised);
            assert_eq!(p.ticks[5].liquidity_net, 1_000_000_000);
            assert!(p.ticks[44].initialised);
            assert_eq!(p.ticks[44].liquidity_net, -500_000_000);
            // Untouched slots: zero gross ⇒ uninitialised.
            assert!(!p.ticks[0].initialised);
            assert_eq!(p.ticks[0].liquidity_net, 0);
            assert!(!p.ticks[59].initialised);
        }

        #[test]
        fn liquidity_gross_zero_means_uninitialised_even_with_nonzero_net() {
            // Defensive: liquidity_gross is the source of truth for
            // initialised. A malformed account with zero gross but
            // nonzero net must NOT be treated as initialised — applying
            // its liquidity_net delta would corrupt active liquidity.
            // Raydium's writers can't produce this state, so the case
            // covers data corruption / fixture mistakes only.
            let blob = make_blob(0, &[(10, 12_345, 0)]);
            let p = parse_tick_array(&blob).unwrap();
            assert!(!p.ticks[10].initialised);
        }

        #[test]
        fn parse_rejects_short_blob() {
            assert!(parse_tick_array(&[0u8; 100]).is_none());
            assert!(parse_tick_array(&vec![0u8; MIN_LAYOUT_LEN - 1]).is_none());
            assert!(parse_tick_array(&vec![0u8; MIN_LAYOUT_LEN]).is_some());
        }

        #[test]
        fn liquidity_net_round_trips_signed_extremes() {
            let blob = make_blob(0, &[(0, i128::MAX, 1), (1, i128::MIN, 1), (2, -1, 1)]);
            let p = parse_tick_array(&blob).unwrap();
            assert_eq!(p.ticks[0].liquidity_net, i128::MAX);
            assert_eq!(p.ticks[1].liquidity_net, i128::MIN);
            assert_eq!(p.ticks[2].liquidity_net, -1);
        }

        #[test]
        fn ticks_per_array_span_uses_60_not_88() {
            // Raydium's TICK_ARRAY_SIZE differs from Whirlpool's. Pin
            // the divergence so a copy-paste regression to Whirlpool's
            // 88-tick math fails immediately.
            assert_eq!(ticks_per_array_span(1), 60);
            assert_eq!(ticks_per_array_span(64), 60 * 64);
            assert_eq!(ticks_per_array_span(128), 60 * 128);
        }

        #[test]
        fn start_tick_index_for_handles_positives_zero_and_negatives() {
            // tick_spacing=64 ⇒ array span = 60 * 64 = 3840.
            assert_eq!(start_tick_index_for(0, 64), 0);
            assert_eq!(start_tick_index_for(3839, 64), 0);
            assert_eq!(start_tick_index_for(3840, 64), 3840);
            // Negatives: floor toward -∞.
            assert_eq!(start_tick_index_for(-1, 64), -3840);
            assert_eq!(start_tick_index_for(-3840, 64), -3840);
            assert_eq!(start_tick_index_for(-3841, 64), -7680);
        }

        #[test]
        fn tick_array_pda_is_deterministic_and_distinguishes_inputs() {
            let pool = Pubkey::new_unique();
            let (pda1, bump1) = tick_array_pda(&pool, 3840);
            let (pda2, bump2) = tick_array_pda(&pool, 3840);
            assert_eq!(pda1, pda2);
            assert_eq!(bump1, bump2);
            // Different start_tick_index ⇒ different PDA.
            let (pda_other, _) = tick_array_pda(&pool, 0);
            assert_ne!(pda1, pda_other);
            // Different pool ⇒ different PDA.
            let other_pool = Pubkey::new_unique();
            let (pda_other_pool, _) = tick_array_pda(&other_pool, 3840);
            assert_ne!(pda1, pda_other_pool);
        }

        #[test]
        fn tick_array_pda_distinguishes_negative_start_indices_via_be_bytes() {
            // Raw i32 big-endian — sign bit lands in the high byte.
            // Pin the seed encoding by ensuring (-3840) and 3840 produce
            // different PDAs; the bytewise hash of `[0,0,0x0F,0]` (3840
            // BE) and `[0xFF,0xFF,0xF0,0]` (-3840 BE) is what makes
            // them distinct on-chain.
            let pool = Pubkey::new_unique();
            let (pos, _) = tick_array_pda(&pool, 3840);
            let (neg, _) = tick_array_pda(&pool, -3840);
            assert_ne!(pos, neg);
        }
    }
}
