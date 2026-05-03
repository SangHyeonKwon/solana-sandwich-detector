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

/// Raydium CLMM program ID on Solana mainnet. Used by the (yet-to-land)
/// TickArray fetch path to derive PDAs.
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
