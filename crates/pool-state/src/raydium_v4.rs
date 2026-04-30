//! Raydium V4 AMM pool account layout + config fetch.
//!
//! Raydium V4's `AmmInfo` struct is a C-style packed layout (not Anchor/Borsh).
//! We only need the vault addresses and fee rates — not the full state —
//! so we deserialize only the fields we need by offset.
//!
//! Layout reference:
//!   <https://github.com/raydium-io/raydium-amm/blob/master/program/src/state.rs>
//!
//! Field offsets (in bytes) within the 752-byte AmmInfo:
//!   - status:                      0   (u64)
//!   - nonce:                       8   (u64)
//!   - order_num:                  16   (u64)
//!   - depth:                      24   (u64)
//!   - coin_decimals:              32   (u64)
//!   - pc_decimals:                40   (u64)
//!   - state:                      48   (u64)
//!   - reset_flag:                 56   (u64)
//!   - min_size:                   64   (u64)
//!   - vol_max_cut_ratio:          72   (u64)
//!   - amount_wave:                80   (u64)
//!   - coin_lot_size:              88   (u64)
//!   - pc_lot_size:                96   (u64)
//!   - min_price_multiplier:      104   (u64)
//!   - max_price_multiplier:      112   (u64)
//!   - sys_decimal_value:         120   (u64)
//!   - fees:                      128   (Fees, 64 bytes — see below)
//!   - out_put:                   192   (StateData, 80 bytes)
//!   - coin_vault:                272   (Pubkey, 32 bytes)
//!   - pc_vault:                  304   (Pubkey, 32 bytes)
//!   - coin_vault_mint:           336   (Pubkey)
//!   - pc_vault_mint:             368   (Pubkey)
//!
//! Fees struct (starts at offset 128):
//!   - min_separate_numerator:      0 (u64)
//!   - min_separate_denominator:    8 (u64)
//!   - trade_fee_numerator:        16 (u64)
//!   - trade_fee_denominator:      24 (u64)
//!
//! (Remaining fields are not needed for replay.)
//!
//! So within the account data:
//!   - trade_fee_numerator   = offset 128 + 16 = 144
//!   - trade_fee_denominator = offset 128 + 24 = 152

use solana_sdk::pubkey::Pubkey;
use swap_events::dex::is_quote_mint;

use crate::lookup::{AmmKind, PoolConfig};

const COIN_VAULT_OFFSET: usize = 272;
const PC_VAULT_OFFSET: usize = 304;
const COIN_MINT_OFFSET: usize = 336;
const PC_MINT_OFFSET: usize = 368;
const TRADE_FEE_NUM_OFFSET: usize = 144;
const TRADE_FEE_DEN_OFFSET: usize = 152;

/// Minimum account data length we need to read all fields we care about.
const MIN_LAYOUT_LEN: usize = PC_MINT_OFFSET + 32;

/// Parse a Raydium V4 AMM pool account into a [`PoolConfig`].
///
/// Returns `None` if the account data is too short to contain the fields we need.
pub fn parse_config(pool_address: &str, account_data: &[u8]) -> Option<PoolConfig> {
    if account_data.len() < MIN_LAYOUT_LEN {
        return None;
    }

    let coin_vault = read_pubkey(account_data, COIN_VAULT_OFFSET)?;
    let pc_vault = read_pubkey(account_data, PC_VAULT_OFFSET)?;
    let coin_mint = read_pubkey(account_data, COIN_MINT_OFFSET)?;
    let pc_mint = read_pubkey(account_data, PC_MINT_OFFSET)?;
    let fee_num = read_u64(account_data, TRADE_FEE_NUM_OFFSET)?;
    let fee_den = read_u64(account_data, TRADE_FEE_DEN_OFFSET)?;

    // Sanity: fee must be non-degenerate. Fallback to 25/10_000 if pool reports 0/0.
    let (fee_num, fee_den) = if fee_den == 0 || fee_num >= fee_den {
        (25, 10_000)
    } else {
        (fee_num, fee_den)
    };

    // Orient base/quote against the recognised quote mint set. Raydium V4's
    // `coin` / `pc` convention is already supposed to put the quote-like
    // token in `pc`, but we don't trust that blindly. If neither side is a
    // recognised quote (wSOL / USDC / USDT), refuse to enrich — see the same
    // guard in `raydium_cpmm::parse_config` for the rationale.
    let coin_mint_s = coin_mint.to_string();
    let pc_mint_s = pc_mint.to_string();
    let (vault_base, vault_quote, base_mint, quote_mint) =
        match (is_quote_mint(&coin_mint_s), is_quote_mint(&pc_mint_s)) {
            (true, false) => (
                pc_vault.to_string(),
                coin_vault.to_string(),
                pc_mint_s,
                coin_mint_s,
            ),
            (false, true) | (true, true) => (
                coin_vault.to_string(),
                pc_vault.to_string(),
                coin_mint_s,
                pc_mint_s,
            ),
            (false, false) => return None,
        };

    Some(PoolConfig {
        kind: AmmKind::RaydiumV4,
        pool: pool_address.to_string(),
        vault_base,
        vault_quote,
        base_mint,
        quote_mint,
        fee_num,
        fee_den,
        // Constant-product math reads everything from vault_base/quote;
        // the a/b axis flag is meaningful for concentrated-liquidity
        // DEXes only.
        base_is_token_a: false,
    })
}

fn read_pubkey(data: &[u8], offset: usize) -> Option<Pubkey> {
    let bytes: [u8; 32] = data.get(offset..offset + 32)?.try_into().ok()?;
    Some(Pubkey::new_from_array(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Wrapped SOL — `parse_config` requires at least one side of the pair to
    /// be a recognised quote mint, so the fixtures plant WSOL into pc_mint.
    /// Without this, `parse_config` rightly refuses to enrich the synthetic
    /// pool (matches production behaviour for memecoin/memecoin pairs).
    const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";

    /// Constructs a synthetic Raydium V4 account blob with known fields and
    /// verifies we pull them out correctly.
    #[test]
    fn parses_synthetic_layout() {
        let mut data = vec![0u8; MIN_LAYOUT_LEN];

        // Fee numerator = 25, denominator = 10_000
        data[TRADE_FEE_NUM_OFFSET..TRADE_FEE_NUM_OFFSET + 8].copy_from_slice(&25u64.to_le_bytes());
        data[TRADE_FEE_DEN_OFFSET..TRADE_FEE_DEN_OFFSET + 8]
            .copy_from_slice(&10_000u64.to_le_bytes());

        // Distinct non-zero bytes for each pubkey field so we can distinguish
        // them. pc_mint is WSOL so the quote-mint guard accepts the pool.
        let coin_vault = Pubkey::new_unique();
        let pc_vault = Pubkey::new_unique();
        let coin_mint = Pubkey::new_unique();
        let pc_mint = Pubkey::from_str(WSOL_MINT).unwrap();
        data[COIN_VAULT_OFFSET..COIN_VAULT_OFFSET + 32].copy_from_slice(coin_vault.as_ref());
        data[PC_VAULT_OFFSET..PC_VAULT_OFFSET + 32].copy_from_slice(pc_vault.as_ref());
        data[COIN_MINT_OFFSET..COIN_MINT_OFFSET + 32].copy_from_slice(coin_mint.as_ref());
        data[PC_MINT_OFFSET..PC_MINT_OFFSET + 32].copy_from_slice(pc_mint.as_ref());

        let cfg = parse_config("POOL_ADDR", &data).unwrap();
        assert_eq!(cfg.kind, AmmKind::RaydiumV4);
        assert_eq!(cfg.pool, "POOL_ADDR");
        assert_eq!(cfg.vault_base, coin_vault.to_string());
        assert_eq!(cfg.vault_quote, pc_vault.to_string());
        assert_eq!(cfg.base_mint, coin_mint.to_string());
        assert_eq!(cfg.quote_mint, pc_mint.to_string());
        assert_eq!(cfg.fee_num, 25);
        assert_eq!(cfg.fee_den, 10_000);
    }

    #[test]
    fn rejects_short_data() {
        let short = vec![0u8; 100];
        assert!(parse_config("POOL", &short).is_none());
    }

    #[test]
    fn falls_back_to_default_fee_on_degenerate_config() {
        let mut data = vec![0u8; MIN_LAYOUT_LEN];
        // Plant WSOL in pc_mint so the quote-mint guard accepts the layout —
        // the fields under test (fee fallback) are independent of mint choice.
        let pc_mint = Pubkey::from_str(WSOL_MINT).unwrap();
        data[PC_MINT_OFFSET..PC_MINT_OFFSET + 32].copy_from_slice(pc_mint.as_ref());

        // fee_num = fee_den = 0 — degenerate
        let cfg = parse_config("POOL", &data).unwrap();
        assert_eq!(cfg.fee_num, 25);
        assert_eq!(cfg.fee_den, 10_000);

        // fee_num >= fee_den — also degenerate
        data[TRADE_FEE_NUM_OFFSET..TRADE_FEE_NUM_OFFSET + 8]
            .copy_from_slice(&20_000u64.to_le_bytes());
        data[TRADE_FEE_DEN_OFFSET..TRADE_FEE_DEN_OFFSET + 8]
            .copy_from_slice(&10_000u64.to_le_bytes());
        let cfg2 = parse_config("POOL", &data).unwrap();
        assert_eq!(cfg2.fee_num, 25);
        assert_eq!(cfg2.fee_den, 10_000);
    }
}
