//! Raydium CPMM pool account layout + config fetch.
//!
//! CPMM is Raydium's CP-Swap (constant-product) program on Anchor. The state
//! account `PoolState` uses an 8-byte Anchor discriminator prefix, then the
//! Borsh-packed fields.
//!
//! Layout reference:
//!   <https://github.com/raydium-io/raydium-cp-swap/blob/master/programs/cp-swap/src/states/pool.rs>
//!
//! Byte offsets (after the 8-byte Anchor discriminator):
//!   offset 0   amm_config:       Pubkey (32)
//!   offset 32  pool_creator:     Pubkey (32)
//!   offset 64  token_0_vault:    Pubkey (32)     ← base vault
//!   offset 96  token_1_vault:    Pubkey (32)     ← quote vault
//!   offset 128 lp_mint:          Pubkey (32)
//!   offset 160 token_0_mint:     Pubkey (32)     ← base mint
//!   offset 192 token_1_mint:     Pubkey (32)     ← quote mint
//!   ...
//!
//! CPMM pools reference a shared `AmmConfig` account for fee rates. For Week 1
//! we use the default 25bps; fetching the real fee via the `amm_config` link is
//! a follow-up. Raydium CPMM pools in production are almost all 25bps.

use solana_sdk::pubkey::Pubkey;
use swap_events::dex::is_quote_mint;

use crate::lookup::{AmmKind, PoolConfig};

/// Anchor adds an 8-byte discriminator prefix before the Borsh fields.
const DISCRIMINATOR_LEN: usize = 8;

const TOKEN_0_VAULT_OFFSET: usize = DISCRIMINATOR_LEN + 64;
const TOKEN_1_VAULT_OFFSET: usize = DISCRIMINATOR_LEN + 96;
const TOKEN_0_MINT_OFFSET: usize = DISCRIMINATOR_LEN + 160;
const TOKEN_1_MINT_OFFSET: usize = DISCRIMINATOR_LEN + 192;

const MIN_LAYOUT_LEN: usize = TOKEN_1_MINT_OFFSET + 32;

/// Parse a Raydium CPMM `PoolState` account into a [`PoolConfig`].
///
/// Uses the default 25/10_000 fee rate until `amm_config` resolution lands.
pub fn parse_config(pool_address: &str, account_data: &[u8]) -> Option<PoolConfig> {
    if account_data.len() < MIN_LAYOUT_LEN {
        return None;
    }

    let token_0_vault = read_pubkey(account_data, TOKEN_0_VAULT_OFFSET)?.to_string();
    let token_1_vault = read_pubkey(account_data, TOKEN_1_VAULT_OFFSET)?.to_string();
    let token_0_mint = read_pubkey(account_data, TOKEN_0_MINT_OFFSET)?.to_string();
    let token_1_mint = read_pubkey(account_data, TOKEN_1_MINT_OFFSET)?.to_string();

    // Orient base/quote so it matches swap-events' Buy/Sell convention:
    //   - The recognised quote (wSOL / USDC / USDT) goes on the quote side.
    //   - The other token goes on the base side.
    // If neither token is a recognised quote (e.g. obscure stable like "USD1"
    // paired with a memecoin), we *cannot* reliably orient — the swap parser
    // will also have ambiguous Buy/Sell semantics for that pool, and the AMM
    // replay would produce nonsense numbers. Refuse to emit a config in that
    // case so enrichment skips the pool cleanly.
    let (vault_base, vault_quote, base_mint, quote_mint) =
        match (is_quote_mint(&token_0_mint), is_quote_mint(&token_1_mint)) {
            (true, false) => (token_1_vault, token_0_vault, token_1_mint, token_0_mint),
            (false, true) => (token_0_vault, token_1_vault, token_0_mint, token_1_mint),
            (true, true) => {
                // Stable-stable pool (e.g. USDC/USDT). Pick token_0 as base
                // arbitrarily — direction Buy/Sell still maps consistently
                // because both sides are quote-like.
                (token_0_vault, token_1_vault, token_0_mint, token_1_mint)
            }
            (false, false) => return None,
        };

    Some(PoolConfig {
        kind: AmmKind::RaydiumCpmm,
        pool: pool_address.to_string(),
        vault_base,
        vault_quote,
        base_mint,
        quote_mint,
        fee_num: 25,
        fee_den: 10_000,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrapped SOL mint, the canonical quote for memecoin pools. Used in
    /// tests so the orientation guard accepts the synthetic layout.
    const WSOL: &str = "So11111111111111111111111111111111111111112";

    fn write_layout(
        data: &mut [u8],
        t0_vault: &Pubkey,
        t1_vault: &Pubkey,
        t0_mint: &Pubkey,
        t1_mint: &Pubkey,
    ) {
        data[TOKEN_0_VAULT_OFFSET..TOKEN_0_VAULT_OFFSET + 32].copy_from_slice(t0_vault.as_ref());
        data[TOKEN_1_VAULT_OFFSET..TOKEN_1_VAULT_OFFSET + 32].copy_from_slice(t1_vault.as_ref());
        data[TOKEN_0_MINT_OFFSET..TOKEN_0_MINT_OFFSET + 32].copy_from_slice(t0_mint.as_ref());
        data[TOKEN_1_MINT_OFFSET..TOKEN_1_MINT_OFFSET + 32].copy_from_slice(t1_mint.as_ref());
    }

    #[test]
    fn parses_synthetic_layout_token1_quote() {
        // token_0 = memecoin, token_1 = wSOL → no swap; base = token_0.
        let mut data = vec![0u8; MIN_LAYOUT_LEN];
        let memecoin_vault = Pubkey::new_unique();
        let wsol_vault = Pubkey::new_unique();
        let memecoin_mint = Pubkey::new_unique();
        let wsol_mint: Pubkey = WSOL.parse().unwrap();
        write_layout(
            &mut data,
            &memecoin_vault,
            &wsol_vault,
            &memecoin_mint,
            &wsol_mint,
        );

        let cfg = parse_config("POOL", &data).unwrap();
        assert_eq!(cfg.kind, AmmKind::RaydiumCpmm);
        assert_eq!(cfg.vault_base, memecoin_vault.to_string());
        assert_eq!(cfg.vault_quote, wsol_vault.to_string());
        assert_eq!(cfg.base_mint, memecoin_mint.to_string());
        assert_eq!(cfg.quote_mint, wsol_mint.to_string());
    }

    #[test]
    fn parses_synthetic_layout_token0_quote_swaps_roles() {
        // token_0 = wSOL, token_1 = memecoin → orientation swap; base = token_1.
        let mut data = vec![0u8; MIN_LAYOUT_LEN];
        let wsol_vault = Pubkey::new_unique();
        let memecoin_vault = Pubkey::new_unique();
        let wsol_mint: Pubkey = WSOL.parse().unwrap();
        let memecoin_mint = Pubkey::new_unique();
        write_layout(
            &mut data,
            &wsol_vault,
            &memecoin_vault,
            &wsol_mint,
            &memecoin_mint,
        );

        let cfg = parse_config("POOL", &data).unwrap();
        assert_eq!(cfg.vault_base, memecoin_vault.to_string());
        assert_eq!(cfg.vault_quote, wsol_vault.to_string());
        assert_eq!(cfg.base_mint, memecoin_mint.to_string());
        assert_eq!(cfg.quote_mint, wsol_mint.to_string());
    }

    #[test]
    fn refuses_pool_without_recognised_quote() {
        // Both mints unknown → cannot orient base/quote reliably.
        let mut data = vec![0u8; MIN_LAYOUT_LEN];
        let v0 = Pubkey::new_unique();
        let v1 = Pubkey::new_unique();
        let m0 = Pubkey::new_unique();
        let m1 = Pubkey::new_unique();
        write_layout(&mut data, &v0, &v1, &m0, &m1);
        assert!(parse_config("POOL", &data).is_none());
    }

    #[test]
    fn rejects_short_data() {
        assert!(parse_config("POOL", &[0u8; 10]).is_none());
    }
}
