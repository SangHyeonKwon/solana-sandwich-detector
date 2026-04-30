pub mod jupiter;
pub mod meteora;
pub mod orca;
pub mod phoenix;
pub mod pumpfun;
pub mod raydium;
pub mod raydium_clmm;
pub mod raydium_cpmm;

use std::collections::HashSet;

use crate::types::{
    SolBalanceChange, SwapDirection, SwapEvent, TokenBalanceChange, TransactionData,
};

/// Known quote/base token mints (SOL, USDC, USDT)
/// Mints treated as the "quote" side of a pool across the whole codebase.
/// Shared with pool-state so that pool configs label base/quote the same way
/// swap parsers do (Buy = spend quote → receive base).
pub const QUOTE_MINTS: &[&str] = &[
    "So11111111111111111111111111111111111111112", // Wrapped SOL
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", // USDC
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // USDT
];

pub trait DexParser: Send + Sync {
    fn program_id(&self) -> &str;
    /// Parse swap events. Called only when `program_id()` is present in the transaction.
    fn parse_swaps(&self, tx: &TransactionData) -> Vec<SwapEvent>;
}

/// Returns all available DEX parsers.
pub fn all_parsers() -> Vec<Box<dyn DexParser>> {
    vec![
        Box::new(raydium::RaydiumV4Parser),
        Box::new(raydium_clmm::RaydiumClmmParser),
        Box::new(raydium_cpmm::RaydiumCpmmParser),
        Box::new(orca::OrcaWhirlpoolParser),
        Box::new(jupiter::JupiterV6Parser),
        Box::new(meteora::MeteoraDlmmParser),
        Box::new(pumpfun::PumpFunParser),
        Box::new(phoenix::PhoenixParser),
    ]
}

/// Extract swap events from a transaction using all parsers.
/// Pre-filters by program_id so only relevant parsers are invoked.
pub fn extract_swaps(tx: &TransactionData, parsers: &[Box<dyn DexParser>]) -> Vec<SwapEvent> {
    let invoked: HashSet<&str> = tx
        .instructions
        .iter()
        .map(|ix| ix.program_id.as_str())
        .chain(
            tx.inner_instructions
                .iter()
                .flat_map(|g| g.instructions.iter().map(|ix| ix.program_id.as_str())),
        )
        .collect();

    let mut swaps = Vec::new();
    for parser in parsers {
        if invoked.contains(parser.program_id()) {
            swaps.extend(parser.parse_swaps(tx));
        }
    }
    swaps
}

/// Check if any instruction (top-level or inner) invokes the given program.
/// Useful when calling a `DexParser` directly outside of `extract_swaps`.
#[allow(dead_code)]
pub(crate) fn invokes_program(tx: &TransactionData, program_id: &str) -> bool {
    tx.instructions.iter().any(|ix| ix.program_id == program_id)
        || tx.inner_instructions.iter().any(|group| {
            group
                .instructions
                .iter()
                .any(|ix| ix.program_id == program_id)
        })
}

/// True if `mint` is a recognised quote-side mint (wSOL / USDC / USDT).
/// Used by swap parsers to decide Buy/Sell and by pool-state to orient
/// pool configs; they share one list so the two sides can't drift.
pub fn is_quote_mint(mint: &str) -> bool {
    QUOTE_MINTS.contains(&mint)
}

/// Determine swap direction and details from token balance changes + SOL deltas.
/// Returns `(direction, token_mint, amount_in, amount_out)`.
pub fn determine_swap_from_balances(
    changes: &[TokenBalanceChange],
    sol_changes: &[SolBalanceChange],
    signer: &str,
    fee: u64,
) -> Option<(SwapDirection, String, u64, u64)> {
    let signer_changes: Vec<&TokenBalanceChange> =
        changes.iter().filter(|c| c.owner == signer).collect();

    let increasing: Vec<&&TokenBalanceChange> =
        signer_changes.iter().filter(|c| c.delta() > 0).collect();
    let decreasing: Vec<&&TokenBalanceChange> =
        signer_changes.iter().filter(|c| c.delta() < 0).collect();

    // Case 1: Standard token-to-token swap (1 token up, 1 token down)
    if increasing.len() == 1 && decreasing.len() == 1 {
        let got = increasing[0];
        let spent = decreasing[0];

        return if is_quote_mint(&spent.mint) {
            Some((
                SwapDirection::Buy,
                got.mint.clone(),
                (-spent.delta()) as u64,
                got.delta() as u64,
            ))
        } else if is_quote_mint(&got.mint) {
            Some((
                SwapDirection::Sell,
                spent.mint.clone(),
                (-spent.delta()) as u64,
                got.delta() as u64,
            ))
        } else {
            Some((
                SwapDirection::Buy,
                got.mint.clone(),
                (-spent.delta()) as u64,
                got.delta() as u64,
            ))
        };
    }

    // Signer's net SOL change, excluding the fee (fee always reduces SOL)
    let sol_delta: i64 = sol_changes
        .iter()
        .find(|sc| sc.account == signer)
        .map(|sc| sc.delta() + fee as i64)
        .unwrap_or(0);

    // Case 2: Spent SOL (unwrapped), got a token => Buy
    if increasing.len() == 1 && decreasing.is_empty() && sol_delta < 0 {
        let got = increasing[0];
        return Some((
            SwapDirection::Buy,
            got.mint.clone(),
            (-sol_delta) as u64,
            got.delta() as u64,
        ));
    }

    // Case 3: Spent a token, got SOL (unwrapped) => Sell
    if decreasing.len() == 1 && increasing.is_empty() && sol_delta > 0 {
        let spent = decreasing[0];
        return Some((
            SwapDirection::Sell,
            spent.mint.clone(),
            (-spent.delta()) as u64,
            sol_delta as u64,
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SolBalanceChange, TokenBalanceChange};

    #[test]
    fn token_to_token_swap() {
        let changes = vec![
            TokenBalanceChange {
                mint: "USDC".into(),
                account: "user_usdc_acc".into(),
                owner: "user".into(),
                pre_amount: 1000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: "TOKEN".into(),
                account: "user_token_acc".into(),
                owner: "user".into(),
                pre_amount: 0,
                post_amount: 500,
            },
        ];
        let result = determine_swap_from_balances(&changes, &[], "user", 5000);
        let (dir, mint, amt_in, amt_out) = result.unwrap();
        assert_eq!(dir, SwapDirection::Buy);
        assert_eq!(mint, "TOKEN");
        assert_eq!(amt_in, 1000);
        assert_eq!(amt_out, 500);
    }

    #[test]
    fn sol_buy_swap() {
        // Signer spent SOL (unwrapped), got a token
        let changes = vec![TokenBalanceChange {
            mint: "TOKEN".into(),
            account: "user_token_acc".into(),
            owner: "user".into(),
            pre_amount: 0,
            post_amount: 500,
        }];
        let sol_changes = vec![SolBalanceChange {
            account: "user".into(),
            pre_lamports: 10_000_000,
            post_lamports: 4_995_000,
        }];
        // fee = 5000, raw delta = -5_005_000, intentional delta = -5_005_000 + 5000 = -5_000_000
        let result = determine_swap_from_balances(&changes, &sol_changes, "user", 5000);
        let (dir, mint, amt_in, amt_out) = result.unwrap();
        assert_eq!(dir, SwapDirection::Buy);
        assert_eq!(mint, "TOKEN");
        assert_eq!(amt_in, 5_000_000);
        assert_eq!(amt_out, 500);
    }

    #[test]
    fn sol_sell_swap() {
        // Signer spent a token, got SOL (unwrapped)
        let changes = vec![TokenBalanceChange {
            mint: "TOKEN".into(),
            account: "user_token_acc".into(),
            owner: "user".into(),
            pre_amount: 500,
            post_amount: 0,
        }];
        let sol_changes = vec![SolBalanceChange {
            account: "user".into(),
            pre_lamports: 1_000_000,
            post_lamports: 5_995_000,
        }];
        // fee = 5000, raw delta = +4_995_000, intentional delta = +4_995_000 + 5000 = +5_000_000
        let result = determine_swap_from_balances(&changes, &sol_changes, "user", 5000);
        let (dir, mint, amt_in, amt_out) = result.unwrap();
        assert_eq!(dir, SwapDirection::Sell);
        assert_eq!(mint, "TOKEN");
        assert_eq!(amt_in, 500);
        assert_eq!(amt_out, 5_000_000);
    }

    #[test]
    fn fee_only_no_swap() {
        // Only fee deduction, no token changes => not a swap
        let sol_changes = vec![SolBalanceChange {
            account: "user".into(),
            pre_lamports: 1_000_000,
            post_lamports: 995_000,
        }];
        let result = determine_swap_from_balances(&[], &sol_changes, "user", 5000);
        assert!(result.is_none());
    }
}
