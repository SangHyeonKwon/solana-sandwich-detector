//! Extract pool vault reserves from a transaction's token balance meta.
//!
//! The detector already parses `pre_token_balances` / `post_token_balances`
//! into [`swap_events::types::TokenBalanceChange`]. Given the pool's known
//! vault addresses (from [`PoolConfig`](crate::PoolConfig)), we look up the
//! two vault balances at tx-time. This avoids any historical RPC query.

use swap_events::types::{TokenBalanceChange, TransactionData};

use crate::PoolConfig;

/// Pool reserves at the two boundaries of a single tx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxReserves {
    /// `(base, quote)` reserves before the tx executed.
    pub pre: (u128, u128),
    /// `(base, quote)` reserves after the tx executed.
    pub post: (u128, u128),
}

/// Extract the `(base, quote)` reserves before/after a tx.
///
/// Token balance changes in Solana tx meta are keyed by the SPL token account
/// pubkey (the `account` field), not by the authority (`owner`). Match against
/// the pool's known vault addresses, which are token-account pubkeys taken
/// from the Raydium/CPMM pool-state layout.
///
/// Returns `None` if either vault is absent from the tx meta — shouldn't
/// happen for the detected frontrun/victim/backrun.
pub fn extract(tx: &TransactionData, pool: &PoolConfig) -> Option<TxReserves> {
    let base = find_vault(&tx.token_balance_changes, &pool.vault_base)?;
    let quote = find_vault(&tx.token_balance_changes, &pool.vault_quote)?;
    Some(TxReserves {
        pre: (base.pre_amount as u128, quote.pre_amount as u128),
        post: (base.post_amount as u128, quote.post_amount as u128),
    })
}

fn find_vault<'a>(
    balances: &'a [TokenBalanceChange],
    vault_address: &str,
) -> Option<&'a TokenBalanceChange> {
    balances.iter().find(|b| b.account == vault_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup::AmmKind;
    use swap_events::types::TokenBalanceChange;

    fn make_config(vault_base: &str, vault_quote: &str) -> PoolConfig {
        PoolConfig {
            kind: AmmKind::RaydiumV4,
            pool: "pool1".into(),
            vault_base: vault_base.into(),
            vault_quote: vault_quote.into(),
            base_mint: "base_mint".into(),
            quote_mint: "quote_mint".into(),
            fee_num: 25,
            fee_den: 10_000,
            base_is_token_a: false,
        }
    }

    fn make_tx(balances: Vec<TokenBalanceChange>) -> TransactionData {
        TransactionData {
            signature: "sig".into(),
            signer: "signer".into(),
            success: true,
            tx_index: 0,
            account_keys: vec![],
            instructions: vec![],
            inner_instructions: vec![],
            token_balance_changes: balances,
            sol_balance_changes: vec![],
            fee: 5000,
            log_messages: vec![],
        }
    }

    #[test]
    fn extracts_reserves_by_vault_account() {
        let config = make_config("VAULT_BASE_ACC", "VAULT_QUOTE_ACC");
        let tx = make_tx(vec![
            TokenBalanceChange {
                mint: "base_mint".into(),
                account: "VAULT_BASE_ACC".into(),
                owner: "POOL_AUTHORITY".into(),
                pre_amount: 1_000_000,
                post_amount: 900_000,
            },
            TokenBalanceChange {
                mint: "quote_mint".into(),
                account: "VAULT_QUOTE_ACC".into(),
                owner: "POOL_AUTHORITY".into(),
                pre_amount: 2_000_000,
                post_amount: 2_100_000,
            },
            // Unrelated balance — should be ignored
            TokenBalanceChange {
                mint: "other".into(),
                account: "user_other_acc".into(),
                owner: "user_wallet".into(),
                pre_amount: 100,
                post_amount: 50,
            },
        ]);

        let reserves = extract(&tx, &config).unwrap();
        assert_eq!(reserves.pre, (1_000_000, 2_000_000));
        assert_eq!(reserves.post, (900_000, 2_100_000));
    }

    #[test]
    fn returns_none_when_vault_missing() {
        let config = make_config("VAULT_BASE_ACC", "VAULT_QUOTE_ACC");
        let tx = make_tx(vec![TokenBalanceChange {
            mint: "base_mint".into(),
            account: "VAULT_BASE_ACC".into(),
            owner: "POOL_AUTHORITY".into(),
            pre_amount: 100,
            post_amount: 200,
        }]);
        // Quote vault not in tx meta — can't compute reserves
        assert!(extract(&tx, &config).is_none());
    }

    #[test]
    fn same_authority_on_both_vaults_still_distinguishes() {
        // Realistic Raydium case: both vaults share one pool-authority PDA as
        // `owner`. Matching must use `account`, not `owner`, or this fails.
        let config = make_config("VAULT_BASE_ACC", "VAULT_QUOTE_ACC");
        let tx = make_tx(vec![
            TokenBalanceChange {
                mint: "base_mint".into(),
                account: "VAULT_BASE_ACC".into(),
                owner: "POOL_AUTHORITY".into(),
                pre_amount: 10,
                post_amount: 20,
            },
            TokenBalanceChange {
                mint: "quote_mint".into(),
                account: "VAULT_QUOTE_ACC".into(),
                owner: "POOL_AUTHORITY".into(),
                pre_amount: 30,
                post_amount: 40,
            },
        ]);
        let r = extract(&tx, &config).unwrap();
        assert_eq!(r.pre, (10, 30));
        assert_eq!(r.post, (20, 40));
    }
}
