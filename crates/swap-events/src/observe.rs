//! Re-extract a swap's accounting from a `getTransaction` payload, using
//! the same balance-delta heuristic the detector uses at parse time.
//!
//! The block-stream parser ([`crate::parser`]) walks `pre_token_balances`
//! / `post_token_balances` (plus signer SOL deltas) and runs them through
//! [`crate::dex::determine_swap_from_balances`] to produce a `SwapEvent`.
//! `SandwichAttack.victim.amount_out` carries that result through to the
//! consumer. To validate that number end-to-end against on-chain truth we
//! need to ask Solana the same question a second time — via standard
//! `getTransaction` (fully archival on every major provider) — and run
//! the identical heuristic on the fresh response.
//!
//! A non-zero diff between the recorded and re-observed amount_out points
//! to a parser-stable failure mode: account-key drift between block
//! snapshot and tx fetch (e.g. lookup-table updates), token-balance
//! representation differences, or RPC-side serialisation inconsistencies.
//! Replay-math bugs do *not* show up here — they live in
//! [`pool_state::diff_test::WhirlpoolDiffReport`] instead.

use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedTransaction, EncodedTransactionWithStatusMeta,
    UiMessage, UiTransactionStatusMeta,
};

use crate::dex::determine_swap_from_balances;
use crate::parser::{parse_sol_balance_changes, parse_token_balance_changes};
use crate::types::SwapDirection;

/// Re-derived swap details for a single transaction. Mirrors the four
/// fields [`determine_swap_from_balances`] returns plus the signer it
/// was attributed to (the cross-check key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedSwap {
    pub signer: String,
    pub direction: SwapDirection,
    pub token_mint: String,
    pub amount_in: u64,
    pub amount_out: u64,
}

/// Inner observation pass — operates directly on a parsed
/// [`UiTransactionStatusMeta`] plus the resolved account-key list. Split
/// from [`observe_swap_from_tx`] so tests can hand in a synthetic meta
/// without building the surrounding [`EncodedTransactionWithStatusMeta`]
/// wrapper.
///
/// Returns `None` when the meta carries an error, the first account key
/// (= fee payer) doesn't match `expected_signer`, or
/// [`determine_swap_from_balances`] can't classify the deltas (multi-leg
/// route, no signer-side change, etc.).
pub fn observe_swap_from_meta(
    meta: &UiTransactionStatusMeta,
    account_keys: &[String],
    expected_signer: &str,
) -> Option<ObservedSwap> {
    if meta.err.is_some() {
        return None;
    }
    let signer = account_keys.first()?;
    if signer != expected_signer {
        return None;
    }
    let token_balance_changes = parse_token_balance_changes(meta, account_keys);
    let sol_balance_changes = parse_sol_balance_changes(meta, account_keys);
    let (direction, token_mint, amount_in, amount_out) = determine_swap_from_balances(
        &token_balance_changes,
        &sol_balance_changes,
        signer,
        meta.fee,
    )?;
    Some(ObservedSwap {
        signer: signer.clone(),
        direction,
        token_mint,
        amount_in,
        amount_out,
    })
}

/// Re-extract a swap from a `getTransaction` payload. Wraps
/// [`observe_swap_from_meta`] with the [`EncodedTransaction`] →
/// `(meta, account_keys)` unwrapping the block parser already does.
///
/// Returns `None` when:
///   * `tx.meta` is missing,
///   * `tx.transaction` isn't [`EncodedTransaction::Json`] (other
///     encodings unsupported by the parser),
///   * the message isn't [`UiMessage::Raw`],
///   * the inner [`observe_swap_from_meta`] short-circuits.
pub fn observe_swap_from_tx(
    tx: &EncodedTransactionWithStatusMeta,
    expected_signer: &str,
) -> Option<ObservedSwap> {
    let meta = tx.meta.as_ref()?;
    let ui_tx = match &tx.transaction {
        EncodedTransaction::Json(t) => t,
        _ => return None,
    };
    let raw_message = match &ui_tx.message {
        UiMessage::Raw(raw) => raw,
        _ => return None,
    };
    let mut account_keys: Vec<String> = raw_message.account_keys.clone();
    if let OptionSerializer::Some(loaded) = &meta.loaded_addresses {
        account_keys.extend(loaded.writable.iter().cloned());
        account_keys.extend(loaded.readonly.iter().cloned());
    }
    observe_swap_from_meta(meta, &account_keys, expected_signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `UiTransactionStatusMeta` from a JSON literal with the
    /// shape `getTransaction` returns. Going through serde rather than
    /// constructing the struct directly keeps the test free of the
    /// out-of-tree `solana_account_decoder_client_types::UiTokenAmount`
    /// dep (not re-exported by `solana_transaction_status`) and makes
    /// fixtures read like real RPC payloads.
    fn meta_from_json(value: serde_json::Value) -> UiTransactionStatusMeta {
        serde_json::from_value(value).expect("meta deserialises")
    }

    #[test]
    fn observes_token_to_token_buy() {
        // Signer's USDC drops 1_000, a non-quote token rises 500 → Buy.
        // Use a synthetic non-quote mint for the "got" side; wSOL is in
        // QUOTE_MINTS and would invert the direction inference.
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let token = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let meta = meta_from_json(serde_json::json!({
            "err": null,
            "status": { "Ok": null },
            "fee": 5_000,
            "preBalances": [10_000_000u64, 0u64],
            "postBalances": [10_000_000u64, 0u64],
            "preTokenBalances": [
                { "accountIndex": 1, "mint": usdc, "owner": "user", "uiTokenAmount": { "amount": "1000", "decimals": 6, "uiAmount": null, "uiAmountString": "1000" } },
                { "accountIndex": 2, "mint": token, "owner": "user", "uiTokenAmount": { "amount": "0", "decimals": 6, "uiAmount": null, "uiAmountString": "0" } },
            ],
            "postTokenBalances": [
                { "accountIndex": 1, "mint": usdc, "owner": "user", "uiTokenAmount": { "amount": "0", "decimals": 6, "uiAmount": null, "uiAmountString": "0" } },
                { "accountIndex": 2, "mint": token, "owner": "user", "uiTokenAmount": { "amount": "500", "decimals": 6, "uiAmount": null, "uiAmountString": "500" } },
            ],
        }));
        let account_keys = vec![
            "user".to_string(),
            "user_usdc_acc".to_string(),
            "user_token_acc".to_string(),
        ];
        let observed = observe_swap_from_meta(&meta, &account_keys, "user").unwrap();
        assert_eq!(observed.signer, "user");
        assert_eq!(observed.direction, SwapDirection::Buy);
        assert_eq!(observed.token_mint, token);
        assert_eq!(observed.amount_in, 1_000);
        assert_eq!(observed.amount_out, 500);
    }

    #[test]
    fn observes_token_to_token_sell() {
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let token = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let meta = meta_from_json(serde_json::json!({
            "err": null,
            "status": { "Ok": null },
            "fee": 5_000,
            "preBalances": [10_000_000u64, 0u64],
            "postBalances": [10_000_000u64, 0u64],
            "preTokenBalances": [
                { "accountIndex": 1, "mint": token, "owner": "user", "uiTokenAmount": { "amount": "500", "decimals": 6, "uiAmount": null, "uiAmountString": "500" } },
                { "accountIndex": 2, "mint": usdc,  "owner": "user", "uiTokenAmount": { "amount": "0",   "decimals": 6, "uiAmount": null, "uiAmountString": "0" } },
            ],
            "postTokenBalances": [
                { "accountIndex": 1, "mint": token, "owner": "user", "uiTokenAmount": { "amount": "0",   "decimals": 6, "uiAmount": null, "uiAmountString": "0" } },
                { "accountIndex": 2, "mint": usdc,  "owner": "user", "uiTokenAmount": { "amount": "980", "decimals": 6, "uiAmount": null, "uiAmountString": "980" } },
            ],
        }));
        let account_keys = vec![
            "user".to_string(),
            "user_token_acc".to_string(),
            "user_usdc_acc".to_string(),
        ];
        let observed = observe_swap_from_meta(&meta, &account_keys, "user").unwrap();
        assert_eq!(observed.direction, SwapDirection::Sell);
        assert_eq!(observed.token_mint, token);
        assert_eq!(observed.amount_in, 500);
        assert_eq!(observed.amount_out, 980);
    }

    #[test]
    fn observes_sol_to_token_buy_via_lamport_delta() {
        // Signer spent native SOL (lamport drop minus fee), got TOKEN.
        // No pre/post token entry on the SOL side — the parser falls
        // back to sol_balance_changes for amount_in.
        let token = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let post_sol_user: u64 = 10_000_000 - 1_000_000 - 5_000;
        let meta = meta_from_json(serde_json::json!({
            "err": null,
            "status": { "Ok": null },
            "fee": 5_000,
            "preBalances": [10_000_000u64, 0u64],
            "postBalances": [post_sol_user, 0u64],
            "preTokenBalances": [
                { "accountIndex": 1, "mint": token, "owner": "user", "uiTokenAmount": { "amount": "0",   "decimals": 6, "uiAmount": null, "uiAmountString": "0" } },
            ],
            "postTokenBalances": [
                { "accountIndex": 1, "mint": token, "owner": "user", "uiTokenAmount": { "amount": "500", "decimals": 6, "uiAmount": null, "uiAmountString": "500" } },
            ],
        }));
        let account_keys = vec!["user".to_string(), "user_token_acc".to_string()];
        let observed = observe_swap_from_meta(&meta, &account_keys, "user").unwrap();
        assert_eq!(observed.direction, SwapDirection::Buy);
        assert_eq!(observed.token_mint, token);
        assert_eq!(observed.amount_in, 1_000_000);
        assert_eq!(observed.amount_out, 500);
    }

    #[test]
    fn returns_none_when_signer_mismatches() {
        let token = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let meta = meta_from_json(serde_json::json!({
            "err": null,
            "status": { "Ok": null },
            "fee": 5_000,
            "preBalances": [0u64, 0u64],
            "postBalances": [0u64, 0u64],
            "preTokenBalances": [
                { "accountIndex": 1, "mint": token, "owner": "alien", "uiTokenAmount": { "amount": "0",   "decimals": 6, "uiAmount": null, "uiAmountString": "0" } },
            ],
            "postTokenBalances": [
                { "accountIndex": 1, "mint": token, "owner": "alien", "uiTokenAmount": { "amount": "500", "decimals": 6, "uiAmount": null, "uiAmountString": "500" } },
            ],
        }));
        let account_keys = vec!["alien".to_string(), "alien_token_acc".to_string()];
        assert!(observe_swap_from_meta(&meta, &account_keys, "user").is_none());
    }

    #[test]
    fn returns_none_on_failed_tx() {
        // `err` populated → cross-check is undefined.
        let meta = meta_from_json(serde_json::json!({
            "err": { "AccountInUse": null },
            "status": { "Err": { "AccountInUse": null } },
            "fee": 5_000,
            "preBalances": [0u64],
            "postBalances": [0u64],
        }));
        let account_keys = vec!["user".to_string()];
        assert!(observe_swap_from_meta(&meta, &account_keys, "user").is_none());
    }

    #[test]
    fn returns_none_when_account_keys_empty() {
        let meta = meta_from_json(serde_json::json!({
            "err": null,
            "status": { "Ok": null },
            "fee": 0,
            "preBalances": [],
            "postBalances": [],
        }));
        assert!(observe_swap_from_meta(&meta, &[], "user").is_none());
    }
}
