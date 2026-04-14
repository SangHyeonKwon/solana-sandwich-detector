use crate::types::{DexType, SwapEvent, TransactionData};

use super::{determine_swap_from_balances, DexParser};

pub const PUMPFUN_PROGRAM_ID: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";

/// Anchor discriminator for "buy"
const BUY_DISCRIMINATOR: [u8; 8] = [102, 6, 61, 18, 1, 218, 235, 234];
/// Anchor discriminator for "sell"
const SELL_DISCRIMINATOR: [u8; 8] = [51, 230, 133, 164, 1, 127, 131, 173];

pub struct PumpFunParser;

impl DexParser for PumpFunParser {
    fn program_id(&self) -> &str {
        PUMPFUN_PROGRAM_ID
    }

    fn parse_swaps(&self, tx: &TransactionData) -> Vec<SwapEvent> {
        let Some(pool) = find_pool(tx) else {
            return Vec::new();
        };

        let Some((direction, token_mint, amount_in, amount_out)) = determine_swap_from_balances(
            &tx.token_balance_changes,
            &tx.sol_balance_changes,
            &tx.signer,
            tx.fee,
        ) else {
            return Vec::new();
        };

        vec![SwapEvent {
            signature: tx.signature.clone(),
            signer: tx.signer.clone(),
            dex: DexType::PumpFun,
            pool,
            direction,
            token_mint,
            amount_in,
            amount_out,
            tx_index: tx.tx_index,
        }]
    }
}

fn is_swap_ix(data: &[u8]) -> bool {
    data.len() >= 8 && (data[..8] == BUY_DISCRIMINATOR || data[..8] == SELL_DISCRIMINATOR)
}

/// Bonding curve account is at accounts[2] in Pump.fun buy/sell
/// (after global, fee_recipient).
fn find_pool(tx: &TransactionData) -> Option<String> {
    for ix in &tx.instructions {
        if ix.program_id == PUMPFUN_PROGRAM_ID && is_swap_ix(&ix.data) && ix.accounts.len() > 2 {
            return Some(ix.accounts[2].clone());
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if ix.program_id == PUMPFUN_PROGRAM_ID && is_swap_ix(&ix.data) && ix.accounts.len() > 2
            {
                return Some(ix.accounts[2].clone());
            }
        }
    }
    None
}
