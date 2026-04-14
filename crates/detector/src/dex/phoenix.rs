use crate::types::{DexType, SwapEvent, TransactionData};

use super::{determine_swap_from_balances, DexParser};

pub const PHOENIX_PROGRAM_ID: &str = "PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY";

/// Phoenix swap instruction discriminator (byte 0)
const SWAP_DISCRIMINATOR: u8 = 0;

pub struct PhoenixParser;

impl DexParser for PhoenixParser {
    fn program_id(&self) -> &str {
        PHOENIX_PROGRAM_ID
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
            dex: DexType::Phoenix,
            pool,
            direction,
            token_mint,
            amount_in,
            amount_out,
            tx_index: tx.tx_index,
        }]
    }
}

/// Market account is at accounts[0] in Phoenix swap.
fn find_pool(tx: &TransactionData) -> Option<String> {
    for ix in &tx.instructions {
        if ix.program_id == PHOENIX_PROGRAM_ID
            && ix.data.first() == Some(&SWAP_DISCRIMINATOR)
            && !ix.accounts.is_empty()
        {
            return Some(ix.accounts[0].clone());
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if ix.program_id == PHOENIX_PROGRAM_ID
                && ix.data.first() == Some(&SWAP_DISCRIMINATOR)
                && !ix.accounts.is_empty()
            {
                return Some(ix.accounts[0].clone());
            }
        }
    }
    None
}
