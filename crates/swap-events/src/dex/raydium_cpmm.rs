use crate::types::{DexType, SwapEvent, TransactionData};

use super::{determine_swap_from_balances, DexParser};

pub const RAYDIUM_CPMM_PROGRAM_ID: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";

/// Anchor discriminator for "swap_base_input"
const SWAP_BASE_INPUT_DISCRIMINATOR: [u8; 8] = [143, 190, 90, 218, 196, 30, 51, 222];
/// Anchor discriminator for "swap_base_output"
const SWAP_BASE_OUTPUT_DISCRIMINATOR: [u8; 8] = [55, 217, 98, 86, 163, 74, 180, 173];

pub struct RaydiumCpmmParser;

impl DexParser for RaydiumCpmmParser {
    fn program_id(&self) -> &str {
        RAYDIUM_CPMM_PROGRAM_ID
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
            dex: DexType::RaydiumCpmm,
            pool,
            direction,
            token_mint,
            amount_in,
            amount_out,
            tx_index: tx.tx_index,
            slot: None,
            fee: Some(tx.fee),
        }]
    }
}

fn is_swap_ix(data: &[u8]) -> bool {
    data.len() >= 8
        && (data[..8] == SWAP_BASE_INPUT_DISCRIMINATOR
            || data[..8] == SWAP_BASE_OUTPUT_DISCRIMINATOR)
}

/// Pool state is at accounts[2] in Raydium CPMM swap
/// (after payer, authority).
fn find_pool(tx: &TransactionData) -> Option<String> {
    for ix in &tx.instructions {
        if ix.program_id == RAYDIUM_CPMM_PROGRAM_ID && is_swap_ix(&ix.data) && ix.accounts.len() > 2
        {
            return Some(ix.accounts[2].clone());
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if ix.program_id == RAYDIUM_CPMM_PROGRAM_ID
                && is_swap_ix(&ix.data)
                && ix.accounts.len() > 2
            {
                return Some(ix.accounts[2].clone());
            }
        }
    }
    None
}
