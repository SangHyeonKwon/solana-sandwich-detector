use crate::types::{DexType, SwapEvent, TransactionData};

use super::{determine_swap_from_balances, DexParser};

pub const RAYDIUM_CLMM_PROGRAM_ID: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";

/// Anchor discriminator for "swap" instruction
const SWAP_DISCRIMINATOR: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];
/// Anchor discriminator for "swap_v2" instruction
const SWAP_V2_DISCRIMINATOR: [u8; 8] = [43, 4, 237, 11, 26, 201, 30, 98];

pub struct RaydiumClmmParser;

impl DexParser for RaydiumClmmParser {
    fn program_id(&self) -> &str {
        RAYDIUM_CLMM_PROGRAM_ID
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
            dex: DexType::RaydiumClmm,
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

/// Pool state is at accounts[1] in Raydium CLMM swap instructions
/// (after payer/signer at [0]).
fn is_swap_ix(data: &[u8]) -> bool {
    data.len() >= 8 && (data[..8] == SWAP_DISCRIMINATOR || data[..8] == SWAP_V2_DISCRIMINATOR)
}

fn find_pool(tx: &TransactionData) -> Option<String> {
    for ix in &tx.instructions {
        if ix.program_id == RAYDIUM_CLMM_PROGRAM_ID && is_swap_ix(&ix.data) && ix.accounts.len() > 1
        {
            return Some(ix.accounts[1].clone());
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if ix.program_id == RAYDIUM_CLMM_PROGRAM_ID
                && is_swap_ix(&ix.data)
                && ix.accounts.len() > 1
            {
                return Some(ix.accounts[1].clone());
            }
        }
    }
    None
}
