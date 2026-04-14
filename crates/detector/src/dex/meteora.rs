use crate::types::{DexType, SwapEvent, TransactionData};

use super::{determine_swap_from_balances, DexParser};

pub const METEORA_DLMM_PROGRAM_ID: &str = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo";

/// Anchor discriminator for "swap"
const SWAP_DISCRIMINATOR: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];

pub struct MeteoraDlmmParser;

impl DexParser for MeteoraDlmmParser {
    fn program_id(&self) -> &str {
        METEORA_DLMM_PROGRAM_ID
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
            dex: DexType::MeteoraDlmm,
            pool,
            direction,
            token_mint,
            amount_in,
            amount_out,
            tx_index: tx.tx_index,
        }]
    }
}

/// LB pair account is at accounts[0] in Meteora DLMM swap.
fn find_pool(tx: &TransactionData) -> Option<String> {
    for ix in &tx.instructions {
        if ix.program_id == METEORA_DLMM_PROGRAM_ID
            && ix.data.len() >= 8
            && ix.data[..8] == SWAP_DISCRIMINATOR
            && !ix.accounts.is_empty()
        {
            return Some(ix.accounts[0].clone());
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if ix.program_id == METEORA_DLMM_PROGRAM_ID
                && ix.data.len() >= 8
                && ix.data[..8] == SWAP_DISCRIMINATOR
                && !ix.accounts.is_empty()
            {
                return Some(ix.accounts[0].clone());
            }
        }
    }
    None
}
