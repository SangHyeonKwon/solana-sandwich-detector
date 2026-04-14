use crate::types::{DexType, SwapEvent, TransactionData};

use super::{determine_swap_from_balances, DexParser};

pub const ORCA_WHIRLPOOL_PROGRAM_ID: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";

/// Anchor discriminator for the "swap" instruction (sha256("global:swap")[..8])
const SWAP_DISCRIMINATOR: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];

pub struct OrcaWhirlpoolParser;

impl DexParser for OrcaWhirlpoolParser {
    fn program_id(&self) -> &str {
        ORCA_WHIRLPOOL_PROGRAM_ID
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
            dex: DexType::OrcaWhirlpool,
            pool,
            direction,
            token_mint,
            amount_in,
            amount_out,
            tx_index: tx.tx_index,
        }]
    }
}

/// In Orca Whirlpool the pool account is at index 2 (after token_program, token_authority).
fn find_pool(tx: &TransactionData) -> Option<String> {
    for ix in &tx.instructions {
        if ix.program_id == ORCA_WHIRLPOOL_PROGRAM_ID
            && ix.data.len() >= 8
            && ix.data[..8] == SWAP_DISCRIMINATOR
            && ix.accounts.len() > 2
        {
            return Some(ix.accounts[2].clone());
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if ix.program_id == ORCA_WHIRLPOOL_PROGRAM_ID
                && ix.data.len() >= 8
                && ix.data[..8] == SWAP_DISCRIMINATOR
                && ix.accounts.len() > 2
            {
                return Some(ix.accounts[2].clone());
            }
        }
    }
    None
}
