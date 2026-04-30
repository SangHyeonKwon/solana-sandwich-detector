use crate::types::{DexType, SwapEvent, TransactionData};

use super::{determine_swap_from_balances, DexParser};

pub const RAYDIUM_V4_PROGRAM_ID: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";

/// Raydium V4 swap instruction discriminators.
///   9  = SwapBaseIn  (user specifies exact amount_in)
///   11 = SwapBaseOut (user specifies exact amount_out)
/// Both are real user swaps that move pool reserves, so sandwich detection
/// must treat them equivalently. The AMM account layout is the same for
/// both (amm_id at index 1), so `find_pool` works unchanged.
const SWAP_BASE_IN_DISCRIMINATOR: u8 = 9;
const SWAP_BASE_OUT_DISCRIMINATOR: u8 = 11;

fn is_swap_discriminator(byte: u8) -> bool {
    byte == SWAP_BASE_IN_DISCRIMINATOR || byte == SWAP_BASE_OUT_DISCRIMINATOR
}

pub struct RaydiumV4Parser;

impl DexParser for RaydiumV4Parser {
    fn program_id(&self) -> &str {
        RAYDIUM_V4_PROGRAM_ID
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
            dex: DexType::RaydiumV4,
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

/// In Raydium V4 swap the AMM ID sits at account index 1.
fn find_pool(tx: &TransactionData) -> Option<String> {
    for ix in &tx.instructions {
        if ix.program_id == RAYDIUM_V4_PROGRAM_ID
            && ix.data.first().copied().is_some_and(is_swap_discriminator)
            && ix.accounts.len() > 1
        {
            return Some(ix.accounts[1].clone());
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if ix.program_id == RAYDIUM_V4_PROGRAM_ID
                && ix.data.first().copied().is_some_and(is_swap_discriminator)
                && ix.accounts.len() > 1
            {
                return Some(ix.accounts[1].clone());
            }
        }
    }
    None
}
