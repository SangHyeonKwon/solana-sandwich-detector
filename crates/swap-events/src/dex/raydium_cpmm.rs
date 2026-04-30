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

/// Pool state is at accounts[3] in Raydium CPMM swap.
///
/// Swap account layout (from raydium-io/raydium-cp-swap):
///   0: payer (signer)
///   1: authority (PDA)
///   2: amm_config
///   3: pool_state              ← the pool whose reserves we care about
///   4: input_token_account
///   5: output_token_account
///   6: input_vault
///   7: output_vault
///   8+: programs, mints, observation_state
///
/// Earlier versions of this parser used index 2, which returned the
/// `amm_config` PDA — a 236-byte shared config account, not the pool.
/// Downstream pool-state enrichment then failed with `ReservesMissing`
/// because the parsed "vault" offsets pointed to unrelated bytes.
fn find_pool(tx: &TransactionData) -> Option<String> {
    for ix in &tx.instructions {
        if ix.program_id == RAYDIUM_CPMM_PROGRAM_ID && is_swap_ix(&ix.data) && ix.accounts.len() > 3
        {
            return Some(ix.accounts[3].clone());
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if ix.program_id == RAYDIUM_CPMM_PROGRAM_ID
                && is_swap_ix(&ix.data)
                && ix.accounts.len() > 3
            {
                return Some(ix.accounts[3].clone());
            }
        }
    }
    None
}
