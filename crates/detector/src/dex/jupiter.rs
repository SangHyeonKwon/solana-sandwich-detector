use crate::types::{DexType, SwapEvent, TransactionData};

use super::{determine_swap_from_balances, DexParser};

pub const JUPITER_V6_PROGRAM_ID: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

pub struct JupiterV6Parser;

impl DexParser for JupiterV6Parser {
    fn program_id(&self) -> &str {
        JUPITER_V6_PROGRAM_ID
    }

    fn parse_swaps(&self, tx: &TransactionData) -> Vec<SwapEvent> {
        // Jupiter is a router — resolve the underlying pool from inner CPI calls.
        // Fallback to a tx-unique ID to avoid false grouping in the detector.
        let pool = find_underlying_pool(tx)
            .unwrap_or_else(|| format!("jup:{}", &tx.signature[..16.min(tx.signature.len())]));

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
            dex: DexType::JupiterV6,
            pool,
            direction,
            token_mint,
            amount_in,
            amount_out,
            tx_index: tx.tx_index,
        }]
    }
}

/// Try to find the underlying pool from inner CPI calls to known DEXes.
fn find_underlying_pool(tx: &TransactionData) -> Option<String> {
    use super::orca::ORCA_WHIRLPOOL_PROGRAM_ID;
    use super::raydium::RAYDIUM_V4_PROGRAM_ID;

    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            // Raydium V4 swap (discriminator 9), pool at accounts[1]
            if ix.program_id == RAYDIUM_V4_PROGRAM_ID
                && ix.data.first() == Some(&9)
                && ix.accounts.len() > 1
            {
                return Some(ix.accounts[1].clone());
            }

            // Orca Whirlpool swap, pool at accounts[2]
            if ix.program_id == ORCA_WHIRLPOOL_PROGRAM_ID && ix.data.len() >= 8 {
                let disc: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];
                if ix.data[..8] == disc && ix.accounts.len() > 2 {
                    return Some(ix.accounts[2].clone());
                }
            }
        }
    }

    None
}
