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

fn is_swap_ix(data: &[u8]) -> bool {
    data.len() >= 8 && (data[..8] == SWAP_DISCRIMINATOR || data[..8] == SWAP_V2_DISCRIMINATOR)
}

/// Pool state is at accounts[2] in Raydium CLMM `swap` and `swap_v2` instructions.
///
/// Account layout (from raydium-io/raydium-clmm `SwapSingle` / `SwapSingleV2`):
///   0: payer (signer)
///   1: amm_config              ← shared fee-tier PDA, NOT the pool
///   2: pool_state              ← the pool whose reserves we care about
///   3: input_token_account
///   4: output_token_account
///   5: input_vault
///   6: output_vault
///   7: observation_state
///   8+: token programs, memo program, vault mints, tick arrays
///
/// Earlier versions of this parser used index 1, returning the
/// `amm_config` PDA — a 117-byte fee-tier account shared across many
/// pools. The same swap-events SwapEvent then carried an `amm_config`
/// address as its `pool` field, so the same-block detector grouped
/// unrelated swaps (different mint pairs, different real pools) under
/// one "pool" address and emitted false-positive sandwiches; downstream
/// pool-state enrichment then silently failed because the 117-byte
/// `AmmConfig` isn't a 1544-byte `PoolState`. Identical class of bug to
/// the one previously fixed in `raydium_cpmm.rs` — see comments there.
fn find_pool(tx: &TransactionData) -> Option<String> {
    for ix in &tx.instructions {
        if ix.program_id == RAYDIUM_CLMM_PROGRAM_ID && is_swap_ix(&ix.data) && ix.accounts.len() > 2
        {
            return Some(ix.accounts[2].clone());
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if ix.program_id == RAYDIUM_CLMM_PROGRAM_ID
                && is_swap_ix(&ix.data)
                && ix.accounts.len() > 2
            {
                return Some(ix.accounts[2].clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{InnerInstructionGroup, InstructionData, TokenBalanceChange};

    const SIGNER: &str = "Signer11111111111111111111111111111111111111";
    const AMM_CONFIG: &str = "AmmConfig11111111111111111111111111111111111";
    const POOL_STATE: &str = "PoolState1111111111111111111111111111111111";
    const INPUT_ATA: &str = "InputAta11111111111111111111111111111111111";
    const OUTPUT_ATA: &str = "OutputAta1111111111111111111111111111111111";
    const INPUT_VAULT: &str = "InputVault111111111111111111111111111111111";
    const OUTPUT_VAULT: &str = "OutputVault11111111111111111111111111111111";
    const TOKEN_MINT: &str = "TokenMint1111111111111111111111111111111111";
    /// USDC — must be a real quote mint so `determine_swap_from_balances`
    /// returns `Sell` direction (it whitelists known quote mints).
    const QUOTE_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn swap_v2_data() -> Vec<u8> {
        let mut d = SWAP_V2_DISCRIMINATOR.to_vec();
        // 48 bytes of arg payload (amount, other_amount_threshold, sqrt_price_limit, is_base_input)
        d.extend_from_slice(&[0u8; 48]);
        d
    }

    fn swap_data() -> Vec<u8> {
        let mut d = SWAP_DISCRIMINATOR.to_vec();
        d.extend_from_slice(&[0u8; 48]);
        d
    }

    /// Token-to-token balance changes that satisfy
    /// `determine_swap_from_balances` Case 1 (1 down + 1 up on the signer).
    /// Signer sells `TOKEN_MINT` for `QUOTE_MINT`.
    fn signer_sold_token_for_quote() -> Vec<TokenBalanceChange> {
        vec![
            TokenBalanceChange {
                mint: TOKEN_MINT.into(),
                account: "SignerTokenAta".into(),
                owner: SIGNER.into(),
                pre_amount: 1_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: QUOTE_MINT.into(),
                account: "SignerQuoteAta".into(),
                owner: SIGNER.into(),
                pre_amount: 0,
                post_amount: 500_000,
            },
        ]
    }

    fn clmm_ix(data: Vec<u8>) -> InstructionData {
        InstructionData {
            program_id: RAYDIUM_CLMM_PROGRAM_ID.into(),
            accounts: vec![
                SIGNER.into(),
                AMM_CONFIG.into(),
                POOL_STATE.into(),
                INPUT_ATA.into(),
                OUTPUT_ATA.into(),
                INPUT_VAULT.into(),
                OUTPUT_VAULT.into(),
            ],
            data,
        }
    }

    fn tx_with_top_level(ix: InstructionData) -> TransactionData {
        TransactionData {
            signature: "TestSig".into(),
            signer: SIGNER.into(),
            success: true,
            tx_index: 0,
            account_keys: vec![],
            instructions: vec![ix],
            inner_instructions: vec![],
            token_balance_changes: signer_sold_token_for_quote(),
            sol_balance_changes: vec![],
            fee: 5000,
            log_messages: vec![],
        }
    }

    fn tx_with_inner(ix: InstructionData) -> TransactionData {
        TransactionData {
            signature: "TestSig".into(),
            signer: SIGNER.into(),
            success: true,
            tx_index: 0,
            account_keys: vec![],
            // Some non-CLMM router program at the top
            instructions: vec![InstructionData {
                program_id: "Router1111111111111111111111111111111111111".into(),
                accounts: vec![],
                data: vec![],
            }],
            inner_instructions: vec![InnerInstructionGroup {
                index: 0,
                instructions: vec![ix],
            }],
            token_balance_changes: signer_sold_token_for_quote(),
            sol_balance_changes: vec![],
            fee: 5000,
            log_messages: vec![],
        }
    }

    #[test]
    fn top_level_swap_v2_returns_pool_state_not_amm_config() {
        let tx = tx_with_top_level(clmm_ix(swap_v2_data()));
        let events = RaydiumClmmParser.parse_swaps(&tx);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].pool, POOL_STATE,
            "pool must be accounts[2] (pool_state), not accounts[1] (amm_config)"
        );
        assert_ne!(events[0].pool, AMM_CONFIG);
    }

    #[test]
    fn top_level_swap_returns_pool_state() {
        let tx = tx_with_top_level(clmm_ix(swap_data()));
        let events = RaydiumClmmParser.parse_swaps(&tx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pool, POOL_STATE);
    }

    #[test]
    fn inner_cpi_swap_v2_returns_pool_state() {
        // Mainnet pattern: a router program (e.g. routeUGWg…) makes a CPI
        // to CLMM swap_v2. The pool state must still be at accounts[2] of
        // the CLMM inner instruction.
        let tx = tx_with_inner(clmm_ix(swap_v2_data()));
        let events = RaydiumClmmParser.parse_swaps(&tx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pool, POOL_STATE);
    }

    #[test]
    fn rejects_short_account_list() {
        // A swap_v2 instruction with fewer than 3 accounts cannot identify
        // the pool — must return None rather than panic or pick the wrong
        // account.
        let mut ix = clmm_ix(swap_v2_data());
        ix.accounts.truncate(2); // [signer, amm_config] only
        let tx = tx_with_top_level(ix);
        let events = RaydiumClmmParser.parse_swaps(&tx);
        assert!(events.is_empty());
    }
}
