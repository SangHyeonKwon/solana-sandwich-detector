use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedTransaction, EncodedTransactionWithStatusMeta,
    UiConfirmedBlock, UiInstruction, UiMessage, UiTransactionStatusMeta,
};

use crate::error::Result;
use crate::types::*;

/// Parse a raw Solana block (from RPC with Json encoding) into our internal format.
pub fn parse_block(slot: u64, block: UiConfirmedBlock) -> Result<BlockData> {
    let mut transactions = Vec::new();

    let raw_txs = block.transactions.unwrap_or_default();

    for (idx, tx_with_meta) in raw_txs.into_iter().enumerate() {
        match parse_transaction(idx, tx_with_meta) {
            Ok(Some(tx)) => transactions.push(tx),
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("Skip tx at index {}: {}", idx, e);
            }
        }
    }

    Ok(BlockData {
        slot,
        block_time: block.block_time,
        transactions,
    })
}

fn parse_transaction(
    tx_index: usize,
    tx_with_meta: EncodedTransactionWithStatusMeta,
) -> Result<Option<TransactionData>> {
    let meta = match tx_with_meta.meta {
        Some(meta) => meta,
        None => return Ok(None),
    };

    // Skip failed transactions
    if meta.err.is_some() {
        return Ok(None);
    }

    let ui_tx = match tx_with_meta.transaction {
        EncodedTransaction::Json(ui_tx) => ui_tx,
        _ => return Ok(None),
    };

    let signature = ui_tx.signatures.first().cloned().unwrap_or_default();

    let raw_message = match ui_tx.message {
        UiMessage::Raw(raw) => raw,
        _ => return Ok(None),
    };

    // Build full account key list: static keys + loaded addresses from lookup tables
    let mut account_keys: Vec<String> = raw_message.account_keys.clone();

    if let OptionSerializer::Some(ref loaded) = meta.loaded_addresses {
        account_keys.extend(loaded.writable.iter().cloned());
        account_keys.extend(loaded.readonly.iter().cloned());
    }

    let signer = account_keys.first().cloned().unwrap_or_default();

    let instructions = parse_compiled_instructions(&raw_message.instructions, &account_keys);
    let inner_instructions = parse_inner_instructions(&meta, &account_keys);
    let token_balance_changes = parse_token_balance_changes(&meta);
    let sol_balance_changes = parse_sol_balance_changes(&meta, &account_keys);
    let fee = meta.fee;

    let log_messages = match &meta.log_messages {
        OptionSerializer::Some(logs) => logs.clone(),
        _ => Vec::new(),
    };

    Ok(Some(TransactionData {
        signature,
        signer,
        success: true,
        tx_index,
        account_keys,
        instructions,
        inner_instructions,
        token_balance_changes,
        sol_balance_changes,
        fee,
        log_messages,
    }))
}

fn parse_compiled_instructions(
    instructions: &[solana_transaction_status::UiCompiledInstruction],
    account_keys: &[String],
) -> Vec<InstructionData> {
    instructions
        .iter()
        .filter_map(|ix| {
            let program_id = account_keys.get(ix.program_id_index as usize)?.clone();
            let accounts: Vec<String> = ix
                .accounts
                .iter()
                .filter_map(|&i| account_keys.get(i as usize).cloned())
                .collect();
            let data = bs58::decode(&ix.data).into_vec().ok()?;
            Some(InstructionData {
                program_id,
                accounts,
                data,
            })
        })
        .collect()
}

fn parse_inner_instructions(
    meta: &UiTransactionStatusMeta,
    account_keys: &[String],
) -> Vec<InnerInstructionGroup> {
    let inner = match &meta.inner_instructions {
        OptionSerializer::Some(inner) => inner,
        _ => return Vec::new(),
    };

    inner
        .iter()
        .map(|group| {
            let instructions = group
                .instructions
                .iter()
                .filter_map(|ix| match ix {
                    UiInstruction::Compiled(compiled) => {
                        let program_id = account_keys
                            .get(compiled.program_id_index as usize)?
                            .clone();
                        let accounts: Vec<String> = compiled
                            .accounts
                            .iter()
                            .filter_map(|&i| account_keys.get(i as usize).cloned())
                            .collect();
                        let data = bs58::decode(&compiled.data).into_vec().ok()?;
                        Some(InstructionData {
                            program_id,
                            accounts,
                            data,
                        })
                    }
                    _ => None,
                })
                .collect();

            InnerInstructionGroup {
                index: group.index,
                instructions,
            }
        })
        .collect()
}

fn parse_sol_balance_changes(
    meta: &UiTransactionStatusMeta,
    account_keys: &[String],
) -> Vec<SolBalanceChange> {
    meta.pre_balances
        .iter()
        .zip(meta.post_balances.iter())
        .enumerate()
        .filter_map(|(idx, (&pre, &post))| {
            if pre == post {
                return None;
            }
            let account = account_keys.get(idx)?.clone();
            Some(SolBalanceChange {
                account,
                pre_lamports: pre,
                post_lamports: post,
            })
        })
        .collect()
}

fn parse_token_balance_changes(meta: &UiTransactionStatusMeta) -> Vec<TokenBalanceChange> {
    let pre_balances = match &meta.pre_token_balances {
        OptionSerializer::Some(b) => b,
        _ => return Vec::new(),
    };
    let post_balances = match &meta.post_token_balances {
        OptionSerializer::Some(b) => b,
        _ => return Vec::new(),
    };

    let mut changes = Vec::new();

    for post_bal in post_balances {
        let pre_amount = pre_balances
            .iter()
            .find(|p| p.account_index == post_bal.account_index)
            .and_then(|p| p.ui_token_amount.amount.parse::<u64>().ok())
            .unwrap_or(0);

        let post_amount = post_bal.ui_token_amount.amount.parse::<u64>().unwrap_or(0);

        if pre_amount == post_amount {
            continue;
        }

        let owner = match &post_bal.owner {
            OptionSerializer::Some(o) => o.clone(),
            _ => continue,
        };

        changes.push(TokenBalanceChange {
            mint: post_bal.mint.clone(),
            owner,
            pre_amount,
            post_amount,
        });
    }

    changes
}
