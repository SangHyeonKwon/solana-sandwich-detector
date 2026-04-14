use std::fmt;

use serde::{Deserialize, Serialize};

/// Supported DEX protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DexType {
    RaydiumV4,
    RaydiumClmm,
    RaydiumCpmm,
    OrcaWhirlpool,
    JupiterV6,
    MeteoraDlmm,
    PumpFun,
    Phoenix,
}

impl fmt::Display for DexType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DexType::RaydiumV4 => write!(f, "Raydium V4"),
            DexType::RaydiumClmm => write!(f, "Raydium CLMM"),
            DexType::RaydiumCpmm => write!(f, "Raydium CPMM"),
            DexType::OrcaWhirlpool => write!(f, "Orca Whirlpool"),
            DexType::JupiterV6 => write!(f, "Jupiter V6"),
            DexType::MeteoraDlmm => write!(f, "Meteora DLMM"),
            DexType::PumpFun => write!(f, "Pump.fun"),
            DexType::Phoenix => write!(f, "Phoenix"),
        }
    }
}

/// Direction of a token swap
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapDirection {
    /// Buying the token (SOL/quote -> token)
    Buy,
    /// Selling the token (token -> SOL/quote)
    Sell,
}

impl SwapDirection {
    pub fn opposite(&self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }
}

/// A single swap event extracted from a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapEvent {
    /// Transaction signature
    pub signature: String,
    /// Transaction signer (fee payer)
    pub signer: String,
    /// DEX that executed the swap
    pub dex: DexType,
    /// Pool/AMM address
    pub pool: String,
    /// Swap direction
    pub direction: SwapDirection,
    /// The non-SOL/non-quote token mint
    pub token_mint: String,
    /// Amount of token going in (in smallest unit)
    pub amount_in: u64,
    /// Amount of token going out
    pub amount_out: u64,
    /// Transaction index within the block (determines ordering)
    pub tx_index: usize,
}

/// A detected sandwich attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandwichAttack {
    /// Slot number where the sandwich occurred
    pub slot: u64,
    /// Attacker's wallet address
    pub attacker: String,
    /// The frontrun transaction (attacker's first trade)
    pub frontrun: SwapEvent,
    /// The victim transaction (sandwiched trade)
    pub victim: SwapEvent,
    /// The backrun transaction (attacker's closing trade)
    pub backrun: SwapEvent,
    /// Pool where the sandwich occurred
    pub pool: String,
    /// DEX protocol
    pub dex: DexType,
    /// Estimated profit for the attacker in quote token's smallest unit.
    /// v1 heuristic: `backrun.amount_out - frontrun.amount_in`
    pub estimated_attacker_profit: Option<i64>,
    /// Estimated loss for the victim. `None` in v1 (requires pool state reconstruction).
    pub estimated_victim_loss: Option<i64>,
}

// ---------------------------------------------------------------------------
// Internal block/transaction types (not serialized to JSON output)
// ---------------------------------------------------------------------------

/// A processed block ready for analysis
#[derive(Debug, Clone)]
pub struct BlockData {
    pub slot: u64,
    pub block_time: Option<i64>,
    pub transactions: Vec<TransactionData>,
}

/// A processed transaction with resolved accounts
#[derive(Debug, Clone)]
pub struct TransactionData {
    pub signature: String,
    pub signer: String,
    pub success: bool,
    pub tx_index: usize,
    /// All account keys (static + loaded from address lookup tables)
    pub account_keys: Vec<String>,
    /// Top-level instructions
    pub instructions: Vec<InstructionData>,
    /// Inner (CPI) instructions grouped by outer instruction index
    pub inner_instructions: Vec<InnerInstructionGroup>,
    /// Token balance changes
    pub token_balance_changes: Vec<TokenBalanceChange>,
    /// Native SOL (lamport) balance changes
    pub sol_balance_changes: Vec<SolBalanceChange>,
    /// Transaction fee in lamports
    pub fee: u64,
    /// Log messages
    pub log_messages: Vec<String>,
}

/// A compiled instruction
#[derive(Debug, Clone)]
pub struct InstructionData {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub data: Vec<u8>,
}

/// Group of inner instructions from a single outer instruction
#[derive(Debug, Clone)]
pub struct InnerInstructionGroup {
    pub index: u8,
    pub instructions: Vec<InstructionData>,
}

/// Token balance change for a single account
#[derive(Debug, Clone)]
pub struct TokenBalanceChange {
    pub mint: String,
    pub owner: String,
    pub pre_amount: u64,
    pub post_amount: u64,
}

impl TokenBalanceChange {
    pub fn delta(&self) -> i64 {
        self.post_amount as i64 - self.pre_amount as i64
    }
}

/// Native SOL (lamport) balance change for a single account
#[derive(Debug, Clone)]
pub struct SolBalanceChange {
    pub account: String,
    pub pre_lamports: u64,
    pub post_lamports: u64,
}

impl SolBalanceChange {
    pub fn delta(&self) -> i64 {
        self.post_lamports as i64 - self.pre_lamports as i64
    }
}
