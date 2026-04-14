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
    /// Slot number (needed for cross-slot correlation). `None` for same-block only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    /// Transaction fee in lamports. `None` if not available from parser context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,
}

/// How a sandwich was detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    SameBlock,
    CrossSlotWindow { window_size: usize },
    JitoBundleConfirmed { bundle_id: String },
}

/// Jito bundle relationship of a sandwich triplet.
///
/// Determines confidence: `AtomicBundle` ≈ 100%, `Organic` needs economic proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleProvenance {
    /// All 3 txs in the same Jito bundle — near-certain sandwich.
    AtomicBundle,
    /// Frontrun + backrun in the same bundle, victim separate — high confidence.
    SpanningBundle,
    /// All 3 are in bundles, but different ones — medium confidence.
    TipRace,
    /// None of the txs are in a bundle — needs economic/victim filters.
    Organic,
}

impl BundleProvenance {
    /// Base confidence weight for scoring. Higher = more confident.
    pub fn confidence_weight(&self) -> f64 {
        match self {
            Self::AtomicBundle => 0.95,
            Self::SpanningBundle => 0.80,
            Self::TipRace => 0.50,
            Self::Organic => 0.20,
        }
    }
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
    /// For cross-slot sandwiches: slot of the frontrun tx.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontrun_slot: Option<u64>,
    /// For cross-slot sandwiches: slot of the backrun tx.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backrun_slot: Option<u64>,
    /// How this sandwich was detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_method: Option<DetectionMethod>,
    /// Jito bundle provenance classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_provenance: Option<BundleProvenance>,
    /// Composite confidence score [0.0, 1.0] incorporating provenance + economics + victim plausibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// Net economic profit for the attacker after costs (fees + tip + gas).
    /// `None` if cost data unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_profit: Option<i64>,
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
