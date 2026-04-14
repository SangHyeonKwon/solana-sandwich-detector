use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single labeled sandwich example (positive or negative).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledExample {
    /// Unique ID for this label (human-readable slug).
    pub id: String,

    /// Slot where this sandwich was observed (or expected).
    pub slot: u64,

    /// The three transaction signatures: [frontrun, victim, backrun].
    /// For negative examples, these are the transactions that were
    /// incorrectly flagged or that form a "looks like but isn't" pattern.
    pub tx_signatures: SandwichTxSigs,

    /// The pool address where the attack occurred.
    pub pool: String,

    /// True = this is a real sandwich attack. False = this is NOT a sandwich.
    pub is_sandwich: bool,

    /// Attacker wallet(s). May have multiple for multi-wallet attackers.
    /// Empty for negative examples.
    #[serde(default)]
    pub attacker_wallets: Vec<String>,

    /// How this label was created.
    pub provenance: LabelProvenance,

    /// Free-form notes about why this was labeled this way.
    #[serde(default)]
    pub notes: String,

    /// When this label was created/last updated.
    pub labeled_at: DateTime<Utc>,

    /// Who created this label.
    pub labeled_by: String,
}

/// The three tx signatures forming a sandwich triplet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandwichTxSigs {
    pub frontrun: String,
    pub victim: String,
    pub backrun: String,
}

/// How was this label generated?
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelProvenance {
    /// Derived from Jito bundle API (bundle contained all 3 txs atomically).
    JitoBundle { bundle_id: String },
    /// Hand-labeled by a human using Helius enhanced TX data or Solscan.
    HandLabeled,
    /// Semi-automated: flagged by detector, confirmed by human.
    DetectorConfirmed,
    /// Semi-automated: flagged by detector, rejected by human.
    DetectorRejected,
}

/// A complete label dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelDataset {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// Dataset metadata.
    pub metadata: DatasetMetadata,
    /// The actual labeled examples.
    pub labels: Vec<LabeledExample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetMetadata {
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub slot_range: (u64, u64),
    pub total_slots_sampled: usize,
}

impl LabelDataset {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let dataset: Self = serde_json::from_str(&contents)?;
        Ok(dataset)
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn positive_count(&self) -> usize {
        self.labels.iter().filter(|l| l.is_sandwich).count()
    }

    pub fn negative_count(&self) -> usize {
        self.labels.iter().filter(|l| !l.is_sandwich).count()
    }
}
