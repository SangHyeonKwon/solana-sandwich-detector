use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Supported DEX protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    SameBlock,
    CrossSlotWindow { window_size: usize },
    JitoBundleConfirmed { bundle_id: String },
}

/// Stable attack-type taxonomy mirrored to Vigil's `mev_attack.type` column.
/// Today the detector emits `Sandwich` (contiguous, single-slot) or
/// `WideSandwich` (intervening txs or cross-slot). The remaining variants are
/// placeholders for future tiers — backrun-only exploitation and the
/// authority-hop heuristic — so the schema doesn't churn when those land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    Sandwich,
    WideSandwich,
    Backrun,
    AuthorityHop,
}

/// Severity tier for surface display (Vigil `mev_attack.severity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Bucket a victim-loss to pool-reserve ratio. Anything that nudges the
    /// pool by a basis point counts as Medium; consuming 1% of pool depth
    /// (a meaningful liquidity event) is Critical.
    pub fn from_loss_ratio(loss_to_pool: f64) -> Self {
        if loss_to_pool >= 0.01 {
            Self::Critical
        } else if loss_to_pool >= 0.001 {
            Self::High
        } else if loss_to_pool >= 0.0001 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Text bucket of the float `confidence` score (Vigil `mev_receipt.loss_confidence`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

impl ConfidenceLevel {
    /// Bucket the composite confidence score `[0.0, 1.0]` for surface display.
    /// `High` (≥0.8) is the conventional "trustworthy" tier; `Low` (<0.5)
    /// flags edge cases the BE can warn on. These tiers sit *above* whatever
    /// survives the `FilteredWindowDetector` emission gate (default
    /// `min_confidence: 0.30` in `detector-window/src/filters.rs`) — they
    /// classify already-emitted detections, they don't gate emission.
    pub fn from_score(score: f64) -> Self {
        if score >= 0.8 {
            Self::High
        } else if score >= 0.5 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Per-victim projection of a [`SandwichAttack`] mirroring Vigil's `mev_receipt`
/// table columns. BE-managed columns (receipt id, USD pricing, protection
/// metadata, share urls, created_at) are intentionally omitted — those are
/// filled by the Vigil backend, not the detector.
///
/// A single sandwich today produces exactly one receipt; the field on
/// `SandwichAttack` is `Vec<MevReceipt>` so wide-sandwich variants with
/// multiple victims can fan out without breaking the schema later.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MevReceipt {
    pub victim_tx_signature: String,
    /// FK to `mev_attack.signature` — set to whatever the parent attack uses
    /// as its canonical id (today: the victim tx signature).
    pub attack_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<i64>,
    pub victim_wallet: String,
    pub victim_action: SwapDirection,
    pub victim_dex: DexType,
    /// Input token mint. `None` when the parser didn't resolve the quote-side
    /// mint of the pair (today only the non-quote token is tracked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_in_mint: Option<String>,
    /// Output token mint. Same caveat as `token_in_mint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_out_mint: Option<String>,
    pub amount_in: u64,
    /// Counterfactual victim output (what they would have received without
    /// the frontrun). `None` when AMM-replay enrichment didn't run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_amount_out: Option<u64>,
    pub actual_amount_out: u64,
    /// `(expected − actual) / expected`, in `[0.0, 1.0]`. `None` when expected
    /// is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slippage: Option<f64>,
    /// Always `true` on emitted receipts; column kept so the BE can persist
    /// negative receipts later without a schema change.
    pub mev_detected: bool,
    pub mev_type: AttackType,
    pub severity: Severity,
    /// Loss in quote-token smallest units. `None` when AMM replay didn't run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_amount: Option<i64>,
    /// Lower / upper bounds of the victim-loss confidence interval (Tier 3.3),
    /// mirrored from `SandwichAttack.victim_loss_lamports_{lower,upper}`.
    /// Same quote-token unit as `loss_amount`. Both `None` when no
    /// observation-based CI was derivable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_amount_lower: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_amount_upper: Option<i64>,
    /// `loss_amount / counterfactual_value`, in `[0.0, 1.0]`. `None` when
    /// not derivable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_percent: Option<f64>,
    pub loss_confidence: ConfidenceLevel,
    /// Vigil `validator_identity` — slot leader at the victim's slot.
    /// `None` until Tier 2 enrichment is wired up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_identity: Option<String>,
}

impl MevReceipt {
    /// Project a [`SandwichAttack`] into a per-victim receipt mirroring
    /// Vigil's `mev_receipt` row shape. Fields the detector cannot resolve
    /// from current state (quote-side mint, validator identity, USD prices)
    /// are left as `None` so later stages can fill them without recomputing.
    pub fn from_attack(attack: &SandwichAttack) -> Self {
        let actual_amount_out = attack.victim.amount_out;
        let expected_amount_out = attack
            .amm_replay
            .as_ref()
            .map(|r| r.counterfactual_victim_out);
        let slippage = expected_amount_out.and_then(|expected| {
            if expected == 0 {
                None
            } else {
                Some((expected.saturating_sub(actual_amount_out) as f64) / (expected as f64))
            }
        });
        let loss_percent = match (attack.victim_loss_lamports, expected_amount_out) {
            (Some(loss), Some(expected)) if expected > 0 && loss >= 0 => {
                Some((loss as f64) / (expected as f64))
            }
            _ => None,
        };
        let attack_signature = attack
            .attack_signature
            .clone()
            .unwrap_or_else(|| attack.victim.signature.clone());
        let mev_type = attack.attack_type.unwrap_or(AttackType::Sandwich);
        let severity = attack.severity.unwrap_or(Severity::Low);
        let loss_confidence = attack
            .confidence_level
            .unwrap_or_else(|| ConfidenceLevel::from_score(attack.confidence.unwrap_or(0.0)));

        // Vigil wants both sides of the swap pair. Today only the non-quote
        // side is tracked on `SwapEvent`; the quote side stays `None` until
        // parser-level enrichment exposes the pair.
        let (token_in_mint, token_out_mint) = match attack.victim.direction {
            SwapDirection::Buy => (None, Some(attack.victim.token_mint.clone())),
            SwapDirection::Sell => (Some(attack.victim.token_mint.clone()), None),
        };

        Self {
            victim_tx_signature: attack.victim.signature.clone(),
            attack_signature,
            timestamp_ms: attack.timestamp_ms,
            victim_wallet: attack.victim.signer.clone(),
            victim_action: attack.victim.direction,
            victim_dex: attack.victim.dex,
            token_in_mint,
            token_out_mint,
            amount_in: attack.victim.amount_in,
            expected_amount_out,
            actual_amount_out,
            slippage,
            mev_detected: true,
            mev_type,
            severity,
            loss_amount: attack.victim_loss_lamports,
            loss_amount_lower: attack.victim_loss_lamports_lower,
            loss_amount_upper: attack.victim_loss_lamports_upper,
            loss_percent,
            loss_confidence,
            validator_identity: attack.slot_leader.clone(),
        }
    }
}

/// Jito bundle relationship of a sandwich triplet.
///
/// Determines confidence: `AtomicBundle` ≈ 100%, `Organic` needs economic proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
    /// Naive profit estimate (quote token, smallest unit): `backrun.amount_out - frontrun.amount_in`.
    /// Wrong for multi-token pairs and doesn't account for price-impact dynamics.
    /// Kept for backwards compatibility with rule-based consumers; prefer `attacker_profit`.
    pub estimated_attacker_profit: Option<i64>,
    /// AMM-correct victim loss in the quote-token smallest unit: the difference between
    /// what the victim would have received without the frontrun and what they actually got.
    /// Populated by `pool-state` enrichment when a [`PoolStateLookup`](../../pool-state)
    /// is available; `None` if pool state couldn't be resolved.
    /// Mirrors Vigil `mev_attack.victim_loss_lamports`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub victim_loss_lamports: Option<i64>,
    /// Lower bound of the victim-loss confidence interval (Tier 3.3),
    /// in the same quote-token smallest unit as `victim_loss_lamports`.
    /// Width is derived from the worst per-step model/parser disagreement
    /// (`Signal::InvariantResidual`); both bounds are `None` when
    /// observations are missing on every step or the residual is
    /// pathological (≥100%). Pairs with `victim_loss_lamports_upper` —
    /// emit either both or neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub victim_loss_lamports_lower: Option<i64>,
    /// Upper bound of the victim-loss confidence interval. See
    /// `victim_loss_lamports_lower` for the derivation and pairing rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub victim_loss_lamports_upper: Option<i64>,
    /// AMM-correct attacker gross profit via counterfactual replay. Populated alongside
    /// `victim_loss_lamports`. Can differ significantly from `estimated_attacker_profit`
    /// — the re-classification from "naive profitable" to "AMM unprofitable" is the
    /// signal that distinguishes real extraction from false positives.
    /// Mirrors Vigil `mev_attack.attacker_profit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attacker_profit: Option<i64>,
    /// Price impact of the frontrun in basis points (|Δprice| / price_before × 10_000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_impact_bps: Option<u32>,
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
    /// Structured reasoning trace. Each emitted detection carries the set of
    /// orthogonal signals that fired, so a reader can independently verify why
    /// we flagged the triplet. `None` on attacks emitted before evidence wiring
    /// (maintains JSONL backwards compatibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<DetectionEvidence>,
    /// Snapshot of the AMM replay used to compute `victim_loss_lamports` /
    /// `attacker_profit`. Exposed so readers can recompute victim loss
    /// themselves from the raw pool arithmetic. `None` when pool-state
    /// enrichment didn't run or the DEX isn't supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amm_replay: Option<AmmReplayTrace>,
    /// Whirlpool-specific replay trace — populated only when `dex` is
    /// `OrcaWhirlpool` and pool-state enrichment ran successfully.
    /// Mirrors [`AmmReplayTrace`] in spirit: lets a reader recompute
    /// victim loss / attacker profit from the raw concentrated-liquidity
    /// arithmetic. Distinct field rather than an enum so the existing
    /// `amm_replay` shape stays backward-compatible for ConstantProduct
    /// consumers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub whirlpool_replay: Option<WhirlpoolReplayTrace>,

    // -- Vigil-aligned fields (schema `vigil-v1`) ----------------------------
    // Additive; populated by callers via [`SandwichAttack::finalize_for_vigil`]
    // or set explicitly. Defaulted/skip-on-None so legacy JSONL still
    // round-trips.
    /// Canonical attack signature mirrored to Vigil's `mev_attack.signature`.
    /// Today set to the victim tx signature so per-victim receipts can FK by
    /// `attack_signature`. `None` on records emitted before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_signature: Option<String>,
    /// Block timestamp in milliseconds since epoch (Vigil `mev_attack.timestamp_ms`).
    /// Populated when the upstream block source reports `block_time`; `None`
    /// for synthetic test fixtures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<i64>,
    /// Stable attack-type taxonomy (Vigil `mev_attack.type`). `None` on records
    /// predating this enum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_type: Option<AttackType>,
    /// Vigil-style severity bucket. Derivation requires pool-reserve context
    /// the caller has at enrichment time, so this is set externally rather
    /// than by `finalize_for_vigil`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Text bucket of `confidence` (Vigil `mev_receipt.loss_confidence`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_level: Option<ConfidenceLevel>,
    /// Slot leader at the victim's slot (Vigil `validator_identity`). `None`
    /// until Tier 2 enrichment lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_leader: Option<String>,
    /// `true` when the frontrun and backrun are separated by intervening txs
    /// (`tx_index` gap > 1) or by more than one slot. Mirrors Vigil's
    /// `sandwich_detail.is_wide_sandwich`. Defaults to `false` on legacy records.
    #[serde(default)]
    pub is_wide_sandwich: bool,
    /// Per-victim receipt projection for Vigil's `mev_receipt` table. Today a
    /// single attack maps to one receipt; `Vec` shape allows wide-sandwich
    /// variants with multiple victims to fan out without changing the schema.
    /// Empty on legacy records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<MevReceipt>,

    // -- Vigil ERD-level projections of nested victim/replay data ----------
    // Promoted to top-level so Vigil BE can `prisma.mevAttack.create({data: row})`
    // without a mapping layer. Populated by `finalize_for_vigil()` from the
    // nested `victim` SwapEvent and `amm_replay` trace. All `Option` so legacy
    // records and pre-finalize structs still serialize.
    /// Mirrors Vigil `mev_attack.victim_signer`. Promoted from `victim.signer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub victim_signer: Option<String>,
    /// Mirrors Vigil `mev_attack.victim_amount_in`. Promoted from `victim.amount_in`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub victim_amount_in: Option<u64>,
    /// Mirrors Vigil `mev_attack.victim_amount_out`. Promoted from `victim.amount_out`
    /// (what the victim actually received).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub victim_amount_out: Option<u64>,
    /// Mirrors Vigil `mev_attack.victim_amount_out_expected`. Promoted from
    /// `amm_replay.counterfactual_victim_out` — what the victim would have
    /// received without the frontrun. `None` when AMM replay didn't run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub victim_amount_out_expected: Option<u64>,
}

impl SandwichAttack {
    /// Compute `is_wide_sandwich` from the current frontrun/victim/backrun
    /// positions: any tx-index gap > 1, or any backrun_slot/frontrun_slot
    /// differing from `slot`, marks the detection as wide.
    pub fn compute_is_wide(&self) -> bool {
        let front_gap = self.victim.tx_index.saturating_sub(self.frontrun.tx_index);
        let back_gap = self.backrun.tx_index.saturating_sub(self.victim.tx_index);
        let cross_slot = self.frontrun_slot.is_some_and(|fs| fs != self.slot)
            || self.backrun_slot.is_some_and(|bs| bs != self.slot);
        front_gap > 1 || back_gap > 1 || cross_slot
    }

    /// Populate Vigil-aligned derived fields from data this struct already
    /// carries: `attack_signature`, `attack_type`, `is_wide_sandwich`,
    /// `confidence_level`, and `receipts`. Idempotent — fields that are
    /// already set are left untouched (so callers can pre-fill specific
    /// values, e.g. a non-default `attack_type`, before finalizing).
    ///
    /// `severity` is intentionally not derived here because it requires
    /// pool-reserve context the caller holds at enrichment time.
    pub fn finalize_for_vigil(&mut self) {
        if self.attack_signature.is_none() {
            self.attack_signature = Some(self.victim.signature.clone());
        }
        // Always recompute is_wide_sandwich from current positions so a
        // partially-populated struct doesn't disagree with itself.
        self.is_wide_sandwich = self.compute_is_wide();
        if self.attack_type.is_none() {
            // Authority-Hop wins over Wide / Sandwich because it's more
            // specific: it tells you the attacker swapped wallets between
            // the frontrun and backrun. The downstream consumer can still
            // see `is_wide_sandwich = true` if the gap was wide.
            let has_authority_hop = self.evidence.as_ref().is_some_and(|ev| {
                ev.passing
                    .iter()
                    .any(|s| matches!(s, Signal::AuthorityChain { .. }))
            });
            self.attack_type = Some(if has_authority_hop {
                AttackType::AuthorityHop
            } else if self.is_wide_sandwich {
                AttackType::WideSandwich
            } else {
                AttackType::Sandwich
            });
        }
        if self.confidence_level.is_none() {
            if let Some(score) = self.confidence {
                self.confidence_level = Some(ConfidenceLevel::from_score(score));
            }
        }
        // Promote nested victim/replay data to top-level Vigil ERD columns.
        // Always overwrite — the nested structs are the source of truth.
        self.victim_signer = Some(self.victim.signer.clone());
        self.victim_amount_in = Some(self.victim.amount_in);
        self.victim_amount_out = Some(self.victim.amount_out);
        self.victim_amount_out_expected = self
            .amm_replay
            .as_ref()
            .map(|r| r.counterfactual_victim_out);
        // Receipt projection runs last so it sees the populated fields above.
        self.receipts = vec![MevReceipt::from_attack(self)];
    }
}

// ---------------------------------------------------------------------------
// Ensemble evidence: structured reasoning attached to every emitted detection.
// ---------------------------------------------------------------------------

/// One of the orthogonal signals considered when scoring a candidate sandwich.
///
/// Each variant carries the raw evidence value so a reader can judge the call
/// without re-running the detector. Signals are grouped into [`SignalCategory`]
/// for ensemble-agreement counting — a detection that "fires" across more
/// independent categories is more credible than one that scores highly in a
/// single category.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Signal {
    // --- structural ----------------------------------------------------
    /// Victim tx is tightly sandwiched between frontrun and backrun in tx order.
    OrderingTight { front_gap: usize, back_gap: usize },

    // --- temporal ------------------------------------------------------
    /// All three txs landed in the same slot.
    SameBlock,
    /// Cross-slot sandwich; `slot_distance = backrun_slot - frontrun_slot`.
    CrossSlot { slot_distance: u64 },

    // --- provenance ----------------------------------------------------
    /// Jito bundle membership of the triplet, plus the raw bundle id if known.
    Bundle {
        provenance: BundleProvenance,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bundle_id: Option<String>,
    },

    // --- economic ------------------------------------------------------
    /// Naive (same-token) profit decomposition: gross revenue, estimated cost, net.
    NaiveProfit { gross: i64, cost: i64, net: i64 },
    /// AMM-correct attacker profit from pool-state replay.
    AmmProfit { attacker_profit_real: i64 },
    /// Counterfactual victim loss and frontrun price impact from AMM replay.
    VictimLoss { lamports: i64, impact_bps: u32 },
    /// `1 - (actual_victim_out / counterfactual_victim_out)`, clamped to [0, 1].
    /// A value near 1.0 means the victim received almost nothing relative to the
    /// counterfactual — strong AMM-replay evidence of extraction.
    ReplayConfidence { value: f64 },

    // --- plausibility --------------------------------------------------
    /// Ratio of `victim.amount_in / frontrun.amount_in`. Higher is more plausible
    /// (victim is economically meaningful relative to the attacker's position).
    VictimSize { ratio: f64 },
    /// Whether the victim signer appears in the known-attacker list (attacker-on-
    /// attacker detections are almost always false positives).
    KnownAttackerVictim { is_known: bool },
    /// Identity-linkage evidence: an SPL Token `SetAuthority` instruction
    /// transferred control of an account from `from` to `to` within the
    /// victim's window. Used by the Authority-Hop heuristic to fuse a
    /// frontrun signed by `from` with a backrun signed by `to` even though
    /// the two wallets look unrelated. `authority_tx` is the signature of
    /// the tx that carried the SetAuthority — the reader can replay it to
    /// audit the link.
    AuthorityChain {
        from: String,
        to: String,
        authority_tx: String,
    },

    /// Per-step model fidelity check (Tier 3.2). Compares what our AMM
    /// `apply_swap` would predict for `step`'s output, given the reserves
    /// we used at that point in the replay, against `SwapEvent.amount_out`
    /// extracted from chain logs. `residual_bps = (predicted - observed) /
    /// observed × 10_000`, signed.
    ///
    /// Near-zero residual means our reserve reconstruction and constant-
    /// product math agree with the chain's outcome — downstream replay
    /// numbers (`AmmProfit`, `VictimLoss`, `ReplayConfidence`) are trust-
    /// worthy. Large |residual| means we missed something (wrong pre-state,
    /// non-AMM CPI inside the tx, or a DEX whose math we don't model
    /// correctly) and the replay-derived figures should be discounted.
    /// Routed to the Economic category so a Fail here weighs against the
    /// other replay signals.
    InvariantResidual { step: ReplayStep, residual_bps: i32 },

    /// Counterfactual attacker outcome (Tier 3.5): what the attacker would
    /// have netted if the victim's tx had not happened. Computed by replaying
    /// `frontrun → backrun` directly on the post-frontrun pool, skipping the
    /// victim. Both values are in quote-token smallest units, normalised the
    /// same way as `attacker_profit`.
    ///
    /// A pure sandwich *needs* the victim to extract value, so the canonical
    /// shape is `with_victim > 0` and `without_victim ≤ 0`. When
    /// `without_victim` is also strongly positive, the candidate is more
    /// likely an arbitrage that happened to bracket an unrelated swap — the
    /// signal Fails so the ensemble downweights it.
    CounterfactualAttackerProfit {
        with_victim: i64,
        without_victim: i64,
    },

    /// End-state model-vs-chain check (Tier 3.1). Compares
    /// `amm_replay.reserves_post_back` (what our replay says the pool's
    /// vaults should hold after the backrun) against the chain's actual
    /// post-backrun vault balances, taken from the backrun tx's
    /// `post_token_balances`. `divergence_bps` is the larger of the two
    /// side-wise relative deltas (base, quote), expressed in basis points.
    ///
    /// This is the headline self-proof for the replay engine: where
    /// `InvariantResidual` checks each step against parser-observed
    /// `amount_out`, this checks the *final* reconstructed pool state
    /// against on-chain ground truth. A small divergence is positive
    /// confirmation that every reserves transition we computed lined up with
    /// the chain — which means the upstream `victim_loss` /
    /// `attacker_profit_real` numbers can be trusted at face value. A large
    /// divergence indicates we missed an instruction (rebalance, fee
    /// withdrawal, multi-hop CPI) and the replay-derived figures should be
    /// discounted. Routed to the Economic category. Pass on its own isn't
    /// evidence *for* a sandwich — that comes from the AMM-replay signals —
    /// so this signal only votes Fail (or Informational) per the
    /// `InvariantResidual` precedent.
    ReservesMatchPostState { divergence_bps: u32, passed: bool },
}

/// Replay step where an [`Signal::InvariantResidual`] was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStep {
    Frontrun,
    Victim,
    Backrun,
}

/// Grouping used for ensemble-agreement counting. A detection "fires" in a
/// category when at least one signal in that category has a Pass verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignalCategory {
    Structural,
    Temporal,
    Provenance,
    Economic,
    Plausibility,
}

/// Number of distinct categories the ensemble considers. Used as the
/// denominator for `ensemble_agreement`.
pub const ENSEMBLE_CATEGORY_COUNT: u8 = 5;

/// Whether a signal supports, contradicts, or is neutral about the detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignalVerdict {
    /// Signal is evidence *for* the sandwich call.
    Pass,
    /// Signal was computed and points *against* the call. Only surfaced in
    /// `--evidence-mode full`; detections are still emitted if `confidence`
    /// passes the existing gate.
    Fail,
    /// Signal is neutral context (e.g. slot distance, AMM intermediate values)
    /// that helps interpretation but doesn't vote.
    Informational,
}

impl Signal {
    /// Which ensemble category this signal contributes to.
    pub fn category(&self) -> SignalCategory {
        match self {
            Signal::OrderingTight { .. } => SignalCategory::Structural,
            Signal::SameBlock | Signal::CrossSlot { .. } => SignalCategory::Temporal,
            Signal::Bundle { .. } => SignalCategory::Provenance,
            Signal::NaiveProfit { .. }
            | Signal::AmmProfit { .. }
            | Signal::VictimLoss { .. }
            | Signal::ReplayConfidence { .. }
            | Signal::InvariantResidual { .. }
            | Signal::ReservesMatchPostState { .. } => SignalCategory::Economic,
            Signal::VictimSize { .. }
            | Signal::KnownAttackerVictim { .. }
            | Signal::AuthorityChain { .. }
            | Signal::CounterfactualAttackerProfit { .. } => SignalCategory::Plausibility,
        }
    }

    /// Pass/fail/informational classification. Thresholds here are the ones
    /// used for ensemble agreement; they are intentionally conservative so
    /// a signal firing Pass is meaningful on its own.
    pub fn verdict(&self) -> SignalVerdict {
        match *self {
            // Structural
            Signal::OrderingTight {
                front_gap,
                back_gap,
            } => {
                if front_gap <= 2 && back_gap <= 2 {
                    SignalVerdict::Pass
                } else {
                    SignalVerdict::Fail
                }
            }
            // Temporal
            Signal::SameBlock => SignalVerdict::Pass,
            Signal::CrossSlot { slot_distance } => {
                // Same-slot is SameBlock; window-detected cross-slot within a
                // reasonable window is still Pass. Detectors only emit within
                // `window_size` so this will be <= window_size in practice.
                if slot_distance > 0 {
                    SignalVerdict::Pass
                } else {
                    SignalVerdict::Informational
                }
            }
            // Provenance — Organic carries no positive evidence on its own.
            Signal::Bundle { provenance, .. } => match provenance {
                BundleProvenance::AtomicBundle
                | BundleProvenance::SpanningBundle
                | BundleProvenance::TipRace => SignalVerdict::Pass,
                BundleProvenance::Organic => SignalVerdict::Informational,
            },
            // Economic
            Signal::NaiveProfit { net, .. } => {
                if net > 0 {
                    SignalVerdict::Pass
                } else {
                    SignalVerdict::Fail
                }
            }
            Signal::AmmProfit {
                attacker_profit_real,
            } => {
                if attacker_profit_real > 0 {
                    SignalVerdict::Pass
                } else {
                    SignalVerdict::Fail
                }
            }
            Signal::VictimLoss { lamports, .. } => {
                if lamports > 0 {
                    SignalVerdict::Pass
                } else {
                    SignalVerdict::Fail
                }
            }
            Signal::ReplayConfidence { value } => {
                // A 5 bps shortfall is already meaningful for large trades.
                if value >= 0.0005 {
                    SignalVerdict::Pass
                } else {
                    SignalVerdict::Informational
                }
            }
            // Plausibility
            Signal::VictimSize { ratio } => {
                if ratio >= 0.01 {
                    SignalVerdict::Pass
                } else {
                    SignalVerdict::Fail
                }
            }
            Signal::KnownAttackerVictim { is_known } => {
                if is_known {
                    SignalVerdict::Fail
                } else {
                    SignalVerdict::Pass
                }
            }
            // The presence of an A→B authority hop is itself the evidence —
            // detector wouldn't emit this signal unless the hop ties the
            // frontrun to the backrun, so it's always a positive vote.
            Signal::AuthorityChain { .. } => SignalVerdict::Pass,

            // Model fidelity: small residual is just context (replay is
            // trustworthy); large residual is a Fail because the AMM-replay
            // numbers downstream may be wrong. Faithful math on its own
            // isn't evidence *for* a sandwich, so Pass isn't an outcome
            // here — Pass on a sandwich call comes from the AMM-replay
            // signals themselves (AmmProfit, VictimLoss).
            Signal::InvariantResidual { residual_bps, .. } => {
                if residual_bps.unsigned_abs() < 100 {
                    SignalVerdict::Informational
                } else {
                    SignalVerdict::Fail
                }
            }

            // Sandwich shape check.
            //   - Profitable only with the victim → Pass (clean MEV).
            //   - Profitable even without the victim by ≥ 50% of the with-
            //     victim haul → Fail (arbitrage masquerading as a sandwich,
            //     victim was incidental).
            //   - Anything else (e.g. unprofitable both ways, or a marginal
            //     mix) → Informational; the rest of the ensemble decides.
            Signal::CounterfactualAttackerProfit {
                with_victim,
                without_victim,
            } => {
                if with_victim > 0 && without_victim <= 0 {
                    SignalVerdict::Pass
                } else if without_victim > 0
                    && with_victim > 0
                    && without_victim.saturating_mul(2) >= with_victim
                {
                    SignalVerdict::Fail
                } else {
                    SignalVerdict::Informational
                }
            }

            // End-state model fidelity. `passed` is the precomputed verdict
            // (divergence_bps < threshold). Pass-as-vote isn't an outcome
            // here — same rationale as InvariantResidual: faithful math is
            // not evidence *for* a sandwich, only a guarantee that the
            // replay numbers are trustworthy. Big divergence flips to Fail
            // so a downstream consumer doesn't quote a victim_loss the
            // model couldn't reproduce.
            Signal::ReservesMatchPostState { passed, .. } => {
                if passed {
                    SignalVerdict::Informational
                } else {
                    SignalVerdict::Fail
                }
            }
        }
    }
}

/// Structured trace of everything the detector considered for one detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct DetectionEvidence {
    /// Signals whose verdict was Pass.
    pub passing: Vec<Signal>,
    /// Signals whose verdict was Fail. Empty by default — populated only when
    /// `--evidence-mode full` is set on the CLI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failing: Vec<Signal>,
    /// Signals classified as Informational (context, not a vote).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub informational: Vec<Signal>,
    /// Fraction of ensemble categories with at least one passing signal,
    /// in `[0.0, 1.0]`. Denominator is [`ENSEMBLE_CATEGORY_COUNT`].
    pub ensemble_agreement: f64,
    /// Integer companion to `ensemble_agreement` — `categories_with_pass` count.
    /// Easier to quote in prose ("4 of 5 signals fired").
    pub categories_fired: u8,
}

impl DetectionEvidence {
    /// Build from a flat list of signals. Routes each by its verdict, then
    /// computes `categories_fired` / `ensemble_agreement` from the passing set.
    pub fn from_signals(signals: Vec<Signal>) -> Self {
        let mut passing = Vec::new();
        let mut failing = Vec::new();
        let mut informational = Vec::new();
        for s in signals {
            match s.verdict() {
                SignalVerdict::Pass => passing.push(s),
                SignalVerdict::Fail => failing.push(s),
                SignalVerdict::Informational => informational.push(s),
            }
        }
        let mut cats = std::collections::HashSet::new();
        for s in &passing {
            cats.insert(s.category());
        }
        let categories_fired = cats.len() as u8;
        let ensemble_agreement = categories_fired as f64 / ENSEMBLE_CATEGORY_COUNT as f64;
        Self {
            passing,
            failing,
            informational,
            ensemble_agreement,
            categories_fired,
        }
    }

    /// Append additional signals (typically produced later in the pipeline,
    /// e.g. pool-state enrichment). Recomputes `categories_fired` /
    /// `ensemble_agreement`.
    pub fn extend(&mut self, signals: impl IntoIterator<Item = Signal>) {
        for s in signals {
            match s.verdict() {
                SignalVerdict::Pass => self.passing.push(s),
                SignalVerdict::Fail => self.failing.push(s),
                SignalVerdict::Informational => self.informational.push(s),
            }
        }
        let mut cats = std::collections::HashSet::new();
        for s in &self.passing {
            cats.insert(s.category());
        }
        self.categories_fired = cats.len() as u8;
        self.ensemble_agreement = self.categories_fired as f64 / ENSEMBLE_CATEGORY_COUNT as f64;
    }
}

/// Snapshot of the AMM replay used to compute victim loss / attacker profit.
///
/// Exposed on `SandwichAttack` so a reader can recompute victim loss from the
/// raw pool arithmetic using only these fields (reserves at each step + fee).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AmmReplayTrace {
    /// (base, quote) reserves immediately before the frontrun.
    pub reserves_pre: (u64, u64),
    /// Reserves after the frontrun, before the victim.
    pub reserves_post_front: (u64, u64),
    /// Reserves after the victim, before the backrun.
    pub reserves_post_victim: (u64, u64),
    /// Reserves after the backrun (end of the triplet).
    pub reserves_post_back: (u64, u64),
    /// Spot price (quote/base) before the frontrun.
    pub spot_price_pre: f64,
    /// Spot price after the frontrun — used for `price_impact_bps`.
    pub spot_price_post_front: f64,
    /// What the victim would have received if the frontrun hadn't happened.
    pub counterfactual_victim_out: u64,
    /// What the victim actually received.
    pub actual_victim_out: u64,
    /// Numerator of the pool's constant-product fee (e.g. 25 for 25bps).
    pub fee_num: u32,
    /// Denominator of the pool's fee (e.g. 10000).
    pub fee_den: u32,
}

/// Whirlpool (concentrated-liquidity) replay trace — the analogue of
/// [`AmmReplayTrace`] for the V3-style swap math added in Tier 3.4.
///
/// Surfaces the per-step sqrt_price / liquidity / tick the replay walked
/// through, so a reader can reconstruct the swap arithmetic the same way
/// `AmmReplayTrace` lets them re-derive constant-product victim_loss from
/// raw reserves.
///
/// `u128` fields (sqrt_price, liquidity) serialise as **base-10 decimal
/// strings** to preserve precision in JSON consumers — JS's `number` is
/// a 53-bit float and would lose information on values past `2^53`.
/// Q64.64 sqrt_prices sit around `2^64`, well past that. TS-side parsers
/// should use `BigInt(...)` to read these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WhirlpoolReplayTrace {
    /// Q64.64 sqrt(price) immediately before the frontrun.
    #[serde(with = "u128_string")]
    #[schemars(with = "String")]
    pub sqrt_price_pre: u128,
    /// Sqrt-price after the frontrun, before the victim.
    #[serde(with = "u128_string")]
    #[schemars(with = "String")]
    pub sqrt_price_post_front: u128,
    /// Sqrt-price after the victim, before the backrun.
    #[serde(with = "u128_string")]
    #[schemars(with = "String")]
    pub sqrt_price_post_victim: u128,
    /// Sqrt-price after the backrun (end of the triplet).
    #[serde(with = "u128_string")]
    #[schemars(with = "String")]
    pub sqrt_price_post_back: u128,

    /// Active liquidity at each step. Constant within one tick band, but
    /// changes when a leg's swap walks past an initialised tick boundary
    /// (LP positions activate / deactivate per V3 conventions).
    #[serde(with = "u128_string")]
    #[schemars(with = "String")]
    pub liquidity_pre: u128,
    #[serde(with = "u128_string")]
    #[schemars(with = "String")]
    pub liquidity_post_front: u128,
    #[serde(with = "u128_string")]
    #[schemars(with = "String")]
    pub liquidity_post_victim: u128,
    #[serde(with = "u128_string")]
    #[schemars(with = "String")]
    pub liquidity_post_back: u128,

    /// Tick (price bucket) at each step. `floor(log_{1.0001}(price))`.
    /// Fits in `i32` per Whirlpool's own layout; safe in JSON.
    pub tick_current_pre: i32,
    pub tick_current_post_front: i32,
    pub tick_current_post_victim: i32,
    pub tick_current_post_back: i32,

    /// What the victim would have received without the frontrun.
    pub counterfactual_victim_out: u64,
    /// What the victim actually received.
    pub actual_victim_out: u64,

    /// LP fee fraction. Whirlpool uses `fee_num` in hundredths-of-bps
    /// against `fee_den = 1_000_000` (e.g. `3000 / 1_000_000` = 30 bps).
    pub fee_num: u32,
    pub fee_den: u32,
}

/// Serde adapter that serialises a `u128` as a base-10 decimal string
/// rather than a JSON number, so JS consumers can `BigInt(...)` it
/// without losing precision past `2^53`. Only used by
/// [`WhirlpoolReplayTrace`] today.
mod u128_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<u128, D::Error> {
        let s = String::deserialize(de)?;
        s.parse::<u128>().map_err(serde::de::Error::custom)
    }
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

/// Token balance change for a single SPL token account.
#[derive(Debug, Clone)]
pub struct TokenBalanceChange {
    /// SPL Token mint.
    pub mint: String,
    /// Address of the SPL token account itself (the account whose balance changed).
    /// Used by pool-state enrichment to match against a pool's vault addresses,
    /// which are token account pubkeys — not to be confused with `owner`.
    pub account: String,
    /// Authority that owns the token account (e.g. the user's wallet for user
    /// balances, or the pool's authority PDA for vault balances).
    pub owner: String,
    pub pre_amount: u64,
    pub post_amount: u64,
}

impl TokenBalanceChange {
    /// Note: wraps if amounts exceed i64::MAX (~9.2e18). Rare for SPL tokens in practice.
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

#[cfg(test)]
mod evidence_tests {
    use super::*;

    #[test]
    fn ensemble_agreement_math() {
        // 3 distinct categories fire (Temporal, Economic, Plausibility) →
        // agreement = 3/5 = 0.60, categories_fired = 3.
        let signals = vec![
            Signal::SameBlock,
            Signal::NaiveProfit {
                gross: 100,
                cost: 10,
                net: 90,
            },
            Signal::VictimSize { ratio: 0.5 },
        ];
        let ev = DetectionEvidence::from_signals(signals);
        assert_eq!(ev.categories_fired, 3);
        assert!((ev.ensemble_agreement - 0.6).abs() < 1e-9);
        assert_eq!(ev.passing.len(), 3);
        assert!(ev.failing.is_empty());
        assert!(ev.informational.is_empty());
    }

    #[test]
    fn fail_verdicts_routed_separately() {
        // One passing, one failing, one informational.
        let signals = vec![
            Signal::SameBlock, // Pass (Temporal)
            Signal::NaiveProfit {
                gross: -50,
                cost: 10,
                net: -60, // Fail
            },
            Signal::Bundle {
                provenance: BundleProvenance::Organic, // Informational
                bundle_id: None,
            },
        ];
        let ev = DetectionEvidence::from_signals(signals);
        assert_eq!(ev.passing.len(), 1);
        assert_eq!(ev.failing.len(), 1);
        assert_eq!(ev.informational.len(), 1);
        assert_eq!(ev.categories_fired, 1); // only Temporal fired
    }

    #[test]
    fn agreement_counts_categories_not_signals() {
        // Two Economic signals both pass — still counts as ONE category firing.
        let signals = vec![
            Signal::NaiveProfit {
                gross: 100,
                cost: 0,
                net: 100,
            },
            Signal::AmmProfit {
                attacker_profit_real: 50,
            },
        ];
        let ev = DetectionEvidence::from_signals(signals);
        assert_eq!(ev.categories_fired, 1);
        assert!((ev.ensemble_agreement - 0.2).abs() < 1e-9);
    }

    #[test]
    fn extend_recomputes_agreement() {
        let mut ev = DetectionEvidence::from_signals(vec![Signal::SameBlock]);
        assert_eq!(ev.categories_fired, 1);

        ev.extend(vec![Signal::NaiveProfit {
            gross: 100,
            cost: 0,
            net: 100,
        }]);
        assert_eq!(ev.categories_fired, 2);
        assert!((ev.ensemble_agreement - 0.4).abs() < 1e-9);
    }

    #[test]
    fn stage1_jsonl_roundtrip() {
        // Build a fully-populated SandwichAttack (both evidence and amm_replay
        // present) and ensure it round-trips through JSON without field loss.
        let swap = |sig: &str, signer: &str, dir: SwapDirection| SwapEvent {
            signature: sig.into(),
            signer: signer.into(),
            dex: DexType::RaydiumV4,
            pool: "POOL".into(),
            direction: dir,
            token_mint: "MINT".into(),
            amount_in: 1_000_000,
            amount_out: 900_000,
            tx_index: 0,
            slot: Some(10),
            fee: Some(5000),
        };

        let evidence = DetectionEvidence::from_signals(vec![
            Signal::SameBlock,
            Signal::OrderingTight {
                front_gap: 1,
                back_gap: 1,
            },
            Signal::NaiveProfit {
                gross: 200,
                cost: 10,
                net: 190,
            },
            Signal::VictimSize { ratio: 0.4 },
            Signal::Bundle {
                provenance: BundleProvenance::AtomicBundle,
                bundle_id: Some("bundle-abc".into()),
            },
        ]);
        let replay = AmmReplayTrace {
            reserves_pre: (1_000, 1_000),
            reserves_post_front: (900, 1_100),
            reserves_post_victim: (850, 1_150),
            reserves_post_back: (1_000, 1_000),
            spot_price_pre: 1.0,
            spot_price_post_front: 1.22,
            counterfactual_victim_out: 100,
            actual_victim_out: 80,
            fee_num: 25,
            fee_den: 10_000,
        };

        let attack = SandwichAttack {
            slot: 10,
            attacker: "atk".into(),
            frontrun: swap("f", "atk", SwapDirection::Buy),
            victim: swap("v", "vic", SwapDirection::Buy),
            backrun: swap("b", "atk", SwapDirection::Sell),
            pool: "POOL".into(),
            dex: DexType::RaydiumV4,
            estimated_attacker_profit: Some(200),
            victim_loss_lamports: Some(20),
            victim_loss_lamports_lower: None,
            victim_loss_lamports_upper: None,
            attacker_profit: Some(150),
            price_impact_bps: Some(42),
            frontrun_slot: Some(10),
            backrun_slot: Some(10),
            detection_method: Some(DetectionMethod::SameBlock),
            bundle_provenance: Some(BundleProvenance::AtomicBundle),
            confidence: Some(0.88),
            net_profit: Some(190),
            evidence: Some(evidence),
            amm_replay: Some(replay),
            whirlpool_replay: None,
            attack_signature: None,
            timestamp_ms: None,
            attack_type: None,
            severity: None,
            confidence_level: None,
            slot_leader: None,
            is_wide_sandwich: false,
            receipts: vec![],
            victim_signer: None,
            victim_amount_in: None,
            victim_amount_out: None,
            victim_amount_out_expected: None,
        };

        let json = serde_json::to_string(&attack).unwrap();
        let back: SandwichAttack = serde_json::from_str(&json).unwrap();

        let ev_in = attack.evidence.as_ref().unwrap();
        let ev_out = back.evidence.as_ref().unwrap();
        assert_eq!(ev_in.passing.len(), ev_out.passing.len());
        assert_eq!(ev_in.categories_fired, ev_out.categories_fired);
        assert!((ev_in.ensemble_agreement - ev_out.ensemble_agreement).abs() < 1e-9);
        assert_eq!(
            attack.amm_replay.unwrap().reserves_pre,
            back.amm_replay.unwrap().reserves_pre,
        );
    }
}

#[cfg(test)]
mod vigil_schema_tests {
    //! Schema-contract tests for the `vigil-v1` output.
    //!
    //! These pin the JSONL shape Vigil's BE depends on: field names, the set
    //! of new keys this tier added, and the round-trip of every new field
    //! through serde. If any of these break, downstream Prisma persistence
    //! breaks too — bump `crate::SCHEMA_VERSION` before merging.

    use super::*;
    use serde_json::Value;

    fn swap(sig: &str, signer: &str, dir: SwapDirection, tx_index: usize) -> SwapEvent {
        SwapEvent {
            signature: sig.into(),
            signer: signer.into(),
            dex: DexType::RaydiumV4,
            pool: "POOL".into(),
            direction: dir,
            token_mint: "MINT".into(),
            amount_in: 1_000_000,
            amount_out: 900_000,
            tx_index,
            slot: Some(10),
            fee: Some(5_000),
        }
    }

    fn fresh_attack() -> SandwichAttack {
        SandwichAttack {
            slot: 10,
            attacker: "atk".into(),
            frontrun: swap("f", "atk", SwapDirection::Buy, 1),
            victim: swap("v", "vic", SwapDirection::Buy, 2),
            backrun: swap("b", "atk", SwapDirection::Sell, 3),
            pool: "POOL".into(),
            dex: DexType::RaydiumV4,
            estimated_attacker_profit: Some(100),
            victim_loss_lamports: Some(50),
            victim_loss_lamports_lower: None,
            victim_loss_lamports_upper: None,
            attacker_profit: Some(80),
            price_impact_bps: Some(42),
            frontrun_slot: Some(10),
            backrun_slot: Some(10),
            detection_method: Some(DetectionMethod::SameBlock),
            bundle_provenance: None,
            confidence: Some(0.85),
            net_profit: Some(95),
            evidence: None,
            amm_replay: Some(AmmReplayTrace {
                reserves_pre: (1_000, 1_000),
                reserves_post_front: (900, 1_100),
                reserves_post_victim: (850, 1_150),
                reserves_post_back: (1_000, 1_000),
                spot_price_pre: 1.0,
                spot_price_post_front: 1.22,
                counterfactual_victim_out: 100,
                actual_victim_out: 80,
                fee_num: 25,
                fee_den: 10_000,
            }),
            whirlpool_replay: None,
            attack_signature: None,
            timestamp_ms: None,
            attack_type: None,
            severity: None,
            confidence_level: None,
            slot_leader: None,
            is_wide_sandwich: false,
            receipts: vec![],
            victim_signer: None,
            victim_amount_in: None,
            victim_amount_out: None,
            victim_amount_out_expected: None,
        }
    }

    #[test]
    fn schema_version_constant_pinned() {
        // Vigil's BE matches on this exact string. Treat as a public contract.
        assert_eq!(crate::SCHEMA_VERSION, "vigil-v1");
    }

    #[test]
    fn severity_buckets_match_thresholds() {
        // Boundary values — losing 1% of pool depth is Critical, 0.1% High,
        // 0.01% Medium, anything below Low.
        assert_eq!(Severity::from_loss_ratio(0.0), Severity::Low);
        assert_eq!(Severity::from_loss_ratio(0.00009), Severity::Low);
        assert_eq!(Severity::from_loss_ratio(0.0001), Severity::Medium);
        assert_eq!(Severity::from_loss_ratio(0.001), Severity::High);
        assert_eq!(Severity::from_loss_ratio(0.01), Severity::Critical);
        assert_eq!(Severity::from_loss_ratio(0.5), Severity::Critical);
    }

    #[test]
    fn confidence_level_buckets_match_display_tiers() {
        // Display tiers: <0.5 Low, [0.5, 0.8) Medium, ≥0.8 High. Independent
        // of the emission gate; this is a UX bucket on already-emitted rows.
        assert_eq!(ConfidenceLevel::from_score(0.0), ConfidenceLevel::Low);
        assert_eq!(ConfidenceLevel::from_score(0.49), ConfidenceLevel::Low);
        assert_eq!(ConfidenceLevel::from_score(0.5), ConfidenceLevel::Medium);
        assert_eq!(ConfidenceLevel::from_score(0.79), ConfidenceLevel::Medium);
        assert_eq!(ConfidenceLevel::from_score(0.8), ConfidenceLevel::High);
        assert_eq!(ConfidenceLevel::from_score(1.0), ConfidenceLevel::High);
    }

    #[test]
    fn finalize_for_vigil_populates_derived_fields() {
        let mut attack = fresh_attack();
        attack.finalize_for_vigil();

        // attack_signature defaults to victim signature
        assert_eq!(attack.attack_signature.as_deref(), Some("v"));
        // contiguous tx_indices 1/2/3 → not wide
        assert!(!attack.is_wide_sandwich);
        assert_eq!(attack.attack_type, Some(AttackType::Sandwich));
        // confidence 0.85 → High
        assert_eq!(attack.confidence_level, Some(ConfidenceLevel::High));
        // exactly one receipt projected
        assert_eq!(attack.receipts.len(), 1);
        let r = &attack.receipts[0];
        assert_eq!(r.victim_tx_signature, "v");
        assert_eq!(r.attack_signature, "v");
        assert_eq!(r.victim_wallet, "vic");
        assert!(r.mev_detected);
        // amm_replay was populated, so receipt sees the counterfactual
        assert_eq!(r.expected_amount_out, Some(100));
        assert_eq!(r.actual_amount_out, 900_000);
        // Vigil ERD-aligned promoted fields are populated from nested data.
        assert_eq!(attack.victim_signer.as_deref(), Some("vic"));
        assert_eq!(attack.victim_amount_in, Some(1_000_000));
        assert_eq!(attack.victim_amount_out, Some(900_000));
        assert_eq!(attack.victim_amount_out_expected, Some(100));
    }

    #[test]
    fn finalize_for_vigil_flags_wide_sandwich_on_index_gap() {
        let mut attack = fresh_attack();
        attack.frontrun.tx_index = 0;
        attack.victim.tx_index = 5;
        attack.backrun.tx_index = 10;

        attack.finalize_for_vigil();

        assert!(attack.is_wide_sandwich);
        assert_eq!(attack.attack_type, Some(AttackType::WideSandwich));
    }

    #[test]
    fn finalize_for_vigil_flags_wide_sandwich_on_cross_slot() {
        let mut attack = fresh_attack();
        attack.frontrun_slot = Some(9);
        attack.backrun_slot = Some(11);

        attack.finalize_for_vigil();

        assert!(attack.is_wide_sandwich);
        assert_eq!(attack.attack_type, Some(AttackType::WideSandwich));
    }

    #[test]
    fn finalize_for_vigil_picks_authority_hop_over_wide_when_chain_signal_present() {
        // Authority-Hop heuristic: a Signal::AuthorityChain in passing
        // evidence overrides the default Sandwich/WideSandwich classification.
        // This is the integration contract between
        // `detector::authority_hop` and the emission path — promote rejected
        // wallet-mismatch candidates into AttackType::AuthorityHop.
        let mut attack = fresh_attack();
        attack.frontrun.tx_index = 0;
        attack.victim.tx_index = 5;
        attack.backrun.tx_index = 10; // wide gaps, but authority-hop wins.
        attack.evidence = Some(DetectionEvidence::from_signals(vec![
            Signal::SameBlock,
            Signal::AuthorityChain {
                from: "WALLET_A".into(),
                to: "WALLET_B".into(),
                authority_tx: "tx_hop_sig".into(),
            },
        ]));

        attack.finalize_for_vigil();

        assert_eq!(attack.attack_type, Some(AttackType::AuthorityHop));
        // is_wide_sandwich is still computed truthfully — readers can see
        // both attributes.
        assert!(attack.is_wide_sandwich);
    }

    #[test]
    fn finalize_for_vigil_falls_back_to_wide_when_no_chain_signal() {
        // Same wide layout but without the AuthorityChain signal — should
        // pick WideSandwich, the next-most-specific bucket.
        let mut attack = fresh_attack();
        attack.frontrun.tx_index = 0;
        attack.victim.tx_index = 5;
        attack.backrun.tx_index = 10;
        attack.evidence = Some(DetectionEvidence::from_signals(vec![Signal::SameBlock]));

        attack.finalize_for_vigil();

        assert_eq!(attack.attack_type, Some(AttackType::WideSandwich));
    }

    #[test]
    fn finalize_for_vigil_is_idempotent() {
        // Pre-set values must be preserved (caller-supplied attack_type, etc.).
        let mut attack = fresh_attack();
        attack.attack_signature = Some("custom-sig".into());
        attack.attack_type = Some(AttackType::AuthorityHop);
        attack.confidence_level = Some(ConfidenceLevel::Low);

        attack.finalize_for_vigil();

        assert_eq!(attack.attack_signature.as_deref(), Some("custom-sig"));
        assert_eq!(attack.attack_type, Some(AttackType::AuthorityHop));
        assert_eq!(attack.confidence_level, Some(ConfidenceLevel::Low));

        // Receipts are always rebuilt — calling twice should still leave one.
        attack.finalize_for_vigil();
        assert_eq!(attack.receipts.len(), 1);
    }

    #[test]
    fn vigil_v1_jsonl_round_trip_preserves_new_fields() {
        let mut attack = fresh_attack();
        attack.timestamp_ms = Some(1_700_000_000_000);
        attack.severity = Some(Severity::High);
        attack.slot_leader = Some("validator-pubkey".into());
        attack.finalize_for_vigil();

        let json = serde_json::to_string(&attack).expect("serialize");
        let back: SandwichAttack = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.attack_signature, attack.attack_signature);
        assert_eq!(back.timestamp_ms, attack.timestamp_ms);
        assert_eq!(back.attack_type, attack.attack_type);
        assert_eq!(back.severity, attack.severity);
        assert_eq!(back.confidence_level, attack.confidence_level);
        assert_eq!(back.slot_leader, attack.slot_leader);
        assert_eq!(back.is_wide_sandwich, attack.is_wide_sandwich);
        assert_eq!(back.receipts.len(), attack.receipts.len());
        let (r_in, r_out) = (&attack.receipts[0], &back.receipts[0]);
        assert_eq!(r_in.victim_tx_signature, r_out.victim_tx_signature);
        assert_eq!(r_in.severity, r_out.severity);
        assert_eq!(r_in.loss_confidence, r_out.loss_confidence);
        assert_eq!(r_in.validator_identity, r_out.validator_identity);
    }

    #[test]
    fn vigil_v1_emits_expected_top_level_keys() {
        let mut attack = fresh_attack();
        attack.severity = Some(Severity::Medium);
        attack.timestamp_ms = Some(123);
        attack.slot_leader = Some("leader".into());
        attack.finalize_for_vigil();

        let v: Value = serde_json::to_value(&attack).expect("to_value");
        let obj = v.as_object().expect("object");
        for key in [
            "attack_signature",
            "timestamp_ms",
            "attack_type",
            "severity",
            "confidence_level",
            "slot_leader",
            "is_wide_sandwich",
            "receipts",
            "victim_signer",
            "victim_amount_in",
            "victim_amount_out",
            "victim_amount_out_expected",
        ] {
            assert!(obj.contains_key(key), "missing top-level key: {key}");
        }
        // Receipts should serialize as an array of mev_receipt rows.
        let receipts = obj["receipts"].as_array().expect("receipts is array");
        assert_eq!(receipts.len(), 1);
        let r = &receipts[0];
        for key in [
            "victim_tx_signature",
            "attack_signature",
            "victim_wallet",
            "victim_action",
            "victim_dex",
            "amount_in",
            "actual_amount_out",
            "mev_detected",
            "mev_type",
            "severity",
            "loss_confidence",
        ] {
            assert!(
                r.get(key).is_some(),
                "missing receipt key: {key}, full: {r}"
            );
        }
    }

    #[test]
    fn legacy_jsonl_without_new_fields_still_deserializes() {
        // Construct a minimal JSON object with only pre-vigil-v1 fields and
        // verify it still parses (back-compat for old fixtures).
        let legacy = serde_json::json!({
            "slot": 1,
            "attacker": "a",
            "frontrun": {
                "signature": "f", "signer": "a",
                "dex": "raydium_v4", "pool": "p",
                "direction": "buy", "token_mint": "m",
                "amount_in": 1, "amount_out": 1,
                "tx_index": 0
            },
            "victim": {
                "signature": "v", "signer": "v",
                "dex": "raydium_v4", "pool": "p",
                "direction": "buy", "token_mint": "m",
                "amount_in": 1, "amount_out": 1,
                "tx_index": 1
            },
            "backrun": {
                "signature": "b", "signer": "a",
                "dex": "raydium_v4", "pool": "p",
                "direction": "sell", "token_mint": "m",
                "amount_in": 1, "amount_out": 1,
                "tx_index": 2
            },
            "pool": "p",
            "dex": "raydium_v4",
            "estimated_attacker_profit": null,
            "victim_loss_lamports": null
        });
        let attack: SandwichAttack =
            serde_json::from_value(legacy).expect("legacy json must still parse");
        assert!(attack.attack_signature.is_none());
        assert!(attack.attack_type.is_none());
        assert!(attack.receipts.is_empty());
        assert!(!attack.is_wide_sandwich);
    }

    // ----- Tier 3.2 — InvariantResidual -----------------------------------

    #[test]
    fn invariant_residual_verdict_thresholds() {
        // |residual_bps| < 100 (1%) → Informational (model agrees with chain).
        // |residual_bps| >= 100 → Fail (don't trust the AMM-replay numbers).
        // Pass is intentionally not an outcome — a faithful model alone is
        // not evidence *for* a sandwich, it's just context for the other
        // replay signals.
        for residual_bps in [-99, -1, 0, 1, 99] {
            let s = Signal::InvariantResidual {
                step: ReplayStep::Frontrun,
                residual_bps,
            };
            assert_eq!(
                s.verdict(),
                SignalVerdict::Informational,
                "small residual {residual_bps} should be informational",
            );
        }
        for residual_bps in [-101, -10_000, 100, 10_000] {
            let s = Signal::InvariantResidual {
                step: ReplayStep::Victim,
                residual_bps,
            };
            assert_eq!(
                s.verdict(),
                SignalVerdict::Fail,
                "large residual {residual_bps} should fail",
            );
        }
    }

    #[test]
    fn invariant_residual_category_is_economic() {
        let s = Signal::InvariantResidual {
            step: ReplayStep::Backrun,
            residual_bps: 0,
        };
        assert_eq!(s.category(), SignalCategory::Economic);
    }

    // ----- Tier 3.5 — CounterfactualAttackerProfit ------------------------

    #[test]
    fn counterfactual_attacker_clean_sandwich_passes() {
        // Profitable only with the victim — canonical sandwich shape.
        let s = Signal::CounterfactualAttackerProfit {
            with_victim: 1_000,
            without_victim: -50,
        };
        assert_eq!(s.verdict(), SignalVerdict::Pass);
        // Boundary: zero counterfactual (no profit, no loss) is still clean.
        let s = Signal::CounterfactualAttackerProfit {
            with_victim: 1_000,
            without_victim: 0,
        };
        assert_eq!(s.verdict(), SignalVerdict::Pass);
    }

    #[test]
    fn counterfactual_attacker_arbitrage_fails() {
        // Without-victim profit is at least half of with-victim → the victim
        // tx was incidental, this is arbitrage masquerading as a sandwich.
        let s = Signal::CounterfactualAttackerProfit {
            with_victim: 1_000,
            without_victim: 600,
        };
        assert_eq!(s.verdict(), SignalVerdict::Fail);
        // Boundary: exactly half qualifies as Fail.
        let s = Signal::CounterfactualAttackerProfit {
            with_victim: 1_000,
            without_victim: 500,
        };
        assert_eq!(s.verdict(), SignalVerdict::Fail);
    }

    #[test]
    fn counterfactual_attacker_marginal_is_informational() {
        // Less than half of with-victim — keeps quiet, lets the rest of the
        // ensemble decide. The signal is still emitted so a downstream
        // viewer can see the counterfactual numbers.
        let s = Signal::CounterfactualAttackerProfit {
            with_victim: 1_000,
            without_victim: 100,
        };
        assert_eq!(s.verdict(), SignalVerdict::Informational);
        // Both unprofitable — degenerate, no Pass evidence here either.
        let s = Signal::CounterfactualAttackerProfit {
            with_victim: -100,
            without_victim: -200,
        };
        assert_eq!(s.verdict(), SignalVerdict::Informational);
    }

    #[test]
    fn counterfactual_attacker_category_is_plausibility() {
        let s = Signal::CounterfactualAttackerProfit {
            with_victim: 0,
            without_victim: 0,
        };
        assert_eq!(s.category(), SignalCategory::Plausibility);
    }

    #[test]
    fn new_signal_variants_round_trip_through_json() {
        // Round-trip both new variants together as part of a flat Vec<Signal>
        // so we exercise the serde tagged-enum encoding the JSONL stream uses.
        let inputs = vec![
            Signal::InvariantResidual {
                step: ReplayStep::Frontrun,
                residual_bps: -42,
            },
            Signal::InvariantResidual {
                step: ReplayStep::Victim,
                residual_bps: 0,
            },
            Signal::InvariantResidual {
                step: ReplayStep::Backrun,
                residual_bps: 500,
            },
            Signal::CounterfactualAttackerProfit {
                with_victim: 1_234,
                without_victim: -7,
            },
        ];
        let json = serde_json::to_string(&inputs).expect("serialize");
        let back: Vec<Signal> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.len(), 4);
        // Spot-check by matching on each variant — `PartialEq` isn't derived
        // on `Signal` so equality is structural via match arms.
        match &back[0] {
            Signal::InvariantResidual {
                step: ReplayStep::Frontrun,
                residual_bps: -42,
            } => {}
            other => panic!("expected Frontrun residual -42, got {other:?}"),
        }
        match &back[3] {
            Signal::CounterfactualAttackerProfit {
                with_victim: 1_234,
                without_victim: -7,
            } => {}
            other => panic!("expected CounterfactualAttackerProfit, got {other:?}"),
        }
    }

    #[test]
    fn ensemble_routes_new_signals_through_economic_and_plausibility() {
        // Build a minimal evidence set and check categories_fired increments
        // appropriately when only the new signals are present.
        let ev = DetectionEvidence::from_signals(vec![
            Signal::InvariantResidual {
                step: ReplayStep::Frontrun,
                residual_bps: 5,
            }, // Informational — does not bump categories_fired
            Signal::CounterfactualAttackerProfit {
                with_victim: 100,
                without_victim: -10,
            }, // Pass → Plausibility fires
        ]);
        // Plausibility category should fire from the clean-sandwich Pass;
        // Economic does NOT fire because InvariantResidual is Informational.
        assert_eq!(ev.categories_fired, 1);
        assert_eq!(ev.passing.len(), 1);
        assert_eq!(ev.informational.len(), 1);
    }

    #[test]
    fn whirlpool_replay_trace_round_trips_with_string_u128_fields() {
        // u128 fields (sqrt_price, liquidity) serialise as base-10
        // strings. Round-trip pins both directions and the on-the-wire
        // shape Vigil's BE will see.
        let trace = WhirlpoolReplayTrace {
            sqrt_price_pre: 1u128 << 64,
            sqrt_price_post_front: (1u128 << 64) - 12_345,
            sqrt_price_post_victim: (1u128 << 64) - 23_456,
            sqrt_price_post_back: (1u128 << 64) - 1_000,
            liquidity_pre: 1_500_000_000,
            liquidity_post_front: 500_000_000,
            liquidity_post_victim: 500_000_000,
            liquidity_post_back: 1_500_000_000,
            tick_current_pre: 0,
            tick_current_post_front: -129,
            tick_current_post_victim: -150,
            tick_current_post_back: -1,
            counterfactual_victim_out: 100,
            actual_victim_out: 80,
            fee_num: 3_000,
            fee_den: 1_000_000,
        };
        let json = serde_json::to_string(&trace).expect("serialise");
        // sqrt_price = 1<<64 = 18_446_744_073_709_551_616 — past u53,
        // proves we serialise as string rather than JSON number.
        assert!(
            json.contains("\"sqrt_price_pre\":\"18446744073709551616\""),
            "u128 sqrt_price should serialise as a base-10 string, got: {json}",
        );
        assert!(
            json.contains("\"liquidity_pre\":\"1500000000\""),
            "u128 liquidity should serialise as a base-10 string, got: {json}",
        );
        // Round-trip back.
        let decoded: WhirlpoolReplayTrace = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(decoded, trace);
    }

    #[test]
    fn sandwich_attack_skips_whirlpool_replay_when_none() {
        // The new optional field is `skip_serializing_if = "Option::is_none"`
        // — legacy ConstantProduct attacks must round-trip unchanged in
        // shape (no rogue `whirlpool_replay: null` keys).
        let attack = fresh_attack();
        assert!(attack.whirlpool_replay.is_none());
        let json = serde_json::to_string(&attack).expect("serialise");
        assert!(
            !json.contains("whirlpool_replay"),
            "skip-on-None should keep the key out of the JSON; got: {json}",
        );
    }

    #[test]
    fn sandwich_attack_emits_whirlpool_replay_when_some() {
        let mut attack = fresh_attack();
        attack.dex = DexType::OrcaWhirlpool;
        attack.whirlpool_replay = Some(WhirlpoolReplayTrace {
            sqrt_price_pre: 1u128 << 64,
            sqrt_price_post_front: 1u128 << 63,
            sqrt_price_post_victim: 1u128 << 63,
            sqrt_price_post_back: 1u128 << 64,
            liquidity_pre: 1_000_000,
            liquidity_post_front: 1_000_000,
            liquidity_post_victim: 1_000_000,
            liquidity_post_back: 1_000_000,
            tick_current_pre: 0,
            tick_current_post_front: -1,
            tick_current_post_victim: -2,
            tick_current_post_back: 0,
            counterfactual_victim_out: 100,
            actual_victim_out: 80,
            fee_num: 3_000,
            fee_den: 1_000_000,
        });
        let json = serde_json::to_string(&attack).expect("serialise");
        let value: Value = serde_json::from_str(&json).expect("parse");
        let trace = value
            .get("whirlpool_replay")
            .expect("whirlpool_replay key present when Some");
        assert_eq!(
            trace["sqrt_price_pre"].as_str(),
            Some("18446744073709551616"),
        );
        assert_eq!(trace["tick_current_post_front"].as_i64(), Some(-1));
    }
}
