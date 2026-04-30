/**
 * TypeScript types matching sandwich-detector's JSON output.
 * Copy this into your downstream project (e.g., Vigil NestJS server).
 *
 * Schema version: vigil-v1 (matches `swap_events::SCHEMA_VERSION`).
 * Source of truth: crates/swap-events/src/types.rs and the JSON Schema at
 *                  crates/swap-events/schema/vigil-v1.json.
 *
 * The CLI emits a JSONL stream where each line is one of:
 *   - `JsonlHeader`     — first line, identifies the schema/tool version.
 *   - `JsonlHeartbeat`  — periodic liveness ping in `--follow` mode.
 *   - `SandwichAttack`  — one detection.
 *
 * Use `parseDetectorLine` to discriminate.
 */

// ---------------------------------------------------------------------------
// Framing — non-data lines emitted by the CLI alongside detections.
// ---------------------------------------------------------------------------

export interface JsonlHeader {
  _header: true;
  schema_version: "vigil-v1";
  tool_version: string;
  /** Detector wall-clock at startup, unix epoch ms. */
  started_at_ms: number;
}

export interface JsonlHeartbeat {
  /** Detector wall-clock unix epoch ms; emitted periodically in `--follow`. */
  _heartbeat: number;
}

export type DetectorLine = JsonlHeader | JsonlHeartbeat | SandwichAttack;

/** Discriminator helper. Throws if the line doesn't match a known shape. */
export function parseDetectorLine(raw: string): DetectorLine {
  const obj = JSON.parse(raw);
  if (obj && obj._header === true) return obj as JsonlHeader;
  if (obj && typeof obj._heartbeat === "number") return obj as JsonlHeartbeat;
  return obj as SandwichAttack;
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export type DexType =
  | "raydium_v4"
  | "raydium_clmm"
  | "raydium_cpmm"
  | "orca_whirlpool"
  | "jupiter_v6"
  | "meteora_dlmm"
  | "pump_fun"
  | "phoenix";

export type SwapDirection = "buy" | "sell";

export type AttackType = "sandwich" | "wide_sandwich" | "backrun" | "authority_hop";

export type Severity = "low" | "medium" | "high" | "critical";

export type ConfidenceLevel = "low" | "medium" | "high";

export type BundleProvenance =
  | "atomic_bundle"
  | "spanning_bundle"
  | "tip_race"
  | "organic";

export type SignalCategory =
  | "structural"
  | "temporal"
  | "provenance"
  | "economic"
  | "plausibility";

export type SignalVerdict = "pass" | "fail" | "informational";

export type DetectionMethod =
  | { same_block: Record<string, never> } // `"same_block"` in serde — see below
  | { cross_slot_window: { window_size: number } }
  | { jito_bundle_confirmed: { bundle_id: string } };
// NOTE: `serde(rename_all = "snake_case")` on a unit variant produces the bare
// string `"same_block"`, not a tagged object. The union above mixes string and
// object shapes; in practice a runtime check looks like:
//   typeof dm === "string" ? dm === "same_block" : "cross_slot_window" in dm

// ---------------------------------------------------------------------------
// Reasoning trace — Signal / DetectionEvidence
// ---------------------------------------------------------------------------

export type Signal =
  | { kind: "ordering_tight"; front_gap: number; back_gap: number }
  | { kind: "same_block" }
  | { kind: "cross_slot"; slot_distance: number }
  | { kind: "bundle"; provenance: BundleProvenance; bundle_id?: string | null }
  | { kind: "naive_profit"; gross: number; cost: number; net: number }
  | { kind: "amm_profit"; attacker_profit_real: number }
  | { kind: "victim_loss"; lamports: number; impact_bps: number }
  | { kind: "replay_confidence"; value: number }
  | { kind: "victim_size"; ratio: number }
  | { kind: "known_attacker_victim"; is_known: boolean }
  /**
   * Authority-Hop linkage: an SPL Token `SetAuthority` instruction transferred
   * an account from `from` to `to` inside the victim's window, fusing a
   * frontrun by `from` to a backrun by `to`. `authority_tx` is the audit
   * pointer back to the SetAuthority tx.
   */
  | { kind: "authority_chain"; from: string; to: string; authority_tx: string };

export interface DetectionEvidence {
  passing: Signal[];
  failing?: Signal[];
  informational?: Signal[];
  /** [0.0, 1.0] — fraction of ensemble categories that fired Pass. */
  ensemble_agreement: number;
  /** Companion to `ensemble_agreement`; categories with ≥1 Pass signal. */
  categories_fired: number;
}

// ---------------------------------------------------------------------------
// AMM replay trace — exposes the pool arithmetic backing the loss numbers.
// ---------------------------------------------------------------------------

export interface AmmReplayTrace {
  /** (base, quote) reserves before the frontrun. */
  reserves_pre: [number, number];
  reserves_post_front: [number, number];
  reserves_post_victim: [number, number];
  reserves_post_back: [number, number];
  spot_price_pre: number;
  spot_price_post_front: number;
  counterfactual_victim_out: number;
  actual_victim_out: number;
  fee_num: number;
  fee_den: number;
}

// ---------------------------------------------------------------------------
// Per-tx swap event (frontrun / victim / backrun)
// ---------------------------------------------------------------------------

export interface SwapEvent {
  signature: string;
  signer: string;
  dex: DexType;
  pool: string;
  direction: SwapDirection;
  token_mint: string;
  amount_in: number;
  amount_out: number;
  tx_index: number;
  /** Slot — `null` for same-block-only fixtures. */
  slot?: number | null;
  /** Transaction fee in lamports. `null` if unknown. */
  fee?: number | null;
}

// ---------------------------------------------------------------------------
// Per-victim receipt — Vigil `mev_receipt` row shape.
// ---------------------------------------------------------------------------

export interface MevReceipt {
  victim_tx_signature: string;
  /** FK to `mev_attack.signature` (= the parent attack's `attack_signature`). */
  attack_signature: string;
  timestamp_ms?: number | null;
  victim_wallet: string;
  victim_action: SwapDirection;
  victim_dex: DexType;
  token_in_mint?: string | null;
  token_out_mint?: string | null;
  amount_in: number;
  expected_amount_out?: number | null;
  actual_amount_out: number;
  /** `(expected − actual) / expected` in [0, 1]. `null` when expected unknown. */
  slippage?: number | null;
  /** Always `true` on emitted receipts; column reserved for negative receipts. */
  mev_detected: boolean;
  mev_type: AttackType;
  severity: Severity;
  /** Quote-token smallest units. `null` when AMM replay didn't run. */
  loss_amount?: number | null;
  loss_percent?: number | null;
  loss_confidence: ConfidenceLevel;
  /** Vigil `validator_identity` — slot leader at the victim's slot. */
  validator_identity?: string | null;
}

// ---------------------------------------------------------------------------
// Top-level detection — Vigil `mev_attack` + `sandwich_detail` row.
// ---------------------------------------------------------------------------

export interface SandwichAttack {
  slot: number;
  attacker: string;
  frontrun: SwapEvent;
  victim: SwapEvent;
  backrun: SwapEvent;
  pool: string;
  dex: DexType;

  // -- legacy / naive numbers (kept for rule-based consumers) --
  estimated_attacker_profit: number | null;

  // -- AMM-replay numbers (Vigil ERD `mev_attack.*`) --
  victim_loss_lamports?: number | null;
  attacker_profit?: number | null;
  price_impact_bps?: number | null;

  // -- triplet bookkeeping --
  frontrun_slot?: number | null;
  backrun_slot?: number | null;
  detection_method?: DetectionMethod | null;
  bundle_provenance?: BundleProvenance | null;
  confidence?: number | null;
  net_profit?: number | null;

  evidence?: DetectionEvidence | null;
  amm_replay?: AmmReplayTrace | null;

  // -- Vigil v1 — populated by `finalize_for_vigil()` --
  /** Canonical attack id (= victim signature today). FK target for receipts. */
  attack_signature?: string | null;
  /** Block timestamp in unix ms. `null` for synthetic fixtures. */
  timestamp_ms?: number | null;
  attack_type?: AttackType | null;
  severity?: Severity | null;
  confidence_level?: ConfidenceLevel | null;
  /** Slot leader at the victim's slot. `null` until Tier 2 enrichment lands. */
  slot_leader?: string | null;
  /** True when the triplet is non-contiguous (tx-index gap > 1) or cross-slot. */
  is_wide_sandwich: boolean;
  /** Per-victim projection — empty on legacy records. */
  receipts: MevReceipt[];

  // -- top-level promotions of nested data (Vigil ERD `mev_attack.*`) --
  victim_signer?: string | null;
  victim_amount_in?: number | null;
  victim_amount_out?: number | null;
  victim_amount_out_expected?: number | null;
}
