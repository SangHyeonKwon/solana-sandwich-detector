/**
 * TypeScript types matching sandwich-detector's JSON output.
 * Copy this into your downstream project (e.g., Vigil NestJS server).
 *
 * Generated from: crates/detector/src/types.rs
 */

export type DexType = "raydium_v4" | "orca_whirlpool" | "jupiter_v6";
export type SwapDirection = "buy" | "sell";

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
}

export interface SandwichAttack {
  slot: number;
  attacker: string;
  frontrun: SwapEvent;
  victim: SwapEvent;
  backrun: SwapEvent;
  pool: string;
  dex: DexType;
  estimated_attacker_profit: number | null;
  estimated_victim_loss: number | null;
}
