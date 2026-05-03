# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-03

**Phase 5 closure: 7 of 8 supported DEXes have AMM-replay enrichment, and the
detector is production-ready for 24/7 mainnet operation.**

### Added

- **Pump.fun enrichment** via virtual-reserve recovery from `TradeEvent` log
  emissions, including bonding-curve replay (#29).
- **Raydium CLMM enrichment** with within-tick replay using the V3 sqrt-price
  primitives shared with Orca Whirlpool (#31), and **cross-tick walk** backed
  by a `TickArrayState` parser and PDA helpers (#33).
- **Jupiter V6 dispatch** that resolves the underlying DEX from the Jupiter
  route and pivots single-hop swaps to the existing per-DEX replay path
  (multi-hop deferred) (#32).
- **Per-DEX `EnrichmentMetrics`** bucketing in the heartbeat JSON wire format,
  giving operators per-DEX visibility into enrichment success rate (#28).

### Changed

- `WhirlpoolReplayTrace` → `ClmmReplayTrace`, and `whirlpool_replay` →
  `clmm_replay`, generalising the V3 trace surface so Raydium CLMM and Orca
  Whirlpool share one schema (#30).
- README (en/ko/es) updated to reflect the 7/8 enriched matrix and the
  per-DEX heartbeat shape (#34).

### Fixed

- **Pump.fun `TradeEvent` extended payload (mainnet hotfix).** The on-chain
  program shipped a backwards-compatible upgrade that appended
  `real_sol_reserves`, `real_token_reserves`, and `fee_recipient`, growing the
  event from 113 to 298 bytes. The parser previously enforced
  `data.len() != 113` strict equality and rejected every new event, dropping
  enrichment to 0% on a live mainnet sample. The check is now
  `data.len() < TRADE_EVENT_LEN` plus field-shape guards (prefix-only decode),
  with a real-mainnet capture pinned as a regression fixture (#35).

### Deferred

- **Phoenix CLOB enrichment.** The 1k-slot mainnet sample showed Phoenix at
  19.4% of CPI traffic, but the activity is dominated by `place limit order`
  / `cancel` rather than taker `swap`. CLOB sandwich patterns (limit-order
  placement) do not match the frontrun/victim/backrun model the detector is
  built around, so closing the gap means new detection logic, not just an
  enrichment module. Phoenix retains detection-only coverage; the call will
  be revisited once 24/7 mainnet operation accumulates a larger sample.

### Operational notes

- All 7 enriched DEXes were validated end-to-end on a 1000-slot mainnet range
  (`417235145..417236145`, 2026-05-03 UTC) after the #35 hotfix: 3/3 detected
  Pump.fun sandwiches enriched, AMM-replay reclassification surfaced two
  cases where the rule-based engine called sandwich but the attacker actually
  lost SOL on the round-trip.
- Vigil integration contract (`vigil-v1`) and the per-DEX heartbeat key shape
  are stable as of this release; consumers can pin to `vigil-v1`.

## [0.1.0] and earlier — pre-2026-05-03

Pre-1.0 development is recorded in git history. High-level milestones:

- **Phase 1 — 8-DEX swap parsing + initial AMM replay.** Raydium V4 / CPMM,
  Orca Whirlpool (within-tick + cross-tick).
- **Phases 2–3 — DLMM enrichment + Tier 3 economic signals.** Meteora DLMM
  within-bin and cross-bin replay, including the bitmap-aware walker;
  per-step residual, end-state reserves-diff, and victim-loss confidence
  intervals.
- **Phase 4 — Operational hardening.** `balance-diff` CLI for parser-vs-RPC
  victim cross-check, `archival-diff` placeholder, `f64`-cast precision audit
  at ratio sites, DLMM iteration cap with active-id mirroring.

For step-by-step history, see `git log` and the merged PRs (#1 through #27).

[1.0.0]: https://github.com/SangHyeonKwon/solana-sandwich-detector/releases/tag/v1.0.0
