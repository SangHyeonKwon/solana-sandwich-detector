<p align="center">
  <h1 align="center">solana-sandwich-detector</h1>
  <p align="center">
    A Rust library for detecting same-block and cross-slot sandwich attacks on Solana.<br/>
    Parses swap events from 8 DEXes and identifies frontrun/victim/backrun patterns using sliding-window correlation and precision filters.
  </p>
</p>

<p align="center">
  <a href="https://github.com/SangHyeonKwon/solana-sandwich-detector/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/SangHyeonKwon/solana-sandwich-detector/ci.yml?style=for-the-badge&label=CI" alt="CI" /></a>
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/Solana-9945FF?style=for-the-badge&logo=solana&logoColor=white" alt="Solana" />
  <img src="https://img.shields.io/badge/Tokio-232323?style=for-the-badge&logo=rust&logoColor=white" alt="Tokio" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License" />
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#use-as-a-library">Library</a> &middot;
  <a href="#scope">Scope</a> &middot;
  <a href="#contributing">Contributing</a>
</p>

---

Sandwich attacks are the most common form of MEV exploitation on Solana. An attacker front-runs a victim's swap, pushes the price, and back-runs to profit -- within the same block or across nearby slots.

**solana-sandwich-detector** is a Rust library that turns a stream of Solana blocks into a stream of detected attacks. It supports **same-block detection** (classic single-slot pattern) and **cross-slot window detection** (attacks spanning multiple slots, with Jito bundle provenance, economic feasibility, and victim plausibility filters). A thin streaming CLI (`sandwich-detect`) and an evaluation framework (`sandwich-eval`) are shipped alongside.

> Used by [Vigil](https://github.com/EarthIsMine/Vigil-RPC) -- a Solana MEV transparency platform -- as the detection primitive. Validator scoring, persistence, alerting, and dashboards live in Vigil, not here. See [Scope](#scope).

### Supported DEXes

| DEX | Coverage |
|-----|----------|
| Raydium V4 | Direct swaps + CPI |
| Raydium CLMM | Direct swaps + CPI |
| Raydium CPMM | Direct swaps + CPI |
| Orca Whirlpool | Direct swaps + CPI |
| Jupiter V6 | Route-through (resolves underlying pool) |
| Meteora DLMM | Direct swaps + CPI |
| Pump.fun | Direct swaps + CPI |
| Phoenix | Direct swaps + CPI |

> Adding a new DEX takes ~50 lines. See [Contributing](#contributing).

---

## Quick Start

The repo ships with `sandwich-detect`, a thin streaming CLI that wraps the library -- useful for smoke-testing, ad-hoc analysis, and piping detections into other tools. For embedding in your own service, [use the library directly](#use-as-a-library).

```bash
# Build
cargo build --release

# Stream new blocks and print detected sandwiches as JSON lines
./target/release/sandwich-detect --rpc $RPC_URL --follow
```

Each detected sandwich prints as a JSON line to stdout:

```jsonc
{
  "slot": 285012345,
  "attacker": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
  "frontrun": {
    "signature": "4vJ9JU1b...",
    "dex": "raydium_v4",
    "direction": "buy",
    "amount_in": 5000000000,
    "amount_out": 128934512
  },
  "victim": {
    "signature": "3kPnR8xz...",
    "dex": "raydium_v4",
    "direction": "buy",
    "amount_in": 2000000000,
    "amount_out": 48201100
  },
  "backrun": {
    "signature": "5tYm2Wqp...",
    "dex": "raydium_v4",
    "direction": "sell",
    "amount_in": 128934512,
    "amount_out": 5127300000
  },
  "pool": "58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2",
  "dex": "raydium_v4"
}
```

Pipe it anywhere -- `jq`, a database, an alert system, your own dashboard.

### More examples

```bash
# Analyze a specific slot
sandwich-detect --rpc $RPC_URL --slot 285012345

# Scan a range of slots
sandwich-detect --rpc $RPC_URL --range 285012000-285012100

# Cross-slot detection with a 4-slot sliding window
sandwich-detect --rpc $RPC_URL --range 285012000-285012100 --window 4

# Pretty-print for humans
sandwich-detect --rpc $RPC_URL --follow --format pretty

# Scan a range and print an aggregate economics summary at the end
# (enrichment is on by default; pass --no-enrich to disable, --summary to
# emit the aggregate to stderr)
sandwich-detect --rpc $RPC_URL --range 285012000-285012100 --window 4 --summary
```

`RPC_URL` can be passed via `--rpc` flag or as an environment variable. Pool-state enrichment also uses that RPC by default; set `--pool-state $OTHER_URL` (or `POOL_STATE_RPC`) to route config fetches elsewhere.

---

## How It Works

### Same-block detection

```
Block (slot N)
 |
 +-- Parse transactions --> Extract swap events per DEX
 |                          (instruction accounts + token balance deltas)
 |
 +-- Group by pool
 |
 +-- Detect pattern:
      tx[i]  attacker BUYS   -+
      tx[j]  victim   BUYS    +-- same pool, same direction
      tx[k]  attacker SELLS  -+   opposite direction, same signer as tx[i]
```

### Cross-slot window detection

```
Slot N:    attacker BUYS in pool P   (frontrun)
Slot N+1:  victim BUYS in pool P     (same direction as frontrun)
Slot N+2:  attacker SELLS in pool P  (backrun -- opposite direction)
```

The cross-slot detector (`FilteredWindowDetector`) maintains a per-pool sliding window of W slots and applies three precision filters:

1. **Bundle provenance** -- Checks Jito bundle co-location (AtomicBundle > SpanningBundle > TipRace > Organic)
2. **Economic feasibility** -- `backrun.amount_out - frontrun.amount_in > tx fees`
3. **Victim plausibility** -- Size ratio check + known-attacker exclusion

Each detection gets a composite **confidence score** (0.0-1.0) weighted across these filters.

### Detection rules

| Condition | Why |
|-----------|-----|
| `frontrun.signer == backrun.signer` | Same attacker |
| `frontrun.direction != backrun.direction` | Opposite trades (buy then sell) |
| `victim.direction == frontrun.direction` | Victim pushes price further |
| `victim.signer != attacker` | Different wallet |
| Same pool | Price impact is local to the pool |
| Same slot (same-block) or within W slots (window) | Temporal proximity |

The detector uses a **hybrid parsing approach**: instruction discriminators identify the DEX program and pool address, while pre/post token balance changes determine swap direction and amounts. This is more robust than pure instruction decoding since it works even when instruction formats change.

### Victim loss measurement (AMM replay)

Rule-based detection answers *"was this a sandwich?"* but not *"how much did the victim lose?"* — the naive `backrun.amount_out - frontrun.amount_in` heuristic breaks for multi-token pairs and doesn't account for price-impact dynamics. The `pool-state` crate fixes both by replaying each swap through the AMM's math:

```
state_0  = pool reserves just before the frontrun  (from tx meta)
state_1  = state_0 after frontrun
state_2  = state_1 after victim
victim_actual_out   = what the victim received (via state_1)
victim_expected_out = what they would have received without the frontrun (via state_0)
victim_loss         = victim_expected_out - victim_actual_out
```

Reserves at each step come from the transaction's own `pre_token_balances` / `post_token_balances` — no historical RPC needed. Pool config (vault addresses, fee rate) is fetched once per pool via `getAccountInfo` and cached. Currently supported: **Raydium V4** and **Raydium CPMM** (constant-product). CLMM/Whirlpool tick math is a follow-up.

When enrichment succeeds, each `SandwichAttack` gets:

- `victim_loss_lamports` — AMM-correct, in the quote token's smallest unit (Vigil ERD `mev_attack.victim_loss_lamports`)
- `attacker_profit` — counterfactual attacker gross profit (Vigil ERD `mev_attack.attacker_profit`); differs from the naive `estimated_attacker_profit` when rule-based logic over-attributes
- `price_impact_bps` — frontrun-induced price shift in basis points

Attacks on unsupported DEXes pass through with these fields set to `None`.

---

## Use as a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
sandwich-detector = { git = "https://github.com/SangHyeonKwon/solana-sandwich-detector" }
```

### Same-block detection

```rust
use sandwich_detector::{detector, dex, source::{BlockSource, rpc::RpcBlockSource}};

let source = RpcBlockSource::new("https://api.mainnet-beta.solana.com");
let parsers = dex::all_parsers();

let block = source.get_block(slot).await?;
let swaps: Vec<_> = block.transactions.iter()
    .flat_map(|tx| dex::extract_swaps(tx, &parsers))
    .collect();

let sandwiches = detector::detect_sandwiches(slot, &swaps);
```

### Cross-slot window detection

```rust
use sandwich_detector::window::{FilteredWindowDetector, WindowDetector};

let mut detector = FilteredWindowDetector::new(4); // 4-slot window

// Feed slots in order
for (slot, swaps) in blocks_stream {
    let attacks = detector.ingest_slot(slot, swaps);
    for attack in &attacks {
        println!("Sandwich detected: confidence={:.2}", attack.confidence.unwrap_or(0.0));
    }
}

// Flush remaining buffered detections
let remaining = detector.flush();
```

### Key types

| Type | Description |
|------|-------------|
| `SwapEvent` | A single parsed swap (signer, pool, direction, amounts) |
| `SandwichAttack` | A detected sandwich (frontrun + victim + backrun + confidence) |
| `BlockSource` | Trait -- plug in your own block fetcher (RPC, gRPC, WebSocket) |
| `DexParser` | Trait -- add support for any DEX in ~50 lines |
| `WindowDetector` | Trait -- cross-slot detection with sliding window |
| `FilteredWindowDetector` | Production detector with 3 precision filters + confidence scoring |
| `FilterConfig` | Configurable thresholds (min profit, victim ratio, confidence) |
| `BundleLookup` | Trait -- inject Jito bundle data for provenance classification |

---

## Project Structure

```
crates/
  swap-events/           Swap event types, DEX parsers, block sources
  detector-sameblock/    Same-block sandwich detection
  detector-window/       Cross-slot window detector + precision filters
  pool-state/            AMM math + pool-state enrichment (victim loss, real profit)
  detector/              Facade crate (re-exports for backward compatibility)
  cli/                   CLI binary (sandwich-detect)
  eval/                  Evaluation framework + economic aggregates
```

---

## Scope

This library covers **detection over a stream of blocks** -- both same-block and cross-slot patterns. Anything stateful, opinionated, or product-shaped is out of scope and lives in [Vigil](https://github.com/EarthIsMine/Vigil-RPC) instead.

**In scope** (PRs welcome):

- New DEX parsers (Lifinity, Marinade, Sanctum, ...)
- New `BlockSource` implementations (Yellowstone gRPC, Geyser, fixture file, WebSocket)
- Same-block and cross-slot detection accuracy fixes
- Confidence scoring and filter tuning
- Jito bundle integration improvements
- Eval framework improvements (metrics, labeling tools)
- Pool-state coverage for more AMMs (Orca Whirlpool CLMM, Raydium CLMM, Meteora DLMM)
- Mainnet test fixtures
- Performance: allocation reduction, parallelism, batching
- API ergonomics, documentation, examples
- CLI flags that stay within "stream in -> stream out"

**Out of scope** (these belong in a downstream consumer like Vigil):

- Validator-aware or leader-aware analysis
- Multi-hop Jupiter route resolution
- Wash-trading false-positive filters
- ML-based confidence scoring
- Persistence (databases, file stores, indexers)
- Alerting (webhooks, Slack, Discord, email, ...)
- Metrics endpoints (Prometheus, OpenTelemetry, ...)
- Web UIs, dashboards, visualizations
- Stateful services of any kind built into the CLI

The rule of thumb: **"compute over a stream"** stays here, **"state, output, presentation"** goes downstream.

---

## Contributing

PRs welcome. Here's where help is most valuable:

- **Add a DEX parser** -- implement `DexParser` for a new protocol (Lifinity, Marinade, Sanctum, ...)
- **Add test fixtures** -- capture mainnet blocks with confirmed sandwiches under `fixtures/`
- **Improve detection** -- edge cases, cross-slot accuracy, confidence tuning
- **Eval framework** -- add labeled datasets, improve metrics, new evaluation modes
- **Add block sources** -- gRPC (Yellowstone), WebSocket subscriptions

```bash
# Run tests
cargo test --workspace

# Check everything compiles
cargo check --workspace
```

---

## Reproduce the numbers

The measurement flow is deterministic — given a slot range and RPC endpoint, anyone gets the same output. To reproduce a run:

```bash
# Raw detections as JSONL (one per line). Use this for any multi-day run —
# the scanner doesn't buffer, it just streams to disk.
sandwich-detect \
    --rpc $RPC_URL \
    --range <START>-<END> \
    --window 4 \
    --pool-state $RPC_URL \
  > detections.jsonl

# Aggregate the JSONL into the headline report (human-readable or JSON).
sandwich-eval summarize --input detections.jsonl > report.txt
sandwich-eval summarize --input detections.jsonl --json > report.json
```

For short runs the scanner can also emit the report itself by passing `--summary`; the aggregation is done in-memory, which is fine up to a few hundred MB of detections but not for multi-day scans.

The summary includes total victim loss (quote-token smallest unit), unique attackers/victims/pools, per-DEX breakdown, top attackers by extracted value, and a *reclassification rate* — the share of sandwiches the naive rule-based profit flags as profitable but AMM replay shows to be losing money. That reclassification is the signal that makes pool-state enrichment worth running.

Results for specific slot ranges (and the raw JSONL used to produce them) will be published alongside write-ups; see [Vigil](https://github.com/EarthIsMine/Vigil-RPC) for ongoing runs.

---

## License

MIT
