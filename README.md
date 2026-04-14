<p align="center">
  <h1 align="center">solana-sandwich-detector</h1>
  <p align="center">
    A Rust library for detecting sandwich attacks in Solana blocks.<br/>
    Parses swap events from major DEXes and identifies frontrun/victim/backrun patterns in transaction-ordered streams.
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

Sandwich attacks are the most common form of MEV exploitation on Solana. An attacker front-runs a victim's swap, pushes the price, and back-runs to profit — all within the same block.

**solana-sandwich-detector** is a Rust library that turns a stream of Solana blocks into a stream of detected attacks. It parses swap instructions across major DEXes, groups them by pool, and flags the classic frontrun-victim-backrun pattern. A thin streaming CLI (`sandwich-detect`) is shipped alongside as a reference consumer.

> Used by [Vigil](https://github.com/SangHyeonKwon/vigil) — a Solana MEV transparency platform — as the same-block detection primitive. Cross-slot detection, validator scoring, persistence, alerting, and dashboards live in Vigil, not here. See [Scope](#scope).

### Supported DEXes

| DEX | Coverage |
|-----|----------|
| Raydium V4 | Direct swaps + CPI |
| Orca Whirlpool | Direct swaps + CPI |
| Jupiter V6 | Route-through (resolves underlying pool) |

> Adding a new DEX takes ~50 lines. See [Contributing](#contributing).

---

## Quick Start

The repo ships with `sandwich-detect`, a thin streaming CLI that wraps the library — useful for smoke-testing, ad-hoc analysis, and piping detections into other tools. For embedding in your own service, [use the library directly](#use-as-a-library).

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

Pipe it anywhere — `jq`, a database, an alert system, your own dashboard.

### More examples

```bash
# Analyze a specific slot
sandwich-detect --rpc $RPC_URL --slot 285012345

# Scan a range of slots
sandwich-detect --rpc $RPC_URL --range 285012000-285012100

# Pretty-print for humans
sandwich-detect --rpc $RPC_URL --follow --format pretty
```

`RPC_URL` can be passed via `--rpc` flag or as an environment variable.

---

## How It Works

```
Block (slot N)
 │
 ├─ Parse transactions ──► Extract swap events per DEX
 │                          (instruction accounts + token balance deltas)
 │
 ├─ Group by pool
 │
 └─ Detect pattern:
      tx[i]  attacker BUYS   ─┐
      tx[j]  victim   BUYS    ├─ same pool, same direction
      tx[k]  attacker SELLS  ─┘  opposite direction, same signer as tx[i]
```

**Detection rules:**

| Condition | Why |
|-----------|-----|
| `frontrun.signer == backrun.signer` | Same attacker |
| `frontrun.direction != backrun.direction` | Opposite trades (buy then sell) |
| `victim.direction == frontrun.direction` | Victim pushes price further |
| `victim.signer != attacker` | Different wallet |
| All in the same slot & pool | Same-block sandwich |

The detector uses a **hybrid parsing approach**: instruction discriminators identify the DEX program and pool address, while pre/post token balance changes determine swap direction and amounts. This is more robust than pure instruction decoding since it works even when instruction formats change.

---

## Use as a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
sandwich-detector = { git = "https://github.com/SangHyeonKwon/solana-sandwich-detector" }
```

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

### Key types

| Type | Description |
|------|-------------|
| `SwapEvent` | A single parsed swap (signer, pool, direction, amounts) |
| `SandwichAttack` | A detected sandwich (frontrun + victim + backrun) |
| `BlockSource` | Trait — plug in your own block fetcher (RPC, gRPC, WebSocket) |
| `DexParser` | Trait — add support for any DEX in ~50 lines |

---

## Project Structure

```
crates/
  detector/              Core library
    src/
      types.rs           Domain types (SwapEvent, SandwichAttack, ...)
      detector.rs        Detection algorithm + unit tests
      parser.rs          Solana block/tx parsing (handles v0 + lookup tables)
      dex/
        raydium.rs       Raydium V4 parser
        orca.rs          Orca Whirlpool parser
        jupiter.rs       Jupiter V6 router parser
      source/
        rpc.rs           JSON-RPC block source
  cli/                   CLI binary (sandwich-detect)
```

---

## Scope

This library is intentionally narrow: **compute over a stream of blocks → emit detected attacks**. Anything stateful, opinionated, or product-shaped is out of scope and lives in [Vigil](https://github.com/SangHyeonKwon/vigil) instead. The CLI follows the same rule — it's a thin streaming wrapper, not a service.

**In scope** (PRs welcome):

- New DEX parsers (Meteora, Phoenix, Lifinity, Pump.fun, Raydium CLMM, ...)
- New `BlockSource` implementations (Yellowstone gRPC, Geyser, fixture file, WebSocket)
- Same-block detection accuracy fixes and edge cases
- Mainnet test fixtures
- Performance: allocation reduction, parallelism, batching
- API ergonomics, documentation, examples
- CLI flags that stay within "stream in → stream out" (input source, output format, filtering)

**Out of scope** (these belong in a downstream consumer like Vigil, not here):

- Cross-slot / multi-block sandwich detection
- Validator-aware or leader-aware analysis
- Pool reserve reconstruction for precise victim loss
- Multi-hop Jupiter route resolution
- Wash-trading false-positive filters
- ML-based confidence scoring
- Persistence (databases, file stores, indexers)
- Alerting (webhooks, Slack, Discord, email, ...)
- Metrics endpoints (Prometheus, OpenTelemetry, ...)
- Web UIs, dashboards, visualizations
- Stateful services of any kind built into the CLI

The rule of thumb: **"compute over a stream"** stays here, **"state, output, presentation"** goes downstream. If you're building a product on top of this, fork the library boundary, not the library itself.

---

## Contributing

PRs welcome. Here's where help is most valuable:

- **Add a DEX parser** — implement `DexParser` for a new protocol (Meteora, Phoenix, Lifinity, ...)
- **Add test fixtures** — capture mainnet blocks with confirmed sandwiches under `fixtures/`
- **Improve pool ID resolution** — better instruction-level parsing for existing DEXes
- **Add block sources** — gRPC (Yellowstone), WebSocket subscriptions

```bash
# Run tests
cargo test

# Check everything compiles
cargo check --workspace
```

---

## License

MIT
