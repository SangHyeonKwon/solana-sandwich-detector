use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Parser;
use futures::StreamExt;
use pool_state::{
    enrich_attack, EnrichmentResult, NoPoolLookup, NoSlotLeaderLookup, PoolStateLookup,
    RpcPoolLookup, RpcSlotLeaderLookup, SlotLeaderLookup,
};
use sandwich_detector::{
    authority_hop::{index_by_wallet_pair, scan_block, AuthorityHop},
    detector,
    dex::{self, DexParser},
    source::{rpc::RpcBlockSource, BlockSource},
    types::{BlockData, DexType, SandwichAttack, TransactionData},
    window::{FilteredWindowDetector, WindowDetector},
    SCHEMA_VERSION,
};
use sandwich_eval::economics;
use serde::Serialize;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "sandwich-detect")]
#[command(about = "Detect sandwich attacks on Solana")]
struct Cli {
    /// Solana RPC endpoint URL
    #[arg(long, env = "RPC_URL")]
    rpc: String,

    /// RPC endpoint for pool-account fetches used by victim-loss enrichment.
    /// Defaults to `--rpc`. Set separately to route pool config lookups to a
    /// dedicated endpoint (e.g. a higher-rate archival node).
    #[arg(long, env = "POOL_STATE_RPC")]
    pool_state: Option<String>,

    /// Disable pool-state enrichment even if an RPC is available.
    #[arg(long)]
    no_enrich: bool,

    /// Follow new blocks in real-time
    #[arg(long)]
    follow: bool,

    /// Analyze a specific slot
    #[arg(long)]
    slot: Option<u64>,

    /// Analyze a range of slots (e.g., "12345-12400")
    #[arg(long)]
    range: Option<String>,

    /// Output format
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Polling interval in milliseconds for follow mode
    #[arg(long, default_value = "1000")]
    poll_interval: u64,

    /// Enable cross-slot window detector (N-slot sliding window)
    #[arg(long)]
    window: Option<usize>,

    /// Collect all emitted sandwiches in memory and print an aggregate
    /// economics report to stderr when the run finishes. Requires a bounded
    /// run (`--slot` or `--range`); ignored in `--follow` mode.
    #[arg(long)]
    summary: bool,

    /// Number of top attackers to include in the summary. Default 10.
    #[arg(long, default_value = "10")]
    summary_top_n: usize,

    /// Max attempts per `getBlock` call on transient RPC errors (rate limits,
    /// network blips). Permanent errors — the slot was skipped or is outside
    /// the node's history — are not retried regardless of this setting.
    #[arg(long, default_value = "5")]
    max_retries: u32,

    /// How much of the structured reasoning trace to include on each emitted
    /// `SandwichAttack`. `passing` (default) keeps the Pass-verdict signals
    /// only, `full` additionally includes Fail and Informational signals for
    /// debugging, `off` strips the evidence block entirely.
    #[arg(long, default_value = "passing")]
    evidence_mode: EvidenceMode,

    /// Max concurrent `getBlock` requests in range mode. Higher values
    /// saturate the RPC tier's rate limit and make long scans tractable;
    /// too-high values risk 429s. Tune per your Helius plan (paid tiers can
    /// comfortably sit at 32-64). Window detection still consumes blocks in
    /// slot order — this only parallelizes the fetch leg.
    #[arg(long, default_value = "16")]
    concurrency: usize,

    /// Output schema contract for the JSONL stream. Today only `vigil-v1` is
    /// emitted; the flag is kept so future v2 consumers can opt in without
    /// breaking v1 readers. Mirrors `swap_events::SCHEMA_VERSION`.
    #[arg(long, default_value = "vigil-v1", value_enum)]
    schema: SchemaVersion,

    /// Suppress the leading `_header` JSONL line. Useful when the consumer
    /// already opens the stream mid-flight or replays fixtures that pre-date
    /// the header format. Heartbeats in `--follow` are still emitted.
    #[arg(long)]
    no_header: bool,

    /// Heartbeat interval (seconds) emitted as `{"_heartbeat": <unix_ms>}`
    /// during `--follow`. Lets a long-poll consumer distinguish "no
    /// detections yet" from "detector crashed". Set to 0 to disable.
    #[arg(long, default_value = "30")]
    heartbeat_secs: u64,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Pretty,
}

#[derive(Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
enum SchemaVersion {
    /// Vigil v1 contract. Fields documented on `SandwichAttack` and `MevReceipt`
    /// in the `swap-events` crate; pinned by `swap_events::SCHEMA_VERSION`.
    #[value(name = "vigil-v1")]
    VigilV1,
}

impl SchemaVersion {
    fn as_str(self) -> &'static str {
        match self {
            SchemaVersion::VigilV1 => "vigil-v1",
        }
    }
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum EvidenceMode {
    /// Keep only `evidence.passing`; strip failing/informational.
    Passing,
    /// Keep all three signal lists (debugging / auditing).
    Full,
    /// Strip `evidence` entirely — size-sensitive mainnet runs.
    Off,
}

/// Apply the configured `EvidenceMode` to a detection in place.
fn apply_evidence_mode(attack: &mut SandwichAttack, mode: EvidenceMode) {
    match mode {
        EvidenceMode::Full => {} // keep everything
        EvidenceMode::Passing => {
            if let Some(ev) = attack.evidence.as_mut() {
                ev.failing.clear();
                ev.informational.clear();
            }
        }
        EvidenceMode::Off => {
            attack.evidence = None;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env if present. Ignore errors — env vars may already be set, or
    // the user may be passing `--rpc` directly.
    let _ = dotenvy::dotenv();

    // stdout is reserved for JSONL output; logs go to stderr so downstream
    // consumers can pipe `sandwich-detect ... > detections.jsonl` cleanly.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let source = RpcBlockSource::new(&cli.rpc);
    let parsers = dex::all_parsers();
    let lookup: Arc<dyn PoolStateLookup> = build_lookup(&cli);
    let leader_lookup: Arc<dyn SlotLeaderLookup> = build_leader_lookup(&cli);
    let mut collected: Option<Vec<SandwichAttack>> = cli.summary.then(Vec::new);

    // Sanity-check the schema flag against the compiled-in version. If a future
    // SCHEMA_VERSION drifts from the flag value, fail loud rather than emitting
    // a `_header` that disagrees with the body.
    debug_assert_eq!(cli.schema.as_str(), SCHEMA_VERSION);

    if !cli.no_header && matches!(cli.format, OutputFormat::Json) {
        write_header(&mut io::stdout(), cli.schema)?;
    }

    let ctx = EmitContext {
        format: cli.format.clone(),
        evidence_mode: cli.evidence_mode,
    };

    if let Some(slot) = cli.slot {
        process_slot(
            &source,
            &parsers,
            slot,
            &ctx,
            lookup.as_ref(),
            leader_lookup.as_ref(),
            collected.as_mut(),
            cli.max_retries,
        )
        .await?;
    } else if let Some(range) = &cli.range {
        let (start, end) = parse_range(range)?;
        if let Some(window_size) = cli.window {
            process_range_with_window(
                &source,
                &parsers,
                start,
                end,
                window_size,
                &ctx,
                lookup.as_ref(),
                leader_lookup.as_ref(),
                collected.as_mut(),
                cli.max_retries,
                cli.concurrency,
            )
            .await?;
        } else {
            for slot in start..=end {
                process_slot(
                    &source,
                    &parsers,
                    slot,
                    &ctx,
                    lookup.as_ref(),
                    leader_lookup.as_ref(),
                    collected.as_mut(),
                    cli.max_retries,
                )
                .await?;
            }
        }
    } else if cli.follow {
        follow_mode(
            &source,
            &parsers,
            &ctx,
            cli.poll_interval,
            cli.window,
            lookup.as_ref(),
            leader_lookup.as_ref(),
            cli.max_retries,
            cli.heartbeat_secs,
        )
        .await?;
    } else {
        let slot = source.get_latest_slot().await?;
        tracing::info!("Processing latest slot: {}", slot);
        process_slot(
            &source,
            &parsers,
            slot,
            &ctx,
            lookup.as_ref(),
            leader_lookup.as_ref(),
            collected.as_mut(),
            cli.max_retries,
        )
        .await?;
    }

    if let Some(attacks) = collected {
        let report = economics::aggregate(&attacks, cli.summary_top_n);
        eprintln!("{}", report);
    }

    Ok(())
}

/// Bundled-up emit configuration so process functions don't need a parameter
/// per knob. Cloned cheaply.
#[derive(Clone)]
struct EmitContext {
    format: OutputFormat,
    evidence_mode: EvidenceMode,
}

/// Emit the leading `_header` line so a Vigil consumer can validate the schema
/// before persisting any attack rows. Writer-parameterised so tests can capture
/// the exact bytes that go to stdout.
fn write_header<W: Write>(out: &mut W, schema: SchemaVersion) -> Result<()> {
    let header = serde_json::json!({
        "_header": true,
        "schema_version": schema.as_str(),
        "tool_version": env!("CARGO_PKG_VERSION"),
        "started_at_ms": now_ms() as i64,
    });
    writeln!(out, "{}", serde_json::to_string(&header)?)?;
    Ok(())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn build_lookup(cli: &Cli) -> Arc<dyn PoolStateLookup> {
    if cli.no_enrich {
        return Arc::new(NoPoolLookup);
    }
    let url = cli.pool_state.as_deref().unwrap_or(&cli.rpc);
    Arc::new(RpcPoolLookup::new(url))
}

/// Build the [`SlotLeaderLookup`] used to fill `attack.slot_leader`. Tied to
/// the same `--no-enrich` toggle as the pool-state lookup so a fixture-replay
/// run (`--no-enrich`) doesn't try to hit `getSlotLeaders`. Reuses the
/// `--pool-state` URL when set so a dedicated archival endpoint serves both.
fn build_leader_lookup(cli: &Cli) -> Arc<dyn SlotLeaderLookup> {
    if cli.no_enrich {
        return Arc::new(NoSlotLeaderLookup);
    }
    let url = cli.pool_state.as_deref().unwrap_or(&cli.rpc);
    Arc::new(RpcSlotLeaderLookup::new(url))
}

#[allow(clippy::too_many_arguments)]
async fn process_slot(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    slot: u64,
    ctx: &EmitContext,
    lookup: &dyn PoolStateLookup,
    leader_lookup: &dyn SlotLeaderLookup,
    mut collected: Option<&mut Vec<SandwichAttack>>,
    max_retries: u32,
) -> Result<()> {
    let Some(block) = fetch_block_with_retry(source, slot, max_retries).await else {
        return Ok(());
    };

    let block_time_ms = block.block_time.map(|t| t * 1000);

    let mut all_swaps = Vec::new();
    for tx in &block.transactions {
        let swaps = dex::extract_swaps(tx, parsers);
        all_swaps.extend(swaps);
    }

    let sandwiches = detector::detect_sandwiches(slot, &all_swaps);
    let tx_by_sig = index_block(&block);
    let sandwich_count = sandwiches.len();

    for mut sandwich in sandwiches {
        enrich_from_cache(&mut sandwich, &tx_by_sig, lookup).await;
        attach_slot_leader(&mut sandwich, leader_lookup).await;
        sandwich.timestamp_ms = block_time_ms;
        output_sandwich(&mut sandwich, ctx)?;
        if let Some(c) = collected.as_deref_mut() {
            c.push(sandwich);
        }
    }

    // Authority-Hop pass — promotes wallet-mismatched candidates the
    // sameblock detector dropped when an SPL Token SetAuthority hop ties
    // the frontrun and backrun signers together. The two passes are
    // disjoint by construction (sameblock requires `front == back`,
    // authority-hop requires `front != back`), so no dedup is needed.
    let hop_index = build_hop_index(&block);
    let hop_sandwiches = detector::detect_authority_hop_sandwiches(slot, &all_swaps, &hop_index);
    let hop_count = hop_sandwiches.len();
    for mut sandwich in hop_sandwiches {
        enrich_from_cache(&mut sandwich, &tx_by_sig, lookup).await;
        attach_slot_leader(&mut sandwich, leader_lookup).await;
        sandwich.timestamp_ms = block_time_ms;
        output_sandwich(&mut sandwich, ctx)?;
        if let Some(c) = collected.as_deref_mut() {
            c.push(sandwich);
        }
    }

    tracing::info!(
        "Slot {}: {} swap(s), {} sandwich(es), {} authority-hop",
        slot,
        all_swaps.len(),
        sandwich_count,
        hop_count,
    );

    Ok(())
}

/// Wrap [`scan_block`] + [`index_by_wallet_pair`] for the CLI's per-slot
/// authority-hop pass. The result is cheap to build (one pass over the
/// block, only SPL Token / Token-2022 instructions are inspected) and is
/// recomputed per slot — there's no cross-slot Authority-Hop variant yet,
/// so caching across slots would buy nothing.
fn build_hop_index(block: &BlockData) -> HashMap<(String, String), Vec<AuthorityHop>> {
    let hops = scan_block(block);
    index_by_wallet_pair(hops)
}

#[allow(clippy::too_many_arguments)]
async fn process_range_with_window(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    start: u64,
    end: u64,
    window_size: usize,
    ctx: &EmitContext,
    lookup: &dyn PoolStateLookup,
    leader_lookup: &dyn SlotLeaderLookup,
    mut collected: Option<&mut Vec<SandwichAttack>>,
    max_retries: u32,
    concurrency: usize,
) -> Result<()> {
    let mut window_detector = FilteredWindowDetector::new(window_size);
    let mut tx_cache = TxCache::new(window_size);
    let mut total_sameblock = 0usize;
    let mut total_window = 0usize;
    let mut total_hop = 0usize;

    // Pipeline block fetches: up to `concurrency` in-flight getBlock calls,
    // results yielded in slot order so the window detector still sees a
    // monotonic stream. Detection work runs on the single consumer task;
    // only the I/O leg is parallel.
    let concurrency = concurrency.max(1);
    let mut block_stream = futures::stream::iter(start..=end)
        .map(|slot| async move {
            (
                slot,
                fetch_block_with_retry(source, slot, max_retries).await,
            )
        })
        .buffered(concurrency);

    while let Some((slot, block_opt)) = block_stream.next().await {
        let Some(block) = block_opt else {
            continue;
        };

        tx_cache.ingest(slot, &block);

        let swaps: Vec<_> = block
            .transactions
            .iter()
            .flat_map(|tx| dex::extract_swaps(tx, parsers))
            .collect();

        // Same-block detection
        let sameblock = detector::detect_sandwiches(slot, &swaps);
        total_sameblock += sameblock.len();
        for mut s in sameblock {
            enrich_from_cache(&mut s, tx_cache.sig_map(), lookup).await;
            attach_slot_leader(&mut s, leader_lookup).await;
            s.timestamp_ms = tx_cache.block_time_ms_for(slot);
            output_sandwich(&mut s, ctx)?;
            if let Some(c) = collected.as_deref_mut() {
                c.push(s);
            }
        }

        // Authority-Hop pass — same-slot only, disjoint from sameblock by
        // wallet-equality construction. Cross-slot Authority-Hop would need
        // a window-aware variant.
        let hop_index = build_hop_index(&block);
        let hop_sandwiches = detector::detect_authority_hop_sandwiches(slot, &swaps, &hop_index);
        total_hop += hop_sandwiches.len();
        for mut s in hop_sandwiches {
            enrich_from_cache(&mut s, tx_cache.sig_map(), lookup).await;
            attach_slot_leader(&mut s, leader_lookup).await;
            s.timestamp_ms = tx_cache.block_time_ms_for(slot);
            output_sandwich(&mut s, ctx)?;
            if let Some(c) = collected.as_deref_mut() {
                c.push(s);
            }
        }

        // Window detection (cross-slot only). The cache holds block_time for
        // the victim's slot so cross-slot detections are timestamped against
        // the slot the victim landed in, not the trailing emission slot.
        let window_results = window_detector.ingest_slot(slot, swaps);
        total_window += window_results.len();
        for mut s in window_results {
            enrich_from_cache(&mut s, tx_cache.sig_map(), lookup).await;
            attach_slot_leader(&mut s, leader_lookup).await;
            s.timestamp_ms = tx_cache.block_time_ms_for(s.slot);
            output_sandwich(&mut s, ctx)?;
            if let Some(c) = collected.as_deref_mut() {
                c.push(s);
            }
        }
    }

    // Flush remaining
    let flushed = window_detector.flush();
    total_window += flushed.len();
    for mut s in flushed {
        enrich_from_cache(&mut s, tx_cache.sig_map(), lookup).await;
        attach_slot_leader(&mut s, leader_lookup).await;
        s.timestamp_ms = tx_cache.block_time_ms_for(s.slot);
        output_sandwich(&mut s, ctx)?;
        if let Some(c) = collected.as_deref_mut() {
            c.push(s);
        }
    }

    tracing::info!(
        "Range {}-{}: {} same-block, {} cross-slot, {} authority-hop",
        start,
        end,
        total_sameblock,
        total_window,
        total_hop,
    );

    Ok(())
}

/// Final stop before stdout. Applies the evidence-mode filter, runs
/// `finalize_for_vigil()` so the row carries the Vigil ERD-aligned derived
/// fields (attack_signature / attack_type / receipts / promoted top-level
/// victim columns), and writes a single JSONL line.
fn output_sandwich(sandwich: &mut SandwichAttack, ctx: &EmitContext) -> Result<()> {
    write_sandwich(&mut io::stdout(), sandwich, ctx)
}

fn write_sandwich<W: Write>(
    out: &mut W,
    sandwich: &mut SandwichAttack,
    ctx: &EmitContext,
) -> Result<()> {
    apply_evidence_mode(sandwich, ctx.evidence_mode);
    sandwich.finalize_for_vigil();
    match ctx.format {
        OutputFormat::Json => writeln!(out, "{}", serde_json::to_string(sandwich)?)?,
        OutputFormat::Pretty => writeln!(out, "{}", serde_json::to_string_pretty(sandwich)?)?,
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn follow_mode(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    ctx: &EmitContext,
    poll_interval: u64,
    window: Option<usize>,
    lookup: &dyn PoolStateLookup,
    leader_lookup: &dyn SlotLeaderLookup,
    max_retries: u32,
    heartbeat_secs: u64,
) -> Result<()> {
    let mut last_slot = source.get_latest_slot().await?;
    tracing::info!("Follow mode -- starting from slot {}", last_slot);

    let mut consecutive_errors: u32 = 0;
    let mut window_detector = window.map(FilteredWindowDetector::new);
    // Cross-slot lookups need a rolling cache of tx metas sized to the window.
    // In same-block-only follow mode, a 1-slot cache is enough.
    let cache_window = window.unwrap_or(1);
    let mut tx_cache = TxCache::new(cache_window);

    // Termination signals — Vigil's BE supervises this process, so SIGTERM
    // means "shut down cleanly". On Ctrl-C (SIGINT) we do the same. Both flush
    // the window detector before returning so any pending cross-slot
    // detections still make it to stdout.
    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;
    // Heartbeat ticker; `None` disables the feature entirely.
    let mut heartbeat = if heartbeat_secs > 0 {
        Some(tokio::time::interval(tokio::time::Duration::from_secs(
            heartbeat_secs,
        )))
    } else {
        None
    };
    if let Some(h) = heartbeat.as_mut() {
        // The first tick fires immediately; skip it so we don't double-emit
        // right after the header.
        h.tick().await;
    }

    loop {
        // Race the polling tick against shutdown signals and the heartbeat
        // ticker. Heartbeats only emit while idle so they don't interleave
        // mid-batch with a detection.
        tokio::select! {
            _ = term.recv() => {
                tracing::info!("SIGTERM received, flushing");
                break;
            }
            _ = intr.recv() => {
                tracing::info!("SIGINT received, flushing");
                break;
            }
            _ = async {
                if let Some(h) = heartbeat.as_mut() {
                    h.tick().await;
                } else {
                    futures::future::pending::<()>().await;
                }
            } => {
                emit_heartbeat()?;
                continue;
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval)) => {}
        }

        let current_slot = match source.get_latest_slot().await {
            Ok(slot) => {
                consecutive_errors = 0;
                slot
            }
            Err(e) => {
                consecutive_errors += 1;
                let backoff = std::cmp::min(1000 * 2u64.pow(consecutive_errors), 30_000);
                tracing::warn!(
                    "RPC error (attempt {}): {}. Retrying in {}ms",
                    consecutive_errors,
                    e,
                    backoff
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(backoff)).await;
                continue;
            }
        };

        if current_slot > last_slot {
            for slot in (last_slot + 1)..=current_slot {
                let Some(block) = fetch_block_with_retry(source, slot, max_retries).await else {
                    continue;
                };

                tx_cache.ingest(slot, &block);

                let swaps: Vec<_> = block
                    .transactions
                    .iter()
                    .flat_map(|tx| dex::extract_swaps(tx, parsers))
                    .collect();

                // Same-block detection
                let sandwiches = detector::detect_sandwiches(slot, &swaps);
                let sb_count = sandwiches.len();
                for mut s in sandwiches {
                    enrich_from_cache(&mut s, tx_cache.sig_map(), lookup).await;
                    attach_slot_leader(&mut s, leader_lookup).await;
                    s.timestamp_ms = tx_cache.block_time_ms_for(slot);
                    output_sandwich(&mut s, ctx)?;
                }

                // Authority-Hop pass (same-slot)
                let hop_index = build_hop_index(&block);
                let hop_sandwiches =
                    detector::detect_authority_hop_sandwiches(slot, &swaps, &hop_index);
                let hop_count = hop_sandwiches.len();
                for mut s in hop_sandwiches {
                    enrich_from_cache(&mut s, tx_cache.sig_map(), lookup).await;
                    attach_slot_leader(&mut s, leader_lookup).await;
                    s.timestamp_ms = tx_cache.block_time_ms_for(slot);
                    output_sandwich(&mut s, ctx)?;
                }

                tracing::info!(
                    "Slot {}: {} swap(s), {} sandwich(es), {} authority-hop",
                    slot,
                    swaps.len(),
                    sb_count,
                    hop_count,
                );

                // Window detection if enabled
                if let Some(ref mut wd) = window_detector {
                    let cross = wd.ingest_slot(slot, swaps);
                    for mut s in cross {
                        enrich_from_cache(&mut s, tx_cache.sig_map(), lookup).await;
                        attach_slot_leader(&mut s, leader_lookup).await;
                        s.timestamp_ms = tx_cache.block_time_ms_for(s.slot);
                        output_sandwich(&mut s, ctx)?;
                    }
                }
            }
            last_slot = current_slot;
        }
    }

    // Drain whatever is still buffered in the window detector — these may be
    // legitimate cross-slot sandwiches we'd otherwise drop on shutdown.
    if let Some(mut wd) = window_detector {
        let flushed = wd.flush();
        for mut s in flushed {
            enrich_from_cache(&mut s, tx_cache.sig_map(), lookup).await;
            attach_slot_leader(&mut s, leader_lookup).await;
            s.timestamp_ms = tx_cache.block_time_ms_for(s.slot);
            output_sandwich(&mut s, ctx)?;
        }
    }

    Ok(())
}

fn emit_heartbeat() -> Result<()> {
    write_heartbeat(&mut io::stdout(), now_ms() as i64)
}

fn write_heartbeat<W: Write>(out: &mut W, ts_ms: i64) -> Result<()> {
    let line = serde_json::json!({
        "_heartbeat": ts_ms,
        "metrics": enrichment_metrics().snapshot(),
    });
    writeln!(out, "{}", serde_json::to_string(&line)?)?;
    Ok(())
}

/// Process-lifetime counters for enrichment outcomes, bucketed by
/// [`DexType`]. Updated inside [`enrich_from_cache`] every time
/// `enrich_attack` returns; emitted in the JSONL heartbeat under
/// `metrics`. Per-DEX bucketing lets ops watch the
/// concentrated-liquidity fetch window (Whirlpool 5-array TickArray
/// bracket or DLMM 5-array BinArray bracket) on the actual DEX where
/// the trouble is — `meteora_dlmm.cross_boundary_unsupported` climbing
/// without `orca_whirlpool.cross_boundary_unsupported` moving means
/// it's a DLMM-side bracket issue, not a Whirlpool one. Buckets for
/// every [`DexType`] variant are pre-populated so the wire shape is
/// stable and Vigil's BE can iterate keys without missing-key handling.
#[derive(Debug)]
struct EnrichmentMetrics {
    by_dex: HashMap<DexType, EnrichmentMetricsBucket>,
}

/// Per-DEX slice of [`EnrichmentMetrics`]. Same six counters as the
/// flat (pre-#4) shape — only the dispatch key changed.
#[derive(Debug, Default)]
struct EnrichmentMetricsBucket {
    enriched: AtomicU64,
    unsupported_dex: AtomicU64,
    config_unavailable: AtomicU64,
    reserves_missing: AtomicU64,
    replay_failed: AtomicU64,
    cross_boundary_unsupported: AtomicU64,
}

/// Static list of every [`DexType`] variant. Used to pre-populate the
/// metrics map so the heartbeat wire shape is stable from t=0 (no
/// missing-key surprises in Vigil's BE) and `record()` can take a
/// non-mutable `&self`.
///
/// Adding a DEX variant: append it here too, or `record(new_variant, ...)`
/// will hit the `expect` in production. The
/// `all_dex_types_constant_covers_every_dextype_variant` test keeps
/// this in sync — its exhaustive `match` on `DexType` is a compile
/// error on a missing variant, and the runtime loop pins the array
/// length so a typo in this literal is caught.
const ALL_DEX_TYPES: [DexType; 8] = [
    DexType::RaydiumV4,
    DexType::RaydiumClmm,
    DexType::RaydiumCpmm,
    DexType::OrcaWhirlpool,
    DexType::JupiterV6,
    DexType::MeteoraDlmm,
    DexType::PumpFun,
    DexType::Phoenix,
];

impl Default for EnrichmentMetrics {
    fn default() -> Self {
        let by_dex = ALL_DEX_TYPES
            .iter()
            .map(|&d| (d, EnrichmentMetricsBucket::default()))
            .collect();
        Self { by_dex }
    }
}

impl EnrichmentMetrics {
    /// Bump the counter matching `(dex, result)`. `Ordering::Relaxed`
    /// is fine — we don't synchronise reads against any other state,
    /// just want monotonic per-thread increments visible in the
    /// heartbeat snapshot. Pre-population in `Default` guarantees the
    /// `HashMap::get` is infallible for any [`DexType`] variant.
    fn record(&self, dex: DexType, result: EnrichmentResult) {
        let bucket = self
            .by_dex
            .get(&dex)
            .expect("ALL_DEX_TYPES pre-populates every variant");
        let counter = match result {
            EnrichmentResult::Enriched => &bucket.enriched,
            EnrichmentResult::UnsupportedDex => &bucket.unsupported_dex,
            EnrichmentResult::ConfigUnavailable => &bucket.config_unavailable,
            EnrichmentResult::ReservesMissing => &bucket.reserves_missing,
            EnrichmentResult::ReplayFailed => &bucket.replay_failed,
            EnrichmentResult::CrossBoundaryUnsupported => &bucket.cross_boundary_unsupported,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> EnrichmentMetricsSnapshot {
        let by_dex = self
            .by_dex
            .iter()
            .map(|(&dex, bucket)| (dex, bucket.snapshot()))
            .collect();
        EnrichmentMetricsSnapshot { by_dex }
    }
}

impl EnrichmentMetricsBucket {
    fn snapshot(&self) -> EnrichmentMetricsBucketSnapshot {
        EnrichmentMetricsBucketSnapshot {
            enriched: self.enriched.load(Ordering::Relaxed),
            unsupported_dex: self.unsupported_dex.load(Ordering::Relaxed),
            config_unavailable: self.config_unavailable.load(Ordering::Relaxed),
            reserves_missing: self.reserves_missing.load(Ordering::Relaxed),
            replay_failed: self.replay_failed.load(Ordering::Relaxed),
            cross_boundary_unsupported: self.cross_boundary_unsupported.load(Ordering::Relaxed),
        }
    }
}

/// Wire shape of the enrichment metrics field on the JSONL heartbeat.
/// Mirrored into `contrib/vigil-types.ts` so Vigil's BE can `.metrics`
/// off a heartbeat line without guessing field names. The `#[serde(flatten)]`
/// inlines per-DEX buckets at the `metrics` object's top level — i.e.
/// `{ "metrics": { "raydium_v4": {...}, "orca_whirlpool": {...}, ... } }`
/// rather than `{ "metrics": { "by_dex": {...} } }`.
#[derive(Debug, Clone, Default, Serialize)]
struct EnrichmentMetricsSnapshot {
    #[serde(flatten)]
    by_dex: HashMap<DexType, EnrichmentMetricsBucketSnapshot>,
}

/// Per-DEX bucket as it appears on the wire. `Copy` is a free win on
/// a 48-byte POD of `u64` counters — keeps `EnrichmentMetricsSnapshot`
/// cloneable as a bit-copy and lets callers pass a snapshot through
/// without an explicit `.clone()`.
#[derive(Debug, Clone, Copy, Default, Serialize)]
struct EnrichmentMetricsBucketSnapshot {
    enriched: u64,
    unsupported_dex: u64,
    config_unavailable: u64,
    reserves_missing: u64,
    replay_failed: u64,
    cross_boundary_unsupported: u64,
}

/// Global metrics accessor — process-lifetime singleton, lazy-init.
/// Tests share it across calls (counters accumulate across the
/// process); fixture-level isolation isn't needed because the snapshot
/// is just non-decreasing counters.
fn enrichment_metrics() -> &'static EnrichmentMetrics {
    static METRICS: OnceLock<EnrichmentMetrics> = OnceLock::new();
    METRICS.get_or_init(EnrichmentMetrics::default)
}

/// Fetch a block, retrying transient RPC failures with exponential backoff.
///
/// Returns `None` for slots that are legitimately unavailable (skipped by the
/// validator, or outside the node's history) — those are permanent and retrying
/// wastes quota. Also returns `None` after `max_attempts` retries on a
/// transient error, so a long scan can keep going rather than abort.
async fn fetch_block_with_retry(
    source: &RpcBlockSource,
    slot: u64,
    max_attempts: u32,
) -> Option<BlockData> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match source.get_block(slot).await {
            Ok(block) => return Some(block),
            Err(e) => {
                let msg = e.to_string();
                if is_permanent_slot_error(&msg) {
                    tracing::debug!("Slot {}: unavailable ({})", slot, msg);
                    return None;
                }
                if attempt >= max_attempts {
                    tracing::warn!(
                        "Slot {}: giving up after {} attempts: {}",
                        slot,
                        attempt,
                        msg,
                    );
                    return None;
                }
                // 500ms, 1s, 2s, 4s, 8s — capped at 15s.
                let backoff_ms = std::cmp::min(500u64 * 2u64.pow(attempt - 1), 15_000);
                tracing::warn!(
                    "Slot {} attempt {}/{}: {}. Retrying in {}ms",
                    slot,
                    attempt,
                    max_attempts,
                    msg,
                    backoff_ms,
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
            }
        }
    }
}

/// Solana RPC error codes / messages that mean "this slot will never come back"
/// — skipped by the validator, never produced, or aged out of the node. These
/// are not retried because doing so just burns quota for the same None answer.
fn is_permanent_slot_error(msg: &str) -> bool {
    // -32004: block not available
    // -32007: slot was skipped or long-term storage missing
    // -32009: slot was skipped
    // -32014: block status not yet available (treated as transient elsewhere;
    //         not listed here)
    msg.contains("-32004")
        || msg.contains("-32007")
        || msg.contains("-32009")
        || msg.contains("Block not available")
        || msg.contains("Slot was skipped")
        || msg.contains("was skipped, or missing")
}

fn parse_range(range: &str) -> Result<(u64, u64)> {
    let parts: Vec<&str> = range.split('-').collect();
    anyhow::ensure!(
        parts.len() == 2,
        "Invalid range format. Use 'start-end' (e.g., '12345-12400')"
    );
    let start: u64 = parts[0].parse()?;
    let end: u64 = parts[1].parse()?;
    anyhow::ensure!(start <= end, "Range start must be <= end");
    Ok((start, end))
}

// ---------------------------------------------------------------------------
// Enrichment helpers
// ---------------------------------------------------------------------------

/// Rolling signature -> tx-meta cache, bounded by the detector window.
///
/// Pool-state enrichment needs the frontrun tx's `pre_token_balances` to read
/// vault reserves. For cross-slot detections the frontrun was seen in an
/// earlier slot, so we must hold onto tx metas for the full detector window.
struct TxCache {
    by_sig: HashMap<String, TransactionData>,
    by_slot: VecDeque<(u64, Vec<String>)>,
    /// Slot → unix-ms block_time, populated from `BlockData.block_time` at
    /// ingest. Looked up on emission to backfill `SandwichAttack.timestamp_ms`
    /// against the *victim's* slot rather than the trailing emit slot.
    block_time_ms: HashMap<u64, i64>,
    window_slots: usize,
}

impl TxCache {
    fn new(window_slots: usize) -> Self {
        Self {
            by_sig: HashMap::new(),
            by_slot: VecDeque::new(),
            block_time_ms: HashMap::new(),
            window_slots: window_slots.max(1),
        }
    }

    fn ingest(&mut self, slot: u64, block: &BlockData) {
        let mut sigs = Vec::with_capacity(block.transactions.len());
        for tx in &block.transactions {
            sigs.push(tx.signature.clone());
            self.by_sig.insert(tx.signature.clone(), tx.clone());
        }
        if let Some(t) = block.block_time {
            self.block_time_ms.insert(slot, t * 1000);
        }
        self.by_slot.push_back((slot, sigs));
        self.evict(slot);
    }

    fn evict(&mut self, latest_slot: u64) {
        let cutoff = latest_slot.saturating_sub(self.window_slots as u64 - 1);
        while let Some((s, _)) = self.by_slot.front() {
            if *s >= cutoff {
                break;
            }
            let (s_evicted, sigs) = self.by_slot.pop_front().unwrap();
            for sig in sigs {
                self.by_sig.remove(&sig);
            }
            self.block_time_ms.remove(&s_evicted);
        }
    }

    fn sig_map(&self) -> &HashMap<String, TransactionData> {
        &self.by_sig
    }

    fn block_time_ms_for(&self, slot: u64) -> Option<i64> {
        self.block_time_ms.get(&slot).copied()
    }
}

/// Build a signature -> tx map from a single block. Used by same-block paths
/// that don't maintain a rolling cache.
fn index_block(block: &BlockData) -> HashMap<String, TransactionData> {
    block
        .transactions
        .iter()
        .map(|tx| (tx.signature.clone(), tx.clone()))
        .collect()
}

async fn enrich_from_cache(
    attack: &mut SandwichAttack,
    cache: &HashMap<String, TransactionData>,
    lookup: &dyn PoolStateLookup,
) {
    let Some(tx) = cache.get(&attack.frontrun.signature) else {
        tracing::debug!(
            "enrich skip {}: frontrun tx {} not in cache",
            attack.pool,
            &attack.frontrun.signature[..16.min(attack.frontrun.signature.len())],
        );
        return;
    };
    // Backrun tx is optional: when present, enrichment will emit the Tier 3.1
    // ReservesMatchPostState diff signal. When absent (cross-slot detection
    // where the backrun fell out of the rolling cache), the rest of the
    // enrichment still runs unmodified.
    let backrun_tx = cache.get(&attack.backrun.signature);
    let result = enrich_attack(attack, tx, backrun_tx, lookup).await;
    enrichment_metrics().record(attack.dex, result);
    if !matches!(result, EnrichmentResult::Enriched) {
        tracing::debug!(
            "enrich {:?} {}: {:?}",
            attack.dex,
            &attack.pool[..16.min(attack.pool.len())],
            result,
        );
    }
}

/// Populate `attack.slot_leader` via the configured [`SlotLeaderLookup`].
/// Idempotent: a caller-set value (e.g. fixture replay or test) is left
/// untouched. Uses the *victim's* slot — same source of truth Vigil's
/// `mev_attack.slot` column tracks, so the receipt's `validator_identity`
/// FK matches.
async fn attach_slot_leader(attack: &mut SandwichAttack, lookup: &dyn SlotLeaderLookup) {
    if attack.slot_leader.is_some() {
        return;
    }
    if let Some(leader) = lookup.slot_leader(attack.slot).await {
        attack.slot_leader = Some(leader);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_skipped_slots_as_permanent() {
        // Real strings Solana RPC returns for skipped / unavailable slots.
        assert!(is_permanent_slot_error(
            "RPC error: -32009 Slot was skipped, or missing in long-term storage"
        ));
        assert!(is_permanent_slot_error("error -32007: Slot was skipped"));
        assert!(is_permanent_slot_error(
            "-32004: Block not available for slot 100"
        ));
    }

    #[test]
    fn classifies_transient_errors_as_retryable() {
        assert!(!is_permanent_slot_error("429 Too Many Requests"));
        assert!(!is_permanent_slot_error(
            "error trying to connect: connection reset"
        ));
        assert!(!is_permanent_slot_error("timeout elapsed"));
        assert!(!is_permanent_slot_error(
            "-32014: Block status not yet available"
        ));
    }

    // ---------------------------------------------------------------------
    // CLI stdout → JSON.parse → SandwichAttack roundtrip.
    //
    // Vigil's BE consumes our JSONL stream by spawning sandwich-detect and
    // calling readline → JSON.parse on each line. These tests pin the line
    // shapes the BE depends on: header / heartbeat framing, plus a fully
    // populated detection that round-trips through serde without field loss.
    // ---------------------------------------------------------------------

    use sandwich_detector::types::{
        AmmReplayTrace, AttackType, ConfidenceLevel, DetectionMethod, DexType, Severity,
        SwapDirection, SwapEvent,
    };
    use serde_json::Value;

    fn fixture_swap(sig: &str, signer: &str, dir: SwapDirection, idx: usize) -> SwapEvent {
        SwapEvent {
            signature: sig.into(),
            signer: signer.into(),
            dex: DexType::RaydiumV4,
            pool: "POOL".into(),
            direction: dir,
            token_mint: "MINT".into(),
            amount_in: 1_000_000,
            amount_out: 900_000,
            tx_index: idx,
            slot: Some(42),
            fee: Some(5_000),
        }
    }

    fn fixture_attack() -> SandwichAttack {
        SandwichAttack {
            slot: 42,
            attacker: "atk".into(),
            frontrun: fixture_swap("f", "atk", SwapDirection::Buy, 1),
            victim: fixture_swap("v", "vic", SwapDirection::Buy, 2),
            backrun: fixture_swap("b", "atk", SwapDirection::Sell, 3),
            pool: "POOL".into(),
            dex: DexType::RaydiumV4,
            estimated_attacker_profit: Some(100),
            victim_loss_lamports: Some(50),
            victim_loss_lamports_lower: None,
            victim_loss_lamports_upper: None,
            attacker_profit: Some(80),
            price_impact_bps: Some(42),
            frontrun_slot: Some(42),
            backrun_slot: Some(42),
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
            clmm_replay: None,
            dlmm_replay: None,
            attack_signature: None,
            timestamp_ms: Some(1_700_000_000_000),
            attack_type: None,
            severity: Some(Severity::High),
            confidence_level: None,
            slot_leader: Some("validator-pubkey".into()),
            is_wide_sandwich: false,
            receipts: vec![],
            victim_signer: None,
            victim_amount_in: None,
            victim_amount_out: None,
            victim_amount_out_expected: None,
        }
    }

    #[test]
    fn header_line_parses_as_jsonl_header() {
        let mut buf: Vec<u8> = Vec::new();
        write_header(&mut buf, SchemaVersion::VigilV1).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // Exactly one line, terminated by '\n' so JSONL readers don't choke.
        assert!(s.ends_with('\n'));
        assert_eq!(s.lines().count(), 1);
        let v: Value = serde_json::from_str(s.trim_end()).unwrap();
        assert_eq!(v["_header"], Value::Bool(true));
        assert_eq!(v["schema_version"], Value::String("vigil-v1".into()));
        // tool_version comes from CARGO_PKG_VERSION; just check it's non-empty.
        assert!(!v["tool_version"].as_str().unwrap_or("").is_empty());
        // started_at_ms is unix ms — generous lower bound to avoid clock skew.
        assert!(v["started_at_ms"].as_i64().unwrap() > 1_700_000_000_000);
    }

    #[test]
    fn heartbeat_line_parses() {
        let mut buf: Vec<u8> = Vec::new();
        write_heartbeat(&mut buf, 1_735_000_000_000).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: Value = serde_json::from_str(s.trim_end()).unwrap();
        assert_eq!(v["_heartbeat"], Value::from(1_735_000_000_000i64));
        // metrics field always present (default-zero before any
        // enrichment) — Vigil's BE shouldn't have to handle a missing
        // key. Per-DEX bucketing means top-level keys are DEX names;
        // each bucket carries the same six counters as the pre-#4
        // flat shape.
        let metrics = v
            .get("metrics")
            .expect("heartbeat carries a metrics snapshot");
        for dex_key in [
            "raydium_v4",
            "raydium_clmm",
            "raydium_cpmm",
            "orca_whirlpool",
            "jupiter_v6",
            "meteora_dlmm",
            "pump_fun",
            "phoenix",
        ] {
            let bucket = metrics
                .get(dex_key)
                .unwrap_or_else(|| panic!("heartbeat metrics missing DEX {dex_key}: {metrics:?}"));
            for counter_key in [
                "enriched",
                "unsupported_dex",
                "config_unavailable",
                "reserves_missing",
                "replay_failed",
                "cross_boundary_unsupported",
            ] {
                assert!(
                    bucket.get(counter_key).is_some(),
                    "heartbeat metrics[{dex_key}] missing counter {counter_key}: {bucket:?}",
                );
            }
        }
    }

    #[test]
    fn enrichment_metrics_record_increments_matching_counter() {
        // Counter mapping is what downstream ops keys off of — pin
        // each variant lands in the right field of the right DEX's
        // bucket. Mixes DEXes to verify per-DEX dispatch doesn't
        // bleed across buckets.
        let metrics = EnrichmentMetrics::default();
        metrics.record(DexType::RaydiumV4, EnrichmentResult::Enriched);
        metrics.record(DexType::RaydiumV4, EnrichmentResult::Enriched);
        metrics.record(
            DexType::OrcaWhirlpool,
            EnrichmentResult::CrossBoundaryUnsupported,
        );
        metrics.record(DexType::JupiterV6, EnrichmentResult::UnsupportedDex);
        metrics.record(DexType::MeteoraDlmm, EnrichmentResult::ReservesMissing);
        let snap = metrics.snapshot();
        assert_eq!(snap.by_dex[&DexType::RaydiumV4].enriched, 2);
        assert_eq!(
            snap.by_dex[&DexType::OrcaWhirlpool].cross_boundary_unsupported,
            1
        );
        assert_eq!(snap.by_dex[&DexType::JupiterV6].unsupported_dex, 1);
        assert_eq!(snap.by_dex[&DexType::MeteoraDlmm].reserves_missing, 1);
        // Cross-bucket isolation: RaydiumV4's enriched bumps shouldn't
        // leak into any other DEX bucket.
        assert_eq!(snap.by_dex[&DexType::OrcaWhirlpool].enriched, 0);
        assert_eq!(snap.by_dex[&DexType::MeteoraDlmm].enriched, 0);
    }

    #[test]
    fn enrichment_metrics_snapshot_serializes_with_snake_case_keys() {
        // Vigil's TS types expect snake_case keys at both layers:
        // top-level DEX keys (`raydium_v4`, `orca_whirlpool`, ...) and
        // counter keys inside each bucket. `#[serde(flatten)]` on
        // by_dex inlines the HashMap entries at the top level rather
        // than nesting under a `by_dex` field.
        let mut by_dex = HashMap::new();
        by_dex.insert(
            DexType::RaydiumV4,
            EnrichmentMetricsBucketSnapshot {
                enriched: 7,
                cross_boundary_unsupported: 3,
                ..Default::default()
            },
        );
        let snap = EnrichmentMetricsSnapshot { by_dex };
        let json = serde_json::to_value(snap).unwrap();
        assert_eq!(json["raydium_v4"]["enriched"], 7);
        assert_eq!(json["raydium_v4"]["cross_boundary_unsupported"], 3);
        assert_eq!(json["raydium_v4"]["unsupported_dex"], 0);
    }

    #[test]
    fn snapshot_json_preserves_per_dex_dispatch_with_zero_filled_untouched_buckets() {
        // End-to-end pin on the contract Vigil's BE consumes: record
        // events on two DEXes, then serialize the snapshot to JSON and
        // verify (a) the per-DEX dispatch lands the right counter in
        // the right bucket, (b) the same counter under different DEXes
        // stays separate (the entire reason this refactor exists —
        // distinguishing DLMM bracket walk-offs from Whirlpool ones),
        // and (c) untouched DEXes still emit a zero-filled bucket so
        // Vigil's BE never has to handle a missing key.
        let metrics = EnrichmentMetrics::default();
        metrics.record(DexType::OrcaWhirlpool, EnrichmentResult::Enriched);
        metrics.record(
            DexType::OrcaWhirlpool,
            EnrichmentResult::CrossBoundaryUnsupported,
        );
        metrics.record(
            DexType::MeteoraDlmm,
            EnrichmentResult::CrossBoundaryUnsupported,
        );
        metrics.record(
            DexType::MeteoraDlmm,
            EnrichmentResult::CrossBoundaryUnsupported,
        );

        let json = serde_json::to_value(metrics.snapshot()).unwrap();

        // (a) Whirlpool bucket reflects only Whirlpool events.
        assert_eq!(json["orca_whirlpool"]["enriched"], 1);
        assert_eq!(json["orca_whirlpool"]["cross_boundary_unsupported"], 1);

        // (b) Same counter, different DEX, different total. Pre-#4
        // this would have been a single `cross_boundary_unsupported: 3`
        // with no way to attribute the DLMM half from operator-side.
        assert_eq!(json["meteora_dlmm"]["cross_boundary_unsupported"], 2);
        assert_eq!(json["meteora_dlmm"]["enriched"], 0);

        // (c) Pre-population guarantee: every `DexType` variant emits
        // a bucket even with zero events. Picks one untouched
        // supported DEX (raydium_v4) and one unsupported one
        // (pump_fun) to spot-check the contract.
        assert_eq!(json["raydium_v4"]["enriched"], 0);
        assert_eq!(json["raydium_v4"]["cross_boundary_unsupported"], 0);
        assert_eq!(json["pump_fun"]["enriched"], 0);
        assert_eq!(json["pump_fun"]["unsupported_dex"], 0);
    }

    #[test]
    fn all_dex_types_constant_covers_every_dextype_variant() {
        // Pin: `ALL_DEX_TYPES` and the `DexType` enum stay in sync.
        // Adding a variant to `DexType` without adding it to
        // `ALL_DEX_TYPES` means `record(new_variant, ...)` panics in
        // production (the `expect` on the HashMap lookup). The
        // exhaustive match below forces a compile error if a new
        // variant is added — the runtime length check is just a
        // double-check the array literal didn't drift.
        fn _exhaustive_dex_check(d: DexType) -> &'static str {
            match d {
                DexType::RaydiumV4 => "raydium_v4",
                DexType::RaydiumClmm => "raydium_clmm",
                DexType::RaydiumCpmm => "raydium_cpmm",
                DexType::OrcaWhirlpool => "orca_whirlpool",
                DexType::JupiterV6 => "jupiter_v6",
                DexType::MeteoraDlmm => "meteora_dlmm",
                DexType::PumpFun => "pump_fun",
                DexType::Phoenix => "phoenix",
            }
        }
        assert_eq!(ALL_DEX_TYPES.len(), 8);

        // Belt-and-braces: actually exercise `record` against every
        // variant in the constant. If the constant ever gets out of
        // sync with the enum (via an erroneous edit) this panics.
        let metrics = EnrichmentMetrics::default();
        for dex in ALL_DEX_TYPES {
            metrics.record(dex, EnrichmentResult::Enriched);
        }
        let snap = metrics.snapshot();
        for dex in ALL_DEX_TYPES {
            assert_eq!(snap.by_dex[&dex].enriched, 1);
        }
    }

    #[test]
    fn sandwich_line_round_trips_through_serde() {
        let mut attack = fixture_attack();
        let ctx = EmitContext {
            format: OutputFormat::Json,
            evidence_mode: EvidenceMode::Passing,
        };

        let mut buf: Vec<u8> = Vec::new();
        write_sandwich(&mut buf, &mut attack, &ctx).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // One line, NDJSON-shaped.
        assert!(s.ends_with('\n'));
        assert_eq!(s.lines().count(), 1);

        // Re-parse and verify Vigil ERD-aligned fields survived. This is the
        // contract Vigil's BE leans on when it does
        // `prisma.mevAttack.create({ data: JSON.parse(line) })`.
        let v: Value = serde_json::from_str(s.trim_end()).unwrap();
        assert!(v["_header"].is_null());
        assert_eq!(v["attack_signature"].as_str(), Some("v"));
        assert_eq!(v["timestamp_ms"].as_i64(), Some(1_700_000_000_000));
        assert_eq!(v["attack_type"].as_str(), Some("sandwich"));
        assert_eq!(v["severity"].as_str(), Some("high"));
        assert_eq!(v["confidence_level"].as_str(), Some("high"));
        assert_eq!(v["slot_leader"].as_str(), Some("validator-pubkey"));
        assert_eq!(v["is_wide_sandwich"].as_bool(), Some(false));
        assert_eq!(v["victim_signer"].as_str(), Some("vic"));
        assert_eq!(v["victim_amount_in"].as_u64(), Some(1_000_000));
        assert_eq!(v["victim_amount_out"].as_u64(), Some(900_000));
        assert_eq!(v["victim_amount_out_expected"].as_u64(), Some(100));
        assert_eq!(v["attacker_profit"].as_i64(), Some(80));
        assert_eq!(v["victim_loss_lamports"].as_i64(), Some(50));
        // Receipts fan out one-per-victim today.
        let receipts = v["receipts"].as_array().expect("receipts is array");
        assert_eq!(receipts.len(), 1);
        let r = &receipts[0];
        assert_eq!(r["attack_signature"].as_str(), Some("v"));
        assert_eq!(r["victim_wallet"].as_str(), Some("vic"));
        assert_eq!(r["validator_identity"].as_str(), Some("validator-pubkey"));

        // Full SandwichAttack roundtrip — the BE could rehydrate this back
        // into a Rust-side struct if it ever wanted to (e.g. for a bench).
        let back: SandwichAttack = serde_json::from_value(v).unwrap();
        assert_eq!(back.attack_signature.as_deref(), Some("v"));
        assert_eq!(back.severity, Some(Severity::High));
        assert_eq!(back.attack_type, Some(AttackType::Sandwich));
        assert_eq!(back.confidence_level, Some(ConfidenceLevel::High));
        assert_eq!(back.victim_amount_out_expected, Some(100));
    }

    // ---------------------------------------------------------------------
    // attach_slot_leader: end-to-end of the SlotLeaderLookup → SandwichAttack
    // path that fills `slot_leader` and (after finalize) `validator_identity`
    // on the receipt projection. This is the Tier 2 slot of the Vigil
    // validator scorecard; the fixture roundtrip test above only proves the
    // schema carries the value, not that the production wire-up sets it.
    // ---------------------------------------------------------------------

    use async_trait::async_trait;
    use pool_state::SlotLeaderLookup;

    struct MockSlotLeaderLookup {
        leader_for_slot: HashMap<u64, String>,
    }

    #[async_trait]
    impl SlotLeaderLookup for MockSlotLeaderLookup {
        async fn slot_leader(&self, slot: u64) -> Option<String> {
            self.leader_for_slot.get(&slot).cloned()
        }
    }

    #[tokio::test]
    async fn attach_slot_leader_fills_field_then_finalize_propagates_to_receipt() {
        let mut attack = fixture_attack();
        // Fixture pre-sets slot_leader; clear it so we exercise the lookup path.
        attack.slot_leader = None;

        let lookup = MockSlotLeaderLookup {
            leader_for_slot: HashMap::from([(42u64, "leader-from-rpc".to_string())]),
        };

        attach_slot_leader(&mut attack, &lookup).await;
        assert_eq!(attack.slot_leader.as_deref(), Some("leader-from-rpc"));

        // Finalize should fan the slot leader out to the receipt's
        // validator_identity FK (mirrors Vigil's mev_receipt schema).
        attack.finalize_for_vigil();
        assert_eq!(attack.receipts.len(), 1);
        assert_eq!(
            attack.receipts[0].validator_identity.as_deref(),
            Some("leader-from-rpc")
        );
    }

    #[tokio::test]
    async fn attach_slot_leader_is_idempotent_when_caller_set_value() {
        let mut attack = fixture_attack();
        // Caller already populated slot_leader (e.g. fixture replay path).
        attack.slot_leader = Some("preset-leader".into());

        // Lookup would return a different leader for the same slot; the
        // pre-existing value must win so caller-supplied data is sticky.
        let lookup = MockSlotLeaderLookup {
            leader_for_slot: HashMap::from([(42u64, "rpc-leader".to_string())]),
        };

        attach_slot_leader(&mut attack, &lookup).await;
        assert_eq!(attack.slot_leader.as_deref(), Some("preset-leader"));
    }

    #[tokio::test]
    async fn attach_slot_leader_leaves_field_none_when_lookup_fails() {
        let mut attack = fixture_attack();
        attack.slot_leader = None;
        // Empty map — every lookup returns None (RPC unreachable / unknown slot).
        let lookup = MockSlotLeaderLookup {
            leader_for_slot: HashMap::new(),
        };

        attach_slot_leader(&mut attack, &lookup).await;
        assert!(attack.slot_leader.is_none());
    }

    #[test]
    fn full_jsonl_stream_discriminates_header_heartbeat_and_attack() {
        // Simulate one complete `--follow` session: header, heartbeat,
        // detection, heartbeat. Every line must be parseable by
        // discriminating on the leading underscore-prefixed keys, mirroring
        // the TS `parseDetectorLine` helper in `contrib/vigil-types.ts`.
        let mut buf: Vec<u8> = Vec::new();
        write_header(&mut buf, SchemaVersion::VigilV1).unwrap();
        write_heartbeat(&mut buf, 1).unwrap();
        let mut attack = fixture_attack();
        let ctx = EmitContext {
            format: OutputFormat::Json,
            evidence_mode: EvidenceMode::Off,
        };
        write_sandwich(&mut buf, &mut attack, &ctx).unwrap();
        write_heartbeat(&mut buf, 2).unwrap();

        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 4);

        let h: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(h["_header"], Value::Bool(true));

        let hb1: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(hb1["_heartbeat"].as_i64(), Some(1));
        assert!(hb1.get("_header").is_none());

        let body: Value = serde_json::from_str(lines[2]).unwrap();
        assert!(body.get("_header").is_none());
        assert!(body.get("_heartbeat").is_none());
        assert_eq!(body["attack_signature"].as_str(), Some("v"));

        let hb2: Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(hb2["_heartbeat"].as_i64(), Some(2));
    }
}
