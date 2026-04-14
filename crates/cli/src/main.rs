use anyhow::Result;
use clap::Parser;
use sandwich_detector::{
    detector,
    dex::{self, DexParser},
    source::{rpc::RpcBlockSource, BlockSource},
    window::{NaiveWindowDetector, WindowDetector},
};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "sandwich-detect")]
#[command(about = "Detect sandwich attacks on Solana")]
struct Cli {
    /// Solana RPC endpoint URL
    #[arg(long, env = "RPC_URL")]
    rpc: String,

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
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Pretty,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let source = RpcBlockSource::new(&cli.rpc);
    let parsers = dex::all_parsers();

    if let Some(slot) = cli.slot {
        process_slot(&source, &parsers, slot, &cli.format).await?;
    } else if let Some(range) = &cli.range {
        let (start, end) = parse_range(range)?;
        if let Some(window_size) = cli.window {
            process_range_with_window(&source, &parsers, start, end, window_size, &cli.format)
                .await?;
        } else {
            for slot in start..=end {
                process_slot(&source, &parsers, slot, &cli.format).await?;
            }
        }
    } else if cli.follow {
        follow_mode(&source, &parsers, &cli.format, cli.poll_interval, cli.window).await?;
    } else {
        let slot = source.get_latest_slot().await?;
        tracing::info!("Processing latest slot: {}", slot);
        process_slot(&source, &parsers, slot, &cli.format).await?;
    }

    Ok(())
}

async fn process_slot(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    slot: u64,
    format: &OutputFormat,
) -> Result<()> {
    let block = match source.get_block(slot).await {
        Ok(block) => block,
        Err(e) => {
            tracing::warn!("Slot {}: {}", slot, e);
            return Ok(());
        }
    };

    let mut all_swaps = Vec::new();
    for tx in &block.transactions {
        let swaps = dex::extract_swaps(tx, parsers);
        all_swaps.extend(swaps);
    }

    let sandwiches = detector::detect_sandwiches(slot, &all_swaps);

    for sandwich in &sandwiches {
        match format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string(sandwich)?);
            }
            OutputFormat::Pretty => {
                println!("{}", serde_json::to_string_pretty(sandwich)?);
            }
        }
    }

    tracing::info!(
        "Slot {}: {} swap(s), {} sandwich(es)",
        slot,
        all_swaps.len(),
        sandwiches.len()
    );

    Ok(())
}

async fn process_range_with_window(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    start: u64,
    end: u64,
    window_size: usize,
    format: &OutputFormat,
) -> Result<()> {
    let mut window_detector = NaiveWindowDetector::new(window_size);
    let mut total_sameblock = 0usize;
    let mut total_window = 0usize;

    for slot in start..=end {
        let block = match source.get_block(slot).await {
            Ok(block) => block,
            Err(e) => {
                tracing::warn!("Slot {}: {}", slot, e);
                continue;
            }
        };

        let swaps: Vec<_> = block
            .transactions
            .iter()
            .flat_map(|tx| dex::extract_swaps(tx, parsers))
            .collect();

        // Same-block detection
        let sameblock = detector::detect_sandwiches(slot, &swaps);
        total_sameblock += sameblock.len();
        for s in &sameblock {
            output_sandwich(s, format)?;
        }

        // Window detection (cross-slot only)
        let window_results = window_detector.ingest_slot(slot, swaps);
        total_window += window_results.len();
        for s in &window_results {
            output_sandwich(s, format)?;
        }
    }

    // Flush remaining
    let flushed = window_detector.flush();
    total_window += flushed.len();
    for s in &flushed {
        output_sandwich(s, format)?;
    }

    tracing::info!(
        "Range {}-{}: {} same-block, {} cross-slot sandwiches",
        start,
        end,
        total_sameblock,
        total_window,
    );

    Ok(())
}

fn output_sandwich(
    sandwich: &sandwich_detector::types::SandwichAttack,
    format: &OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string(sandwich)?),
        OutputFormat::Pretty => println!("{}", serde_json::to_string_pretty(sandwich)?),
    }
    Ok(())
}

async fn follow_mode(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    format: &OutputFormat,
    poll_interval: u64,
    window: Option<usize>,
) -> Result<()> {
    let mut last_slot = source.get_latest_slot().await?;
    tracing::info!("Follow mode -- starting from slot {}", last_slot);

    let mut consecutive_errors: u32 = 0;
    let mut window_detector = window.map(NaiveWindowDetector::new);

    loop {
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
                let block = match source.get_block(slot).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("Slot {}: {}", slot, e);
                        continue;
                    }
                };

                let swaps: Vec<_> = block
                    .transactions
                    .iter()
                    .flat_map(|tx| dex::extract_swaps(tx, parsers))
                    .collect();

                // Same-block detection
                let sandwiches = detector::detect_sandwiches(slot, &swaps);
                for s in &sandwiches {
                    output_sandwich(s, format)?;
                }
                tracing::info!(
                    "Slot {}: {} swap(s), {} sandwich(es)",
                    slot,
                    swaps.len(),
                    sandwiches.len()
                );

                // Window detection if enabled
                if let Some(ref mut wd) = window_detector {
                    let cross = wd.ingest_slot(slot, swaps);
                    for s in &cross {
                        output_sandwich(s, format)?;
                    }
                }
            }
            last_slot = current_slot;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval)).await;
    }
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
