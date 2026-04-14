use anyhow::Result;
use clap::Parser;
use sandwich_detector::{
    detector,
    dex::{self, DexParser},
    source::{rpc::RpcBlockSource, BlockSource},
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
        for slot in start..=end {
            process_slot(&source, &parsers, slot, &cli.format).await?;
        }
    } else if cli.follow {
        follow_mode(&source, &parsers, &cli.format, cli.poll_interval).await?;
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

async fn follow_mode(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    format: &OutputFormat,
    poll_interval: u64,
) -> Result<()> {
    let mut last_slot = source.get_latest_slot().await?;
    tracing::info!("Follow mode -- starting from slot {}", last_slot);

    let mut consecutive_errors: u32 = 0;

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
                process_slot(source, parsers, slot, format).await?;
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
