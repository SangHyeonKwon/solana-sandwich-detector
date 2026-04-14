use std::io::{self, BufRead, Write};

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use swap_events::source::BlockSource as _;

use sandwich_eval::{
    helius::{self, HeliusClient},
    jito::JitoBundleClient,
    labels::{
        LabelDataset, LabelProvenance, LabeledExample, DatasetMetadata, SandwichTxSigs,
    },
    metrics,
    runner,
    sampler,
};

#[derive(Parser)]
#[command(name = "sandwich-eval")]
#[command(about = "Evaluation framework for Solana sandwich detectors")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch Jito bundle ground truth for a slot range.
    FetchJito {
        #[arg(long)]
        start_slot: u64,
        #[arg(long)]
        end_slot: u64,
        #[arg(long, default_value = "data/jito-bundles.json")]
        output: String,
    },

    /// Run the detector against labeled data and compute metrics.
    Measure {
        /// Path to labels.json
        #[arg(long)]
        labels: String,
        /// Solana RPC endpoint URL
        #[arg(long, env = "RPC_URL")]
        rpc: String,
        /// Which detector to evaluate
        #[arg(long, default_value = "sameblock")]
        detector: DetectorChoice,
        /// Window size in slots (for window detector)
        #[arg(long, default_value = "4")]
        window_slots: usize,
        /// Path to save evaluation results
        #[arg(long)]
        output: Option<String>,
    },

    /// Pretty-print evaluation results.
    Report {
        /// Path to eval-results.json
        #[arg(long)]
        results: String,
    },

    /// Sample random slots for hand-labeling.
    Sample {
        /// Number of random slots to sample
        #[arg(long, default_value = "200")]
        count: usize,
        /// Start of slot range
        #[arg(long)]
        start_slot: u64,
        /// End of slot range
        #[arg(long)]
        end_slot: u64,
        /// Solana RPC endpoint URL
        #[arg(long, env = "RPC_URL")]
        rpc: String,
        /// Output file for sampled slot list
        #[arg(long, default_value = "data/sampled-slots.json")]
        output: String,
    },

    /// Interactively label sandwich candidates.
    Label {
        /// Path to sampled slots file
        #[arg(long)]
        slots: String,
        /// Path to output/append labels
        #[arg(long, default_value = "data/labels.json")]
        output: String,
        /// Solana RPC endpoint URL
        #[arg(long, env = "RPC_URL")]
        rpc: String,
        /// Helius API key for enhanced TX data
        #[arg(long, env = "HELIUS_API_KEY")]
        helius_key: Option<String>,
        /// Your name for the labeled_by field
        #[arg(long, default_value = "anon")]
        labeler: String,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum DetectorChoice {
    Sameblock,
    Window,
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

    match cli.cmd {
        Command::FetchJito {
            start_slot,
            end_slot,
            output,
        } => fetch_jito(start_slot, end_slot, &output).await?,

        Command::Measure {
            labels,
            rpc,
            detector,
            window_slots,
            output,
        } => measure(&labels, &rpc, &detector, window_slots, output.as_deref()).await?,

        Command::Report { results } => report(&results)?,

        Command::Sample {
            count,
            start_slot,
            end_slot,
            rpc,
            output,
        } => sample(count, start_slot, end_slot, &rpc, &output).await?,

        Command::Label {
            slots,
            output,
            rpc,
            helius_key,
            labeler,
        } => label(&slots, &output, &rpc, helius_key.as_deref(), &labeler).await?,
    }

    Ok(())
}

async fn fetch_jito(start_slot: u64, end_slot: u64, output: &str) -> Result<()> {
    tracing::info!("Fetching Jito bundles for slots {}..{}", start_slot, end_slot);

    let client = JitoBundleClient::new();
    let bundles = client.get_bundles_for_range(start_slot, end_slot).await?;

    tracing::info!("Found {} bundles", bundles.len());

    let sandwich_candidates: Vec<_> = bundles
        .iter()
        .filter(|b| b.transactions.len() >= 3)
        .collect();

    tracing::info!(
        "{} bundles have 3+ transactions (sandwich candidates)",
        sandwich_candidates.len()
    );

    let json = serde_json::to_string_pretty(&bundles)?;
    if let Some(parent) = std::path::Path::new(output).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, json)?;
    tracing::info!("Saved to {}", output);

    Ok(())
}

async fn measure(
    labels_path: &str,
    rpc_url: &str,
    detector: &DetectorChoice,
    window_slots: usize,
    output: Option<&str>,
) -> Result<()> {
    let dataset = LabelDataset::load(labels_path)?;
    tracing::info!(
        "Loaded {} labels ({} positive, {} negative)",
        dataset.labels.len(),
        dataset.positive_count(),
        dataset.negative_count()
    );

    let detections = match detector {
        DetectorChoice::Sameblock => {
            runner::run_sameblock_on_labels(&dataset, rpc_url).await?
        }
        DetectorChoice::Window => {
            runner::run_window_on_labels(&dataset, rpc_url, window_slots).await?
        }
    };

    tracing::info!("Detector produced {} detections", detections.len());

    let result = metrics::evaluate(&dataset.labels, &detections);
    println!("{}", result);

    if let Some(output_path) = output {
        let json = serde_json::to_string_pretty(&result)?;
        if let Some(parent) = std::path::Path::new(output_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(output_path, json)?;
        tracing::info!("Results saved to {}", output_path);
    }

    Ok(())
}

fn report(results_path: &str) -> Result<()> {
    let contents = std::fs::read_to_string(results_path)?;
    let result: metrics::EvalResult = serde_json::from_str(&contents)?;
    println!("{}", result);

    println!("Per-example breakdown:");
    for detail in &result.details {
        let status = match detail.match_type {
            metrics::MatchType::TruePositive => "TP",
            metrics::MatchType::FalsePositive => "FP",
            metrics::MatchType::FalseNegative => "FN",
            metrics::MatchType::TrueNegative => "TN",
        };
        println!("  [{}] {}", status, detail.label_id);
    }

    Ok(())
}

async fn sample(
    count: usize,
    start_slot: u64,
    end_slot: u64,
    rpc_url: &str,
    output: &str,
) -> Result<()> {
    tracing::info!(
        "Sampling {} random slots from {}..{}",
        count,
        start_slot,
        end_slot
    );

    let sample_set = sampler::sample_slots(rpc_url, start_slot, end_slot, count).await?;

    let with_blocks = sample_set.sampled.iter().filter(|s| s.has_block).count();
    let with_swaps = sample_set.sampled.iter().filter(|s| s.swap_count > 0).count();
    let with_candidates = sample_set
        .sampled
        .iter()
        .filter(|s| s.sameblock_candidates > 0)
        .count();

    tracing::info!(
        "Sampled {} slots: {} with blocks, {} with swaps, {} with sandwich candidates",
        sample_set.sampled.len(),
        with_blocks,
        with_swaps,
        with_candidates
    );

    let json = serde_json::to_string_pretty(&sample_set)?;
    if let Some(parent) = std::path::Path::new(output).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, json)?;
    tracing::info!("Saved to {}", output);

    Ok(())
}

async fn label(
    slots_path: &str,
    output_path: &str,
    rpc_url: &str,
    helius_key: Option<&str>,
    labeler: &str,
) -> Result<()> {
    let sample_json = std::fs::read_to_string(slots_path)?;
    let sample_set: sampler::SampleSet = serde_json::from_str(&sample_json)?;

    let helius = helius_key.map(HeliusClient::new);

    // Load or create dataset
    let mut dataset = if std::path::Path::new(output_path).exists() {
        LabelDataset::load(output_path)?
    } else {
        LabelDataset {
            version: 1,
            metadata: DatasetMetadata {
                name: "solana-sandwich-eval-v1".into(),
                description: "Open Solana sandwich evaluation dataset".into(),
                created_at: Utc::now(),
                slot_range: (sample_set.start_slot, sample_set.end_slot),
                total_slots_sampled: sample_set.sampled.len(),
            },
            labels: Vec::new(),
        }
    };

    let already_labeled: std::collections::HashSet<u64> =
        dataset.labels.iter().map(|l| l.slot).collect();

    // Process slots with candidates first (more interesting)
    let mut slots_to_label: Vec<_> = sample_set
        .sampled
        .iter()
        .filter(|s| s.has_block && !already_labeled.contains(&s.slot))
        .collect();
    slots_to_label.sort_by(|a, b| b.sameblock_candidates.cmp(&a.sameblock_candidates));

    let source = swap_events::source::rpc::RpcBlockSource::new(rpc_url);
    let parsers = swap_events::dex::all_parsers();
    let stdin = io::stdin();
    let mut reader = stdin.lock();

    println!("\n=== Solana Sandwich Labeling Tool ===");
    println!("  {} slots to label ({} already done)", slots_to_label.len(), already_labeled.len());
    println!("  Commands: [y]es sandwich, [n]ot sandwich, [s]kip, [q]uit\n");

    for (i, sample) in slots_to_label.iter().enumerate() {
        println!("--- [{}/{}] Slot {} ({} swaps, {} candidates) ---",
            i + 1, slots_to_label.len(), sample.slot, sample.swap_count, sample.sameblock_candidates);

        // Get block and run detector
        let block = match source.get_block(sample.slot).await {
            Ok(b) => b,
            Err(e) => {
                println!("  Failed to fetch block: {}", e);
                continue;
            }
        };

        let swaps: Vec<_> = block
            .transactions
            .iter()
            .flat_map(|tx| swap_events::dex::extract_swaps(tx, &parsers))
            .collect();

        let sandwiches = detector_sameblock::detect_sandwiches(sample.slot, &swaps);

        if sandwiches.is_empty() {
            println!("  No sandwich candidates in this slot.");
            continue;
        }

        for (j, sandwich) in sandwiches.iter().enumerate() {
            println!("\n  Candidate {}/{}:", j + 1, sandwiches.len());
            println!("    Pool:    {}", sandwich.pool);
            println!("    DEX:     {}", sandwich.dex);
            println!("    Attacker: {}", sandwich.attacker);
            println!("    Frontrun: {} (Buy: {} -> {})",
                &sandwich.frontrun.signature[..16.min(sandwich.frontrun.signature.len())],
                sandwich.frontrun.amount_in,
                sandwich.frontrun.amount_out);
            println!("    Victim:   {} ({})",
                &sandwich.victim.signature[..16.min(sandwich.victim.signature.len())],
                sandwich.victim.signer);
            println!("    Backrun:  {} (Sell: {} -> {})",
                &sandwich.backrun.signature[..16.min(sandwich.backrun.signature.len())],
                sandwich.backrun.amount_in,
                sandwich.backrun.amount_out);
            if let Some(profit) = sandwich.estimated_attacker_profit {
                println!("    Est. profit: {} lamports", profit);
            }

            // Helius enrichment if available
            if let Some(ref h) = helius {
                let sigs = vec![
                    sandwich.frontrun.signature.clone(),
                    sandwich.victim.signature.clone(),
                    sandwich.backrun.signature.clone(),
                ];
                match h.get_parsed_transactions(&sigs).await {
                    Ok(txs) => {
                        for tx in &txs {
                            println!("\n  Helius data:");
                            print!("{}", helius::format_for_labeling(tx));
                        }
                    }
                    Err(e) => {
                        println!("  (Helius lookup failed: {})", e);
                    }
                }
            }

            print!("\n  Is this a real sandwich? [y/n/s/q]: ");
            io::stdout().flush()?;

            let mut input = String::new();
            reader.read_line(&mut input)?;
            let input = input.trim().to_lowercase();

            match input.as_str() {
                "y" | "yes" => {
                    let label = LabeledExample {
                        id: format!("{}-{}-{}", sample.slot, j, "confirmed"),
                        slot: sample.slot,
                        tx_signatures: SandwichTxSigs {
                            frontrun: sandwich.frontrun.signature.clone(),
                            victim: sandwich.victim.signature.clone(),
                            backrun: sandwich.backrun.signature.clone(),
                        },
                        pool: sandwich.pool.clone(),
                        is_sandwich: true,
                        attacker_wallets: vec![sandwich.attacker.clone()],
                        provenance: LabelProvenance::DetectorConfirmed,
                        notes: String::new(),
                        labeled_at: Utc::now(),
                        labeled_by: labeler.to_string(),
                    };
                    dataset.labels.push(label);
                    dataset.save(output_path)?;
                    println!("  -> Labeled as SANDWICH (saved)");
                }
                "n" | "no" => {
                    let label = LabeledExample {
                        id: format!("{}-{}-{}", sample.slot, j, "rejected"),
                        slot: sample.slot,
                        tx_signatures: SandwichTxSigs {
                            frontrun: sandwich.frontrun.signature.clone(),
                            victim: sandwich.victim.signature.clone(),
                            backrun: sandwich.backrun.signature.clone(),
                        },
                        pool: sandwich.pool.clone(),
                        is_sandwich: false,
                        attacker_wallets: vec![],
                        provenance: LabelProvenance::DetectorRejected,
                        notes: String::new(),
                        labeled_at: Utc::now(),
                        labeled_by: labeler.to_string(),
                    };
                    dataset.labels.push(label);
                    dataset.save(output_path)?;
                    println!("  -> Labeled as NOT SANDWICH (saved)");
                }
                "s" | "skip" => {
                    println!("  -> Skipped");
                    continue;
                }
                "q" | "quit" => {
                    println!("\nLabeling session ended. {} total labels.", dataset.labels.len());
                    return Ok(());
                }
                _ => {
                    println!("  -> Unknown input, skipping");
                }
            }
        }
    }

    println!("\nLabeling complete! {} total labels.", dataset.labels.len());
    Ok(())
}
