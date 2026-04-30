//! Golden corpus replay test.
//!
//! Reads every manifest under `tests/golden/manifests/` and re-runs the
//! detector against the referenced mainnet fixture. Each manifest pins
//! the count window the detector must stay inside — a regression that
//! drops detection count below the floor (false negatives) or pushes it
//! over the ceiling (false positives) fails the suite.
//!
//! Adding a case is a two-step:
//!   1. Drop a block JSON under `fixtures/`.
//!   2. Add a `<name>.json` manifest pointing at it with `min_total` /
//!      `max_total` based on a baseline run.
//!
//! Fixture paths in the manifest are repo-root-relative. The test
//! resolves them against `CARGO_MANIFEST_DIR/../..` so the suite works
//! regardless of where `cargo test` is invoked from.
//!
//! Failure messages always include the manifest filename so a CI failure
//! is one grep away from the offending case.

use std::fs;
use std::path::{Path, PathBuf};

use sandwich_detector::{
    detector,
    dex::{self},
    parser,
    types::{SandwichAttack, SwapEvent},
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GoldenManifest {
    slot: u64,
    /// Repo-root-relative path to the block fixture JSON.
    fixture: String,
    #[allow(dead_code)]
    description: String,
    /// Detection-count floor — fewer than this means the detector
    /// regressed on recall.
    min_total: usize,
    /// Detection-count ceiling — more than this means the detector
    /// regressed on precision (probably a new false-positive class).
    max_total: usize,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn manifests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("manifests")
}

fn load_manifests() -> Vec<(PathBuf, GoldenManifest)> {
    let dir = manifests_dir();
    let entries =
        fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {}: {}", dir.display(), e));
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        let manifest: GoldenManifest = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));
        out.push((path, manifest));
    }
    out
}

fn run_detector_on_fixture(fixture_path: &Path, slot: u64) -> Vec<SandwichAttack> {
    let json = fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("read fixture {}: {}", fixture_path.display(), e));
    let block: solana_transaction_status::UiConfirmedBlock = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("parse fixture {}: {}", fixture_path.display(), e));
    let block_data = parser::parse_block(slot, block).expect("parse_block failed");

    let parsers = dex::all_parsers();
    let swaps: Vec<SwapEvent> = block_data
        .transactions
        .iter()
        .flat_map(|tx| dex::extract_swaps(tx, &parsers))
        .collect();
    detector::detect_sandwiches(slot, &swaps)
}

#[test]
fn golden_corpus_within_count_bounds() {
    let manifests = load_manifests();
    assert!(
        !manifests.is_empty(),
        "no golden manifests found in {}",
        manifests_dir().display()
    );

    let root = repo_root();
    let mut failures: Vec<String> = Vec::new();

    for (manifest_path, manifest) in manifests {
        let fixture_path = root.join(&manifest.fixture);
        if !fixture_path.exists() {
            failures.push(format!(
                "{}: fixture missing at {}",
                manifest_path.display(),
                fixture_path.display()
            ));
            continue;
        }
        let detections = run_detector_on_fixture(&fixture_path, manifest.slot);
        let count = detections.len();
        if count < manifest.min_total || count > manifest.max_total {
            failures.push(format!(
                "{}: slot {} produced {} detections, expected [{}, {}]",
                manifest_path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| manifest_path.display().to_string()),
                manifest.slot,
                count,
                manifest.min_total,
                manifest.max_total,
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "golden corpus regressions:\n  - {}",
            failures.join("\n  - ")
        );
    }
}
