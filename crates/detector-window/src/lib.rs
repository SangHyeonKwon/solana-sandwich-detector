mod filters;
mod naive;
mod pipeline;

use swap_events::types::{SandwichAttack, SwapEvent};

/// A window-based detector that correlates swap events across multiple slots.
pub trait WindowDetector: Send + Sync {
    /// Feed swap events from a new slot into the window.
    /// Returns any newly detected sandwich attacks.
    fn ingest_slot(&mut self, slot: u64, swaps: Vec<SwapEvent>) -> Vec<SandwichAttack>;

    /// Flush any pending detections (e.g., when the window expires).
    fn flush(&mut self) -> Vec<SandwichAttack>;

    /// Current window size in slots.
    fn window_size(&self) -> usize;
}

pub use filters::{BundleLookup, FilterConfig, MemoryBundleLookup};
pub use naive::NaiveWindowDetector;
pub use pipeline::FilteredWindowDetector;
