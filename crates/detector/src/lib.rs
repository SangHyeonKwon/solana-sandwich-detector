// Facade crate: re-exports from sub-crates so existing consumers keep working,
// plus this crate's own modules (Authority-Hop heuristic).

pub mod authority_hop;

pub use swap_events::dex;
pub use swap_events::error;
pub use swap_events::parser;
pub use swap_events::source;
pub use swap_events::types;
pub use swap_events::SCHEMA_VERSION;

pub mod detector {
    pub use crate::authority_hop::detect_authority_hop_sandwiches;
    pub use detector_sameblock::detect_sandwiches;
}

pub mod window {
    pub use detector_window::{
        BundleLookup, FilterConfig, FilteredWindowDetector, MemoryBundleLookup,
        NaiveWindowDetector, WindowDetector,
    };
}
