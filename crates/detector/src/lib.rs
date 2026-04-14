// Facade crate: re-exports from sub-crates so existing consumers keep working.

pub use swap_events::dex;
pub use swap_events::error;
pub use swap_events::parser;
pub use swap_events::source;
pub use swap_events::types;

pub mod detector {
    pub use detector_sameblock::detect_sandwiches;
}

pub mod window {
    pub use detector_window::{
        BundleLookup, FilterConfig, FilteredWindowDetector, MemoryBundleLookup,
        NaiveWindowDetector, WindowDetector,
    };
}
