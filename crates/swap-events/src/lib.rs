pub mod dex;
pub mod error;
pub mod observe;
pub mod parser;
pub mod source;
pub mod types;

/// Output schema version emitted by the detector. Vigil's BE uses this to
/// detect breaking changes — bump it whenever `SandwichAttack` or `MevReceipt`
/// gain or lose fields in a way the consumer cannot ignore.
pub const SCHEMA_VERSION: &str = "vigil-v1";
