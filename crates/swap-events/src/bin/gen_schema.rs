//! Emit the canonical Vigil-v1 JSON Schema for `SandwichAttack` to stdout.
//!
//! Vigil's BE imports this file to generate matching TS types and to validate
//! payloads before persisting. The schema is committed under
//! `crates/swap-events/schema/vigil-v1.json`; CI should diff `cargo run -p
//! swap-events --bin gen-schema` against the committed copy and fail on drift.

use schemars::schema_for;
use swap_events::types::SandwichAttack;
use swap_events::SCHEMA_VERSION;

fn main() {
    let mut schema = schema_for!(SandwichAttack);
    // Stamp the schema's title and metadata so downstream consumers can
    // identify the contract by inspection rather than file path.
    let meta = schema.schema.metadata();
    meta.title = Some(format!("SandwichAttack ({SCHEMA_VERSION})"));
    meta.description = Some(format!(
        "Solana sandwich-detector output schema, version {SCHEMA_VERSION}. \
         Each detection serializes one row of this shape; lines prefixed \
         with `_header` or `_heartbeat` are framing and not validated against \
         this schema."
    ));

    let json = serde_json::to_string_pretty(&schema).expect("serialize schema");
    println!("{json}");
}
