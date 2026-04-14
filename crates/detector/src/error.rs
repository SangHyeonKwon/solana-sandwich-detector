use thiserror::Error;

#[derive(Error, Debug)]
pub enum DetectorError {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Block not available for slot {0}")]
    BlockNotAvailable(u64),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, DetectorError>;
