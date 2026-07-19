use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZexError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("layout policy violation: {0}")]
    LayoutViolation(String),

    #[error("invalid .zex file: {0}")]
    InvalidFormat(String),

    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("manifest integrity check failed: {0}")]
    ManifestMismatch(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ZexError>;
