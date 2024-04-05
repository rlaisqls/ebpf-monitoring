use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("data not found: {0}")]
    NotFound(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("must be paused")]
    MustBePaused,
    #[error("closed")]
    Closed,
    #[error("end of ring")]
    EndOfRing,
    #[error("end of ring")]
    UnexpectedEof,
    #[error("Unknown event: {0}")]
    UnknownEvent(u32),
    #[error("OS Error: {0}")]
    OSError(String),
    #[error("Symbol Error: {0}")]
    SymbolError(String)
}

pub type Result<T, E = Error> = std::result::Result<T, E>;