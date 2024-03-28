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
    UnknownEvent(u32)
}

pub type Result<T, E = Error> = std::result::Result<T, E>;