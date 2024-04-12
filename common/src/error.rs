use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq, Ord, PartialOrd)]
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
    SymbolError(String),
    #[error("ELF Error: {0}")]
    ELFError(String),
    #[error("Proc Error: {0}")]
    ProcError(String),
    #[error("Session Error: {0}")]
    SessionError(String),
    #[error("Map Error: {0}")]
    MapError(String)
}

pub type Result<T, E = Error> = std::result::Result<T, E>;