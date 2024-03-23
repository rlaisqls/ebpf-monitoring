use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("data not found: {0}")]
    NotFound(String),
    #[error("invalid data: {0}")]
    InvalidData(String)
}

pub type Result<T, E = Error> = std::result::Result<T, E>;