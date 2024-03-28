use std::error::Error;

use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct Arguments {
}

#[async_trait]
pub trait Component: Send + Sync {
    async fn run(&self) -> Result<()>;
    async fn update(&mut self, args: Arguments) -> Result<()>;
}