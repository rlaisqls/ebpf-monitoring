use common::error::Result;

use async_trait::async_trait;

pub trait Component {
    fn run(&mut self) -> Result<()>;
}