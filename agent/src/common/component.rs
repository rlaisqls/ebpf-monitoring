use common::error::Result;



pub trait Component {
    fn run(&mut self) -> Result<()>;
}