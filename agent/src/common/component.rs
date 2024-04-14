use common::error::Result;



pub trait Component {
    async fn run(&mut self);
}