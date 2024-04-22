


#[allow(async_fn_in_trait)]
pub trait Component {
    async fn run(&mut self);
}