use log::info;
use std::io::{stdout, Write};

fn main() -> Result<(), ()> {
    env_logger::init();
    info!("No thank you");

    let mut lock = stdout().lock();
    writeln!(lock, "hello world").unwrap();

    Ok(())
}