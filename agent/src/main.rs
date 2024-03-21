use std::panic;
use std::path::Path;
use log::error;
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;

fn main() -> Result<(), ()> {
    panic::set_hook(Box::new(|panic_info| {
        error!("{:?}", panic_info.to_string());
    }));
    // let mut t = trident::Trident::start(
    //     &Path::new(&opts.config_file)
    // )?;
    // wait_on_signals();
    // t.stop();

    Ok(())
}
