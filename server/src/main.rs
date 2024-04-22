use std::io;
use std::net::TcpListener;

use log4rs;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use log::{info, LevelFilter};
use polling::{Event, Events, Poller};

fn main() -> io::Result<()> {

	let stdout = ConsoleAppender::builder().build();
	let config = Config::builder()
		.appender(Appender::builder().build("stdout", Box::new(stdout)))
		.build(Root::builder().appender("stdout").build(LevelFilter::Trace))
		.unwrap();
	let _handle = log4rs::init_config(config).unwrap();

	let l1 = TcpListener::bind("127.0.0.1:8001")?;
	let l2 = TcpListener::bind("127.0.0.1:8002")?;
	l1.set_nonblocking(true)?;
	l2.set_nonblocking(true)?;

	let poller = Poller::new()?;
	unsafe {
		poller.add(&l1, Event::readable(1))?;
		poller.add(&l2, Event::readable(2))?;
	}

	println!("You can connect to the server using `nc`:");
	println!(" $ nc 127.0.0.1 8001");
	println!(" $ nc 127.0.0.1 8002");

	let mut events = Events::new();
	loop {
		events.clear();
		poller.wait(&mut events, None)?;
		dbg!(&events.len());
		for ev in events.iter() {
			dbg!(&ev);
			match ev.key {
				1 => {
					println!("Accept on l1");
					l1.accept()?;
					poller.modify(&l1, Event::readable(1))?;
				}
				2 => {
					println!("Accept on l2");
					l2.accept()?;
					poller.modify(&l2, Event::readable(2))?;
				}
				_ => unreachable!(),
			}
		}
	}
}