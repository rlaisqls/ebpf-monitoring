use std::collections::HashMap;



use std::time::Duration;




pub const ADDRESS_LABEL: &str = "__address__";
pub type Target = HashMap<String, String>;

#[derive(Debug)]
pub struct Arguments {
	pub host: String,
	pub port: u16,
	pub host_networking_host: String,
	pub refresh_interval: Duration,
}

impl Default for Arguments {
	fn default() -> Self {
		Self {
			host: String::from("unix:///var/run/docker.sock"),
			port: 80,
			host_networking_host: String::from("localhost"),
			refresh_interval: Duration::from_secs(60),
		}
	}
}