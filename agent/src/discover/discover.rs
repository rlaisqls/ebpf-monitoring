use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use prometheus::{self, proto};
use serde::{Deserialize, Serialize};

pub const ADDRESS_LABEL: &str = "__address__";
pub type Target = HashMap<String, String>;

#[derive(Debug)]
pub struct Arguments {
	pub host: String
}

impl Default for Arguments {
	fn default() -> Self {
		Self {
			host: String::from("unix:///var/run/docker.sock")
		}
	}
}