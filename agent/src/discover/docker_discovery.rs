use std::{
	collections::HashMap,
	error::Error,
	fmt
	,
	time::Duration,
};
use std::any::Any;
use std::str::FromStr;
use docker_api::Docker;
use docker_api::opts::ContainerListOpts;
use log::info;
use regex::Regex;

use common::error::Result;
use serde::{Deserialize, Serialize};
use url::Url;
use common::ebpf::sd::target::Target;
use common::error::Error::OSError;
use crate::discover::discover::{ADDRESS_LABEL, Arguments};
use crate::discover::network::get_networks_labels;
use crate::ebpf::ebpf_linux::push_api::{PushRequest, RawProfileSeries};

const DOCKER_LABEL: &str = "prometheus_docker_";
const DOCKER_LABEL_CONTAINER_PREFIX: &str = "prometheus_docker_container_";
const DOCKER_LABEL_CONTAINER_ID: &str = "prometheus_docker_container_id";
const DOCKER_LABEL_CONTAINER_NAME: &str = "prometheus_docker_container_name";
const DOCKER_LABEL_CONTAINER_NETWORK_MODE: &str = "prometheus_docker_container_network_mode";
const DOCKER_LABEL_CONTAINER_LABEL_PREFIX: &str = "prometheus_docker_container_label_";
const DOCKER_LABEL_NETWORK_PREFIX: &str = "prometheus_docker_network_";
const DOCKER_LABEL_NETWORK_IP: &str = "prometheus_docker_network_ip";
const DOCKER_LABEL_PORT_PREFIX: &str = "prometheus_docker_port_";
const DOCKER_LABEL_PORT_PRIVATE: &str = "prometheus_docker_port_private";
const DOCKER_LABEL_PORT_PUBLIC: &str = "prometheus_docker_port_public";
const DOCKER_LABEL_PORT_PUBLIC_IP: &str = "prometheus_docker_port_public_ip";

pub struct DockerDiscovery {
	port: u16,
	host_networking_host: String,
	client: Docker
}

impl DockerDiscovery {

	pub fn new(args: Arguments) -> DockerDiscovery {
		let conf = args.convert();
		let docker = Docker::new(&args.host).unwrap();
		let discovery = DockerDiscovery {
			port: conf.port,
			host_networking_host: conf.host_networking_host,
			client: docker
		};
		Ok(discovery)
	}

	pub async fn refresh(&self) -> Vec<Target> {
		let mut tg = Vec::<Target>::new();

		let opts = ContainerListOpts::builder().all(true).build();

		let containers = match self.client.containers().list(&opts).await {
			Ok(containers) => Ok(containers),
			Err(e) => Err(OSError(format!("error while listing containers: {}", e.to_string())))
		}.unwrap();

		let network_labels: HashMap<String, HashMap<String, String>> = match get_networks_labels(&self.client, DOCKER_LABEL).await {
			Ok(network_labels) => Ok(network_labels),
			Err(err) => Err(format!("error while computing network labels: {}", err).into()),
		}.unwrap();

		for c in containers {
			if c.names.is_empty() {
				continue;
			}

			let mut common_labels = HashMap::new();
			common_labels.insert(String::from(DOCKER_LABEL_CONTAINER_ID), c.id.clone());
			common_labels.insert(String::from(DOCKER_LABEL_CONTAINER_NAME), c.names[0].clone());
			common_labels.insert(String::from(DOCKER_LABEL_CONTAINER_NETWORK_MODE), c.host_config.clone().unwrap().network_mode.clone());

			for (k, v) in c.labels {
				let ln = sanitize_label_name(&k);
				common_labels.insert(format!("{}{}", DOCKER_LABEL_CONTAINER_LABEL_PREFIX, ln), v);
			}

			for (id, n) in c.network_settings.clone().unwrap().networks.unwrap() {
				let mut added = false;

				for p in c.ports.clone().unwrap() {
					if p.type_ != "tcp" {
						continue;
					}
					let mut labels = HashMap::new();
					labels.insert(String::from(DOCKER_LABEL_NETWORK_IP), p.ip.unwrap().clone());
					labels.insert(String::from(DOCKER_LABEL_PORT_PRIVATE), p.private_port.to_string());

					if p.public_port > 0 {
						labels.insert(String::from(DOCKER_LABEL_PORT_PUBLIC), p.public_port.to_string());
						labels.insert(String::from(DOCKER_LABEL_PORT_PUBLIC_IP), p.ip.clone());
					}

					for (k, v) in &common_labels {
						labels.insert(k.clone(), v.clone());
					}

					if let Some(network_label) = network_labels.get(&id) {
						for (k, v) in network_label {
							labels.insert(k.clone(), v.clone());
						}
					}
					let addr = format!("{:?}:{}", n.ip_address, p.private_port);
					labels.insert(ADDRESS_LABEL.to_string(), addr.clone());
					tg.push(labels);
					added = true;
				}

				if !added {
					let mut labels = HashMap::new();
					labels.insert(DOCKER_LABEL_NETWORK_IP.to_string(), n.ip_address.unwrap().clone());

					for (k, v) in &common_labels {
						labels.insert(k.clone(), v.clone());
					}

					if let Some(network_label) = network_labels.get(&n.network_id.unwrap()) {
						for (k, v) in network_label {
							labels.insert(k.clone(), v.clone());
						}
					}

					let hc = c.host_config.clone();
					let addr = if hc.unwrap().network_mode.clone() != "host" {
						format!("{:?}:{}", n.ip_address, self.port)
					} else {
						self.host_networking_host.clone()
					};
					labels.insert(ADDRESS_LABEL.to_string(), addr);
					tg.push(labels);
				}
			}
		}
		info!(format!("docker targets: {:?}", tg));
		Ok(vec![tg])
	}
}

pub fn sanitize_label_name(name: &str) -> String {
	let invalid_label_char_re = Regex::new(r"[^a-zA-Z0-9_]").unwrap();
	invalid_label_char_re.replace_all(name, "_").to_string()
}