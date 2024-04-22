use std::{
	collections::HashMap,
};


use docker_api::Docker;
use docker_api::opts::ContainerListOpts;

use log::{info};
use regex::Regex;






use crate::discover::discover::{ADDRESS_LABEL, Arguments, Target};
use crate::discover::network::get_networks_labels;


const DOCKER_LABEL: &str = "__meta_docker_";
const DOCKER_LABEL_CONTAINER_PREFIX: &str = "__meta_docker_container_";
const DOCKER_LABEL_CONTAINER_ID: &str = "__meta_docker_container_id";
const DOCKER_LABEL_CONTAINER_NAME: &str = "__meta_docker_container_name";
const DOCKER_LABEL_CONTAINER_NETWORK_MODE: &str = "__meta_docker_container_network_mode";
const DOCKER_LABEL_CONTAINER_LABEL_PREFIX: &str = "__meta_docker_container_label_";
const DOCKER_LABEL_NETWORK_PREFIX: &str = "__meta_docker_network_";
const DOCKER_LABEL_NETWORK_IP: &str = "__meta_docker_network_ip";
const DOCKER_LABEL_PORT_PREFIX: &str = "__meta_docker_port_";
const DOCKER_LABEL_PORT_PRIVATE: &str = "__meta_docker_port_private";
const DOCKER_LABEL_PORT_PUBLIC: &str = "__meta_docker_port_public";
const DOCKER_LABEL_PORT_PUBLIC_IP: &str = "__meta_docker_port_public_ip";

pub struct DockerDiscovery {
	port: u16,
	host_networking_host: String,
	client: Docker
}

impl DockerDiscovery {

	pub fn new(args: Arguments) -> DockerDiscovery {
		let docker = Docker::new(&args.host).unwrap();
		DockerDiscovery {
			port: args.port,
			host_networking_host: args.host_networking_host,
			client: docker
		}
	}

	pub async fn refresh(&self) -> Vec<Target> {
		let mut tg = Vec::<Target>::new();

		let opts = ContainerListOpts::builder().all(true).build();

		let containers = self.client.containers().list(&opts).await.unwrap();
		let network_labels: HashMap<String, HashMap<String, String>> =
			get_networks_labels(&self.client, DOCKER_LABEL).await.unwrap();

		for c in containers {
			if c.names.clone().unwrap().is_empty() {
				continue;
			}

			let mut common_labels = HashMap::new();

			info!("{} {}", c.names.clone().unwrap()[0].clone(), c.id.clone().unwrap());
			common_labels.insert(DOCKER_LABEL_CONTAINER_ID.to_string(), c.id.clone().unwrap());
			common_labels.insert(DOCKER_LABEL_CONTAINER_NAME.to_string(), c.names.clone().unwrap()[0].clone());
			common_labels.insert(DOCKER_LABEL_CONTAINER_NETWORK_MODE.to_string(), c.host_config.clone().unwrap().network_mode.clone().unwrap());

			for (k, v) in c.labels.unwrap() {
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
					if p.ip.is_some() {
						labels.insert(String::from(DOCKER_LABEL_NETWORK_IP), p.ip.clone().unwrap().clone());
					}
					labels.insert(String::from(DOCKER_LABEL_PORT_PRIVATE), p.private_port.clone().to_string());

					if p.public_port.is_some() && p.public_port.unwrap() > 0 {
						labels.insert(String::from(DOCKER_LABEL_PORT_PUBLIC), p.public_port.clone().unwrap().to_string());
						labels.insert(String::from(DOCKER_LABEL_PORT_PUBLIC_IP), p.ip.clone().unwrap());
					}

					for (k, v) in &common_labels {
						labels.insert(k.clone(), v.clone());
					}

					if let Some(network_label) = network_labels.get(&id) {
						for (k, v) in network_label {
							labels.insert(k.clone(), v.clone());
						}
					}
					if n.ip_address.is_some() {
						let addr = format!("{}:{}", n.ip_address.clone().unwrap(), p.private_port);
						labels.insert(ADDRESS_LABEL.to_string(), addr.clone());
					}
					tg.push(labels);
					added = true;
				}

				if !added {
					let mut labels = HashMap::new();
					labels.insert(DOCKER_LABEL_NETWORK_IP.to_string(), n.ip_address.clone().unwrap());

					for (k, v) in &common_labels {
						labels.insert(k.clone(), v.clone());
					}

					if let Some(network_label) = network_labels.get(&n.network_id.clone().unwrap()) {
						for (k, v) in network_label {
							labels.insert(k.clone(), v.clone());
						}
					}

					let hc = c.host_config.clone();
					let addr = if hc.unwrap().network_mode.clone().unwrap() != "host".to_string() {
						format!("{}:{}", n.ip_address.unwrap(), self.port)
					} else {
						self.host_networking_host.clone()
					};
					labels.insert(ADDRESS_LABEL.to_string(), addr);
					tg.push(labels);
				}
			}
		}
		// info!("docker targets: {:?}", tg);
		tg
	}
}

pub fn sanitize_label_name(name: &str) -> String {
	let invalid_label_char_re = Regex::new(r"[^a-zA-Z0-9_]").unwrap();
	invalid_label_char_re.replace_all(name, "_").to_string()
}