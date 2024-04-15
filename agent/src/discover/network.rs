use std::collections::HashMap;

use docker_api::Docker;
use serde::__private::de::Content::String;

use common::error::Error::OSError;
use common::error::Result;

use crate::discover::docker_discovery::sanitize_label_name;

const LABEL_NETWORK_PREFIX: &str = "network_";
const LABEL_NETWORK_ID: &str = &format!("{}id", LABEL_NETWORK_PREFIX);
const LABEL_NETWORK_NAME: &str = &format!("{}name", LABEL_NETWORK_PREFIX);
const LABEL_NETWORK_SCOPE: &str = &format!("{}scope", LABEL_NETWORK_PREFIX);
const LABEL_NETWORK_INTERNAL: &str = &format!("{}internal", LABEL_NETWORK_PREFIX);
const LABEL_NETWORK_INGRESS: &str = &format!("{}ingress", LABEL_NETWORK_PREFIX);
const LABEL_NETWORK_LABEL_PREFIX: &str = &format!("{}label_", LABEL_NETWORK_PREFIX);

pub async fn get_networks_labels(
	client: &Docker,
	label_prefix: &str,
) -> Result<HashMap<String, HashMap<String, String>>> {

	let networks = tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()
		.unwrap()
		.block_on(async {
			match client.networks().list(&Default::default()).await {
				Ok(networks) => Ok(networks),
				Err(e) => {
					Err(OSError(format!("error while listing networks: {}", e.to_string())))
				}
			}
		}).unwrap();

	let mut labels = HashMap::<String, HashMap<String, String>>::new();
	for network in networks {
		let mut network_labels = HashMap::<String, String>::new();
		network_labels.insert(format!("{}{}", label_prefix, LABEL_NETWORK_ID), network.id.clone().unwrap());
		network_labels.insert(format!("{}{}", label_prefix, LABEL_NETWORK_NAME), network.name.clone().unwrap());
		network_labels.insert(format!("{}{}", label_prefix, LABEL_NETWORK_SCOPE), network.scope.clone().unwrap());
		network_labels.insert(format!("{}{}", label_prefix, LABEL_NETWORK_INTERNAL), network.internal.to_string());
		network_labels.insert(format!("{}{}", label_prefix, LABEL_NETWORK_INGRESS), network.ingress.to_string());

		for (k, v) in network.labels.unwrap() {
			let ln = sanitize_label_name(&k);
			network_labels.insert(
				format!("{}{}{}", label_prefix, LABEL_NETWORK_LABEL_PREFIX, ln),
				v,
			);
		}
		labels.insert(network.id.clone(), network_labels);
	}
	Ok(labels)
}
