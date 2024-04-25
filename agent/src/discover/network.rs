use docker_api::Docker;
use std::collections::HashMap;
use std::string::String;

use iwm::error::Error::OSError;
use iwm::error::Result;

use crate::discover::docker_discovery::sanitize_label_name;

const LABEL_NETWORK_PREFIX: &str = "network_";
const LABEL_NETWORK_ID: &str = "network_id";
const LABEL_NETWORK_NAME: &str = "network_name";
const LABEL_NETWORK_SCOPE: &str = "network_scope";
const LABEL_NETWORK_INTERNAL: &str = "network_internal";
const LABEL_NETWORK_INGRESS: &str = "network_ingress";
const LABEL_NETWORK_LABEL_PREFIX: &str = "network_label_";

pub async fn get_networks_labels(
    client: &Docker,
    label_prefix: &str,
) -> Result<HashMap<String, HashMap<String, String>>> {
    let networks = match client.networks().list(&Default::default()).await {
        Ok(networks) => Ok(networks),
        Err(e) => Err(OSError(format!(
            "error while listing networks: {}",
            e.to_string()
        ))),
    }
    .unwrap();

    let mut labels = HashMap::<String, HashMap<String, String>>::new();
    for network in networks {
        let mut network_labels = HashMap::<String, String>::new();
        network_labels.insert(
            format!("{}{}", label_prefix, LABEL_NETWORK_ID),
            network.id.clone().unwrap(),
        );
        network_labels.insert(
            format!("{}{}", label_prefix, LABEL_NETWORK_NAME),
            network.name.clone().unwrap(),
        );
        network_labels.insert(
            format!("{}{}", label_prefix, LABEL_NETWORK_SCOPE),
            network.scope.clone().unwrap(),
        );
        network_labels.insert(
            format!("{}{}", label_prefix, LABEL_NETWORK_INTERNAL),
            network.internal.unwrap().to_string(),
        );
        network_labels.insert(
            format!("{}{}", label_prefix, LABEL_NETWORK_INGRESS),
            network.ingress.unwrap().to_string(),
        );

        for (k, v) in network.labels.unwrap() {
            let ln = sanitize_label_name(&k);
            network_labels.insert(
                format!("{}{}{}", label_prefix, LABEL_NETWORK_LABEL_PREFIX, ln),
                v,
            );
        }
        labels.insert(network.id.unwrap().clone(), network_labels);
    }
    Ok(labels)
}
