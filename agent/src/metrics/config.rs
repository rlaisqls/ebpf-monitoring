use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

pub struct RemoteWriteConfig {
    url: Url,
    remote_timeout: Duration,
    headers: HashMap<String, String>,
    name: String,
    send_exemplars: bool,
    send_native_histograms: bool,
}

impl Default for RemoteWriteConfig {
    fn default() -> Self {
        Self {
            url: Url::from_str("").unwrap(),
            remote_timeout: Duration::from_secs(10),
            headers: HashMap::new(),
            name: "prometheus".to_string(),
            send_exemplars: false,
            send_native_histograms: false
        }
    }
}