use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::net;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use parking_lot::RwLock as ParkingLotRwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::{Url, UrlQuery};

// TargetHealth describes the health state of a target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum TargetHealth {
    Unknown,
    Good,
    Bad,
}

// Target refers to a singular HTTP or HTTPS endpoint.
#[derive(Debug, Clone)]
struct Target {
    all_labels: Vec<(String, String)>,
    public_labels: Vec<(String, String)>,
    discovered_labels: Vec<(String, String)>,
    params: HashMap<String, String>,
    hash: u64,
    url: String,
    last_error: Option<Box<dyn Error + Send + Sync>>,
    last_scrape: SystemTime,
    last_scrape_duration: Duration,
    health: TargetHealth,
    mtx: RwLock<()>,
}

impl Target {
    fn new(
        lbls: Vec<(String, String)>,
        discovered_labels: Vec<(String, String)>,
        params: HashMap<String, String>,
    ) -> Self {
        let public_labels: Vec<(String, String)> = lbls
            .iter()
            .filter(|(name, _)| !name.starts_with(&model::ReservedLabelPrefix))
            .cloned()
            .collect();
        let url = url_from_target(&lbls, &params);
        let hash = calculate_hash(&public_labels, &url);

        Target {
            all_labels: lbls,
            public_labels,
            discovered_labels,
            params,
            hash,
            url,
            last_error: None,
            last_scrape: SystemTime::now(),
            last_scrape_duration: Duration::from_secs(0),
            health: TargetHealth::Unknown,
            mtx: RwLock::new(()),
        }
    }

    fn offset(&self, interval: Duration) -> Duration {
        let now = SystemTime::now();
        let base = now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() % interval.as_nanos();
        let offset = self.hash % interval.as_nanos() as u64;
        let next = base + offset as u128;

        if next > interval.as_nanos() as u128 {
            Duration::from_nanos((next - interval.as_nanos() as u128) as u64)
        } else {
            Duration::from_nanos(next as u64)
        }
    }

    fn params(&self) -> HashMap<String, String> {
        self.params.clone()
    }

    fn labels(&self) -> Vec<(String, String)> {
        self.public_labels.clone()
    }

    fn discovered_labels(&self) -> Vec<(String, String)> {
        self.discovered_labels.clone()
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn hash(&self) -> u64 {
        self.hash
    }

    fn last_error(&self) -> Option<Box<dyn Error + Send + Sync>> {
        self.last_error.clone()
    }

    fn last_scrape(&self) -> SystemTime {
        self.last_scrape
    }

    fn last_scrape_duration(&self) -> Duration {
        self.last_scrape_duration
    }

    fn health(&self) -> TargetHealth {
        self.health.clone()
    }
}

impl PartialEq for Target {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for Target {}

impl Hash for Target {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

fn url_from_target(lbls: &Vec<(String, String)>, params: &HashMap<String, String>) -> String {
    let mut new_params = params.clone();

    for (k, v) in lbls {
        if k.starts_with(&model::ParamLabelPrefix) {
            let ks = &k[model::ParamLabelPrefix.len()..];

            if let Some(values) = new_params.get_mut(ks) {
                if !values.is_empty() {
                    values[0] = v.clone();
                } else {
                    values.push(v.clone());
                }
            } else {
                new_params.insert(ks.clone(), vec![v.clone()]);
            }
        }
    }

    let mut url = Url::parse(&lbls.get(&model::SchemeLabel).unwrap().1).unwrap();
    url.set_host(Some(&lbls.get(&model::AddressLabel).unwrap().1))
        .unwrap();
    url.set_path(&lbls.get(&ProfilePath).unwrap().1);
    url.set_query(Some(&UrlQuery::from_pairs(new_params.iter())));

    url.into_string()
}

fn calculate_hash(public_labels: &Vec<(String, String)>, url: &str) -> u64 {
    let mut hasher = Sha256::new();

    for (k, v) in public_labels {
        hasher.update(k);
        hasher.update(v);
    }
    hasher.update(url);

    let result = hasher.finalize();
    let bytes = result.as_slice();
    let mut hash = 0u64;

    for &b in bytes.iter() {
        hash = hash << 8 | b as u64;
    }

    hash
}

// Targets is a sortable list of targets.
#[derive(Debug)]
struct Targets(Vec<Arc<RwLock<Target>>>);

impl Targets {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn sort(&mut self) {
        self.0.sort_by(|a, b| a.read().url().cmp(b.read().url()));
    }
}

impl std::ops::Deref for Targets {
    type Target = Vec<Arc<RwLock<Target>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Targets {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<Arc<RwLock<Target>>>> for Targets {
    fn from(targets: Vec<Arc<RwLock<Target>>>) -> Self {
        Targets(targets)
    }
}

impl Into<Vec
