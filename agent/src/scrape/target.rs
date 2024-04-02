use std::collections::HashMap;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::io::{copy, Cursor, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::net;
use std::sync::{Arc, RwLock};
use std::sync::atomic::Ordering;
use std::task::Context;
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest, Sha256};
use tonic::codegen::tokio_stream::StreamExt;
use url::Url;
use common::common::labels::{Label, Labels};
use common::ebpf::sd::target::METRIC_NAME;
use crate::appender::RawSample;
use crate::scrape::Group;
use crate::scrape::scrape::{Arguments, ProfilingConfig, ProfilingTarget};

pub const ALERT_NAME_LABEL: &str = "alertname";
pub const EXPORTED_LABEL_PREFIX: &str = "exported_";
pub const METRIC_NAME_LABEL: &str = "__name__";
pub const SCHEME_LABEL: &str = "__scheme__";
pub const ADDRESS_LABEL: &str = "__address__";
pub const METRICS_PATH_LABEL: &str = "__metrics_path__";
pub const SCRAPE_INTERVAL_LABEL: &str = "__scrape_interval__";
pub const SCRAPE_TIMEOUT_LABEL: &str = "__scrape_timeout__";
pub const RESERVED_LABEL_PREFIX: &str = "__";
pub const META_LABEL_PREFIX: &str = "__meta_";
pub const TMP_LABEL_PREFIX: &str = "__tmp_";
pub const PARAM_LABEL_PREFIX: &str = "__param_";
pub const JOB_LABEL: &str = "job";
pub const INSTANCE_LABEL: &str = "instance";
pub const BUCKET_LABEL: &str = "le";
pub const QUANTILE_LABEL: &str = "quantile";
pub const PROFILE_PATH: &str = "__profile_path__";
pub const PROFILE_NAME: &str = "__name__";
pub const SERVICE_NAME_LABEL: &str = "service_name";
pub const SERVICE_NAME_K8S_LABEL: &str = "__meta_kubernetes_pod_annotation_pyroscope_io_service_name";



// TargetHealth describes the health state of a target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetHealth {
    Unknown,
    Good,
    Bad,
}

// Target refers to a singular HTTP or HTTPS endpoint.
#[derive(Debug, Clone)]
pub struct Target {
    pub(crate) all_labels: Labels,
    public_labels: Labels,
    discovered_labels: Labels,

    params: HashMap<String, String>,
    pub(crate) hash: u64,
    url: String,

    mtx: RwLock<()>,
    pub(crate) last_error: Option<dyn Error>,
    pub(crate) last_scrape: Instant,
    pub(crate) last_scrape_duration: Duration,
    pub(crate) health: TargetHealth,
}

impl Target {
    pub(crate) fn new(
        lbls: Labels,
        discovered_labels: Labels,
        params: HashMap<String, Vec<String>>,
    ) -> Self {
        let public_labels: Vec<(String, String)> = lbls
            .iter()
            .filter(|l| !l.name.starts_with(&RESERVED_LABEL_PREFIX))
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

        if next > interval.as_nanos() {
            Duration::from_nanos((next - interval.as_nanos()) as u64)
        } else {
            Duration::from_nanos(next as u64)
        }
    }
}
impl PartialEq for Target {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}
impl Eq for Target {}

fn url_from_target(lbls: &Labels, params: &HashMap<String, Vec<String>>) -> String {
    let mut new_params = HashMap::new();

    for (k, v) in params.iter() {
        new_params.insert(k.clone(), v.clone());
    }

    for (name, value) in lbls.iter() {
        if !name.starts_with(PARAM_LABEL_PREFIX) { continue; }
        let ks = &name[PARAM_LABEL_PREFIX.len()..];

        if let Some(param) = new_params.get_mut(ks) {
            if !param.is_empty() {
                param[0] = value.clone();
            }
        } else {
            new_params.insert(ks.to_string(), vec![value.clone()]);
        }
    }

    let scheme = lbls.get(SCHEME_LABEL).unwrap_or(&String::new()).clone();
    let host = lbls.get(ADDRESS_LABEL).unwrap_or(&String::new()).clone();
    let path = lbls.get(METRICS_PATH_LABEL).unwrap_or(&String::new()).clone();

    let mut url = Url::parse(&format!("{}://{}{}", scheme, host, path)).unwrap();
    url.set_query(Some(&new_params.iter().map(|(k, v)| format!("{}={}", k, v.join(","))).collect::<Vec<_>>().join("&")));
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

impl Deref for Targets {
    type Target = Vec<Arc<RwLock<Target>>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Targets {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<Arc<RwLock<Target>>>> for Targets {
    fn from(targets: Vec<Arc<RwLock<Target>>>) -> Self {
        Targets(targets)
    }
}

pub fn populate_labels(mut lset: Labels, cfg: Arguments) -> Result<(Labels, Labels), Box<dyn Error>> {

    // Copy labels into the labelset for the target if they are not set already.
    let scrape_labels = vec![
        ("job", cfg.job_name.clone().unwrap_or_default()),
        ("__scheme__", cfg.scheme.clone().unwrap_or_default()),
    ];

    for (name, value) in scrape_labels {
        if lset.get(name).is_none() {
            lset.set(name, value.trim())?;
        }
    }

    // Encode scrape query parameters as labels.
    if let Some(params) = cfg.params {
        for (key, values) in params {
            if let Some(value) = values.first() {
                lset.set(format!("{}{}", PARAM_LABEL_PREFIX, key), value)?;
            }
        }
    }

    if let None = lset.get(ADDRESS_LABEL) {
        return Err("no address".into());
    }

    let add_port = |s: &str| -> bool {
        if let Ok((_, _, err)) = net::SocketAddr::from_str(s) {
            return err.is_none();
        }
        false
    };

    if let Some(addr) = lset.get(ADDRESS_LABEL) {
        if add_port(addr) {
            let scheme = lset.get(SCHEME_LABEL).unwrap_or("http");
            let port = match scheme {
                "http" => "80",
                "https" => "443",
                _ => return Err(format!("invalid scheme: {}", scheme).into()),
            };
            let addr = format!("{}:{}", addr, port).trim();
            lset.set(ADDRESS_LABEL, addr)?;
        }
    }

    for l in lset.iter() {
        if l.name().starts_with(META_LABEL_PREFIX) {
            lset.del(l.name());
        }
    }

    if let None = lset.get(INSTANCE_LABEL) {
        let addr = lset.get(ADDRESS_LABEL).unwrap().trim();
        lset.set(INSTANCE_LABEL, addr)?;
    }

    if let None = lset.get(SERVICE_NAME_LABEL) {
        let inferred_service_name = infer_service_name(&lset).trim();
        lset.set(SERVICE_NAME_LABEL, inferred_service_name)?;
    }

    Ok((lset, lset.clone()));
}

fn targets_from_group(
    group: &Group,
    cfg: Arguments,
    target_types: HashMap<String, ProfilingTarget>,
) -> (Vec<Target>, Vec<Target>, Result<(), String>) {
    let mut targets = Vec::with_capacity(group.targets.len());
    let mut dropped_targets = Vec::new();

    for (i, tlset) in group.targets.iter().enumerate() {
        let mut lbls = Vec::with_capacity(tlset.len() + group.labels.len());

        for (ln, lv) in tlset {
            lbls.push(Label {
                name: ln.clone(),
                value: lv.clone(),
            });
        }
        for (ln, lv) in &group.labels {
            if !tlset.contains_key(ln) {
                lbls.push(Label {
                    name: ln.clone(),
                    value: lv.clone(),
                });
            }
        }

        let lset = Labels(lbls);
        match populate_labels(lset.clone(), cfg.clone()) {
            Ok(mut res) => {
                let lbls = res.0;
                let orig_labels = res.1;
                let mut prof_type = String::new();
                for label in lset.iter() {
                    if label.name() == "profile_name" {
                        prof_type = label.value();
                    }
                }

                if let Some(pcfg) = target_types.get(&prof_type) {
                    if pcfg.delta {
                        let seconds = (cfg.scrape_interval.as_secs() as i64 - 1).to_string();
                        lbls.push(Label {
                            name: "seconds".into(),
                            value: seconds.into(),
                        });
                    }
                }

                let params = cfg.params.clone().unwrap_or_default();
                targets.push(Target::new(lbls, orig_labels, params));
            }
            Err(err) => {
                // This is a dropped target
                // ensure we get the full url path for dropped targets
                let mut params = cfg.params.clone().unwrap_or_default();
                if !params.contains_key("job") {
                    params.insert("job".to_owned(), cfg.job_name.clone().unwrap_or_default());
                }
                dropped_targets.push(Target::new(lset, Default::default(), params));
            }
        }
    }

    (targets, dropped_targets, Ok(()))
}

fn infer_service_name(lset: &Labels) -> String {
    if let Some(k8s_service_name) = lset.get("service_name_k8s_label") {
        return k8s_service_name;
    }
    if let (Some(k8s_namespace), Some(k8s_container)) =
        (lset.get("__meta_kubernetes_namespace"), lset.get("__meta_kubernetes_pod_container_name"))
    {
        return format!("{}/{}", k8s_namespace, k8s_container);
    }
    if let Some(docker_container) = lset.get("__meta_docker_container_name") {
        return docker_container;
    }
    if let Some(swarm_service) = lset.get("__meta_dockerswarm_container_label_service_name") {
        return swarm_service;
    }
    if let Some(swarm_service) = lset.get("__meta_dockerswarm_service_name") {
        return swarm_service;
    }

    "unspecified".to_string()
}

pub fn labels_by_profiles(lset: &Labels, c: &ProfilingConfig) -> Vec<Labels> {
    let mut res = Vec::new();
    for (profile_type, profiling_config) in c.all_targets() {
        for p in profiling_config {
            if p.enabled {
                let mut l = lset.clone();
                l.insert(PROFILE_PATH, p.path.clone());
                l.insert(PROFILE_NAME, profile_type.to_string());
                res.push(l);
            }
        }
    }
    res
}