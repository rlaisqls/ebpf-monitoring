use std::collections::HashMap;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{BufRead, BufReader};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use lru::LruCache;

use crate::common::labels::Labels;

const METRIC_NAME: &str = "__name__";
const LABEL_CONTAINER_ID: &str = "__container_id__";
const LABEL_PID: &str = "__process_pid__";
const LABEL_SERVICE_NAME: &str = "service_name";
const LABEL_SERVICE_NAME_K8S: &str = "__meta_kubernetes_pod_annotation_pyroscope_io_service_name";
const METRIC_VALUE: &str = "process_cpu";
const RESERVED_LABEL_PREFIX: &str = "__";


type DiscoveryTarget = HashMap<String, String>;

struct Target {
    labels: Labels,
    service_name: String,
    fingerprint: u64,
    fingerprint_calculated: bool,
}

impl Target {
    fn new(cid: String, pid: u32, target: DiscoveryTarget) -> Self {
        let service_name = match target.get(LABEL_SERVICE_NAME) {
            Some(name) if !name.is_empty() => name.clone(),
            _ => infer_service_name(target),
        };

        let mut lset = HashMap::with_capacity(target.len());
        for (k, v) in target.iter() {
            if k.starts_with(RESERVED_LABEL_PREFIX) && k != METRIC_NAME {
                continue;
            }
            lset.insert(k.clone(), v.clone());
        }
        if lset.get(METRIC_NAME).map_or(true, |v| v.is_empty()) {
            lset.insert(METRIC_NAME.into(), METRIC_VALUE.into());
        }
        if lset.get(LABEL_SERVICE_NAME).map_or(true, |v| v.is_empty()) {
            lset.insert(LABEL_SERVICE_NAME.into(), service_name.clone());
        }
        if !cid.is_empty() {
            lset.insert(LABEL_CONTAINER_ID.into(), cid.into());
        }
        if pid != 0 {
            lset.insert(LABEL_PID.into(), pid.to_string());
        }

        Target {
            labels: Labels::from_map(lset),
            service_name,
            fingerprint: 0,
            fingerprint_calculated: false,
        }
    }

    fn labels(mut self) -> (u64, Labels) {
        if !self.fingerprint_calculated {
            let mut hasher = DefaultHasher::new();
            self.labels.hash(&mut hasher);
            self.fingerprint = hasher.finish();
            self.fingerprint_calculated = true;
        }
        (self.fingerprint, self.labels)
    }

    fn to_string(&self) -> String {
        self.labels.to_string()
    }

    fn service_name(&self) -> &str {
        &self.service_name
    }
}

fn infer_service_name(target: DiscoveryTarget) -> String {
    let label_service_name_k8s ="__meta_kubernetes_pod_annotation_pyroscope_io_service_name";
    if let Some(k8s_service_name) = target.get(label_service_name_k8s).filter(|s| !s.is_empty()) {
        return k8s_service_name.clone();
    }
    if let (Some(k8s_namespace), Some(k8s_container)) =
        (target.get("__meta_kubernetes_namespace"), target.get("__meta_kubernetes_pod_container_name"))
    {
        if !k8s_namespace.is_empty() && !k8s_container.is_empty() {
            return format!("ebpf/{}/{}", k8s_namespace, k8s_container);
        }
    }
    if let Some(docker_container) = target.get("__meta_docker_container_name").filter(|s| !s.is_empty()) {
        return docker_container.clone();
    }
    if let Some(swarm_service) = target.get("__meta_dockerswarm_container_label_service_name").filter(|s| !s.is_empty()) {
        return swarm_service.clone();
    }
    if let Some(swarm_service) = target.get("__meta_dockerswarm_service_name").filter(|s| !s.is_empty()) {
        return swarm_service.clone();
    }
    "unspecified".to_string()
}

struct TargetFinder {
    cid2target: Arc<Mutex<HashMap<String, Arc<Target>>>>,
    pid2target: Arc<Mutex<HashMap<u32, Arc<Target>>>>,

    container_id_cache: Arc<Mutex<LruCache<u32, String>>>,
    default_target: Option<Arc<Target>>,
    fs: Arc<fs::File>,
    sync: Mutex<()>,
}

lazy_static::lazy_static! {
    static ref CGROUP_CONTAINER_ID_RE: regex::Regex =
        regex::Regex::new(r#"^.*/(?:.*-)?([0-9a-f]{64})(?:\.|\s*$)"#).unwrap();
}

impl TargetFinder {
    fn new(fs: Arc<fs::File>, container_cache_size: usize) -> Self {
        Self {
            cid2target: Arc::new(Mutex::new(HashMap::new())),
            pid2target: Arc::new(Mutex::new(HashMap::new())),
            container_id_cache: Arc::new(
                Mutex::new(LruCache::new(NonZeroUsize::try_from(container_cache_size).unwrap()))
            ),
            default_target: None,
            fs,
            sync: Mutex::new(()),
        }
    }

    fn find_target(&self, pid: u32) -> Option<Arc<Target>> {
        let pid2target = self.pid2target.lock().unwrap();
        if let Some(target) = pid2target.get(&pid) {
            return Some(target.clone());
        }

        let cid = {
            let mut cache = self.container_id_cache.lock().unwrap();
            cache.get(&pid).cloned()
        };

        if let Some(cid) = cid {
            let cid2target = self.cid2target.lock().unwrap();
            cid2target.get(&cid).cloned()
        } else {
            self.default_target.clone()
        }
    }

    fn get_container_id_from_pid(&self, pid: u32) -> Option<ContainerID> {
        let path = format!("/proc/{}/cgroup", pid);
        let file = match self.fs.open(&path) {
            Ok(f) => f,
            Err(_) => return None,
        };
        let reader = BufReader::new(file);

        for line in reader.lines() {
            if let Ok(line) = line {
                if let Some(container_id) = get_container_id_from_cgroup(&line) {
                    return Some(container_id.into());
                }
            }
        }
        None
    }
}

fn get_container_id_from_cgroup(line: &str) -> Option<String> {
    if let Some(captures) = CGROUP_CONTAINER_ID_RE.captures(line) {
        if let Some(cid) = captures.get(1) {
            return Some(cid.as_str().to_owned());
        }
    }
    None
}

const KNOWN_CONTAINER_ID_PREFIXES: [&str; 3] = ["docker://", "containerd://", "cri-o://"];

pub type ContainerID = String;

fn get_container_id_from_k8s(k8s_container_id: &str) -> Option<ContainerID> {
    for &prefix in KNOWN_CONTAINER_ID_PREFIXES.iter() {
        if k8s_container_id.starts_with(prefix) {
            return Some(k8s_container_id.trim_start_matches(prefix).to_owned());
        }
    }
    None
}
