use std::collections::HashMap;
use std::fs::File;
use std::hash::{Hash};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Mutex};
use lru::LruCache;
use log::{debug, warn, info};

use crate::common::labels::Labels;
use crate::ebpf::sd::container_id::{container_id_from_target, get_container_id_from_pid};
use crate::ebpf::session::DiscoveryTarget;

pub const LABEL_CONTAINER_ID: &str = "__container_id__";
pub const METRIC_NAME: &str = "__name__";
pub const LABEL_PID: &str = "__process_pid__";
pub const LABEL_SERVICE_NAME: &str = "service_name";
pub const LABEL_SERVICE_NAME_K8S: &str = "__meta_kubernetes_pod_annotation_iwm_io_service_name";
pub const METRIC_VALUE: &str = "process_cpu";
pub const RESERVED_LABEL_PREFIX: &str = "__";

#[derive(Debug, Clone)]
pub struct EbpfTarget {
    pub labels: Labels,
    service_name: String,
    fingerprint: u64,
    fingerprint_calculated: bool,
}

impl EbpfTarget {
    fn new(cid: String, pid: u32, target: DiscoveryTarget) -> Self {
        let service_name = match target.get(LABEL_SERVICE_NAME) {
            Some(name) if !name.is_empty() => name.clone(),
            _ => infer_service_name(target.clone()),
        };

        let mut lset = HashMap::with_capacity(target.clone().len());
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

        EbpfTarget {
            labels: Labels::from_map(lset),
            service_name,
            fingerprint: 0,
            fingerprint_calculated: false,
        }
    }

    pub(crate) fn labels(mut self) -> (u64, Labels) {
        if !self.fingerprint_calculated {
            self.fingerprint = self.labels.hash();
            self.fingerprint_calculated = true;
        }
        (self.fingerprint, self.labels)
    }

    fn to_string(&self) -> String {
        self.labels.to_string()
    }

    pub(crate) fn service_name(&self) -> &str {
        &self.service_name
    }
}

fn infer_service_name(target: DiscoveryTarget) -> String {
    let label_service_name_k8s ="__meta_kubernetes_pod_annotation_iwm_io_service_name";
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

#[derive(Debug)]
pub struct TargetsOptions {
    pub targets: Vec<DiscoveryTarget>,
    pub targets_only: bool,
    pub container_cache_size: usize,
}

pub struct TargetFinder {
    cid2target: HashMap<String, EbpfTarget>,
    pid2target: HashMap<u32, EbpfTarget>,
    container_id_cache: Mutex<LruCache<u32, String>>,
    default_target: Option<EbpfTarget>,
    fs: File
}

impl TargetFinder {
    pub fn new(container_cache_size: usize, fs: File) -> TargetFinder {
        TargetFinder {
            cid2target: HashMap::new(),
            pid2target: HashMap::new(),
            container_id_cache: Mutex::new(
                LruCache::new(NonZeroUsize::try_from(container_cache_size).unwrap())
            ),
            default_target: None,
            fs
        }
    }

    pub(crate) fn find_target(&self, pid: &u32) -> Option<EbpfTarget> {
        if let Some(target) = self.pid2target.get(pid) {
            return Some(target.clone());
        }

        let mut cache = self.container_id_cache.lock().unwrap();
        if let Some(cid) = cache.get(pid).cloned() {
            return self.cid2target.get(&cid).cloned()
        }

        if let Some(cid) = get_container_id_from_pid(pid) {
            cache.put(pid.clone(), cid.clone());
            return self.cid2target.get(&cid).cloned();
        }
        return None;
    }

    pub(crate) fn remove_dead_pid(&mut self, pid: &u32) {
        self.pid2target.remove(pid);
        let mut cache = self.container_id_cache.lock().unwrap();
        cache.pop(pid);
    }

    pub(crate) fn update(&mut self, args: &TargetsOptions) {
        info!("target update");
        self.set_targets(args);
        self.resize_container_id_cache(args.container_cache_size);
    }

    fn set_targets(&mut self, opts: &TargetsOptions) {
        debug!("targets opts {:?}", opts);
        debug!("set targets count {}", opts.targets.len());
        let mut container_id2_target = HashMap::new();
        let mut pid2_target = HashMap::new();

        for target in &opts.targets {
            info!("{}", target["__address__"]);
            if let Some(pid) = pid_from_target(target) {
                let t = EbpfTarget::new("".to_string(), pid.clone(), target.clone());
                pid2_target.insert(pid, t);
            } else if let Some(cid) = container_id_from_target(target) {
                let t = EbpfTarget::new(cid.clone(), 0, target.clone());
                dbg!(&t);
                container_id2_target.insert(cid, t);
            }
        }

        if !opts.targets.is_empty() && container_id2_target.is_empty() && pid2_target.is_empty() {
            warn!("No targets found");
        }

        self.cid2target = container_id2_target;
        self.pid2target = pid2_target;

        self.default_target = None;
        debug!("created targets: {}", self.cid2target.len());
    }

    fn resize_container_id_cache(&mut self, size: usize) {
        self.container_id_cache.lock().unwrap().resize(NonZeroUsize::try_from(size).unwrap());
    }

    pub fn debug_info(&mut self) -> Vec<String> {
        self.cid2target.clone()
            .iter_mut()
            .map(|(_, &mut ref target)| {
                let (key, value) = target.clone().labels();
                format!("{}: {}", key, value)
            })
            .collect()
    }

    fn targets(&self) -> Vec<EbpfTarget> {
        self.cid2target.values().cloned().collect()
    }
}

fn pid_from_target(target: &DiscoveryTarget) -> Option<u32> {
    if let Some(t) = target.get(LABEL_PID) {
        if let Ok(pid) = u32::from_str(t) {
            return Some(pid);
        }
    }
    None
}
