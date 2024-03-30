use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{BufRead, BufReader};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use lru::LruCache;
use log::{debug, warn};

use crate::common::labels::Labels;
use crate::ebpf::sd::container_id::container_id_from_target;

pub const LABEL_CONTAINER_ID: &str = "__container_id__";
const METRIC_NAME: &str = "__name__";
const LABEL_PID: &str = "__process_pid__";
const LABEL_SERVICE_NAME: &str = "service_name";
const LABEL_SERVICE_NAME_K8S: &str = "__meta_kubernetes_pod_annotation_iwm_io_service_name";
const METRIC_VALUE: &str = "process_cpu";
const RESERVED_LABEL_PREFIX: &str = "__";

pub(crate) type DiscoveryTarget = HashMap<String, String>;

#[derive(Debug)]
pub struct Target {
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


pub(crate) struct TargetsOptions {
    targets: Vec<DiscoveryTarget>,
    targets_only: bool,
    default_target: DiscoveryTarget,
    container_cache_size: usize,
}

pub struct TargetFinder {
    cid2target: HashMap<String, Target>,
    pid2target: HashMap<u32, Target>,
    container_id_cache: Mutex<LruCache<u32, String>>,
    default_target: Option<Arc<Target>>,
    fs: File,
    sync: Mutex<()>
}

impl TargetFinder {
    fn new(container_cache_size: usize, fs: File) -> TargetFinder {
        TargetFinder {
            cid2target: HashMap::new(),
            pid2target: HashMap::new(),
            container_id_cache: Mutex::new(
                LruCache::new(NonZeroUsize::try_from(container_cache_size).unwrap())
            ),
            default_target: None,
            fs,
            sync: Mutex::new(())
        }
    }

    pub(crate) fn find_target(&self, pid: u32) -> Option<Target> {
        if let Some(&target) = self.pid2target.get(&pid) {
            return Some(*target.clone());
        }

        let cid = {
            let mut cache = self.container_id_cache.lock().unwrap();
            cache.get(&pid).cloned()
        };

        match cid {
            Some(cid) => self.cid2target.get(&cid).cloned(),
            None => self.default_target.clone(),
        }
    }

    fn remove_dead_pid(&mut self, pid: u32) {
        self.pid2target.remove(&pid);
        let mut cache = self.container_id_cache.lock().unwrap();
        cache.pop(&pid);
    }

    pub(crate) fn update(&mut self, args: TargetsOptions) {
        let mut guard = self.sync.lock().unwrap();
        self.set_targets(&args);
        self.resize_container_id_cache(args.container_cache_size);
    }

    fn set_targets(&mut self, opts: &TargetsOptions) {
        debug!(self.l, "set targets"; "count" => opts.targets.len());
        let mut container_id2_target = HashMap::new();
        let mut pid2_target = HashMap::new();

        for target in &opts.targets {
            if let Some(pid) = pid_from_target(target) {
                let t = Target::new("".to_string(), pid, target.clone());
                pid2_target.insert(pid, t);
            } else if let Some(cid) = container_id_from_target(target) {
                let t = Target::new(cid.clone(), 0, target.clone());
                container_id2_target.insert(cid.clone(), t);
            }
        }

        if !opts.targets.is_empty() && container_id2_target.is_empty() && pid2_target.is_empty() {
            warn!("No targets found");
        }

        self.cid2target = container_id2_target;
        self.pid2target = pid2_target;

        self.default_target = if opts.targets_only {
            None
        } else {
            Some(
                Arc::from(Target::new("".to_string(), 0, opts.default_target.clone()))
            )
        };

        debug!(self.l, "created targets"; "count" => self.cid2target.len());
    }

    fn resize_container_id_cache(&mut self, size: usize) {
        self.container_id_cache.resize(size);
    }

    pub fn debug_info(&mut self) -> Vec<String> {
        self.cid2target.clone()
            .iter_mut()
            .map(|(_, &mut target)| {
                let (key, value) = target.labels(); // Cannot move
                format!("{}: {}", key, value)
            })
            .collect()
    }

    fn targets(&self) -> Vec<Arc<Target>> {
        self.cid2target.values().cloned().collect()
    }
}


fn pid_from_target(target: &DiscoveryTarget) -> u32 {
    if let Some(t) = target.get(LABEL_PID) {
        if let Ok(pid) = u32::from_str(t) {
            return pid;
        }
    }
    0
}
