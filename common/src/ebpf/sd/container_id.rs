use crate::ebpf::sd::target::{LABEL_CONTAINER_ID};
use crate::ebpf::session::DiscoveryTarget;

pub type ContainerID = String;

pub fn container_id_from_target(target: &DiscoveryTarget) -> Option<ContainerID> {
    if let Some(cid) = target.get(LABEL_CONTAINER_ID) {
        if !cid.is_empty() {
            return Some(cid.clone());
        }
    }
    if let Some(cid) = target.get("__meta_kubernetes_pod_container_id") {
        if !cid.is_empty() {
            return Some(get_container_id_from_k8s(cid).unwrap());
        }
    }
    if let Some(cid) = target.get("__meta_docker_container_id") {
        if !cid.is_empty() {
            return Some(cid.clone());
        }
    }
    if let Some(cid) = target.get("__meta_dockerswarm_task_container_id") {
        if !cid.is_empty() {
            return Some(cid.clone());
        }
    }
    None
}

const KNOWN_CONTAINER_ID_PREFIXES: [&str; 3] = ["docker://", "containerd://", "cri-o://"];

pub fn get_container_id_from_k8s(k8s_container_id: &str) -> Option<ContainerID> {
    for &prefix in KNOWN_CONTAINER_ID_PREFIXES.iter() {
        if k8s_container_id.starts_with(prefix) {
            return Some(k8s_container_id.trim_start_matches(prefix).to_owned());
        }
    }
    None
}

lazy_static::lazy_static! {
    static ref CGROUP_CONTAINER_ID_RE: regex::Regex =
        regex::Regex::new(r#"^.*/(?:.*-)?([0-9a-f]{64})(?:\.|\s*$)"#).unwrap();
}

pub fn get_container_id_from_cgroup(line: &str) -> Option<String> {
    if let Some(captures) = CGROUP_CONTAINER_ID_RE.captures(line) {
        if let Some(cid) = captures.get(1) {
            return Some(cid.as_str().to_owned());
        }
    }
    None
}
