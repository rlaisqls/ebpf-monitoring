use std::time::Duration;
use common::ebpf::sd::target::EbpfTarget;
use crate::appender::Appendable;

pub struct Arguments {
    pub forward_to: Vec<Box<dyn Appendable>>,
    pub targets: Option<Vec<EbpfTarget>>,
    pub collect_interval: Option<Duration>,
    pub sample_rate: Option<i32>,
    pub pid_cache_size: Option<i32>,
    pub build_id_cache_size: Option<i32>,
    pub same_file_cache_size: Option<i32>,
    pub container_id_cache_size: Option<i32>,
    pub cache_rounds: Option<i32>,
    pub collect_user_profile: Option<bool>,
    pub collect_kernel_profile: Option<bool>,
    pub demangle: Option<String>,
    pub python_enabled: Option<bool>,
}
