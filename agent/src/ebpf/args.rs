use std::time::Duration;
use crate::pyroscope::Appendable;
use crate::discovery::Target;

pub struct Arguments {
    pub forward_to: Vec<Appendable>,
    pub targets: Option<Vec<Target>>,
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
