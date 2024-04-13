use std::sync::Arc;
use prometheus::{Counter, CounterVec, Gauge};
use crate::ebpf::metrics::metrics::ProfileMetrics;
use crate::ebpf::metrics::registry::Registerer;

pub struct EbpfMetrics {
    pub targets_active: Gauge,
    pub profiling_sessions_total: Counter,
    pub profiling_sessions_failing_total: Counter,
    pub pprofs_total: CounterVec,
    pub pprof_bytes_total: CounterVec,
    pub pprof_samples_total: CounterVec,
    pub profile_metrics: Arc<ProfileMetrics>
}

impl EbpfMetrics {
    pub fn new(reg: &dyn Registerer) -> EbpfMetrics {
        EbpfMetrics {
            targets_active: reg.register_gauge(
                "iwm_ebpf_active_targets",
                "Current number of active targets being tracked by the ebpf component"
            ),
            profiling_sessions_total: reg.register_counter(
                "iwm_ebpf_profiling_sessions_total",
                "Total number of profiling sessions started by the ebpf component"
            ),
            profiling_sessions_failing_total: reg.register_counter(
                "iwm_ebpf_profiling_sessions_failing_total",
                "Total number of profiling sessions failed to complete by the ebpf component"
            ),
            pprofs_total: reg.register_counter_vec(
                "iwm_ebpf_pprofs_total",
                "Total number of pprof profiles collected by the ebpf component",
                &["service_name"]
            ),
            pprof_bytes_total: reg.register_counter_vec(
                "iwm_ebpf_pprof_bytes_total",
                "Total number of pprof profiles collected by the ebpf component",
                &["service_name"]
            ),
            pprof_samples_total: reg.register_counter_vec(
                "iwm_ebpf_pprof_samples_total",
                "Total number of pprof profiles collected by the ebpf component",
                &["service_name"]
            ),
            profile_metrics: Arc::new(ProfileMetrics::new(reg))
        }
    }
}