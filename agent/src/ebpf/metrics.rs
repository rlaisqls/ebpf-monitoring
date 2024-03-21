use prometheus::{Counter, CounterVec, Gauge};
use common::ebpf::metrics::metrics::Metrics;
use common::ebpf::metrics::registry::Registerer;

struct metrics {
    targets_active: Gauge,
    profiling_sessions_total: Counter,
    profiling_sessions_failing_total: Counter,
    pprofs_total: CounterVec,
    pprof_bytes_total: CounterVec,
    pprof_samples_total: CounterVec,
    ebpf_metrics: *Metrics
}

impl metrics {
    pub fn new(reg: &dyn Registerer) -> Metrics {
        metrics {
            targets_active: reg.register_gauge(
                "pyroscope_ebpf_active_targets",
                "Current number of active targets being tracked by the ebpf component"
            ),
            profiling_sessions_total: reg.register_counter(
                "pyroscope_ebpf_profiling_sessions_total",
                "Total number of profiling sessions started by the ebpf component"
            ),
            profiling_sessions_failing_total: reg.register_counter(
                "pyroscope_ebpf_profiling_sessions_failing_total",
                "Total number of profiling sessions failed to complete by the ebpf component"
            ),
            pprofs_total: reg.register_counter_vec(
                "pyroscope_ebpf_pprofs_total",
                "Total number of pprof profiles collected by the ebpf component",
                &["service_name"]
            ),
            pprof_bytes_total: reg.register_counter_vec(
                "pyroscope_ebpf_pprof_bytes_total",
                "Total number of pprof profiles collected by the ebpf component",
                &["service_name"]
            ),
            pprof_samples_total: reg.register_counter_vec(
                "pyroscope_ebpf_pprof_samples_total",
                "Total number of pprof profiles collected by the ebpf component",
                &["service_name"]
            ),
            ebpf_metrics: Metrics::new(reg)
        }
    }
}