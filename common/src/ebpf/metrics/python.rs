use prometheus::{Counter, CounterVec};

use crate::ebpf::metrics::registry::Registerer;

pub struct PythonMetrics {
    pub pid_data_error: CounterVec,
    pub lost_samples: Counter,
    pub symbol_lookup: CounterVec,
    pub unknown_symbols: CounterVec,
    pub stacktrace_error: Counter,
    pub process_init_success: CounterVec,
    pub load: Counter,
    pub load_error: Counter,
}

impl PythonMetrics {
    pub fn new(reg: &dyn Registerer) -> PythonMetrics {
        PythonMetrics {
            pid_data_error: reg.register_counter_vec(
                "pyroscope_ebpf_active_targets",
                "Current number of active targets being tracked by the ebpf component",
                &["service_name"]
            ),
            lost_samples: reg.register_counter(
                "pyroscope_pyperf_lost_samples_total",
                "Total number of samples that were lost due to a buffer overflow",
            ),
            symbol_lookup: reg.register_counter_vec(
                "pyroscope_pyperf_symbol_lookup_total",
                "Total number of symbol lookups",
                &["service_name"]
            ),
            unknown_symbols: reg.register_counter_vec(
                "pyroscope_pyperf_unknown_symbols_total",
                "Total number of unknown symbols",
                &["service_name"]
            ),
            stacktrace_error: reg.register_counter(
                "pyroscope_pyperf_stacktrace_errors_total",
                "Total number of errors while trying to collect stacktrace",
            ),
            process_init_success: reg.register_counter_vec(
                "pyroscope_pyperf_process_init_success_total",
                "Total number of successful init calls",
                &["service_name"]
            ),
            load: reg.register_counter(
                "pyroscope_pyperf_load",
                "Total number of pyperf loads",
            ),
            load_error: reg.register_counter(
                "pyroscope_pyperf_load_error_total",
                "Total number of pyperf load errors",
            ),
        }
    }
}
