use prometheus::{CounterVec, Opts};
use crate::ebpf::metrics::registry::Registerer;

#[derive(Debug, Clone)]
pub struct WriteMetrics {
    pub sent_bytes: CounterVec,
    pub dropped_bytes: CounterVec,
    pub sent_profiles: CounterVec,
    pub dropped_profiles: CounterVec,
    pub retries: CounterVec,
}

impl WriteMetrics {
    pub fn new(reg: &dyn Registerer) -> WriteMetrics {

        let sent_bytes = reg.register_counter_vec(
            "iwm_write_sent_bytes_total",
            "Total number of compressed bytes sent to Pyroscope.",
            &["endpoint"],
        );
        let dropped_bytes = reg.register_counter_vec(
            "iwm_write_dropped_bytes_total",
            "Total number of compressed bytes dropped by Pyroscope.",
            &["endpoint"],
        );
        let sent_profiles = reg.register_counter_vec(
            "iwm_write_sent_profiles_total",
            "Total number of profiles sent to Pyroscope.",
            &["endpoint"],
        );
        let dropped_profiles = reg.register_counter_vec(
            "iwm_write_dropped_profiles_total",
            "Total number of profiles dropped by Pyroscope.",
            &["endpoint"],
        );
        let retries = reg.register_counter_vec(
            "iwm_write_retries_total",
            "Total number of retries to Pyroscope.",
            &["endpoint"],
        );

        WriteMetrics {
            sent_bytes,
            dropped_bytes,
            sent_profiles,
            dropped_profiles,
            retries,
        }
    }
}