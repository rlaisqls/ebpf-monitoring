use prometheus::{CounterVec};
use common::common::labels::Labels;

#[derive(Debug, Copy, Clone)]
pub struct Metrics {
    pub sent_bytes: CounterVec,
    pub dropped_bytes: CounterVec,
    pub sent_profiles: CounterVec,
    pub dropped_profiles: CounterVec,
    pub retries: CounterVec,
}

impl Metrics {
    pub(crate) fn new(reg: &prometheus::Registry) -> Metrics {
        let sent_bytes = register_counter_vec(
            "iwm_write_sent_bytes_total",
            "Total number of compressed bytes sent to Pyroscope.",
            &["endpoint"],
            reg,
        );
        let dropped_bytes = register_counter_vec(
            "iwm_write_dropped_bytes_total",
            "Total number of compressed bytes dropped by Pyroscope.",
            &["endpoint"],
            reg,
        );
        let sent_profiles = register_counter_vec(
            "iwm_write_sent_profiles_total",
            "Total number of profiles sent to Pyroscope.",
            &["endpoint"],
            reg,
        );
        let dropped_profiles = register_counter_vec(
            "iwm_write_dropped_profiles_total",
            "Total number of profiles dropped by Pyroscope.",
            &["endpoint"],
            reg,
        );
        let retries = register_counter_vec(
            "iwm_write_retries_total",
            "Total number of retries to Pyroscope.",
            &["endpoint"],
            reg,
        );

        Metrics {
            sent_bytes,
            dropped_bytes,
            sent_profiles,
            dropped_profiles,
            retries,
        }
    }
}

pub struct Opts {
    namespace: str,
    subsystem: str,
    name: str,
    help: str,
    const_labels: Labels
}

fn register_counter_vec(name: &str, help: &str, labels: &[&str], reg: &prometheus::Registry) -> CounterVec {
    let opts = Opts::new(name, help);
    let counter = CounterVec::new(opts, labels)
        .expect("Failed to create CounterVec");

    if let Some(reg) = reg {
        reg.register(Box::new(counter.clone()))
            .expect("Failed to register CounterVec");
    }
    counter
}
