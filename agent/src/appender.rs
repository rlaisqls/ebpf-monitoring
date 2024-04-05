use common::error::Result;
use std::sync::Arc;
use std::time::Instant;

use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use common::common::labels::Labels;
use common::ebpf::metrics::registry::Registerer;

#[derive(Clone)]
pub struct RawSample {
    pub(crate) raw_profile: Vec<u8>,
}

pub trait Appender {
    fn append(&self, labels: Labels, samples: Vec<RawSample>) -> Result<()>;
}

pub trait Appendable {
    fn appender(&self) -> Arc<dyn Appender + Send + Sync>;
}

pub struct Fanout {
    children: Arc<Vec<dyn Appendable + Send + Sync>>,
    component_id: String,
    write_latency: Histogram,
}

impl Fanout {
    pub(crate) fn new(
        children: Arc<Vec<dyn Appendable>>,
        component_id: String,
        mut register: Arc<dyn Registerer>
    ) -> Self {
        let histogram = Histogram::new(exponential_buckets(1.0, 2.0, 10));
        register.register(
            "iwm_fanout_latency",
            "Write latency for sending to iwm profiles",
            histogram.clone()
        );
        Fanout {
            children: Arc::new(children),
            component_id,
            write_latency: histogram,
        }
    }

    pub fn update_children(&mut self, children: Arc<Vec<dyn Appendable>>) {
        self.children = children;
    }
}

impl Appendable for Fanout {
    fn appender(&self) -> Arc<dyn Appender + Send + Sync> {
        Arc::new(AppenderImpl {
            children: self.children.clone(),
            component_id: self.component_id.clone(),
            write_latency: self.write_latency.clone(),
        })
    }
}

pub struct AppenderImpl {
    children: Arc<Vec<Arc<dyn Appendable + Send + Sync>>>,
    component_id: String,
    write_latency: Histogram,
}

impl Appender for AppenderImpl {
    fn append(&self, labels: Labels, samples: Vec<RawSample>) -> Result<()> {
        let start_time = Instant::now();
        for child in self.children.iter() {
            child.appender().append(labels.clone(), samples.clone()).unwrap();
        }
        let duration = start_time.elapsed();
        self.write_latency.observe(duration.as_secs_f64());
        Ok(())
    }
}
