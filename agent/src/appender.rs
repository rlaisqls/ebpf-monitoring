use std::sync::Arc;
use std::time::Instant;

use prometheus::Histogram;

use common::common::labels::Labels;
use common::ebpf::metrics::registry::Registerer;
use common::error::Result;

#[derive(Clone)]
pub struct RawSample {
    pub(crate) raw_profile: Vec<u8>,
}

pub trait Appender {
    fn append(&self, labels: Labels, samples: Vec<RawSample>) -> Result<()>;
}

pub trait Appendable {
    fn appender(&self) -> Box<dyn Appender>;
}

pub struct Fanout {
    children: Arc<Vec<Box<dyn Appender>>>,
    component_id: String,
    write_latency: Histogram,
}

impl Fanout {
    pub(crate) fn new(
        children: Arc<Vec<Box<dyn Appender>>>,
        component_id: String,
        mut register: Arc<dyn Registerer>
    ) -> Self {
        let histogram = register.register_histogram(
            "iwm_fanout_latency",
            "Write latency for sending to iwm profiles",
        );
        Fanout {
            children,
            component_id,
            write_latency: histogram,
        }
    }
}

impl Appendable for Fanout {
    fn appender(&self) -> Box<dyn Appender> {
        Box::new(AppenderImpl {
            children: self.children.clone(),
            component_id: self.component_id.clone(),
            write_latency: self.write_latency.clone(),
        })
    }
}

pub struct AppenderImpl {
    children: Arc<Vec<Box<dyn Appender>>>,
    component_id: String,
    write_latency: Histogram,
}

impl Appender for AppenderImpl {
    fn append(&self, labels: Labels, samples: Vec<RawSample>) -> Result<()> {
        let start_time = Instant::now();
        for child in self.children.iter() {
            child.append(labels.clone(), samples.clone()).unwrap();
        }
        let duration = start_time.elapsed();
        self.write_latency.observe(duration.as_secs_f64());
        Ok(())
    }
}
