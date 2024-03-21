use std::error::Error;
use std::sync::Arc;
use std::time::Instant;

use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;

#[derive(Clone)]
struct RawSample {
    raw_profile: Vec<u8>,
}

pub trait Appender {
    fn append(&self, samples: Vec<RawSample>) -> Result<(), Box<dyn Error>>;
}

pub trait Appendable {
    fn appender(&self) -> Arc<dyn Appender + Send + Sync>;
}

pub struct Fanout {
    children: Arc<Vec<Arc<dyn Appendable + Send + Sync>>>,
    component_id: String,
    write_latency: Histogram,
}

impl Fanout {
    fn new(
        children: Vec<Arc<dyn Appendable + Send + Sync>>,
        component_id: String,
        mut register: Registry
    ) -> Self {
        let histogram = Histogram::new(exponential_buckets(1.0, 2.0, 10));
        register.register(
            "pyroscope_fanout_latency",
            "Write latency for sending to pyroscope profiles",
            histogram.clone()
        );
        Fanout {
            children: Arc::new(children),
            component_id,
            write_latency: histogram,
        }
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


struct AppenderImpl {
    children: Arc<Vec<Arc<dyn Appendable + Send + Sync>>>,
    component_id: String,
    write_latency: Histogram,
}

impl Appender for AppenderImpl {
    fn append(&self, samples: Vec<RawSample>) -> Result<(), Box<dyn Error>> {
        let start_time = Instant::now();
        for child in self.children.iter() {
            child.appender().append(samples.clone())?;
        }
        let duration = start_time.elapsed();
        self.write_latency.observe(duration.as_secs_f64());
        Ok(())
    }
}
