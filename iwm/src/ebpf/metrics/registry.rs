use prometheus::{Counter, CounterVec, exponential_buckets, Gauge, Histogram, HistogramOpts, Opts, Registry};

pub trait Registerer {
    fn register_gauge(&self, name: &str, help: &str) -> Gauge;
    fn register_counter(&self, name: &str, help: &str) -> Counter;
    fn register_counter_vec(&self, name: &str, help: &str, labels: &[&str]) -> CounterVec;
    fn register_histogram(&self, name: &str, help: &str) -> Histogram;
}

impl Registerer for Registry {

    fn register_gauge(&self, name: &str, help: &str) -> Gauge {
        let gauge = Gauge::new(name, help).unwrap();
        self.register(Box::new(gauge.clone())).unwrap();
        gauge
    }

    fn register_counter(&self, name: &str, help: &str) -> Counter {
        let counter = Counter::new(name, help).unwrap();
        self.register(Box::new(counter.clone())).unwrap();
        counter
    }

    fn register_counter_vec(&self, name: &str, help: &str, labels: &[&str]) -> CounterVec {
        let counter_vec = CounterVec::new(Opts::new(name, help), labels).unwrap();
        self.register(Box::new(counter_vec.clone())).unwrap();
        counter_vec
    }

    fn register_histogram(&self, name: &str, help: &str) -> Histogram {
        let histogram = Histogram::with_opts(
            HistogramOpts::new(name, help)
                .buckets(exponential_buckets(1.0, 2.0, 10).unwrap())
        ).unwrap();
        self.register(Box::new(histogram.clone())).unwrap();
        histogram
    }
}
