use prometheus::{Counter, CounterVec, Gauge, Opts, register, Registry};

pub trait Registerer {
    fn register_gauge(name: &str, help: &str) -> Gauge;
    fn register_counter(name: &str, help: &str) -> Counter;
    fn register_counter_vec(name: &str, help: &str, labels: &[&str]) -> CounterVec;
}

impl Registerer for Registry {

    fn register_gauge(name: &str, help: &str) -> Gauge {
        let gauge = Gauge::new(name, help).unwrap();
        register(Box::new(gauge.clone())).unwrap();
        gauge
    }

    fn register_counter(name: &str, help: &str) -> Counter {
        let counter = Counter::new(name, help).unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    }

    fn register_counter_vec(name: &str, help: &str, labels: &[&str]) -> CounterVec {
        let counter_vec = CounterVec::new(Opts::new(name, help), labels).unwrap();
        register(Box::new(counter_vec.clone())).unwrap();
        counter_vec
    }
}
