use prometheus::Registry;

use crate::ebpf::metrics::python::PythonMetrics;
use crate::ebpf::metrics::symtab::SymtabMetrics;

#[derive(Copy, Clone)]
pub struct Metrics {
    pub symtab: SymtabMetrics
}

impl Metrics {
    pub fn new(reg: &Registry) -> Self {
        let symtab = SymtabMetrics::new(reg);
        reg.register(Box::new(symtab.clone()))
            .expect("Failed to register SymtabMetrics");

        Metrics { symtab }
    }
}