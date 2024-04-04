use prometheus::Registry;

use crate::ebpf::metrics::python::PythonMetrics;
use crate::ebpf::metrics::symtab::SymtabMetrics;

pub struct Metrics {
    pub symtab: SymtabMetrics,
    pub python: PythonMetrics,
}

impl Metrics {
    pub fn new(reg: &Registry) -> Self {
        let symtab = SymtabMetrics::new(reg);
        reg.register(Box::new(symtab.clone()))
            .expect("Failed to register SymtabMetrics");

        let python = PythonMetrics::new(reg);
        reg.register(Box::new(python.clone()))
            .expect("Failed to register PythonMetrics");

        Metrics { symtab, python }
    }
}