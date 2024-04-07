use prometheus::Registry;

use crate::ebpf::metrics::symtab::SymtabMetrics;

#[derive(Clone)]
pub struct Metrics {
    pub symtab: SymtabMetrics
}

impl Metrics {
    pub fn new(reg: &Registry) -> Self {
        let symtab = SymtabMetrics::new(reg);
        Metrics { symtab }
    }
}