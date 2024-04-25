
use crate::ebpf::metrics::registry::Registerer;

use crate::ebpf::metrics::symtab::SymtabMetrics;

#[derive(Clone)]
pub struct ProfileMetrics {
    pub symtab: SymtabMetrics
}

impl ProfileMetrics {
    pub fn new(reg: &dyn Registerer) -> Self {
        let symtab = SymtabMetrics::new(reg);
        ProfileMetrics { symtab }
    }
}