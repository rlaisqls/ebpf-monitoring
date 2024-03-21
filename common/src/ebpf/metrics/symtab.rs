use prometheus::CounterVec;
use crate::ebpf::metrics::registry::Registerer;


pub struct SymtabMetrics {
    pub elf_errors: CounterVec,
    pub proc_errors: CounterVec,
    pub known_symbols: CounterVec,
    pub unknown_symbols: CounterVec,
    pub unknown_modules: CounterVec,
    pub unknown_stacks: CounterVec,
}

impl SymtabMetrics {
    pub fn new(reg: &dyn Registerer) -> SymtabMetrics {
        SymtabMetrics {
            elf_errors: reg.register_counter_vec(
                "pyroscope_symtab_elf_errors_total",
                "Total number of errors while trying to open an elf file",
                &["error"]
            ),
            proc_errors: reg.register_counter_vec(
                "pyroscope_symtab_proc_errors_total",
                "Total number of errors while trying refreshing /proc/pid/maps",
                &["error"]
            ),
            known_symbols: reg.register_counter_vec(
                "pyroscope_symtab_known_symbols_total",
                "Total number of successfully resolved symbols",
                &["service_name"]
            ),
            unknown_symbols: reg.register_counter_vec(
                "pyroscope_symtab_unknown_symbols_total",
                "Total number of unresolved symbols for a module",
                &["service_name"]
            ),
            unknown_modules: reg.register_counter_vec(
                "pyroscope_symtab_unknown_modules_total",
                "Total number of unknown modules - could not find an entry in /proc/pid/maps for a RIP",
                &["service_name"]
            ),
            unknown_stacks: reg.register_counter_vec(
                "pyroscope_symtab_unknown_stacks_total",
                "Total number of stacks with unknowns > knowns",
                &["service_name"]
            ),
        }
    }
}
