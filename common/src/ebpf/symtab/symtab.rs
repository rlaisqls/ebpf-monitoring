use crate::ebpf::symtab::elf::symbol_table::SymTabDebugInfo;
use crate::ebpf::symtab::table::Symbol;

pub trait SymbolTable {
    fn refresh(&mut self);
    fn cleanup(&mut self);
    fn resolve(&mut self, addr: u64) -> Option<&Symbol>;
}

pub trait SymbolNameResolver {
    fn refresh(&mut self);
    fn cleanup(&mut self);
    fn debug_info(&self) -> SymTabDebugInfo;
    fn is_dead(&self) -> bool;
    fn resolve(&mut self, addr: u64) -> Option<String>;
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub struct NoopSymbolNameResolver;

impl SymbolNameResolver for NoopSymbolNameResolver {
    fn refresh(&mut self) {}
    fn cleanup(&mut self) {}
    fn debug_info(&self) -> SymTabDebugInfo {
        SymTabDebugInfo::default()
    }
    fn is_dead(&self) -> bool {
        false
    }
    fn resolve(&mut self, _addr: u64) -> Option<String> {
        None
    }
}
