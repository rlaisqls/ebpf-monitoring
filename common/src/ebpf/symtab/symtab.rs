use goblin::pe::symbol::Symbol;
use crate::ebpf::symtab::elf::symbol_table::SymTabDebugInfo;

pub trait SymbolTable {
    fn refresh(&mut self);
    fn cleanup(&mut self);
    fn resolve(&self, addr: u64) -> Symbol;
}

pub trait SymbolNameResolver {
    fn refresh(&mut self);
    fn cleanup(&mut self);
    fn debug_info(&self) -> SymTabDebugInfo;
    fn is_dead(&self) -> bool;
    fn resolve(&self, addr: u64) -> String;
}

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
    fn resolve(&self, _addr: u64) -> String {
        String::new()
    }
}
