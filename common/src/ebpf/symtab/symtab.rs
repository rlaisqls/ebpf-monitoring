use crate::ebpf::symtab::elf::symbol_table::SymTabDebugInfo;
use crate::ebpf::symtab::gcache::Resource;
use crate::ebpf::symtab::table::Symbol;

pub trait SymbolTable {
    fn refresh(&mut self);
    fn cleanup(&mut self);
    fn resolve(&mut self, addr: u64) -> Option<&Symbol>;
}

impl Resource for dyn SymbolTable {
    fn refresh(&mut self) {
        self.refresh()
    }
    fn cleanup(&mut self) {
        self.cleanup()
    }
}

pub trait SymbolNameResolver {
    fn refresh(&mut self);
    fn cleanup(&mut self);
    fn debug_info(&self) -> SymTabDebugInfo;
    fn is_dead(&self) -> bool;
    fn resolve(&mut self, addr: u64) -> Option<String>;
}

impl Resource for dyn SymbolNameResolver {
    fn refresh(&mut self) {
        self.refresh()
    }
    fn cleanup(&mut self) {
        self.cleanup()
    }
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
