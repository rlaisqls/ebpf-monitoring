use crate::elf::SymTabDebugInfo;

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
    fn is_dead(&self) -> bool {
        false
    }

    fn debug_info(&self) -> SymTabDebugInfo {
        SymTabDebugInfo {}
    }

    fn resolve(&self, _addr: u64) -> String {
        String::new()
    }

    fn refresh(&mut self) {}

    fn cleanup(&mut self) {}
}
