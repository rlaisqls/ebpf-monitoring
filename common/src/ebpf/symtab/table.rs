use crate::ebpf::symtab::symtab::SymbolTable;

#[derive(Debug)]
pub struct SymbolTab {
    pub(crate) symbols: Vec<Sym>,
    base: u64,
}

#[derive(Debug)]
pub struct Sym {
    start: u64,
    name: String,
}

pub struct Symbol {
    pub(crate) start: u64,
    pub(crate) name: String,
    pub(crate) module: String
}

impl SymbolTab {
    pub(crate) fn new(symbols: Vec<Sym>) -> Self {
        SymbolTab { symbols, base: 0 }
    }

    fn rebase(&mut self, base: u64) {
        self.base = base;
    }

    fn debug_string(&self) -> String {
        String::from("SymbolTab {TODO}")
    }
}

impl SymbolTable for SymbolTab {

    fn refresh(&mut self) {
    }

    fn cleanup(&mut self) {
    }

    fn resolve(&self, addr: u64) -> Option<&Sym> {
        if self.symbols.is_empty() {
            return None;
        }
        let addr = addr - self.base;
        if addr < self.symbols[0].start {
            return None;
        }
        let index = self.symbols
            .binary_search_by(|sym| sym.start.cmp(&addr))
            .unwrap_or_else(|index| index - 1);
        self.symbols.get(index)
    }
}