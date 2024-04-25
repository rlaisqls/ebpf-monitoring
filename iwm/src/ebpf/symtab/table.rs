use log::info;
use crate::ebpf::symtab::symtab::SymbolTable;

#[derive(Clone, Debug)]
pub struct Symbol {
    pub(crate) start: u64,
    pub(crate) name: String,
    pub(crate) module: String,
}

impl Default for Symbol {
    fn default() -> Self {
        Self {
            start: 0,
            name: "".to_string(),
            module: "".to_string(),
        }
    }
}

pub struct SymbolTab {
    pub(crate) symbols: Vec<Symbol>,
    base: u64,
}

impl SymbolTab {
    pub(crate) fn new(symbols: Vec<Symbol>) -> Self {
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
    fn refresh(&mut self) {}
    fn cleanup(&mut self) {}

    fn resolve(&mut self, addr: u64) -> Option<Symbol> {
        if self.symbols.is_empty() {
            return None;
        }
        let addr = addr - self.base;
        if addr < self.symbols[0].start {
            return None;
        }
        let index = self
            .symbols
            .binary_search_by(|sym| sym.start.cmp(&addr))
            .unwrap_or_else(|index| index - 1);
        //dbg!(&self.symbols);
        return if let Some(s) = self.symbols.get(index) {
            Some(s.clone())
        } else {
            None
        };
    }
}

